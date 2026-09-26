// Package scheduler drives the benchmark.
//
// The model follows PLAN 3.1: one global worker pool whose unit of work is a
// single DNS server (with its protocol). A worker owns one server for the
// whole of that server's test and splits that server's domains over a small
// fixed number of connections (Options.PerServer, default
// config.DefaultPerServerConcurrency), each connection owned by exactly one
// goroutine so a Querier is never used concurrently. The split exists because
// a server's queries then overlap instead of queueing: measured on 19 real
// servers it halves the time a server spends in the run with no change in
// success rate or latency, while more than a few connections per server starts
// to drop replies (see the config constant's comment). Different servers are
// tested in parallel, bounded by the pool size.
package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"dns-opti/internal/config"
	"dns-opti/internal/dnsclient"
	"dns-opti/internal/model"
)

// unreachableFailStreak is the number of consecutive failed queries (a failed
// warm-up counts as the first strike) after which a server is declared
// unreachable. The remaining queries are then recorded as failures
// immediately, instead of each waiting out the full timeout. This stops a dead
// server — a DoH3 endpoint on a network that blocks QUIC, say — from
// dominating the total run time.
const unreachableFailStreak = 5

// Options configures a scheduler run.
type Options struct {
	// Servers are the test units; each is tested by exactly one worker.
	Servers []model.Server
	// Domains are queried attempts times each, per server; the (domain,
	// attempt) pairs are handed to the server's connections in this order.
	Domains []model.Domain
	// Attempts is the number of queries per domain per server.
	Attempts int
	// Concurrency is the number of workers, i.e. servers tested at once.
	Concurrency int
	// PerServer is how many connections one server is tested with, each
	// driven by its own goroutine and Querier. Values below 1 mean
	// config.DefaultPerServerConcurrency.
	PerServer int
	// Query configures the transport of every query.
	Query dnsclient.Options
}

// ProgressEvent describes one completed query. It carries the running totals
// so a progress display does not have to keep its own counters.
type ProgressEvent struct {
	Server  model.Server
	Domain  string
	Group   string
	Success bool
	Latency time.Duration
	Done    int
	Total   int
}

// Sink receives every raw record as it is produced. A non-nil error aborts the
// run.
type Sink func(record model.RawRecord) error

// ResolvedFunc receives a server once its transport has settled on an address
// family and a literal address. A hostname endpoint only reveals either after
// resolution, so the caller cannot know them before the run; this callback is
// how the resolved values reach the report.
type ResolvedFunc func(server model.Server)

// Scheduler runs the benchmark over a fixed set of servers and domains.
type Scheduler struct {
	opts     Options
	sink     Sink
	progress func(ProgressEvent)
	resolved ResolvedFunc

	total int64 // total number of queries in the run

	mu       sync.Mutex
	done     int
	firstErr error
	abort    context.CancelFunc
}

// New creates a scheduler. progress and resolved may be nil.
func New(opts Options, sink Sink, progress func(ProgressEvent)) *Scheduler {
	if opts.Attempts < 1 {
		opts.Attempts = 1
	}
	if opts.Concurrency < 1 {
		// The same automatic default the CLI uses, so a caller that builds
		// Options directly cannot silently run at a different parallelism.
		opts.Concurrency = config.AutoConcurrency()
	}
	if opts.PerServer < 1 {
		opts.PerServer = config.DefaultPerServerConcurrency
	}
	if opts.Query.Timeout <= 0 {
		opts.Query.Timeout = config.DefaultTimeout
	}
	if sink == nil {
		sink = func(model.RawRecord) error { return nil }
	}
	return &Scheduler{
		opts:     opts,
		sink:     sink,
		progress: progress,
		total:    int64(len(opts.Servers)) * int64(len(opts.Domains)) * int64(opts.Attempts),
	}
}

// OnResolved registers the callback invoked once per server with its resolved
// address family. It must be called before Run.
func (s *Scheduler) OnResolved(fn ResolvedFunc) { s.resolved = fn }

// Total returns the number of queries the run will perform.
func (s *Scheduler) Total() int { return int(s.total) }

// Run tests every server, honouring ctx cancellation. It returns the first
// sink error encountered, if any.
func (s *Scheduler) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.abort = cancel

	sem := make(chan struct{}, s.opts.Concurrency)
	var wg sync.WaitGroup

	for _, server := range s.opts.Servers {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(server model.Server) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				// A panic in one transport must not take down the whole run.
				if r := recover(); r != nil {
					s.fail(&panicError{value: r})
				}
			}()
			s.runServer(ctx, server)
		}(server)
	}

	wg.Wait()
	return s.firstErr
}

// serverTask is one planned query of one server: a domain at a given attempt.
type serverTask struct {
	domain  model.Domain
	attempt int
}

// runServer performs the complete test of one DNS server: open its
// connections, warm them up and then query every domain attempts times,
// spreading those queries over the connections.
func (s *Scheduler) runServer(ctx context.Context, server model.Server) {
	queriers := s.openQueriers(server)
	if len(queriers) == 0 {
		// The server cannot be tested at all (unsupported protocol, malformed
		// DoH address, ...). Every planned query is recorded as a failure so
		// the summary still shows the entry with a 0% success rate instead of
		// silently omitting it.
		s.recordAllFailed(ctx, server)
		return
	}
	defer func() {
		for _, q := range queriers {
			_ = q.Close()
		}
	}()

	// Record the family and the literal address the transport actually settled
	// on. A hostname endpoint only reveals either after resolution, and without
	// them an IPv6 run would be indistinguishable from a dual-stack one in the
	// report, and a hostname row could not be identified by IP. All connections
	// of one server share the endpoint, so the first one speaks for them.
	server.Family = queriers[0].Family()
	if ip := queriers[0].ResolvedIP(); ip != "" {
		server.IP = ip
	}
	if s.resolved != nil {
		s.resolved(server)
	}

	// Warm-up: establishes the connection and validates the endpoint before
	// any measurement starts. Its result is discarded (see PLAN 3.2), but a
	// failed warm-up counts as the first strike against the server below.
	// The strikes and the unreachable flag are shared by every connection of
	// the server: it is one endpoint failing, not one socket.
	st := &serverState{}
	for _, q := range queriers {
		if err := q.Warmup(); err != nil {
			st.strike()
		}
	}

	// The work list is the same set of queries the single-connection version
	// issued in order; the connections pull from it, so a server's progress
	// and totals are identical either way.
	tasks := make([]serverTask, 0, len(s.opts.Domains)*s.opts.Attempts)
	for _, domain := range s.opts.Domains {
		for attempt := 1; attempt <= s.opts.Attempts; attempt++ {
			tasks = append(tasks, serverTask{domain: domain, attempt: attempt})
		}
	}

	var next atomic.Int64
	var wg sync.WaitGroup
	for _, q := range queriers {
		wg.Add(1)
		go func(q dnsclient.Querier) {
			defer wg.Done()
			defer func() {
				// A panic in one transport must not take down the whole run.
				if r := recover(); r != nil {
					s.fail(&panicError{value: r})
				}
			}()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(tasks) {
					return
				}
				if ctx.Err() != nil {
					return
				}
				task := tasks[i]
				if st.blocked() {
					s.emit(server, task.domain, task.attempt, false, 0)
					continue
				}

				latency, qErr := q.Query(task.domain.Name)
				ok := qErr == nil
				s.emit(server, task.domain, task.attempt, ok, latency)
				st.observe(ok)
			}
		}(q)
	}
	wg.Wait()
}

// openQueriers creates the connections one server is tested with. It returns
// nil when the very first one cannot be created, and fewer connections than
// requested when a later one fails — a half-open server is still testable.
func (s *Scheduler) openQueriers(server model.Server) []dnsclient.Querier {
	queriers := make([]dnsclient.Querier, 0, s.opts.PerServer)
	for i := 0; i < s.opts.PerServer; i++ {
		q, err := dnsclient.New(server, s.opts.Query)
		if err != nil {
			if i == 0 {
				return nil
			}
			break
		}
		queriers = append(queriers, q)
	}
	return queriers
}

// serverState tracks the shared health of one server across its connections:
// one endpoint, so one consecutive-failure count.
type serverState struct {
	mu          sync.Mutex
	streak      int
	unreachable bool
}

// blocked reports whether the server has been declared unreachable.
func (st *serverState) blocked() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.unreachable
}

// observe records the outcome of one query and, once the consecutive failures
// reach unreachableFailStreak, declares the server unreachable so the
// remaining queries stop waiting out their timeouts.
func (st *serverState) observe(ok bool) {
	if ok {
		st.mu.Lock()
		st.streak = 0
		st.mu.Unlock()
		return
	}
	st.strike()
}

// strike counts one consecutive failure.
func (st *serverState) strike() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.streak++
	if st.streak >= unreachableFailStreak {
		st.unreachable = true
	}
}

// recordAllFailed writes a failed record for every planned query of a server
// that could not be used at all.
func (s *Scheduler) recordAllFailed(ctx context.Context, server model.Server) {
	for _, domain := range s.opts.Domains {
		for attempt := 1; attempt <= s.opts.Attempts; attempt++ {
			if ctx.Err() != nil {
				return
			}
			s.emit(server, domain, attempt, false, 0)
		}
	}
}

// emit hands one result to the sink and the progress callback.
func (s *Scheduler) emit(server model.Server, domain model.Domain, attempt int, success bool, latency time.Duration) {
	record := model.RawRecord{
		DNS:       server.Address,
		Name:      server.Name,
		Protocol:  server.Protocol,
		Domain:    domain.Name,
		Group:     domain.Group,
		Attempt:   attempt,
		Success:   success,
		LatencyMS: millis(latency),
		TS:        time.Now().Unix(),
	}

	if err := s.sink(record); err != nil {
		s.fail(err)
		return
	}

	s.mu.Lock()
	s.done++
	done := s.done
	s.mu.Unlock()

	if s.progress != nil {
		s.progress(ProgressEvent{
			Server:  server,
			Domain:  domain.Name,
			Group:   domain.Group,
			Success: success,
			Latency: latency,
			Done:    done,
			Total:   int(s.total),
		})
	}
}

// fail records the first fatal error and aborts the run.
func (s *Scheduler) fail(err error) {
	s.mu.Lock()
	if s.firstErr == nil {
		s.firstErr = err
	}
	abort := s.abort
	s.mu.Unlock()
	if abort != nil {
		abort()
	}
}

// millis converts a duration to milliseconds, rounded to microsecond
// precision so that a sub-millisecond local answer is not flattened to zero.
func millis(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d.Round(time.Microsecond)) / float64(time.Millisecond)
}

// panicError wraps a recovered panic into an error.
type panicError struct{ value any }

func (e *panicError) Error() string {
	return "测试过程中发生内部错误: " + toString(e.value)
}

func toString(v any) string {
	switch t := v.(type) {
	case error:
		return t.Error()
	case string:
		return t
	default:
		return "unknown panic"
	}
}
