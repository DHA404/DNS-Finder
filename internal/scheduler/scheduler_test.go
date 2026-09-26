package scheduler

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"dns-opti/internal/config"
	"dns-opti/internal/dnsclient"
	"dns-opti/internal/model"
)

// newTestScheduler builds a scheduler over a tiny workload without touching the
// network.
func newTestScheduler(t *testing.T, opts Options) *Scheduler {
	t.Helper()
	if len(opts.Servers) == 0 {
		opts.Servers = []model.Server{{Name: "x", Address: "127.0.0.1", Protocol: model.ProtocolUDP}}
	}
	if len(opts.Domains) == 0 {
		opts.Domains = []model.Domain{{Name: "example.com", Group: model.GroupCN}}
	}
	return New(opts, nil, nil)
}

// TestNewFallsBackToSharedDefaults verifies the scheduler uses the same
// automatic concurrency and timeout as the CLI, rather than keeping private
// copies that could drift from the documented defaults.
func TestNewFallsBackToSharedDefaults(t *testing.T) {
	s := newTestScheduler(t, Options{})

	if got, want := s.opts.Concurrency, config.AutoConcurrency(); got != want {
		t.Fatalf("默认并发数 = %d, 期望 config.AutoConcurrency() = %d", got, want)
	}
	if got, want := s.opts.Query.Timeout, config.DefaultTimeout; got != want {
		t.Fatalf("默认超时 = %v, 期望 config.DefaultTimeout = %v", got, want)
	}
}

// TestNewConcurrencyIsThreePerCPUThread pins the documented default so a change
// to it has to be deliberate.
func TestNewConcurrencyIsThreePerCPUThread(t *testing.T) {
	s := newTestScheduler(t, Options{})
	if got, want := s.opts.Concurrency, config.AutoConcurrency(); got != want {
		t.Fatalf("并发数 = %d, 期望 %d", got, want)
	}
	if config.DefaultConcurrencyMultiplier != 3 {
		t.Fatalf("DefaultConcurrencyMultiplier = %d, 期望 3", config.DefaultConcurrencyMultiplier)
	}
	if config.DefaultTimeout != 2*time.Second {
		t.Fatalf("DefaultTimeout = %v, 期望 2s", config.DefaultTimeout)
	}
}

// TestNewHonoursExplicitValues verifies an explicit configuration is never
// overridden by the fallbacks.
func TestNewHonoursExplicitValues(t *testing.T) {
	s := newTestScheduler(t, Options{
		Concurrency: 5,
		Query:       dnsclient.Options{Timeout: 9 * time.Second},
	})

	if s.opts.Concurrency != 5 {
		t.Fatalf("显式并发数被覆盖为 %d, 期望 5", s.opts.Concurrency)
	}
	if s.opts.Query.Timeout != 9*time.Second {
		t.Fatalf("显式超时被覆盖为 %v, 期望 9s", s.opts.Query.Timeout)
	}
}

// TestNewClampsAttempts verifies a non-positive attempt count becomes 1 rather
// than producing a zero-query run.
func TestNewClampsAttempts(t *testing.T) {
	for _, attempts := range []int{0, -3} {
		s := newTestScheduler(t, Options{Attempts: attempts})
		if s.opts.Attempts != 1 {
			t.Fatalf("Attempts=%d 被解析为 %d, 期望 1", attempts, s.opts.Attempts)
		}
	}
}

// TestNewFallsBackToSharedPerServer verifies a caller that builds Options
// directly still gets the documented per-server connection count.
func TestNewFallsBackToSharedPerServer(t *testing.T) {
	s := newTestScheduler(t, Options{})
	if got, want := s.opts.PerServer, config.DefaultPerServerConcurrency; got != want {
		t.Fatalf("PerServer = %d, 期望 config.DefaultPerServerConcurrency = %d", got, want)
	}
	if config.DefaultPerServerConcurrency != 2 {
		t.Fatalf("DefaultPerServerConcurrency = %d, 期望 2", config.DefaultPerServerConcurrency)
	}
}

// TestNewClampsPerServer verifies a non-positive per-server count falls back to
// the default instead of running zero connections (which would never query).
func TestNewClampsPerServer(t *testing.T) {
	for _, perServer := range []int{0, -1} {
		s := newTestScheduler(t, Options{PerServer: perServer})
		if s.opts.PerServer != config.DefaultPerServerConcurrency {
			t.Fatalf("PerServer=%d 被解析为 %d, 期望 %d",
				perServer, s.opts.PerServer, config.DefaultPerServerConcurrency)
		}
	}
}

// TestNewHonoursExplicitPerServer verifies an explicit per-server count is kept
// as given, including the single-connection serial mode.
func TestNewHonoursExplicitPerServer(t *testing.T) {
	s := newTestScheduler(t, Options{PerServer: 1})
	if s.opts.PerServer != 1 {
		t.Fatalf("显式 PerServer=1 被覆盖为 %d", s.opts.PerServer)
	}
	s = newTestScheduler(t, Options{PerServer: 4})
	if s.opts.PerServer != 4 {
		t.Fatalf("显式 PerServer=4 被覆盖为 %d", s.opts.PerServer)
	}
}

// TestRunRecordsEveryPlannedQuery verifies that the multi-connection split does
// not lose or duplicate work: an endpoint that cannot be constructed at all
// still produces exactly one record per planned query, with a contiguous
// progress count from 1 to Total. The endpoint is deliberately unusable so the
// test never touches the network.
func TestRunRecordsEveryPlannedQuery(t *testing.T) {
	domains := []model.Domain{
		{Name: "a.com", Group: model.GroupCN},
		{Name: "b.com", Group: model.GroupCN},
		{Name: "c.com", Group: model.GroupIntl},
	}
	for _, perServer := range []int{1, 2} {
		var mu sync.Mutex
		seen := map[string]int{}
		doneSet := map[int]bool{}
		var totals []int

		s := New(Options{
			Servers: []model.Server{
				// An unsupported protocol fails in dnsclient.New, which is the
				// path where a half-built connection set must still be recorded.
				{Name: "a", Address: "127.0.0.1", Protocol: model.Protocol("bogus")},
				{Name: "b", Address: "127.0.0.2", Protocol: model.Protocol("bogus")},
			},
			Domains:     domains,
			Attempts:    3,
			PerServer:   perServer,
			Concurrency: 1,
		}, func(r model.RawRecord) error {
			mu.Lock()
			defer mu.Unlock()
			seen[r.DNS+"|"+r.Domain+"|"+strconv.Itoa(r.Attempt)]++
			return nil
		}, func(ev ProgressEvent) {
			mu.Lock()
			defer mu.Unlock()
			doneSet[ev.Done] = true
			totals = append(totals, ev.Total)
		})

		if err := s.Run(context.Background()); err != nil {
			t.Fatalf("PerServer=%d Run: %v", perServer, err)
		}
		if got := len(seen); got != 18 {
			t.Fatalf("PerServer=%d 记录了 %d 种查询, 期望 18", perServer, got)
		}
		for key, n := range seen {
			if n != 1 {
				t.Fatalf("PerServer=%d 查询 %s 出现 %d 次, 期望 1 次", perServer, key, n)
			}
		}
		for done := 1; done <= 18; done++ {
			if !doneSet[done] {
				t.Fatalf("PerServer=%d 缺少进度 %d/18", perServer, done)
			}
		}
		for _, total := range totals {
			if total != 18 {
				t.Fatalf("PerServer=%d ProgressEvent.Total = %d, 期望 18", perServer, total)
			}
		}
		if s.Total() != 18 {
			t.Fatalf("PerServer=%d Total() = %d, 期望 18", perServer, s.Total())
		}
	}
}

// TestTotalCountsEveryQuery verifies the workload size the progress panel and
// the plan are sized from.
func TestTotalCountsEveryQuery(t *testing.T) {
	s := New(Options{
		Servers: []model.Server{
			{Name: "a", Address: "127.0.0.1", Protocol: model.ProtocolUDP},
			{Name: "b", Address: "127.0.0.2", Protocol: model.ProtocolUDP},
		},
		Domains: []model.Domain{
			{Name: "a.com", Group: model.GroupCN},
			{Name: "b.com", Group: model.GroupCN},
			{Name: "c.com", Group: model.GroupIntl},
		},
		Attempts: 3,
	}, nil, nil)

	if got, want := s.Total(), 2*3*3; got != want {
		t.Fatalf("Total() = %d, 期望 %d", got, want)
	}
}

// TestOnResolvedIsOptional verifies the resolved-family hook is optional, so a
// caller that does not care about it (tests, the plain CLI path) need not
// register one.
func TestOnResolvedIsOptional(t *testing.T) {
	s := newTestScheduler(t, Options{})
	if s.resolved != nil {
		t.Fatal("未注册回调时 resolved 应为 nil")
	}

	called := 0
	s.OnResolved(func(model.Server) { called++ })
	if s.resolved == nil {
		t.Fatal("注册回调后 resolved 仍为 nil")
	}
	s.resolved(model.Server{})
	if called != 1 {
		t.Fatalf("回调被调用 %d 次, 期望 1 次", called)
	}
}

// TestMillisRoundsToMicroseconds verifies a sub-millisecond answer is not
// flattened to zero, which would look like a cache hit rather than a fast reply.
func TestMillisRoundsToMicroseconds(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want float64
	}{
		{0, 0},
		{-time.Millisecond, 0},
		{500 * time.Microsecond, 0.5},
		{1500 * time.Microsecond, 1.5},
		{time.Millisecond, 1},
		{1234567 * time.Nanosecond, 1.235}, // rounds to microseconds
	}
	for _, tt := range tests {
		if got := millis(tt.in); got != tt.want {
			t.Fatalf("millis(%v) = %v, 期望 %v", tt.in, got, tt.want)
		}
	}
}
