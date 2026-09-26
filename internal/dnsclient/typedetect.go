package dnsclient

import (
	"context"
	"fmt"
	"sync"
	"time"

	"dns-opti/internal/model"
	"dns-opti/internal/policy"
)

// TypeDetectOptions configures a resolver type detection run.
type TypeDetectOptions struct {
	// Timeout bounds one probe query.
	Timeout time.Duration
	// Concurrency is how many resolvers are probed at once. Each resolver is
	// probed sequentially, because the probes of one resolver share its
	// connection.
	Concurrency int
}

// TypeDetectProgress is called once per resolver as its detection completes.
//
// It is an alias so the interactive layer can name the type without importing
// this package's transport surface.
type TypeDetectProgress = policy.ProgressFunc

// DetectTypes probes each server against the category test domains and reports
// what it observed.
//
// # What this can and cannot establish
//
// The probes can only prove *that* a resolver filters, not *what* it filters.
// Vendors differ in how they answer a blocked name:
//
//   - Cloudflare's Families resolver returns 0.0.0.0, which is observable.
//   - AdGuard and Quad9 return NXDOMAIN or a sinkhole for their blocklists.
//   - Some resolvers simply let the query time out, which is
//     indistinguishable from a resolver that is unreachable or behind a network
//     that drops the query.
//
// Worse, whether a *documented* filter is observable at all depends on the
// network path: on a host whose provider answers some of these names upstream,
// a filtering resolver can look unfiltered. The consequence is deliberately
// built into the result: a resolver that answers every probe normally is
// reported as 原生 only because nothing was observed, and any resolver that
// produced no usable answer at all is reported as 未确认 rather than 原生.
//
// The verdict is therefore evidence, not proof, and the report says so.
func DetectTypes(ctx context.Context, servers []model.Server, opts TypeDetectOptions, progress TypeDetectProgress) []policy.Detection {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 8
	}

	out := make([]policy.Detection, len(servers))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	for i, s := range servers {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, s model.Server) {
			defer wg.Done()
			defer func() { <-sem }()

			det := detectOne(ctx, s, opts)
			out[i] = det

			mu.Lock()
			done++
			n := done
			mu.Unlock()
			if progress != nil {
				progress(n, len(servers), det)
			}
		}(i, s)
	}
	wg.Wait()
	return out
}

// detectOne probes a single resolver over every category test domain.
func detectOne(ctx context.Context, s model.Server, opts TypeDetectOptions) policy.Detection {
	det := policy.Detection{
		Server:  s.DisplayIP(),
		Name:    s.Name,
		Curated: s.Policy,
		Answers: make([]policy.AnswerState, len(policy.Probes)),
	}

	q, err := New(s, Options{Timeout: opts.Timeout, WarmupDomain: "example.com", Family: s.Family})
	if err != nil {
		det.Observed = policy.VerdictUnknown
		det.Note = "无法建立连接: " + err.Error()
		for i := range det.Answers {
			det.Answers[i] = policy.AnswerUnusable
		}
		return det
	}
	defer q.Close()

	for i, p := range policy.Probes {
		if ctx.Err() != nil {
			det.Answers[i] = policy.AnswerUnusable
			continue
		}
		det.Answers[i] = probeOnce(ctx, q, p, opts.Timeout)
	}

	det.Observed = policy.VerdictFrom(det.Answers)
	if det.Observed == policy.VerdictUnknown {
		det.Note = "三个测试域均无可用应答（可能被网络阻断或服务器不可达），无法判断类型"
	}
	return det
}

// probeOnce queries one probe domain and classifies the answer.
//
// The context is applied through the querier's own timeout rather than by
// cancelling the query, because the transports do not all accept a context; a
// per-probe timeout is what the Options.Timeout already provides.
func probeOnce(_ context.Context, q Querier, p policy.Probe, timeout time.Duration) policy.AnswerState {
	res, err := q.Lookup(p.Domain)
	if err != nil {
		// A transport failure is not evidence about filtering policy.
		return policy.AnswerUnusable
	}
	if !res.Answered() {
		return policy.AnswerUnusable
	}
	return policy.ClassifyAnswer(res.Rcode, res.Addrs)
}

// Summary counts the verdicts of a detection run.
type Summary struct {
	Native    int
	Security  int
	Unknown   int
	Agree     int
	Disagree  int
	NotTested int
}

// Summarize folds a detection run into the counts the report shows.
func Summarize(dets []policy.Detection) Summary {
	var s Summary
	for _, d := range dets {
		if d.Server == "" {
			s.NotTested++
			continue
		}
		switch d.Observed {
		case policy.VerdictSecurity:
			s.Security++
		case policy.VerdictNative:
			s.Native++
		default:
			s.Unknown++
		}
		if d.Curated == policy.Unknown {
			// Nothing was documented to compare against.
			continue
		}
		if d.Observed == policy.VerdictUnknown {
			continue
		}
		if d.Agrees() {
			s.Agree++
		} else {
			s.Disagree++
		}
	}
	return s
}

// Disagreements returns the detections whose observation contradicts the
// curated table, which is the list a maintainer has to review.
func Disagreements(dets []policy.Detection) []policy.Detection {
	var out []policy.Detection
	for _, d := range dets {
		if d.Curated == policy.Unknown || d.Observed == policy.VerdictUnknown {
			continue
		}
		if !d.Agrees() {
			out = append(out, d)
		}
	}
	return out
}

// DescribeDetection renders a one-line verdict for the CLI listing.
func DescribeDetection(d policy.Detection) string {
	return fmt.Sprintf("%s → %s", d.Server, d.Observed.Label())
}
