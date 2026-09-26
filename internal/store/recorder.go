// Package store persists the results of a run.
//
// Raw records are streamed to a temporary JSON Lines file as they are
// produced, so that a long run never has to hold every measurement in memory.
// The summary is aggregated in memory (it is bounded by the number of servers
// times protocols times domain groups) and the final exported document joins
// the two: meta, raw and summary (see PLAN 3.3).
package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"dns-opti/internal/model"
)

// Recorder accumulates the results of a run: raw records go to a temporary
// JSON Lines file, aggregates stay in memory. It is safe for concurrent use.
type Recorder struct {
	mu sync.Mutex

	file *os.File
	buf  *bufio.Writer
	enc  *json.Encoder

	agg       map[string]*aggregate
	order     []string // preserves first-seen bucket order
	count     int
	tempPath  string
	closeOnce sync.Once
}

// aggregate accumulates the statistics of one (dns, protocol, group) bucket.
type aggregate struct {
	summary   model.Summary
	latencies []float64 // successful latencies only, in arrival order
}

// NewRecorder creates the temporary JSON Lines file for the raw records. The
// caller must Close the recorder; the temporary file is removed by Cleanup.
func NewRecorder() (*Recorder, error) {
	f, err := os.CreateTemp("", "dns-opti-raw-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("创建临时文件失败: %w", err)
	}
	buf := bufio.NewWriterSize(f, 64*1024)
	return &Recorder{
		file:     f,
		buf:      buf,
		enc:      json.NewEncoder(buf),
		agg:      make(map[string]*aggregate),
		tempPath: f.Name(),
	}, nil
}

// Record appends one raw record and folds it into the aggregates.
func (r *Recorder) Record(rec model.RawRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.enc.Encode(rec); err != nil {
		return fmt.Errorf("写入原始记录失败: %w", err)
	}
	r.count++

	key := rec.DNS + "|" + string(rec.Protocol) + "|" + rec.Group
	a, ok := r.agg[key]
	if !ok {
		a = &aggregate{summary: model.Summary{
			DNS:      rec.DNS,
			Name:     rec.Name,
			Protocol: rec.Protocol,
			Group:    rec.Group,
		}}
		r.agg[key] = a
		r.order = append(r.order, key)
	}
	a.summary.Total++
	if rec.Success {
		a.summary.Success++
		a.latencies = append(a.latencies, rec.LatencyMS)
	}
	return nil
}

// Count returns how many raw records have been recorded.
func (r *Recorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// Summaries returns the aggregated rows in first-seen order, with the derived
// statistics (success rate, average, p95, standard deviation) computed.
func (r *Recorder) Summaries() []model.Summary {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]model.Summary, 0, len(r.order))
	for _, key := range r.order {
		a := r.agg[key]
		s := a.summary
		if s.Total > 0 {
			s.SuccessRate = float64(s.Success) / float64(s.Total)
		}
		if len(a.latencies) > 0 {
			s.AvgMS = mean(a.latencies)
			s.StdDevMS = stddev(a.latencies, s.AvgMS)
			s.P95MS = percentile(a.latencies, 0.95)
		}
		out = append(out, s)
	}
	return out
}

// BinEdgesMS are the upper bounds (inclusive) of the latency-distribution
// buckets, in milliseconds. The last bucket is open-ended and labelled by
// binLabel.
var BinEdgesMS = []float64{5, 10, 20, 30, 50, 100, 200, 500}

// Histogram is the latency distribution of a run: how many successful queries
// fell into each bucket, per server. It exists only for the local viewer (the
// exported file keeps the PLAN 4.3 shape), so it is derived on demand rather
// than stored.
type Histogram struct {
	// Labels are the bucket labels, aligned with every Counts entry.
	Labels []string `json:"labels"`
	// Counts maps a summary key (dns|protocol|group) to the per-bucket counts
	// of its successful queries.
	Counts map[string][]int `json:"counts"`
}

// LatencyHistogram builds the latency distribution of every recorded bucket.
func (r *Recorder) LatencyHistogram() Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()

	counts := make(map[string][]int, len(r.order))
	for _, key := range r.order {
		a := r.agg[key]
		bins := make([]int, len(BinEdgesMS))
		for _, v := range a.latencies {
			bins[binIndex(v)]++
		}
		counts[a.summary.Key()] = bins
	}
	return Histogram{Labels: binLabels(), Counts: counts}
}

// HistogramFromRecords rebuilds the latency distribution from raw records. It
// is used when a result file is imported into the viewer: the file carries the
// per-query latencies, so the distribution can be recovered exactly.
func HistogramFromRecords(records []model.RawRecord) Histogram {
	counts := map[string][]int{}
	for _, rec := range records {
		if !rec.Success {
			continue
		}
		key := rec.DNS + "|" + string(rec.Protocol) + "|" + rec.Group
		bins, ok := counts[key]
		if !ok {
			bins = make([]int, len(BinEdgesMS))
		}
		bins[binIndex(rec.LatencyMS)]++
		counts[key] = bins
	}
	return Histogram{Labels: binLabels(), Counts: counts}
}

// binLabels renders the bucket labels, aligned with the per-bucket counts.
func binLabels() []string {
	labels := make([]string, len(BinEdgesMS))
	for i, edge := range BinEdgesMS {
		switch {
		case i == 0:
			labels[i] = fmt.Sprintf("≤%gms", edge)
		case i == len(BinEdgesMS)-1:
			labels[i] = fmt.Sprintf(">%gms", BinEdgesMS[i-1])
		default:
			labels[i] = fmt.Sprintf("%g-%gms", BinEdgesMS[i-1], edge)
		}
	}
	return labels
}

// binIndex maps a latency to its bucket.
func binIndex(ms float64) int {
	for i, edge := range BinEdgesMS {
		if ms <= edge {
			return i
		}
	}
	return len(BinEdgesMS) - 1
}

// Flush writes any buffered raw records to disk.
func (r *Recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buf == nil {
		return nil
	}
	return r.buf.Flush()
}

// Close flushes and closes the temporary JSON Lines file.
func (r *Recorder) Close() error {
	var err error
	r.closeOnce.Do(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.buf != nil {
			err = r.buf.Flush()
			r.buf = nil
		}
		if r.file != nil {
			if cerr := r.file.Close(); err == nil {
				err = cerr
			}
			r.file = nil
		}
	})
	return err
}

// Cleanup removes the temporary raw file. It is safe to call after Close, and
// it is intended for the case where the run failed before exporting.
func (r *Recorder) Cleanup() {
	if r.tempPath != "" {
		_ = os.Remove(r.tempPath)
	}
}

// SetServerFlags copies the display-only flags of the servers into the matching
// summary rows. It is called once the server list is final, so that a summary
// row can be rendered without a second lookup.
func (r *Recorder) SetServerFlags(servers []model.Server) {
	flags := make(map[string]model.Server, len(servers))
	for _, s := range servers {
		flags[s.Key()] = s
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.agg {
		if s, ok := flags[string(a.summary.Protocol)+"|"+a.summary.DNS]; ok {
			a.summary.IsSystem = s.IsSystem
			a.summary.IsPrivate = s.IsPrivate
			a.summary.Region = s.Region
			a.summary.Family = s.Family
			a.summary.Policy = s.Policy
			a.summary.Combo = s.Combo
			// The resolved literal address: empty for a hostname endpoint that
			// never resolved, which leaves the row to fall back to its
			// configured address for display.
			if s.IP != "" {
				a.summary.IP = s.IP
			}
			if a.summary.Name == "" {
				a.summary.Name = s.Name
			}
		}
	}
}

// --- statistics helpers ---

// mean returns the arithmetic mean.
func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// stddev returns the population standard deviation around the given mean.
func stddev(values []float64, m float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		d := v - m
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(values)))
}

// percentile returns the nearest-rank percentile of values. It sorts a copy so
// the caller's slice order (arrival order) is preserved.
func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	rank := int(math.Ceil(p * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// TempPath returns the path of the temporary raw file (used by tests).
func (r *Recorder) TempPath() string { return r.tempPath }

// DefaultOutputName builds the file name used when --output is not given.
func DefaultOutputName(dir string) string {
	name := fmt.Sprintf("dns-opti_result_%s.json", timeStamp())
	if dir == "" {
		return name
	}
	return filepath.Join(dir, name)
}
