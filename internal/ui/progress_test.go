package ui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"dns-opti/internal/model"
	"dns-opti/internal/scheduler"
)

// testServers is a small workload covering three protocols.
func testServers() []model.Server {
	return []model.Server{
		{Name: "AliDNS 1", Address: "223.5.5.5", Protocol: model.ProtocolUDP},
		{Name: "AliDNS 2", Address: "223.6.6.6", Protocol: model.ProtocolUDP},
		{Name: "AliDNS", Address: "dns.alidns.com", Protocol: model.ProtocolDoT},
		{Name: "AliDNS", Address: "https://dns.alidns.com/dns-query", Protocol: model.ProtocolDoH},
	}
}

// testDomains is a small domain list.
func testDomains() []model.Domain {
	return []model.Domain{
		{Name: "baidu.com", Group: model.GroupCN},
		{Name: "qq.com", Group: model.GroupCN},
	}
}

// TestProgressTrackerTotals verifies that the per-protocol and overall
// denominators are derived from the workload.
func TestProgressTrackerTotals(t *testing.T) {
	tracker := NewProgressTracker(testServers(), testDomains(), 3, true)

	// 4 servers x 2 domains x 3 attempts = 24 queries.
	if tracker.total != 24 {
		t.Fatalf("total = %d, want 24", tracker.total)
	}
	if got := tracker.perProto[model.ProtocolUDP].total; got != 12 {
		t.Errorf("UDP total = %d, want 12", got)
	}
	if got := tracker.perProto[model.ProtocolDoT].total; got != 6 {
		t.Errorf("DoT total = %d, want 6", got)
	}
	if got := tracker.perProto[model.ProtocolDoH].total; got != 6 {
		t.Errorf("DoH total = %d, want 6", got)
	}
}

// TestProgressTrackerObserve checks the running counters, including that a
// failed query counts towards progress but not towards the latency average.
func TestProgressTrackerObserve(t *testing.T) {
	tracker := NewProgressTracker(testServers(), testDomains(), 1, true)
	server := testServers()[0]

	tracker.Observe(scheduler.ProgressEvent{Server: server, Success: true, Latency: 10 * time.Millisecond})
	tracker.Observe(scheduler.ProgressEvent{Server: server, Success: true, Latency: 20 * time.Millisecond})
	tracker.Observe(scheduler.ProgressEvent{Server: server, Success: false, Latency: 5 * time.Second})

	st := tracker.snapshot()
	if st.done != 3 {
		t.Errorf("done = %d, want 3", st.done)
	}
	if st.success != 2 {
		t.Errorf("success = %d, want 2", st.success)
	}
	if want := 2.0 / 3.0; st.successRate < want-1e-9 || st.successRate > want+1e-9 {
		t.Errorf("successRate = %v, want %v", st.successRate, want)
	}
	// The failed query's 5s latency must not be included: (10+20)/2 = 15ms.
	if st.avgMS < 14.999 || st.avgMS > 15.001 {
		t.Errorf("avgMS = %v, want 15", st.avgMS)
	}
}

// TestProgressTrackerObserveZeroQueries ensures an untouched tracker does not
// divide by zero when rendered.
func TestProgressTrackerObserveZeroQueries(t *testing.T) {
	tracker := NewProgressTracker(nil, nil, 1, true)
	st := tracker.snapshot()
	if st.done != 0 || st.total != 0 || st.successRate != 0 || st.avgMS != 0 {
		t.Fatalf("unexpected zero-state: %+v", st)
	}
	if got := tracker.ratioLocked(); got != 0 {
		t.Errorf("ratio = %v, want 0", got)
	}
}

// TestPanelViewRenders drives the panel's View and checks that it contains the
// sections the CLI promises: overall progress, the per-protocol bars, the
// servers being tested and the live statistics.
func TestPanelViewRenders(t *testing.T) {
	tracker := NewProgressTracker(testServers(), testDomains(), 2, true)
	server := testServers()[0]
	for i := 0; i < 6; i++ {
		tracker.Observe(scheduler.ProgressEvent{
			Server:  server,
			Success: i%3 != 0,
			Latency: time.Duration(10+i) * time.Millisecond,
			Done:    i + 1,
			Total:   16,
		})
	}

	model := progressModel{tracker: tracker, width: 100, height: 40}
	out := model.View()

	for _, want := range []string{"DNS 优选工具", "总进度", "按协议", "当前测试", "成功率", "平均延迟"} {
		if !strings.Contains(out, want) {
			t.Errorf("panel is missing %q\n--- panel ---\n%s", want, out)
		}
	}
	// Every protocol in the workload must have a row.
	for _, proto := range []string{"UDP", "DoT", "DoH"} {
		if !strings.Contains(out, proto) {
			t.Errorf("panel is missing the %s progress row", proto)
		}
	}
	// The progress bar must have been drawn.
	if !strings.Contains(out, "█") && !strings.Contains(out, "░") {
		t.Errorf("panel drew no progress bar:\n%s", out)
	}
	if !strings.Contains(out, "223.5.5.5") {
		t.Errorf("panel does not list the server being tested:\n%s", out)
	}
}

// TestPanelViewAtCompletion checks the finished frame renders at 100%.
func TestPanelViewAtCompletion(t *testing.T) {
	tracker := NewProgressTracker(testServers(), testDomains(), 1, true)
	for _, s := range testServers() {
		for _, d := range testDomains() {
			tracker.Observe(scheduler.ProgressEvent{
				Server:  s,
				Domain:  d.Name,
				Success: true,
				Latency: 12 * time.Millisecond,
			})
		}
	}
	tracker.MarkFinished()

	out := progressModel{tracker: tracker, width: 100, height: 40, stopped: true}.View()
	if !strings.Contains(out, "100.0%") {
		t.Errorf("finished panel is not at 100%%:\n%s", out)
	}
	if !strings.Contains(out, "按 q / Ctrl+C 退出") {
		t.Errorf("finished panel is missing the exit hint:\n%s", out)
	}
}

// TestRenderBarClampsOutOfRange verifies the bar never overflows its width.
func TestRenderBarClampsOutOfRange(t *testing.T) {
	for _, fraction := range []float64{-1, 0, 0.5, 1, 2} {
		got := renderBar(fraction, 10)
		if n := strings.Count(got, "█") + strings.Count(got, "░"); n != 10 {
			t.Errorf("renderBar(%v) produced %d cells, want 10", fraction, n)
		}
	}
}

// TestRenderBarIsValidUTF8WithColorOn is the regression test for the reported
// "██���█████" corruption.
//
// The bar's filled and empty halves used to be produced by slicing one combined
// string at a byte index equal to the number of filled cells. "█" and "░" are
// three bytes each in UTF-8, so any fill count that was not a multiple of three
// cut a glyph in half; the two stray bytes then ended up on either side of the
// ANSI reset sequence, and the terminal rendered each as U+FFFD ("�"). That is
// exactly why only *some* bars looked broken: fill counts of 0, 3, 6, ... landed
// on a glyph boundary by luck.
//
// Colour must be forced on, because lipgloss emits no escape sequences under the
// Ascii profile — and it is precisely the escape sequence inserted between the
// two halves that turns a half-glyph into a visible "�".
func TestRenderBarIsValidUTF8WithColorOn(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })

	for _, width := range []int{1, 2, 3, 5, 11, 22, 40} {
		for cells := 0; cells <= width; cells++ {
			got := renderBar(float64(cells)/float64(width), width)

			if !utf8.ValidString(got) {
				t.Errorf("renderBar(width=%d, filled=%d) 不是合法 UTF-8: %q", width, cells, got)
			}
			if strings.ContainsRune(got, utf8.RuneError) {
				t.Errorf("renderBar(width=%d, filled=%d) 含替换字符 �: %q", width, cells, got)
			}
			// An escape sequence must never sit between the bytes of one glyph:
			// the byte before "\x1b" has to start a rune.
			if idx := strings.IndexByte(got, 0x1b); idx > 0 && !utf8.RuneStart(got[idx-1]) {
				t.Errorf("renderBar(width=%d, filled=%d) 的转义序列切断了字符: %q", width, cells, got)
			}
			if n := strings.Count(got, barFull) + strings.Count(got, barEmpty); n != width {
				t.Errorf("renderBar(width=%d, filled=%d) 渲染出 %d 个格子:\n%q", width, cells, n, got)
			}
			// lipgloss counts ANSI sequences as zero-width, so the measured
			// display width must still equal the requested width.
			if w := lipgloss.Width(got); w != width {
				t.Errorf("renderBar(width=%d, filled=%d) 显示宽度 = %d:\n%q", width, cells, w, got)
			}
		}
	}
}

// TestRenderBarGlyphBoundaryCounts pins the specific fill counts that used to
// break: 1, 2, 4 and 5 cells are not multiples of the 3-byte glyph length.
func TestRenderBarGlyphBoundaryCounts(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })

	for _, filled := range []int{1, 2, 4, 5, 7, 8, 10, 11} {
		got := renderBar(float64(filled)/22, 22)
		if strings.ContainsRune(got, utf8.RuneError) {
			t.Errorf("filled=%d 产生了损坏的进度条: %q", filled, got)
		}
		if n := strings.Count(got, barFull); n != filled {
			t.Errorf("filled=%d 但渲染出 %d 个实心格: %q", filled, n, got)
		}
	}
}

// TestRateGuardsZeroDenominator verifies the success-rate helper.
func TestRateGuardsZeroDenominator(t *testing.T) {
	if got := rate(0, 0); got != 0 {
		t.Errorf("rate(0,0) = %v, want 0", got)
	}
	if got := rate(3, 4); got != 0.75 {
		t.Errorf("rate(3,4) = %v, want 0.75", got)
	}
}

// TestElapsedFormat checks the mm:ss rendering.
func TestElapsedFormat(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{-time.Second, "00:00"},
		{0, "00:00"},
		{9 * time.Second, "00:09"},
		{75 * time.Second, "01:15"},
		{time.Hour, "60:00"},
	}
	for _, c := range cases {
		if got := elapsed(c.in); got != c.want {
			t.Errorf("elapsed(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestMsFormat checks the latency rendering, including the "no data" case.
func TestMsFormat(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "-"},
		{-1, "-"},
		{0.4, "0.4ms"},
		{9.94, "9.9ms"},
		{10, "10ms"},
		{123.4, "123ms"},
	}
	for _, c := range cases {
		if got := ms(c.in); got != c.want {
			t.Errorf("ms(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
