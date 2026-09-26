package ui

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"dns-opti/internal/config"
	"dns-opti/internal/model"
	"dns-opti/internal/scheduler"
	"dns-opti/internal/scorer"
)

// ProgressFunc receives every completed query. It is the callback shape shared
// by the CLI, the interactive menu and the engine.
type ProgressFunc = func(scheduler.ProgressEvent)

// ProgressTracker accumulates the live state of a run and renders it either as
// an interactive bubbletea panel (on a TTY) or as periodic plain-text lines
// (piped / CI). It is safe to call Observe from several goroutines.
type ProgressTracker struct {
	mu sync.Mutex

	total    int
	done     int
	success  int
	latSumMS float64

	protos     []model.Protocol
	perProto   map[model.Protocol]*protoProgress
	active     map[string]activeServer
	activeKeys []string

	// plain-mode bookkeeping
	plain     bool
	lastTick  time.Time
	lastRatio float64
	out       io.Writer

	start    time.Time
	finished bool

	// cancel aborts the run this tracker is reporting on; cancelled records
	// whether it was used, so the caller can report a cancellation rather than
	// a failure.
	cancel    context.CancelFunc
	cancelled bool
}

// protoProgress is the per-protocol slice of the progress.
type protoProgress struct {
	total    int
	done     int
	success  int
	latSumMS float64
}

// activeServer records when a server was last seen, so the panel can list what
// is being tested right now.
type activeServer struct {
	label string
	at    time.Time
}

// NewProgressTracker builds a tracker for the given workload. The per-protocol
// totals are derived from the workload itself, so every progress bar has a
// meaningful denominator from the first frame. When plain is true the tracker
// prints periodic lines instead of taking over the terminal.
func NewProgressTracker(servers []model.Server, domains []model.Domain, attempts int, plain bool) *ProgressTracker {
	if attempts < 1 {
		attempts = 1
	}
	p := &ProgressTracker{
		perProto: make(map[model.Protocol]*protoProgress),
		active:   make(map[string]activeServer),
		out:      os.Stdout,
		plain:    plain,
		start:    time.Now(),
	}

	perServer := len(domains) * attempts
	for _, s := range servers {
		pp, ok := p.perProto[s.Protocol]
		if !ok {
			pp = &protoProgress{}
			p.perProto[s.Protocol] = pp
			p.protos = append(p.protos, s.Protocol)
		}
		pp.total += perServer
		p.total += perServer
	}
	return p
}

// SetOutput redirects the plain-text progress lines (used by --json, where
// stdout carries only the JSON document).
func (p *ProgressTracker) SetOutput(w io.Writer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if w != nil {
		p.out = w
	}
}

// SetCancel stores the function that aborts the run this tracker reports on.
// The interactive menu calls it when the user presses Esc/Ctrl+C.
func (p *ProgressTracker) SetCancel(cancel context.CancelFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancel = cancel
}

// Cancel aborts the run, if a cancel function has been registered. It is safe
// to call when no run is in flight.
func (p *ProgressTracker) Cancel() {
	p.mu.Lock()
	cancel := p.cancel
	p.cancelled = true
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Cancelled reports whether Cancel was called.
func (p *ProgressTracker) Cancelled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cancelled
}

// Observe folds one completed query into the running totals.
func (p *ProgressTracker) Observe(e scheduler.ProgressEvent) {
	p.mu.Lock()
	p.done++
	if e.Success {
		p.success++
		ms := float64(e.Latency.Microseconds()) / 1000
		p.latSumMS += ms
	}
	if pp, ok := p.perProto[e.Server.Protocol]; ok {
		pp.done++
		if e.Success {
			pp.success++
			pp.latSumMS += float64(e.Latency.Microseconds()) / 1000
		}
	}

	key := e.Server.Key()
	if _, seen := p.active[key]; !seen {
		p.activeKeys = append(p.activeKeys, key)
	}
	p.active[key] = activeServer{label: serverLabel(e.Server), at: time.Now()}

	plain := p.plain
	ratio := p.ratioLocked()
	shouldPrint := plain && (ratio-p.lastRatio >= 0.1 || p.done == p.total)
	if shouldPrint {
		p.lastRatio = float64(int(ratio*10)) / 10
	}
	done, total, success, avg := p.done, p.total, p.success, p.avgLocked()
	p.mu.Unlock()

	if shouldPrint {
		fmt.Fprintf(p.out, "  进度 %5.1f%%  (%d/%d)  成功率 %s  平均延迟 %s\n",
			ratio*100, done, total, pct(rate(success, done)), ms(avg))
	}
}

// ratioLocked returns the completed fraction. The caller must hold the lock.
func (p *ProgressTracker) ratioLocked() float64 {
	if p.total == 0 {
		return 0
	}
	return float64(p.done) / float64(p.total)
}

// avgLocked returns the mean successful latency. The caller must hold the lock.
func (p *ProgressTracker) avgLocked() float64 {
	if p.success == 0 {
		return 0
	}
	return p.latSumMS / float64(p.success)
}

// rate is a guarded success rate.
func rate(success, done int) float64 {
	if done == 0 {
		return 0
	}
	return float64(success) / float64(done)
}

// runState is an immutable snapshot of the tracker used for rendering.
type runState struct {
	total       int
	done        int
	success     int
	successRate float64
	avgMS       float64
	elapsed     time.Duration
	finished    bool
	protos      []protoSnapshot
	active      []string
}

// protoSnapshot is the per-protocol part of a snapshot.
type protoSnapshot struct {
	protocol model.Protocol
	done     int
	total    int
	rate     float64
	avgMS    float64
}

// snapshot copies the current state for rendering.
func (p *ProgressTracker) snapshot() runState {
	p.mu.Lock()
	defer p.mu.Unlock()

	st := runState{
		total:       p.total,
		done:        p.done,
		success:     p.success,
		successRate: rate(p.success, p.done),
		avgMS:       p.avgLocked(),
		elapsed:     time.Since(p.start),
		finished:    p.finished,
	}

	for _, proto := range p.protos {
		pp := p.perProto[proto]
		st.protos = append(st.protos, protoSnapshot{
			protocol: proto,
			done:     pp.done,
			total:    pp.total,
			rate:     rate(pp.success, pp.done),
			avgMS:    safeAvg(pp.latSumMS, pp.success),
		})
	}

	// "Currently testing" is the set of servers that produced a result within
	// the last couple of seconds, i.e. those whose worker is still busy.
	cutoff := time.Now().Add(-2 * time.Second)
	type entry struct {
		label string
		at    time.Time
	}
	var live []entry
	for _, key := range p.activeKeys {
		a := p.active[key]
		if a.at.After(cutoff) {
			live = append(live, entry{label: a.label, at: a.at})
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].at.After(live[j].at) })
	for _, e := range live {
		st.active = append(st.active, e.label)
	}
	return st
}

// safeAvg divides, treating a zero denominator as "no data".
func safeAvg(sum float64, n int) float64 {
	if n <= 0 {
		return 0
	}
	return sum / float64(n)
}

// MarkFinished flags the run as complete so the final frame renders at 100%.
func (p *ProgressTracker) MarkFinished() {
	p.mu.Lock()
	p.finished = true
	p.mu.Unlock()
}

// --- bubbletea program ---

// tickMsg drives the periodic refresh.
type tickMsg time.Time

// doneMsg reports that the benchmark finished.
type doneMsg struct{ err error }

// progressModel is the bubbletea model of the progress panel.
type progressModel struct {
	tracker *ProgressTracker
	doneCh  <-chan error
	cancel  context.CancelFunc
	width   int
	height  int
	runErr  error
	stopped bool
}

// Init starts the refresh ticker and waits for the run to finish.
func (m progressModel) Init() tea.Cmd {
	return tea.Batch(tickCmd(), waitCmd(m.doneCh))
}

// Update handles resize, tick, completion and the quit keys.
func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tickMsg:
		if m.stopped {
			return m, tea.Quit
		}
		return m, tickCmd()

	case doneMsg:
		m.runErr = msg.err
		m.stopped = true
		return m, tea.Quit

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "Q":
			// Abort the run as well, so ^C does not leave workers running.
			if m.cancel != nil {
				m.cancel()
			}
			m.stopped = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// View renders the panel.
func (m progressModel) View() string {
	return m.render(true)
}

// render draws the panel. withTitle includes the panel's own headline and rule,
// which the standalone progress screen needs; an embedding host (the
// interactive menu) passes false because it already draws its own header.
func (m progressModel) render(withTitle bool) string {
	width := m.width
	if width <= 0 {
		width = 96
	}
	st := m.tracker.snapshot()

	var b strings.Builder
	if withTitle {
		b.WriteString(styleTitle.Render("DNS 优选工具 · 正在测试"))
		b.WriteString("\n")
		b.WriteString(styleMuted.Render(strings.Repeat("─", min(width, 78))))
		b.WriteString("\n\n")
	}

	overall := 0.0
	if st.total > 0 {
		overall = float64(st.done) / float64(st.total)
	}
	fmt.Fprintf(&b, " %s  %s  %s  %s\n",
		styleHeading.Render("总进度"),
		renderBar(overall, barWidth),
		styleBold.Render(pct(overall)),
		styleMuted.Render(fmt.Sprintf("%d/%d · 用时 %s", st.done, st.total, elapsed(st.elapsed))),
	)

	b.WriteString("\n ")
	b.WriteString(styleHeading.Render("按协议"))
	b.WriteString("\n")
	for _, p := range st.protos {
		fraction := 0.0
		if p.total > 0 {
			fraction = float64(p.done) / float64(p.total)
		}
		fmt.Fprintf(&b, "  %-5s %s  %s  %s  %s\n",
			p.protocol.Label(),
			renderBar(fraction, barWidth),
			styleMuted.Render(pct(fraction)),
			styleMuted.Render(fmt.Sprintf("%d/%d", p.done, p.total)),
			successStyle(p.rate).Render("成功率 "+pct(p.rate))+"  "+styleMuted.Render("平均 "+ms(p.avgMS)),
		)
	}

	b.WriteString("\n ")
	b.WriteString(styleHeading.Render("当前测试"))
	if len(st.active) == 0 {
		b.WriteString(styleMuted.Render("  （等待首个结果…）"))
	} else {
		b.WriteString(styleMuted.Render(fmt.Sprintf("  %d 个服务器", len(st.active))))
	}
	b.WriteString("\n")
	for i, label := range st.active {
		if i >= 6 {
			fmt.Fprintf(&b, "  %s\n", styleMuted.Render(fmt.Sprintf("… 其余 %d 个", len(st.active)-i)))
			break
		}
		fmt.Fprintf(&b, "  %s %s\n", styleMuted.Render("·"), label)
	}

	b.WriteString("\n")
	fmt.Fprintf(&b, " %s %s   %s %s   %s %s\n",
		styleMuted.Render("成功率"),
		successStyle(st.successRate).Render(pct(st.successRate)),
		styleMuted.Render("平均延迟"),
		styleBold.Render(ms(st.avgMS)),
		styleMuted.Render("已失败"),
		styleBad.Render(fmt.Sprintf("%d", st.done-st.success)),
	)

	b.WriteString("\n")
	b.WriteString(styleMuted.Render(" " + riskNotice))
	b.WriteString("\n")
	if m.stopped {
		b.WriteString(styleMuted.Render(" 按 q / Ctrl+C 退出"))
	} else {
		b.WriteString(styleMuted.Render(" 按 q / Ctrl+C 可中止测试"))
	}
	return b.String()
}

// tickCmd schedules the next refresh.
func tickCmd() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// PanelView renders the live progress panel as a plain string for a given
// terminal width. It is the same rendering the standalone bubbletea panel uses,
// exposed so the interactive menu (internal/tui) can embed it without
// duplicating the layout: stopped marks the run as finished so the final frame
// renders at 100% with the exit hint.
func PanelView(tracker *ProgressTracker, width int, stopped bool) string {
	return progressModel{tracker: tracker, width: width, stopped: stopped}.render(true)
}

// PanelViewBare is PanelView without the panel's own headline and rule, for a
// host that already draws a header.
func PanelViewBare(tracker *ProgressTracker, width int, stopped bool) string {
	return progressModel{tracker: tracker, width: width, stopped: stopped}.render(false)
}

// waitCmd reports the run's outcome to the program.
func waitCmd(ch <-chan error) tea.Cmd {
	return func() tea.Msg { return doneMsg{err: <-ch} }
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RunWithProgress executes run while showing the progress panel. On a TTY the
// bubbletea panel is used; otherwise the run proceeds with periodic plain-text
// progress lines (which keeps the command usable in pipes and CI). It returns
// run's result and error.
func RunWithProgress[T any](ctx context.Context, tracker *ProgressTracker, run func(context.Context) (T, error)) (T, error) {
	if tracker.plain || !term.IsTerminal(int(os.Stdout.Fd())) {
		return runPlain(ctx, tracker, run)
	}
	return runPanel(ctx, tracker, run)
}

// runPlain runs the workload without a full-screen panel.
func runPlain[T any](ctx context.Context, tracker *ProgressTracker, run func(context.Context) (T, error)) (T, error) {
	tracker.plain = true
	result, err := run(ctx)
	tracker.MarkFinished()
	return result, err
}

// runPanel runs the workload behind the bubbletea program.
func runPanel[T any](parent context.Context, tracker *ProgressTracker, run func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	type outcome struct {
		result T
		err    error
	}
	outCh := make(chan outcome, 1)
	doneCh := make(chan error, 1)
	go func() {
		result, err := run(ctx)
		outCh <- outcome{result: result, err: err}
		doneCh <- err
	}()

	prog := tea.NewProgram(
		progressModel{tracker: tracker, doneCh: doneCh, cancel: cancel},
		tea.WithOutput(os.Stdout),
	)
	model, err := prog.Run()
	if err != nil {
		// A TUI failure must not lose the benchmark: wait for the run and
		// report its own outcome.
		out := <-outCh
		if out.err != nil {
			return out.result, out.err
		}
		return out.result, fmt.Errorf("进度面板渲染失败: %w", err)
	}

	tracker.MarkFinished()
	out := <-outCh
	if pm, ok := model.(progressModel); ok && pm.runErr != nil {
		return out.result, pm.runErr
	}
	return out.result, out.err
}

// FormulaOptions returns the formula choices with their names, for help output.
func FormulaOptions() string {
	var parts []string
	for _, f := range []config.Formula{
		config.FormulaSpeed, config.FormulaStable,
		config.FormulaComprehensive, config.FormulaJitter,
	} {
		if info, ok := scorer.FormulaByID(f); ok {
			parts = append(parts, fmt.Sprintf("%s(%s)", f, info.Name))
		}
	}
	return strings.Join(parts, ", ")
}
