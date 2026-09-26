package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/scheduler"
	"dns-opti/internal/ui"
)

// --- messages ---

// progressMsg carries one completed query from the run goroutine.
type progressMsg struct{ event scheduler.ProgressEvent }

// runDoneMsg reports that the benchmark finished.
type runDoneMsg struct {
	result  *engine.Result
	report  string
	notices []string
	err     error
}

// planMsg carries the resolved workload (computed off the UI thread).
type planMsg struct {
	plan *engine.Plan
	err  error
}

// tickMsg drives the periodic refresh of the progress panel.
type tickMsg time.Time

// webStartedMsg reports that the local viewer is listening.
type webStartedMsg struct {
	url  string
	stop func()
	err  error
}

// savedMsg reports the outcome of saving the report to a file.
type savedMsg struct {
	path string
	err  error
}

// --- commands ---

// tick schedules the next progress refresh.
func tick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// waitForProgress blocks until the next progress event arrives.
func waitForProgress(ch <-chan progressMsg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// refreshPlan resolves the workload in the background. Building the task list
// probes the network and reads the system DNS configuration, so doing it on the
// UI thread would freeze the menu.
func (m *Model) refreshPlan() tea.Cmd {
	if m.deps.BuildTasks == nil {
		return nil
	}
	cfg := m.cfg
	deps := m.deps
	return func() tea.Msg {
		servers, domains, warns, err := deps.BuildTasks(cfg)
		if err != nil {
			return planMsg{err: err}
		}
		plan := &engine.Plan{
			Servers:  len(servers),
			Domains:  len(domains),
			Attempts: cfg.Attempts,
			Total:    len(servers) * len(domains) * cfg.Attempts,
			ByProto:  map[model.Protocol]int{},
			ByGroup:  map[string]int{},
			Warnings: warns,
		}
		for _, s := range servers {
			plan.ByProto[s.Protocol]++
		}
		for _, d := range domains {
			plan.ByGroup[d.Group]++
		}
		return planMsg{plan: plan}
	}
}

// startRun launches the benchmark and streams progress into the model. It
// returns the screen to show: the running screen on success, or the error
// screen when the workload could not be resolved.
func (m *Model) startRun() (screen, tea.Cmd) {
	m.syncAdvanced()
	m.statusMsg = ""
	m.statusErr = false
	m.notices = nil

	// Resolve the workload before switching screens: the progress panel needs
	// the totals to size its bars, and a failure here must land on the error
	// screen rather than on a running screen that can never progress.
	servers, domains, err := m.tasks()
	if err != nil {
		m.statusMsg = err.Error()
		m.statusErr = true
		return screenError, nil
	}
	tracker := ui.NewProgressTracker(servers, domains, m.cfg.Attempts, true)
	m.tracker = tracker
	m.screen = screenRunning

	cfg := m.cfg
	formula := m.formula
	deps := m.deps
	events := m.events

	return screenRunning, tea.Batch(
		func() tea.Msg {
			ctx, cancel := context.WithCancel(context.Background())
			tracker.SetCancel(cancel)
			defer cancel()

			result, err := deps.Run(ctx, cfg, func(e scheduler.ProgressEvent) {
				// Never block the benchmark on a slow UI: drop the event when
				// the buffer is full. The panel is a live view, not a log, and
				// the authoritative numbers come from the engine's result.
				select {
				case events <- progressMsg{event: e}:
				default:
				}
			})
			if err != nil {
				return runDoneMsg{err: err}
			}
			return runDoneMsg{
				result:  result,
				report:  ui.ResultView(result, formula),
				notices: result.Warned,
			}
		},
		waitForProgress(events),
		tick(),
	)
}

// tasks resolves the configured workload.
func (m *Model) tasks() ([]model.Server, []model.Domain, error) {
	if m.deps.BuildTasks == nil {
		return nil, nil, fmt.Errorf("内部错误：未注入 BuildTasks")
	}
	servers, domains, _, err := m.deps.BuildTasks(m.cfg)
	if err != nil {
		return nil, nil, err
	}
	return servers, domains, nil
}

// startWeb launches the local viewer. StartWeb returns as soon as the socket is
// bound, so the server keeps running in the background while the menu stays
// interactive.
//
// A finished result is passed along when there is one, but it is not required:
// the main menu offers the viewer before any test has run, and the page is
// useful then because it can import an existing result file. The viewer is
// therefore opened with an empty dataset rather than refusing to start.
func (m *Model) startWeb() tea.Cmd {
	if m.deps.StartWeb == nil {
		return nil
	}
	result := m.result
	start := m.deps.StartWeb
	return func() tea.Msg {
		url, stop, err := start(result)
		return webStartedMsg{url: url, stop: stop, err: err}
	}
}

// saveReport writes the rendered report next to the result JSON.
func (m *Model) saveReport() tea.Cmd {
	if m.result == nil {
		return nil
	}
	report := strings.Join(m.resultLines, "\n")
	resultPath := m.result.Path

	return func() tea.Msg {
		path := reportPath(resultPath)
		if err := os.WriteFile(path, []byte(report), 0o644); err != nil {
			return savedMsg{err: err}
		}
		return savedMsg{path: path}
	}
}

// reportPath derives the report file name from the result JSON path.
func reportPath(resultPath string) string {
	if resultPath == "" {
		return fmt.Sprintf("dns-opti_report_%s.txt", time.Now().Format("2006-01-02-15-04-05"))
	}
	return strings.TrimSuffix(resultPath, filepath.Ext(resultPath)) + "_report.txt"
}
