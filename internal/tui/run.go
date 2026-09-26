package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"dns-opti/internal/config"
	"dns-opti/internal/dnsclient"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/ui"
	"dns-opti/internal/web"
)

// Options configures the interactive interface.
type Options struct {
	// Version is shown in the header.
	Version string
	// Out is where the program writes; defaults to stdout.
	Out *os.File
	// SettingsPath is the file preferences are persisted to. Empty disables
	// persistence, so a caller that does not want a settings file created
	// (a test, an embedded use) simply leaves it blank.
	SettingsPath string
}

// Run starts the interactive interface and blocks until the user quits.
//
// It requires a terminal: a bubbletea program needs a TTY to read keys and to
// address the cursor. When stdout is not a terminal (a pipe, a redirect, or a
// CI job) the caller must fall back to the non-interactive commands, so
// Interactive reports that up front.
func Run(opts Options) error {
	if !Interactive() {
		return fmt.Errorf("当前环境不是交互式终端，请使用 `dns-opti test` 等子命令")
	}

	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	m := New(Deps{
		Version:      opts.Version,
		Run:          runEngine,
		StartWeb:     startWeb,
		BuildTasks:   engine.BuildTasks,
		SettingsPath: opts.SettingsPath,
		DetectTypes:  detectTypes,
	})

	prog := tea.NewProgram(m,
		tea.WithOutput(out),
		tea.WithAltScreen(),
	)
	if _, err := prog.Run(); err != nil {
		return fmt.Errorf("交互界面启动失败: %w", err)
	}
	return nil
}

// Interactive reports whether the current process has a usable terminal.
func Interactive() bool {
	return term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd()))
}

// runEngine adapts engine.Run to the interface the menu expects.
func runEngine(ctx context.Context, cfg config.Options, progress ui.ProgressFunc) (*engine.Result, error) {
	// The menu always writes a result file, so the user can analyse the run
	// later or reopen it in the web viewer. The path is made absolute because
	// the interactive interface reports it back to the user: a relative name
	// would be ambiguous when the program was started from a shortcut.
	if cfg.Output == "" {
		abs, err := filepath.Abs(engine.DefaultOutputName())
		if err != nil {
			return nil, fmt.Errorf("无法确定结果文件路径: %w", err)
		}
		cfg.Output = abs
	}
	return engine.Run(ctx, engine.RunOptions{
		Config:   cfg,
		Progress: progress,
	})
}

// detectTypes adapts the DNS client's type detection to the interface the menu
// expects.
//
// The concurrency is bounded well below the benchmark's because each detection
// holds a connection open while it probes sequentially, and the detection is a
// maintenance sweep over the whole inventory rather than a latency measurement.
// Hammering eighty resolvers at once would also make it far more likely that a
// probe is lost to local socket exhaustion, which would show up as a spurious
// 未确认.
func detectTypes(ctx context.Context, servers []model.Server, timeout time.Duration, progress policy.ProgressFunc) []policy.Detection {
	return dnsclient.DetectTypes(ctx, servers, dnsclient.TypeDetectOptions{
		Timeout:     timeout,
		Concurrency: 8,
	}, progress)
}

// startWeb starts the local viewer and returns its URL plus a shutdown
// function. The server runs in the background so the menu stays interactive.
//
// result may be nil: the main menu offers the viewer before any test has run,
// and the page is genuinely useful then because it can import an existing
// result file. In that case the payload is left empty and the page shows its
// import prompt rather than a fabricated dataset.
func startWeb(result *engine.Result) (string, func(), error) {
	var payload *web.Payload
	resultPath := ""
	if result != nil {
		hist := result.Histogram
		payload = (&web.Payload{
			Meta:        result.Meta,
			Summary:     result.Summaries,
			Source:      "run",
			Label:       "本次测试结果",
			Histogram:   &hist,
			Comparisons: result.Comparisons,
		}).Finalize()
		resultPath = result.Path
	}

	srv := web.New(web.Options{
		Payload:     payload,
		ResultPath:  resultPath,
		OpenBrowser: true,
		Out:         os.Stderr,
	})
	url, err := srv.Listen()
	if err != nil {
		return "", nil, err
	}
	return url, srv.Close, nil
}
