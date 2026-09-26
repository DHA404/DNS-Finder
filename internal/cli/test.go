package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"dns-opti/data"
	"dns-opti/internal/config"
	"dns-opti/internal/dnsclient"
	"dns-opti/internal/domainlist"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/region"
	"dns-opti/internal/ui"
	"dns-opti/internal/web"
)

// runTest executes the "test" command.
func runTest(cmd *cobra.Command, o options) error {
	out := cmd.OutOrStdout()

	cfg, formula, err := buildConfig(o)
	if err != nil {
		return err
	}

	// A dry run prints the plan and stops: it never opens a socket.
	servers, domains, warns, err := engine.BuildTasks(cfg)
	if err != nil {
		return err
	}
	if o.dryRun {
		printPlan(out, cfg, servers, domains, warns)
		return nil
	}

	// Ctrl+C (and SIGTERM) cancel the run cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// In JSON mode stdout must carry only the JSON document, so the progress
	// line goes to stderr and the live panel is disabled.
	progressOut := os.Stdout
	if o.jsonOut {
		progressOut = os.Stderr
	}
	plainProgress := o.jsonOut || !term.IsTerminal(int(os.Stdout.Fd()))

	fmt.Fprintln(progressOut, ui.RunBanner(versionString(), len(servers), len(domains), cfg))
	for _, w := range warns {
		fmt.Fprintln(progressOut, ui.WarningLine(w))
	}

	tracker := ui.NewProgressTracker(servers, domains, cfg.Attempts, plainProgress)
	tracker.SetOutput(progressOut)

	// The tracker drives the bubbletea panel on a TTY and periodic plain-text
	// lines otherwise; either way the same engine run is underneath.
	res, err := ui.RunWithProgress(ctx, tracker, func(ctx context.Context) (*engine.Result, error) {
		return engine.Run(ctx, engine.RunOptions{
			Config:   cfg,
			Progress: tracker.Observe,
		})
	})
	if err != nil {
		return err
	}

	if o.jsonOut {
		return ui.WriteJSONReport(out, res, formula)
	}

	ui.PrintReport(out, res, ui.ReportOptions{
		Formula: formula,
		// The same sentences were printed above, before the run. Repeating them
		// in the report would just show the user the identical text twice.
		AlreadyShown: warns,
	})

	// JSON mode only covers the "no web UI" case: mixing a browser launch into
	// a scripted run would be surprising.
	if cfg.JSON && cfg.ShouldOpenWeb() {
		fmt.Fprintln(os.Stderr, ui.WarningLine("--json 与 --web 同时使用：结果以 JSON 输出，Web 页面照常启动"))
	}

	if cfg.ShouldOpenWeb() {
		// The viewer's incidental lines go to stderr, so a --json run still
		// emits a clean document on stdout.
		return serveWeb(ctx, web.Options{
			Port:        cfg.Port,
			Payload:     payloadFromResult(res),
			ResultPath:  res.Path,
			OpenBrowser: !cfg.NoOpenBrowser,
			Out:         os.Stderr,
		})
	}
	return nil
}

// buildConfig validates the flags and turns them into a run configuration.
func buildConfig(o options) (config.Options, config.Formula, error) {
	protocols, combo, err := config.ParseProtocolSelection(o.protocols)
	if err != nil {
		return config.Options{}, "", err
	}
	categories, err := config.ParseServerCategories(o.serverClass)
	if err != nil {
		return config.Options{}, "", err
	}
	regions, err := config.ParseRegions(o.regions)
	if err != nil {
		return config.Options{}, "", err
	}
	policies, err := config.ParsePolicies(o.policy)
	if err != nil {
		return config.Options{}, "", err
	}
	ipVersion, err := config.ParseIPVersion(o.ipVersion)
	if err != nil {
		return config.Options{}, "", err
	}
	formula, err := config.ParseFormula(o.formula)
	if err != nil {
		return config.Options{}, "", err
	}

	cfg := config.Options{
		Domains:          o.domains,
		Protocols:        protocols,
		Combo:            combo,
		ServerCategories: categories,
		Regions:          regions,
		Policies:         policies,
		IPVersion:        ipVersion,
		Servers:          o.servers,
		Output:           o.output,
		Web:              o.web,
		NoWeb:            o.noWeb,
		Timeout:          o.timeout,
		Attempts:         o.attempts,
		SystemDNS:        o.systemDNS,
		Concurrency:      o.concurrency,
		WarmupDomain:     o.warmup,
		Formula:          string(formula),
		JSON:             o.jsonOut,
		Port:             o.webPort,
		NoOpenBrowser:    !o.openBrowser,
	}
	if err := cfg.Validate(); err != nil {
		return config.Options{}, "", err
	}
	return cfg, formula, nil
}

// printPlan describes the workload without running it.
func printPlan(out interface{ Write([]byte) (int, error) }, cfg config.Options, servers []model.Server, domains []model.Domain, warns []string) {
	byProto := map[model.Protocol]int{}
	for _, s := range servers {
		byProto[s.Protocol]++
	}
	byGroup := map[string]int{}
	for _, d := range domains {
		byGroup[d.Group]++
	}

	fmt.Fprintf(out, "%s\n", ui.RunBanner(versionString(), len(servers), len(domains), cfg))
	fmt.Fprintf(out, "并发数: %d（CPU 线程数 %d × %d）\n",
		cfg.EffectiveConcurrency(), runtime.NumCPU(), config.DefaultConcurrencyMultiplier)
	fmt.Fprintf(out, "单次超时: %s   每域名查询次数: %d   预热域名: %s\n", cfg.Timeout, cfg.Attempts, cfg.WarmupDomain)
	if cfg.IsCombo() {
		fmt.Fprintf(out, "协议: %s（组合模式：同一服务商的两种传输并排对比）\n", cfg.ComboLabel())
	} else {
		fmt.Fprintf(out, "协议: %s\n", protocolList(cfg.Protocols))
	}
	fmt.Fprintf(out, "地址族: %s\n", cfg.IPVersion.Label())
	if len(cfg.Regions) > 0 {
		fmt.Fprintf(out, "地区筛选: %s\n", strings.Join(cfg.Regions, ", "))
	}
	fmt.Fprintf(out, "服务器: 共 %d 个", len(servers))
	for _, p := range model.AllProtocols {
		if n := byProto[p]; n > 0 {
			fmt.Fprintf(out, "  %s=%d", p.Label(), n)
		}
	}
	byRegion := map[string]int{}
	for _, s := range servers {
		if s.Region != "" {
			byRegion[s.Region]++
		}
	}
	if len(byRegion) > 0 {
		fmt.Fprint(out, "   地区: ")
		for i, code := range region.Order(byRegion) {
			if i > 0 {
				fmt.Fprint(out, " ")
			}
			fmt.Fprintf(out, "%s=%d", code, byRegion[code])
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "域名: 共 %d 个", len(domains))
	for _, g := range domainlist.Groups(domains) {
		fmt.Fprintf(out, "  %s=%d", model.GroupLabel(g), byGroup[g])
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "计划查询总数: %d\n", len(servers)*len(domains)*cfg.Attempts)
	if cfg.Output != "" {
		fmt.Fprintf(out, "导出路径: %s\n", resolveOutput(cfg.Output))
	} else {
		fmt.Fprintln(out, "导出路径: dns-opti_result_<时间>.json")
	}
	for _, w := range warns {
		fmt.Fprintln(out, ui.WarningLine(w))
	}
	fmt.Fprintln(out, "\n（--dry-run：未发起任何查询）")
}

// protocolList renders a protocol slice for display.
func protocolList(protocols []model.Protocol) string { return ui.ProtocolSummary(protocols) }

// planServers resolves the built-in server list for the informational
// subcommands (servers / --dry-run).
func planServers(protocols []model.Protocol, categories []config.ServerCategory, regions []string, policies []policy.Kind, want model.IPVersion) ([]model.Server, int, error) {
	cats := make([]data.Category, 0, len(categories))
	for _, c := range categories {
		cats = append(cats, data.Category(c))
	}
	all := data.Servers(protocols, cats, regions, policies)
	kept, skipped := dnsclient.FilterReachable(all, want)
	return dnsclient.MarkSpecial(kept), skipped, nil
}
