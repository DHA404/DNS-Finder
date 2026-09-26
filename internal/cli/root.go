// Package cli implements the command-line interface of dns-opti.
//
// The commands are thin: they translate flags into a run configuration, then
// drive the engine and the presentation packages. All benchmark logic lives in
// internal/engine and below.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"dns-opti/data"
	"dns-opti/internal/config"
	"dns-opti/internal/console"
	"dns-opti/internal/domainlist"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/scorer"
	"dns-opti/internal/settings"
	"dns-opti/internal/tui"
	"dns-opti/internal/ui"
)

// Version is the build version, overridable via -ldflags.
var Version = "dev"

// options holds the flag values of the "test" command.
type options struct {
	domains     string
	protocols   string
	servers     string
	serverClass string
	regions     string
	policy      string
	ipVersion   string
	output      string
	web         bool
	noWeb       bool
	webPort     int
	timeout     time.Duration
	attempts    int
	systemDNS   bool
	concurrency int
	warmup      string
	formula     string
	jsonOut     bool
	dryRun      bool
	openBrowser bool
}

// webOptions holds the flag values of the "web" command.
type webOptions struct {
	result   string
	port     int
	noOpen   bool
	formula  string
	domains  string
	protocol string
}

// Execute runs the root command.
//
// With no arguments at all — the case when the executable is double-clicked —
// it opens the interactive menu instead of printing help, so a user who does
// not know the flags still gets a usable interface. Any argument (including
// --help) keeps the ordinary command-line behaviour, which is what scripts and
// power users expect.
func Execute() error {
	if len(os.Args) <= 1 && tui.Interactive() {
		return runInteractive()
	}
	return newRootCmd().Execute()
}

// runInteractive starts the menu and keeps the console open afterwards when the
// process owns it (a double-click), so the user can read the outcome.
func runInteractive() error {
	err := tui.Run(tui.Options{Version: Version, SettingsPath: settings.Path()})
	if err != nil {
		return err
	}
	console.PauseOnExit("按回车键关闭窗口…")
	return nil
}

// newRootCmd builds the command tree.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "dns-opti",
		Short: "DNS 优选工具：并发测试公共 DNS 的延迟与成功率，并给出排名",
		Long: strings.Join([]string{
			"dns-opti 会并发测试一批公共 DNS 服务器（UDP / DoT / DoH / DoH3），",
			"记录每个域名的每一次查询，汇总成功率、平均延迟、P95 与标准差，",
			"再按四套评分公式给出排名，并把结果导出为 JSON。",
			"",
			"直接双击运行（不带任何参数）会打开可视化操作界面；",
			"带参数时则按下面的子命令执行，便于脚本调用。",
			"",
			"提示：测试前请关闭系统代理与加速器；国内与国外域名分组统计，不混用。",
		}, "\n"),
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.SetVersionTemplate("dns-opti {{.Version}}\n")
	root.AddCommand(newInteractiveCmd(), newTestCmd(), newWebCmd(), newFormulasCmd(), newServersCmd(), newDomainsCmd(), newVersionCmd())
	return root
}

// newInteractiveCmd exposes the menu explicitly, so it can also be reached from
// a shell with `dns-opti ui`.
func newInteractiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ui",
		Short: "打开可视化操作界面（也可直接双击程序运行）",
		Long: strings.Join([]string{
			"打开全屏键盘操作界面：选择测试域名范围、协议、评分公式与高级选项，",
			"开始测试后可以实时查看进度，结束后查看排名报告、打开本地 Web 页面或保存报告。",
		}, "\n"),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !tui.Interactive() {
				return fmt.Errorf("当前环境不是交互式终端，请改用 `dns-opti test` 子命令")
			}
			return tui.Run(tui.Options{Version: Version, SettingsPath: settings.Path()})
		},
	}
}

// newVersionCmd prints the build version.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "dns-opti %s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
			return nil
		},
	}
}

// newTestCmd builds the "test" command.
func newTestCmd() *cobra.Command {
	var o options

	cmd := &cobra.Command{
		Use:   "test",
		Short: "测试 DNS 服务器并导出结果",
		Long: strings.Join([]string{
			"测试内置（或 --servers 指定的）DNS 服务器，逐条记录每次查询，",
			"并在结束后输出分域名组的排名，同时把 meta / raw / summary 导出为 JSON。",
		}, "\n"),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTest(cmd, o)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&o.domains, "domains", "d", domainlist.ModeAll,
		"测试域名: cn(仅国内) | intl(仅国外) | all(国内+国外，分组统计) | mixed(国内外混合为一个分组) | 逗号分隔的自定义域名")
	flags.StringVarP(&o.protocols, "protocols", "p", "udp,dot,doh",
		"测试协议: udp,dot,doh,doh3，或组合模式 "+model.ComboUDPDoH+"（同一服务商的 UDP 与 DoH 并排对比）")
	flags.StringVarP(&o.servers, "servers", "s", "",
		"手动指定服务器（逗号分隔），支持 host、IPv4、[IPv6]、udp://host、tls://host、https://host/dns-query、h3://host/dns-query")
	flags.StringVar(&o.serverClass, "server-class", "",
		"内置服务器范围: cn(国内) | intl(国外) | all（默认全部）")
	flags.StringVar(&o.regions, "regions", "",
		"按地区码筛选内置服务器（ISO 3166-1 两位国家码，或 CDN/PRIVATE/UNKNOWN），逗号分隔；如 cn,hk,tw")
	flags.StringVar(&o.policy, "policy", "",
		"按过滤策略筛选内置服务器: native(原生) | security(安全)，逗号分隔；如 native,security")
	flags.StringVar(&o.ipVersion, "ip-version", "both",
		"只测试指定地址族: ipv4 | ipv6 | both（默认 both；主机名会按所选地址族解析）")
	flags.StringVarP(&o.output, "output", "o", "",
		"结果导出路径（默认 dns-opti_result_<时间>.json）")
	flags.BoolVar(&o.web, "web", false, "测试完成后启动本地 Web 结果分析页面")
	flags.BoolVar(&o.noWeb, "no-web", false, "只使用 CLI，不启动 Web 页面（默认行为，用于显式关闭）")
	flags.IntVar(&o.webPort, "web-port", 0, "Web 页面使用的本地端口（默认随机分配）")
	flags.BoolVar(&o.openBrowser, "open-browser", true, "启动 Web 页面时自动打开浏览器")
	flags.DurationVarP(&o.timeout, "timeout", "t", config.DefaultTimeout, "单次查询超时时间")
	flags.IntVarP(&o.attempts, "attempts", "a", config.DefaultAttempts, "每个域名在每个服务器上的查询次数")
	flags.IntVarP(&o.concurrency, "concurrency", "c", config.DefaultConcurrency,
		fmt.Sprintf("同时测试的服务器数量（默认 %d，即 CPU 线程数 × %d）",
			config.AutoConcurrency(), config.DefaultConcurrencyMultiplier))
	flags.BoolVar(&o.systemDNS, "system-dns", true, "检测系统 DNS 并纳入对比")
	flags.StringVar(&o.warmup, "warmup-domain", config.DefaultWarmupDomain, "预热查询使用的域名（不计入结果）")
	flags.StringVarP(&o.formula, "formula", "f", config.DefaultFormula,
		"CLI 排名所用公式: "+ui.FormulaOptions())
	flags.BoolVar(&o.jsonOut, "json", false, "以 JSON 输出结果摘要（进度信息走 stderr）")
	flags.BoolVar(&o.dryRun, "dry-run", false, "只打印将要执行的测试计划，不实际发起查询")

	return cmd
}

// newWebCmd builds the "web" command.
func newWebCmd() *cobra.Command {
	var o webOptions

	cmd := &cobra.Command{
		Use:   "web",
		Short: "打开本地 Web 结果分析页面",
		Long: strings.Join([]string{
			"在 127.0.0.1 上启动一个临时 Web 服务，用于查看测试结果：",
			"切换四套评分公式、导入历史 JSON、导出 JSON，并查看排名 / 延迟 / 成功率图表。",
			"服务仅监听本机回环地址，测试完成后按 Ctrl+C 退出即可。",
		}, "\n"),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWeb(cmd, o)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&o.result, "result", "r", "", "要展示的结果 JSON 文件（本工具或 xxnuo/dns-benchmark / palemoky/dnspick 格式）")
	flags.IntVar(&o.port, "port", 0, "本地端口（默认随机分配）")
	flags.BoolVar(&o.noOpen, "no-open", false, "不自动打开浏览器，只打印地址")
	return cmd
}

// newFormulasCmd prints the catalogue of scoring formulas.
func newFormulasCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "formulas",
		Short: "列出四套评分公式及其适用场景",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			for i, f := range scorer.Formulas {
				fmt.Fprintf(out, "%d. %s（%s）\n", i+1, f.Name, f.ID)
				fmt.Fprintf(out, "   公式: %s\n", f.Expr)
				fmt.Fprintf(out, "   说明: %s\n", f.Desc)
				fmt.Fprintf(out, "   适用: %s\n\n", f.Scenario)
			}
			fmt.Fprintln(out, "提示：同一 DNS 在不同公式下排名可能变化，请结合使用场景选择。")
			return nil
		},
	}
}

// newServersCmd lists the built-in server inventory.
func newServersCmd() *cobra.Command {
	var protocols string
	var class string
	var regions string
	var policies string
	var ipVersion string

	cmd := &cobra.Command{
		Use:   "servers",
		Short: "列出内置的 DNS 服务器",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			protos, _, err := config.ParseProtocolSelection(protocols)
			if err != nil {
				return err
			}
			categories, err := config.ParseServerCategories(class)
			if err != nil {
				return err
			}
			regionCodes, err := config.ParseRegions(regions)
			if err != nil {
				return err
			}
			policyKinds, err := config.ParsePolicies(policies)
			if err != nil {
				return err
			}
			want, err := config.ParseIPVersion(ipVersion)
			if err != nil {
				return err
			}
			servers, skipped, err := planServers(protos, categories, regionCodes, policyKinds, want)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, s := range servers {
				fmt.Fprintf(out, "%-6s %-9s %-46s %-10s %s\n",
					s.Protocol.Label(), familyTag(s.Family), s.Address,
					policy.Label(s.Policy), s.Name)
			}
			fmt.Fprintf(out, "\n共 %d 个服务器。\n", len(servers))
			if skipped > 0 {
				fmt.Fprintf(out, "另有 %d 个服务器因地址族不可用被跳过。\n", skipped)
			}
			fmt.Fprintf(out, "内置清单包含以下地区码: %s\n", strings.Join(data.RegionCodes(), ", "))
			fmt.Fprintf(out, "内置清单的过滤策略分布: %s\n", policySummary(data.PolicyCounts()))
			return nil
		},
	}

	cmd.Flags().StringVarP(&protocols, "protocols", "p", "udp,dot,doh,doh3", "按协议筛选: udp,dot,doh,doh3")
	cmd.Flags().StringVar(&class, "server-class", "", "按来源筛选: cn(国内) | intl(国外) | all")
	cmd.Flags().StringVar(&regions, "regions", "", "按地区码筛选，逗号分隔；如 cn,hk,tw,us,cdn")
	cmd.Flags().StringVar(&policies, "policy", "", "按过滤策略筛选: native | security")
	cmd.Flags().StringVar(&ipVersion, "ip-version", "both", "按地址族筛选: ipv4 | ipv6 | both")
	return cmd
}

// policySummary renders a policy -> count map for display, in canonical order.
func policySummary(counts map[policy.Kind]int) string {
	var parts []string
	for _, k := range policy.Order(counts) {
		parts = append(parts, fmt.Sprintf("%s=%d", policy.Label(k), counts[k]))
	}
	return strings.Join(parts, " ")
}

// familyTag renders a server's address family for the inventory listing.
func familyTag(f model.IPVersion) string {
	if f.IsLiteral() {
		return f.Label()
	}
	return "双栈"
}

// newDomainsCmd lists the built-in domain lists.
func newDomainsCmd() *cobra.Command {
	var mode string

	cmd := &cobra.Command{
		Use:   "domains",
		Short: "列出内置的测试域名",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			domains, err := domainlist.Select(mode)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			current := ""
			for _, d := range domains {
				if d.Group != current {
					current = d.Group
					fmt.Fprintf(out, "[%s]\n", model.GroupLabel(current))
				}
				fmt.Fprintf(out, "  %s\n", d.Name)
			}
			fmt.Fprintf(out, "\n共 %d 个域名。\n", len(domains))
			return nil
		},
	}

	cmd.Flags().StringVarP(&mode, "domains", "d", domainlist.ModeAll, "域名范围: cn | intl | all | mixed")
	return cmd
}

// resolveOutput turns a possibly-relative output path into an absolute one, so
// the message shown at the end of a run can be pasted directly.
func resolveOutput(path string) string {
	if path == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

// versionString is used in the run banner.
func versionString() string {
	return fmt.Sprintf("dns-opti %s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
}
