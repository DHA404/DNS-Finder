// Package tui implements the interactive terminal interface shown when
// dns-opti is started without a subcommand — typically by double-clicking the
// executable.
//
// It is a full-screen keyboard menu built on bubbletea: the user configures the
// test, watches the live progress panel, reads the ranked report and can open
// the local web page, all without typing a single flag. The non-interactive
// subcommands remain available for scripting.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dns-opti/internal/config"
	"dns-opti/internal/domainlist"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/region"
	"dns-opti/internal/scorer"
	"dns-opti/internal/ui"
)

// screen identifies which view is currently shown.
type screen int

const (
	screenMenu screen = iota
	screenAdvanced
	screenRunning
	screenResult
	screenHelp
	screenError
	// screenDetect shows the resolver-type detection: its progress while it
	// runs and its findings once it finishes.
	screenDetect
)

// Deps is everything the interactive interface needs from its host command.
// Injecting it keeps the model testable: the run step can be replaced with a
// stub that produces a fixed result without touching the network.
type Deps struct {
	// Version is shown in the header.
	Version string
	// Run executes a benchmark, reporting progress as queries complete.
	Run func(ctx context.Context, cfg config.Options, progress ui.ProgressFunc) (*engine.Result, error)
	// StartWeb starts the local viewer and returns the bound URL plus a
	// function that shuts it down. It must not block. result may be nil, in
	// which case the viewer opens with an empty dataset and the user can import
	// a result file from the page — that is what makes the main menu's
	// "打开 Web 界面" entry useful before any test has been run.
	StartWeb func(result *engine.Result) (url string, stop func(), err error)
	// BuildTasks resolves the workload, used to size the progress panel and to
	// describe the plan. It may be slow (it probes the network and reads the
	// system DNS configuration), so it is called off the UI thread.
	BuildTasks func(cfg config.Options) ([]model.Server, []model.Domain, []string, error)
	// SettingsPath is the file preferences are persisted to. Empty disables
	// persistence, which is what the tests use so a test run can never
	// overwrite the settings file of whoever ran it.
	SettingsPath string
	// DetectTypes probes a list of resolvers for their filtering behaviour.
	// It is a separate dependency rather than part of Run because the detection
	// is a maintenance action on the *built-in inventory*, not part of a
	// benchmark: it must be manually started, and it deliberately probes every
	// server regardless of the filters the current configuration happens to
	// carry.
	DetectTypes func(ctx context.Context, servers []model.Server, timeout time.Duration, progress policy.ProgressFunc) []policy.Detection
}

// advancedOptions are the secondary knobs, kept off the main menu so the common
// path stays short.
type advancedOptions struct {
	timeout     time.Duration
	attempts    int
	concurrency int
	warmup      string
}

// detectState holds the resolver-type detection's own state. It is kept beside
// the benchmark's state rather than reusing it because the two are independent:
// the detection can run before, after or without any benchmark, and it reports
// its own progress in its own units (servers probed, not queries issued).
type detectState struct {
	// running is true while the probes are in flight.
	running bool
	// done and total count the resolvers probed so far.
	done, total int
	// results are the completed detections, in completion order.
	results []policy.Detection
	// finished is true once the run has produced all its results.
	finished bool
	// cancel stops a run in flight.
	cancel context.CancelFunc
}

// detectEvents streams detection progress into the UI thread. It is created
// once with the model and never closed, so a stray event from a cancelled run
// is dropped rather than panicking on a closed channel.

// Model is the root bubbletea model.
type Model struct {
	deps Deps

	width, height int
	screen        screen

	// Main menu.
	items  []menuItem
	cursor int

	// Configuration under construction.
	cfg     config.Options
	formula config.Formula
	adv     advancedOptions

	// Advanced screen row cursor.
	advCursor int

	// Resolved workload, cached because building it probes the network.
	plan    *engine.Plan
	planErr error

	// Running state.
	tracker *ui.ProgressTracker
	events  chan progressMsg

	// Result state.
	result      *engine.Result
	resultLines []string
	scroll      int
	savedPath   string

	// Formula help screen.
	helpPage int

	// Local web viewer state.
	webURL  string
	webStop func()

	// Settings persistence state.
	settingsLoaded bool
	settingsSaved  bool

	// Type detection state.
	detect       detectState
	detectEvents chan tea.Msg
	detectLines  []string
	detectY      int

	// Status line.
	statusMsg string
	statusErr bool
	// notices are non-fatal remarks worth showing (skipped servers, ...).
	notices []string
}

// menuItem is one row of the main menu.
type menuItem struct {
	title string
	desc  string
	// action applies the change and returns the screen to show next, plus an
	// optional command (e.g. recomputing the plan).
	action func(m *Model) (screen, tea.Cmd)
}

// New builds the interactive interface.
func New(deps Deps) *Model {
	m := &Model{
		deps: deps,
		cfg: config.Options{
			Domains:      domainlist.ModeAll,
			Protocols:    []model.Protocol{model.ProtocolUDP, model.ProtocolDoT, model.ProtocolDoH},
			Timeout:      config.DefaultTimeout,
			Attempts:     config.DefaultAttempts,
			SystemDNS:    true,
			WarmupDomain: config.DefaultWarmupDomain,
			Formula:      string(config.FormulaComprehensive),
		},
		formula: config.FormulaComprehensive,
		adv: advancedOptions{
			timeout:     config.DefaultTimeout,
			attempts:    config.DefaultAttempts,
			concurrency: 0,
			warmup:      config.DefaultWarmupDomain,
		},
		events: make(chan progressMsg, 256),
		// Buffered so a burst of completions does not block the probe workers.
		detectEvents: make(chan tea.Msg, 256),
	}
	// Persisted preferences are applied over the defaults and before the menu
	// is built, so every description reflects them on the first frame.
	m.loadSettings()
	m.refreshMenu()
	return m
}

// Init satisfies tea.Model.
func (m *Model) Init() tea.Cmd { return m.refreshPlan() }

// refreshMenu rebuilds the menu so every description reflects current state.
func (m *Model) refreshMenu() {
	m.items = []menuItem{
		{
			title: "开始测试",
			desc:  m.describeConfig(),
			action: func(m *Model) (screen, tea.Cmd) {
				return m.startRun()
			},
		},
		{
			title: "测试域名范围",
			desc:  "当前: " + domainModeLabel(m.cfg.Domains) + "（回车在 国内 / 国外 / 分组统计 / 混合统计 间切换）",
			action: func(m *Model) (screen, tea.Cmd) {
				m.cfg.Domains = nextDomainMode(m.cfg.Domains)
				return screenMenu, m.refreshPlan()
			},
		},
		{
			title: "测试协议",
			desc:  "当前: " + protocolSelectionLabel(m.cfg.Protocols, m.cfg.Combo) + "（回车在 UDP / DoT / DoH / DoH3 / UDP+DoH 间切换）",
			action: func(m *Model) (screen, tea.Cmd) {
				m.setProtocolSelection(nextProtocolSelection(m.cfg.Protocols, m.cfg.Combo))
				return screenMenu, m.refreshPlan()
			},
		},
		{
			title: "测试地址族",
			desc:  "当前: " + m.cfg.IPVersion.Label() + "（回车在 IPv4 / IPv6 / 两者间切换；主机名会按所选地址族解析）",
			action: func(m *Model) (screen, tea.Cmd) {
				m.cfg.IPVersion = nextIPVersion(m.cfg.IPVersion)
				return screenMenu, m.refreshPlan()
			},
		},
		{
			title: "地区筛选",
			desc:  m.describeRegions(),
			action: func(m *Model) (screen, tea.Cmd) {
				m.cycleRegionPreset()
				return screenMenu, m.refreshPlan()
			},
		},
		{
			title: "过滤策略筛选",
			desc:  m.describePolicies(),
			action: func(m *Model) (screen, tea.Cmd) {
				m.cyclePolicyPreset()
				return screenMenu, m.refreshPlan()
			},
		},
		{
			title: "评测公式",
			desc:  "当前: " + m.formulaInfo().Name + " — " + m.formulaInfo().Scenario,
			action: func(m *Model) (screen, tea.Cmd) {
				m.formula = nextFormula(m.formula)
				m.cfg.Formula = string(m.formula)
				return screenMenu, nil
			},
		},
		{
			title: "是否对比系统 DNS",
			desc:  "当前: " + onOff(m.cfg.SystemDNS) + "（读取本机 DNS 配置并纳入排名）",
			action: func(m *Model) (screen, tea.Cmd) {
				m.cfg.SystemDNS = !m.cfg.SystemDNS
				return screenMenu, m.refreshPlan()
			},
		},
		{
			title: "高级选项",
			desc:  m.describeAdvanced(),
			action: func(m *Model) (screen, tea.Cmd) {
				return screenAdvanced, nil
			},
		},
		{
			title: "打开 Web 界面",
			desc:  m.describeWeb(),
			action: func(m *Model) (screen, tea.Cmd) {
				// The viewer is opened from the main menu with whatever data is
				// at hand: the finished run's report when there is one, and an
				// empty page (with the import button) before any test has run.
				if m.webURL != "" {
					return screenMenu, nil
				}
				return screenMenu, m.startWeb()
			},
		},
		{
			title: "检测内置 DNS 类型",
			desc:  m.describeDetect(),
			action: func(m *Model) (screen, tea.Cmd) {
				return m.startDetect()
			},
		},
		{
			title: "查看公式说明",
			desc:  "四套评分公式的表达式、含义与适用场景",
			action: func(m *Model) (screen, tea.Cmd) {
				m.helpPage = 0
				return screenHelp, nil
			},
		},
		{
			title: "退出",
			desc:  "关闭本窗口",
			action: func(m *Model) (screen, tea.Cmd) {
				return screenMenu, tea.Quit
			},
		},
	}

	if m.cursor >= len(m.items) {
		m.cursor = len(m.items) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// describeConfig summarizes what "开始测试" will do.
func (m *Model) describeConfig() string {
	suffix := ""
	if m.cfg.Combo == model.ComboUDPDoH {
		suffix = " · " + model.ComboUDPDoHLabel
	}
	prefix := domainModeLabel(m.cfg.Domains) + " · " +
		protocolSelectionLabel(m.cfg.Protocols, m.cfg.Combo) + suffix + " · "
	switch {
	case m.planErr != nil:
		return prefix + m.planErr.Error()
	case m.plan == nil:
		return prefix + "正在统计待测服务器…"
	default:
		return prefix + fmtPlan(m.plan)
	}
}

// describeAdvanced summarizes the secondary options.
func (m *Model) describeAdvanced() string {
	return concat("超时 ", m.adv.timeout.String(),
		" · 每域名 ", itoa(m.adv.attempts), " 次",
		" · 并发 ", itoa(m.cfg.EffectiveConcurrency()),
		" · 预热域名 ", m.adv.warmup)
}

// describeRegions renders the current region filter for the menu.
func (m *Model) describeRegions() string {
	if len(m.cfg.Regions) == 0 {
		return "当前: 全部地区（回车在 全部 → 中国 → 亚太 → 欧洲 → 美洲 → CDN → 内网/未知 间切换）"
	}
	names := make([]string, 0, len(m.cfg.Regions))
	for _, code := range m.cfg.Regions {
		names = append(names, region.Label(code))
	}
	return "当前: " + strings.Join(names, " / ") +
		fmt.Sprintf("（%d 个地区码，回车切换下一个预设）", len(m.cfg.Regions))
}

// describePolicies renders the current filtering-policy filter for the menu.
func (m *Model) describePolicies() string {
	if len(m.cfg.Policies) == 0 {
		return "当前: 全部策略（回车在 全部 → 原生 → 安全 间切换；不改 DNS 记录，只筛选服务器）"
	}
	names := make([]string, 0, len(m.cfg.Policies))
	for _, k := range m.cfg.Policies {
		names = append(names, policy.Label(k))
	}
	return "当前: " + strings.Join(names, " / ") + "（" + policy.Description(m.cfg.Policies[0]) + "）"
}

// cyclePolicyPreset advances the policy filter through 全部 → 原生 → 安全.
//
// A preset cycle rather than a multi-select is deliberate: the two policies are
// exclusive answers to "does this resolver filter?", so a user comparing them
// wants them one at a time, and the default 全部 has to stay one keypress away.
// The CLI's --policy covers the multi-select case.
func (m *Model) cyclePolicyPreset() {
	presets := append([]policy.Kind{""}, policy.All()...)
	next := 0
	for i, p := range presets {
		if (p == "" && len(m.cfg.Policies) == 0) ||
			(p != "" && samePolicy(p, m.cfg.Policies)) {
			next = (i + 1) % len(presets)
			break
		}
	}
	if presets[next] == "" {
		m.cfg.Policies = nil
		return
	}
	m.cfg.Policies = []policy.Kind{presets[next]}
}

// samePolicy reports whether a policy filter holds exactly one given kind.
func samePolicy(k policy.Kind, kinds []policy.Kind) bool {
	return len(kinds) == 1 && policy.CanonicalKind(kinds[0]) == policy.CanonicalKind(k)
}

// describeWeb renders the current state of the local viewer for the menu.
func (m *Model) describeWeb() string {
	if m.webURL != "" {
		return "已在运行: " + m.webURL + "（回车保持，按 w 关闭）"
	}
	if m.result != nil {
		return "在浏览器中打开本次测试结果（含明细、图表与公式切换）"
	}
	return "在浏览器中打开可视化页面（暂无数据，可在页面上导入结果 JSON）"
}

// describeDetect renders the detection entry's current state.
func (m *Model) describeDetect() string {
	if m.detect.running {
		return fmt.Sprintf("正在检测… %d/%d（按 Esc 中止）", m.detect.done, m.detect.total)
	}
	if m.detect.finished {
		s := summarizeDetect(m.detect.results)
		return fmt.Sprintf("上次检测: 安全 %d · 原生 %d · 未确认 %d（回车重新检测）",
			s.Security, s.Native, s.Unknown)
	}
	return "逐个探测内置 DNS 对分类测试域的应答，判断其属「安全」还是「原生」（仅手动启动）"
}

// setProtocolSelection records a protocol set and its combined-mode selector
// together, so the two can never drift apart.
func (m *Model) setProtocolSelection(protocols []model.Protocol, combo string) {
	m.cfg.Protocols = protocols
	m.cfg.Combo = combo
}

// cycleRegionPreset advances the region filter through the preset groups.
//
// A preset is used rather than a free-form editor because the filter is a
// coarse "which part of the world" question; the CLI's --regions covers the
// precise case.
func (m *Model) cycleRegionPreset() {
	presets := regionPresets()
	// Find the preset whose codes match the current filter, so cycling
	// continues from where the user is rather than always restarting.
	next := 0
	for i, p := range presets {
		if sameStrings(p.codes, m.cfg.Regions) {
			next = (i + 1) % len(presets)
			break
		}
	}
	m.cfg.Regions = append([]string(nil), presets[next].codes...)
}

// regionPreset is one selectable region filter.
type regionPreset struct {
	label string
	codes []string
}

// regionPresets returns the selectable region filters, starting with "all".
func regionPresets() []regionPreset {
	presets := []regionPreset{{label: "全部地区", codes: nil}}
	for _, g := range region.Groups() {
		// The "special" group (private / unknown) is selectable too: a user
		// auditing their own resolvers wants exactly that slice.
		presets = append(presets, regionPreset{label: g.Label, codes: g.Codes})
	}
	return presets
}

// sameStrings reports whether two string slices hold the same values in order.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// formulaInfo returns the metadata of the selected formula.
func (m *Model) formulaInfo() scorer.FormulaInfo {
	if info, ok := scorer.FormulaByID(m.formula); ok {
		return info
	}
	return scorer.Formulas[0]
}

// syncAdvanced copies the advanced screen values into the run configuration.
func (m *Model) syncAdvanced() {
	m.cfg.Timeout = m.adv.timeout
	m.cfg.Attempts = m.adv.attempts
	m.cfg.Concurrency = m.adv.concurrency
	m.cfg.WarmupDomain = m.adv.warmup
}

// Update handles all messages.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case planMsg:
		m.plan, m.planErr = msg.plan, msg.err
		m.refreshMenu()
		return m, nil

	case progressMsg:
		if m.tracker != nil {
			m.tracker.Observe(msg.event)
		}
		return m, waitForProgress(m.events)

	case runDoneMsg:
		return m.onRunDone(msg)

	case tickMsg:
		if m.screen == screenRunning {
			return m, tick()
		}
		return m, nil

	case webStartedMsg:
		if msg.err != nil {
			m.statusMsg = "启动 Web 页面失败: " + msg.err.Error()
			m.statusErr = true
			return m, nil
		}
		m.webURL = msg.url
		m.webStop = msg.stop
		m.statusMsg = "本地 Web 页面已启动: " + msg.url + "（按 w 关闭）"
		m.statusErr = false
		return m, nil

	case savedMsg:
		if msg.err != nil {
			m.statusMsg = "保存报告失败: " + msg.err.Error()
			m.statusErr = true
		} else {
			m.savedPath = msg.path
			m.statusMsg = "报告已保存: " + msg.path
			m.statusErr = false
		}
		return m, nil

	case detectProgressMsg:
		m.detect.done = msg.done
		m.detect.total = msg.total
		m.detect.results = append(m.detect.results, msg.det)
		return m, waitForDetect(m.detectEvents)

	case detectDoneMsg:
		m.detect.running = false
		m.detect.finished = true
		m.detect.cancel = nil
		if len(msg.results) > 0 {
			m.detect.results = msg.results
		}
		m.detectLines = detectReport(m.detect.results)
		m.detectY = 0
		m.statusMsg = ""
		m.statusErr = false
		m.refreshMenu()
		return m, nil
	}
	return m, nil
}

// handleKey dispatches a key press to the active screen.
func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// The running screen owns ^C / esc / q for cancelling the run.
	if m.screen != screenRunning {
		if key == "ctrl+c" {
			m.stopWeb()
			return m, tea.Quit
		}
	}

	switch m.screen {
	case screenMenu:
		return m.handleMenuKey(key)
	case screenAdvanced:
		return m.handleAdvancedKey(key)
	case screenRunning:
		return m.handleRunningKey(key)
	case screenResult:
		return m.handleResultKey(key)
	case screenHelp:
		return m.handleHelpKey(key)
	case screenError:
		return m.handleErrorKey(key)
	case screenDetect:
		return m.handleDetectKey(key)
	}
	return m, nil
}

// handleDetectKey scrolls the detection report and lets the user cancel a run.
func (m *Model) handleDetectKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.detectY > 0 {
			m.detectY--
		}
	case "down", "j":
		if m.detectY < m.maxDetectScroll() {
			m.detectY++
		}
	case "pgup":
		m.detectY -= m.bodyHeight()
		if m.detectY < 0 {
			m.detectY = 0
		}
	case "pgdown", " ":
		m.detectY += m.bodyHeight()
		if m.detectY > m.maxDetectScroll() {
			m.detectY = m.maxDetectScroll()
		}
	case "home", "g":
		m.detectY = 0
	case "end", "G":
		m.detectY = m.maxDetectScroll()
	case "esc":
		if m.detect.running {
			m.cancelDetect()
			m.statusMsg = "正在中止检测…"
			m.statusErr = false
			return m, nil
		}
		m.screen = screenMenu
		m.refreshMenu()
	case "enter", "backspace", "q":
		if m.detect.running {
			return m, nil
		}
		m.screen = screenMenu
		m.refreshMenu()
	}
	return m, nil
}

// maxDetectScroll is the largest valid scroll offset of the detection report.
func (m *Model) maxDetectScroll() int {
	max := len(m.detectLines) - m.bodyHeight()
	if max < 0 {
		return 0
	}
	return max
}

// handleMenuKey drives the main menu.
func (m *Model) handleMenuKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = len(m.items) - 1
	case "esc":
		m.stopWeb()
		return m, tea.Quit
	case "r":
		// Shortcut for the common case: start immediately.
		next, cmd := m.startRun()
		m.screen = next
		m.refreshMenu()
		return m, cmd
	case "enter", " ", "right", "l":
		next, cmd := m.items[m.cursor].action(m)
		m.screen = next
		m.refreshMenu()
		// Persist after any menu action rather than inside each one, so a new
		// option can never be added without also being remembered. The cost is
		// one small atomic write per keypress, which is nothing next to a
		// network probe, and the benefit is that the saved file always matches
		// what the menu shows.
		m.persist()
		return m, cmd
	}
	return m, nil
}

// handleRunningKey lets the user cancel a run in flight.
func (m *Model) handleRunningKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "ctrl+c", "esc", "q":
		if m.tracker != nil {
			m.tracker.Cancel()
			m.statusMsg = "正在取消测试…"
			m.statusErr = false
		}
	}
	return m, nil
}

// handleResultKey scrolls the report and offers the follow-up actions.
func (m *Model) handleResultKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.scroll > 0 {
			m.scroll--
		}
	case "down", "j":
		if m.scroll < m.maxScroll() {
			m.scroll++
		}
	case "pgup":
		m.scroll -= m.bodyHeight()
		if m.scroll < 0 {
			m.scroll = 0
		}
	case "pgdown", " ":
		m.scroll += m.bodyHeight()
		if m.scroll > m.maxScroll() {
			m.scroll = m.maxScroll()
		}
	case "home", "g":
		m.scroll = 0
	case "end", "G":
		m.scroll = m.maxScroll()
	case "o":
		if m.result == nil {
			return m, nil
		}
		if m.webURL != "" {
			m.statusMsg = "Web 页面已在运行: " + m.webURL
			return m, nil
		}
		return m, m.startWeb()
	case "w":
		if m.webURL == "" {
			return m, nil
		}
		m.stopWeb()
		return m, nil
	case "s":
		return m, m.saveReport()
	case "enter", "esc", "backspace":
		m.screen = screenMenu
		m.scroll = 0
		m.refreshMenu()
	}
	return m, nil
}

// handleHelpKey pages through the formula catalogue.
func (m *Model) handleHelpKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "left", "h", "up", "k":
		if m.helpPage > 0 {
			m.helpPage--
		}
	case "right", "l", "down", "j", " ":
		if m.helpPage < len(scorer.Formulas)-1 {
			m.helpPage++
		}
	case "esc", "enter", "backspace", "q":
		m.screen = screenMenu
	}
	return m, nil
}

// handleErrorKey returns to the menu.
func (m *Model) handleErrorKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "enter", "backspace", "q":
		m.screen = screenMenu
		m.refreshMenu()
	}
	return m, nil
}

// handleAdvancedKey edits the secondary options: up/down picks a row,
// left/right changes its value.
func (m *Model) handleAdvancedKey(key string) (tea.Model, tea.Cmd) {
	const rows = 4
	switch key {
	case "up", "k":
		if m.advCursor > 0 {
			m.advCursor--
		}
	case "down", "j":
		if m.advCursor < rows-1 {
			m.advCursor++
		}
	case "left", "h":
		m.adjustAdvanced(-1)
	case "right", "l", "enter", " ":
		m.adjustAdvanced(1)
	case "esc", "backspace", "q":
		m.syncAdvanced()
		m.screen = screenMenu
		m.refreshMenu()
		// Leaving the advanced screen is the moment its values become the run
		// configuration, so it is also the moment they become worth saving.
		m.persist()
	}
	return m, nil
}

// adjustAdvanced steps the option under the cursor.
func (m *Model) adjustAdvanced(dir int) {
	switch m.advCursor {
	case 0:
		m.adv.timeout = cycle([]time.Duration{
			time.Second, 2 * time.Second, 3 * time.Second,
			5 * time.Second, 8 * time.Second, 10 * time.Second,
		}, m.adv.timeout, dir)
	case 1:
		m.adv.attempts = cycle([]int{1, 2, 3, 5, 8}, m.adv.attempts, dir)
	case 2:
		m.adv.concurrency = cycle([]int{0, 2, 4, 8, 12, 16, 24, 32}, m.adv.concurrency, dir)
	case 3:
		m.adv.warmup = cycle([]string{
			"example.com", "www.baidu.com", "www.google.com", "cloudflare.com",
		}, m.adv.warmup, dir)
	}
	m.syncAdvanced()
}

// onRunDone transitions out of the running screen.
func (m *Model) onRunDone(msg runDoneMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if m.tracker != nil && m.tracker.Cancelled() {
			m.statusMsg = "测试已取消"
			m.statusErr = false
			m.screen = screenMenu
			m.refreshMenu()
			return m, nil
		}
		m.statusMsg = msg.err.Error()
		m.statusErr = true
		m.screen = screenError
		return m, nil
	}

	m.result = msg.result
	m.resultLines = splitLines(msg.report)
	m.scroll = 0
	m.screen = screenResult
	m.statusMsg = ""
	m.statusErr = false
	m.notices = msg.notices
	return m, nil
}

// bodyHeight is the number of content lines available under the header.
func (m *Model) bodyHeight() int {
	body := m.height_() - 6
	if body < 4 {
		body = 4
	}
	return body
}

// maxScroll is the largest valid scroll offset of the result view.
func (m *Model) maxScroll() int {
	max := len(m.resultLines) - m.bodyHeight()
	if max < 0 {
		return 0
	}
	return max
}

// width_ is the usable terminal width.
func (m *Model) width_() int {
	if m.width <= 0 {
		return 96
	}
	return m.width
}

// height_ is the usable terminal height.
func (m *Model) height_() int {
	if m.height <= 0 {
		return 26
	}
	return m.height
}

// stopWeb shuts the local viewer down if it is running.
func (m *Model) stopWeb() {
	if m.webStop != nil {
		m.webStop()
		m.webStop = nil
	}
	if m.webURL != "" {
		m.webURL = ""
		m.statusMsg = "本地 Web 页面已关闭"
		m.statusErr = false
	}
}
