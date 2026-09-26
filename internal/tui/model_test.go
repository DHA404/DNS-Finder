package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dns-opti/internal/config"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/region"
	"dns-opti/internal/scheduler"
	"dns-opti/internal/ui"
)

// stubDeps builds a Deps whose steps are fully in-memory: no network, no
// system DNS, no web server.
func stubDeps(t *testing.T, runErr error) (Deps, *int) {
	t.Helper()
	runCalls := 0
	return Deps{
		Version: "test",
		Run: func(ctx context.Context, cfg config.Options, progress ui.ProgressFunc) (*engine.Result, error) {
			runCalls++
			if runErr != nil {
				return nil, runErr
			}
			// Emit a couple of events so the panel has something to show.
			if progress != nil {
				for i := 0; i < 3; i++ {
					progress(scheduler.ProgressEvent{
						Server:  model.Server{Name: "AliDNS", Address: "223.5.5.5", Protocol: model.ProtocolUDP},
						Domain:  "baidu.com",
						Group:   model.GroupCN,
						Success: true,
						Latency: 12 * time.Millisecond,
						Done:    i + 1,
						Total:   3,
					})
				}
			}
			return &engine.Result{
				Meta: model.Meta{Version: "1.0", Concurrency: 4, WarmupDomain: "example.com"},
				Summaries: []model.Summary{{
					DNS: "223.5.5.5", Name: "AliDNS", Protocol: model.ProtocolUDP,
					Group: model.GroupCN, Total: 3, Success: 3, SuccessRate: 1,
					AvgMS: 12, P95MS: 13, StdDevMS: 0.5,
				}},
				Path:   "result.json",
				Total:  3,
				Failed: 0,
			}, nil
		},
		StartWeb: func(result *engine.Result) (string, func(), error) {
			return "http://127.0.0.1:12345", func() {}, nil
		},
		BuildTasks: func(cfg config.Options) ([]model.Server, []model.Domain, []string, error) {
			return []model.Server{
					{Name: "AliDNS", Address: "223.5.5.5", Protocol: model.ProtocolUDP},
					{Name: "AliDNS", Address: "dns.alidns.com", Protocol: model.ProtocolDoT},
				},
				[]model.Domain{
					{Name: "baidu.com", Group: model.GroupCN},
					{Name: "qq.com", Group: model.GroupCN},
				},
				nil, nil
		},
	}, &runCalls
}

// sized builds a model that has received a window size, so View renders fully.
func sized(t *testing.T, runErr error) (*Model, *int) {
	t.Helper()
	deps, calls := stubDeps(t, runErr)
	m := New(deps)
	// Apply the initial plan resolution so the menu shows a real workload.
	if msg := m.refreshPlan()(); msg != nil {
		m.Update(msg)
	}
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return m, calls
}

// press sends a key and returns the model.
func press(t *testing.T, m *Model, key string) *Model {
	t.Helper()
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
	return next.(*Model)
}

// pressSpecial sends a named key (up/down/enter/esc/...).
func pressSpecial(t *testing.T, m *Model, key tea.KeyType) *Model {
	t.Helper()
	next, _ := m.Update(tea.KeyMsg{Type: key})
	return next.(*Model)
}

// TestNewStartsOnMenu verifies the initial screen and that every menu entry has
// a title and a description.
func TestNewStartsOnMenu(t *testing.T) {
	m, _ := sized(t, nil)
	if m.screen != screenMenu {
		t.Fatalf("初始界面 = %v, 期望 screenMenu", m.screen)
	}
	if len(m.items) < 5 {
		t.Fatalf("主菜单只有 %d 项, 期望至少 5 项", len(m.items))
	}
	for i, item := range m.items {
		if strings.TrimSpace(item.title) == "" {
			t.Errorf("第 %d 个菜单项没有标题", i)
		}
		if strings.TrimSpace(item.desc) == "" {
			t.Errorf("菜单项 %q 没有说明文字", item.title)
		}
	}
}

// TestMenuViewRendersKeyParts checks the menu screen shows its title, every
// entry and the key hints.
func TestMenuViewRendersKeyParts(t *testing.T) {
	m, _ := sized(t, nil)
	out := m.View()

	for _, want := range []string{"DNS 优选工具", "开始测试", "测试域名范围", "测试协议", "评测公式", "高级选项", "退出"} {
		if !strings.Contains(out, want) {
			t.Errorf("菜单缺少 %q\n%s", want, out)
		}
	}
	if !strings.Contains(out, "回车") {
		t.Errorf("菜单没有操作提示:\n%s", out)
	}
	// The selected row must be marked.
	if !strings.Contains(out, "❯") {
		t.Errorf("菜单没有标出当前选中项:\n%s", out)
	}
}

// TestCursorNavigation verifies the cursor moves and clamps.
func TestCursorNavigation(t *testing.T) {
	m, _ := sized(t, nil)

	m = pressSpecial(t, m, tea.KeyUp)
	if m.cursor != 0 {
		t.Errorf("在首项按上键后 cursor = %d, 期望 0（不应越界）", m.cursor)
	}

	m = pressSpecial(t, m, tea.KeyDown)
	if m.cursor != 1 {
		t.Errorf("按下键后 cursor = %d, 期望 1", m.cursor)
	}

	m = pressSpecial(t, m, tea.KeyEnd)
	if m.cursor != len(m.items)-1 {
		t.Errorf("按 End 后 cursor = %d, 期望 %d", m.cursor, len(m.items)-1)
	}
	m = pressSpecial(t, m, tea.KeyDown)
	if m.cursor != len(m.items)-1 {
		t.Errorf("在末项按下键后 cursor = %d, 期望 %d（不应越界）", m.cursor, len(m.items)-1)
	}
}

// TestDomainModeCycles verifies the domain-scope entry cycles through the three
// modes and back.
func TestDomainModeCycles(t *testing.T) {
	m, _ := sized(t, nil)
	// Find the domain scope entry.
	idx := -1
	for i, item := range m.items {
		if strings.Contains(item.title, "域名范围") {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("菜单里找不到「测试域名范围」")
	}
	m.cursor = idx

	start := m.cfg.Domains
	seen := map[string]bool{}
	// Four modes now: cn / intl / all / mixed. The loop must visit every one
	// and return to where it started.
	for i := 0; i < 4; i++ {
		seen[m.cfg.Domains] = true
		m = pressSpecial(t, m, tea.KeyEnter)
	}
	if !seen["cn"] || !seen["intl"] || !seen["all"] || !seen["mixed"] {
		t.Fatalf("域名范围只循环到 %v, 期望覆盖 cn / intl / all / mixed", seen)
	}
	if m.cfg.Domains != start {
		t.Errorf("循环一圈后停在 %q, 期望回到起点 %q", m.cfg.Domains, start)
	}
	if m.screen != screenMenu {
		t.Errorf("切换域名范围后跳到了 %v, 应留在菜单", m.screen)
	}
}

// TestProtocolEntryKeepsOrder verifies the protocol entry always yields a
// non-empty, canonical-order set.
func TestProtocolEntryKeepsOrder(t *testing.T) {
	m, _ := sized(t, nil)
	idx := -1
	for i, item := range m.items {
		if strings.Contains(item.title, "协议") {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("菜单里找不到「测试协议」")
	}
	m.cursor = idx

	for i := 0; i < 6; i++ {
		m = pressSpecial(t, m, tea.KeyEnter)
		if len(m.cfg.Protocols) == 0 {
			t.Fatalf("第 %d 次切换后协议列表为空", i)
		}
		// Order must match the canonical protocol order.
		last := -1
		for _, p := range m.cfg.Protocols {
			pos := -1
			for j, all := range model.AllProtocols {
				if all == p {
					pos = j
				}
			}
			if pos <= last {
				t.Fatalf("协议顺序不规范: %v", m.cfg.Protocols)
			}
			last = pos
		}
	}
}

// TestFormulaEntryCyclesAll verifies the formula entry reaches all four
// formulas and keeps cfg.Formula in sync.
func TestFormulaEntryCyclesAll(t *testing.T) {
	m, _ := sized(t, nil)
	idx := -1
	for i, item := range m.items {
		if strings.Contains(item.title, "公式") {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("菜单里找不到「评测公式」")
	}
	m.cursor = idx

	seen := map[config.Formula]bool{}
	for i := 0; i < 4; i++ {
		seen[m.formula] = true
		if m.cfg.Formula != string(m.formula) {
			t.Fatalf("cfg.Formula = %q 与 formula = %q 不同步", m.cfg.Formula, m.formula)
		}
		m = pressSpecial(t, m, tea.KeyEnter)
	}
	if len(seen) != 4 {
		t.Fatalf("只循环到 %d 套公式, 期望 4 套: %v", len(seen), seen)
	}
}

// TestSystemDNSToggle verifies the boolean entry flips.
func TestSystemDNSToggle(t *testing.T) {
	m, _ := sized(t, nil)
	idx := -1
	for i, item := range m.items {
		if strings.Contains(item.title, "系统 DNS") {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("菜单里找不到「是否对比系统 DNS」")
	}
	m.cursor = idx

	before := m.cfg.SystemDNS
	m = pressSpecial(t, m, tea.KeyEnter)
	if m.cfg.SystemDNS == before {
		t.Error("回车后系统 DNS 开关没有变化")
	}
	m = pressSpecial(t, m, tea.KeyEnter)
	if m.cfg.SystemDNS != before {
		t.Error("再次回车后系统 DNS 开关没有恢复")
	}
}

// TestAdvancedScreenEditsOptions verifies the advanced screen moves between
// rows and changes values, and that the change reaches the run configuration.
func TestAdvancedScreenEditsOptions(t *testing.T) {
	m, _ := sized(t, nil)
	// Jump to 高级选项.
	for i, item := range m.items {
		if strings.Contains(item.title, "高级选项") {
			m.cursor = i
		}
	}
	m = pressSpecial(t, m, tea.KeyEnter)
	if m.screen != screenAdvanced {
		t.Fatalf("回车「高级选项」后界面 = %v, 期望 screenAdvanced", m.screen)
	}
	if out := m.View(); !strings.Contains(out, "高级选项") || !strings.Contains(out, "单次查询超时") {
		t.Errorf("高级选项界面渲染不完整:\n%s", out)
	}

	// Row 0 is the timeout; moving right must change it and sync into cfg.
	before := m.adv.timeout
	m = pressSpecial(t, m, tea.KeyRight)
	if m.adv.timeout == before {
		t.Error("按右键后超时时间没有变化")
	}
	if m.cfg.Timeout != m.adv.timeout {
		t.Errorf("cfg.Timeout = %v 与 adv.timeout = %v 不同步", m.cfg.Timeout, m.adv.timeout)
	}

	// Move down to the attempts row and change it.
	m = pressSpecial(t, m, tea.KeyDown)
	if m.advCursor != 1 {
		t.Fatalf("按下键后 advCursor = %d, 期望 1", m.advCursor)
	}
	beforeAttempts := m.adv.attempts
	m = pressSpecial(t, m, tea.KeyRight)
	if m.adv.attempts == beforeAttempts {
		t.Error("按右键后查询次数没有变化")
	}

	// Row 2 is concurrency; row 3 the warm-up domain.
	m = pressSpecial(t, m, tea.KeyDown)
	m = pressSpecial(t, m, tea.KeyDown)
	if m.advCursor != 3 {
		t.Fatalf("advCursor = %d, 期望 3", m.advCursor)
	}
	beforeWarmup := m.adv.warmup
	m = pressSpecial(t, m, tea.KeyRight)
	if m.adv.warmup == beforeWarmup {
		t.Error("按右键后预热域名没有变化")
	}
	if m.cfg.WarmupDomain != m.adv.warmup {
		t.Errorf("cfg.WarmupDomain = %q 与 adv.warmup = %q 不同步", m.cfg.WarmupDomain, m.adv.warmup)
	}

	// Esc returns to the menu.
	m = pressSpecial(t, m, tea.KeyEsc)
	if m.screen != screenMenu {
		t.Errorf("按 Esc 后界面 = %v, 期望返回菜单", m.screen)
	}
}

// TestHelpScreenPages verifies the formula help pages through all four
// formulas and wraps correctly at the ends.
func TestHelpScreenPages(t *testing.T) {
	m, _ := sized(t, nil)
	for i, item := range m.items {
		if strings.Contains(item.title, "公式说明") {
			m.cursor = i
		}
	}
	m = pressSpecial(t, m, tea.KeyEnter)
	if m.screen != screenHelp {
		t.Fatalf("界面 = %v, 期望 screenHelp", m.screen)
	}

	if out := m.View(); !strings.Contains(out, "评分公式 1/4") {
		t.Errorf("帮助页没有显示页码:\n%s", out)
	}
	// Page forward through all formulas.
	for i := 1; i < 4; i++ {
		m = pressSpecial(t, m, tea.KeyRight)
		want := "评分公式 " + itoa(i+1) + "/4"
		if out := m.View(); !strings.Contains(out, want) {
			t.Errorf("第 %d 次翻页后期望 %q:\n%s", i, want, out)
		}
	}
	// At the last page, paging right must not overflow.
	m = pressSpecial(t, m, tea.KeyRight)
	if m.helpPage != 3 {
		t.Errorf("末页继续右翻后 helpPage = %d, 期望 3", m.helpPage)
	}
	// And left at page 0 must not underflow.
	m = pressSpecial(t, m, tea.KeyLeft)
	m = pressSpecial(t, m, tea.KeyLeft)
	m = pressSpecial(t, m, tea.KeyLeft)
	m = pressSpecial(t, m, tea.KeyLeft)
	if m.helpPage != 0 {
		t.Errorf("首页继续左翻后 helpPage = %d, 期望 0", m.helpPage)
	}
	m = pressSpecial(t, m, tea.KeyEsc)
	if m.screen != screenMenu {
		t.Errorf("按 Esc 后界面 = %v, 期望返回菜单", m.screen)
	}
}

// TestRunFlowReachesResult drives a full run through the model: start, consume
// the progress events, finish, and render the report.
func TestRunFlowReachesResult(t *testing.T) {
	m, calls := sized(t, nil)

	// Choose "开始测试" (the first entry) and run its action.
	m.cursor = 0
	next, runCmd := m.items[0].action(m)
	if next != screenRunning {
		t.Fatalf("开始测试后界面 = %v, 期望 screenRunning", next)
	}
	if m.tracker == nil {
		t.Fatal("开始测试后没有创建进度跟踪器")
	}
	// The progress panel must render while running.
	if out := m.View(); !strings.Contains(out, "正在测试") {
		t.Errorf("运行界面没有标题:\n%s", out)
	}

	// Execute the batch: the first command performs the run and returns a
	// runDoneMsg. Collect messages from the batch until it settles.
	msgs := drainBatch(t, runCmd)
	if *calls != 1 {
		t.Fatalf("Run 被调用 %d 次, 期望 1 次", *calls)
	}

	done, ok := findRunDone(msgs)
	if !ok {
		t.Fatalf("批处理没有产生 runDoneMsg, 实际: %#v", msgs)
	}
	if done.err != nil {
		t.Fatalf("运行返回错误: %v", done.err)
	}
	if done.report == "" {
		t.Fatal("runDoneMsg 没有携带渲染好的报告")
	}

	m.Update(done)
	if m.screen != screenResult {
		t.Fatalf("运行结束后界面 = %v, 期望 screenResult", m.screen)
	}
	if m.result == nil || len(m.resultLines) == 0 {
		t.Fatal("运行结束后没有结果内容")
	}

	out := m.View()
	if !strings.Contains(out, "测试结果") {
		t.Errorf("结果界面没有标题:\n%s", out)
	}
	// The report itself must be present (the summary line from ui.PrintResult).
	if !strings.Contains(out, "查询总数") {
		t.Errorf("结果界面没有渲染报告正文:\n%s", out)
	}
	if !strings.Contains(out, "o 打开 Web 页面") {
		t.Errorf("结果界面没有操作提示:\n%s", out)
	}
}

// TestResultScrolling verifies the report scrolls and clamps at both ends.
func TestResultScrolling(t *testing.T) {
	m, _ := sized(t, nil)
	// Manufacture a long report so scrolling is meaningful.
	m.resultLines = make([]string, 200)
	for i := range m.resultLines {
		m.resultLines[i] = "line-" + itoa(i)
	}
	m.result = &engine.Result{}
	m.screen = screenResult

	if m.maxScroll() <= 0 {
		t.Fatalf("maxScroll() = %d, 期望正数", m.maxScroll())
	}

	m = pressSpecial(t, m, tea.KeyUp)
	if m.scroll != 0 {
		t.Errorf("在顶部按上键后 scroll = %d, 期望 0", m.scroll)
	}

	m = pressSpecial(t, m, tea.KeyEnd)
	if m.scroll != m.maxScroll() {
		t.Errorf("按 End 后 scroll = %d, 期望 %d", m.scroll, m.maxScroll())
	}
	m = pressSpecial(t, m, tea.KeyDown)
	if m.scroll != m.maxScroll() {
		t.Errorf("在底部按下键后 scroll = %d, 期望停在 %d", m.scroll, m.maxScroll())
	}

	m = pressSpecial(t, m, tea.KeyHome)
	if m.scroll != 0 {
		t.Errorf("按 Home 后 scroll = %d, 期望 0", m.scroll)
	}
}

// TestRunFailureShowsErrorScreen verifies a failed run lands on the error
// screen with actionable hints, and that Esc returns to the menu.
func TestRunFailureShowsErrorScreen(t *testing.T) {
	m, _ := sized(t, errors.New("没有可测试的 DNS 服务器（请检查 --protocols / --servers 参数）"))

	m.Update(runDoneMsg{err: errors.New("没有可测试的 DNS 服务器（请检查 --protocols / --servers 参数）")})
	if m.screen != screenError {
		t.Fatalf("失败后界面 = %v, 期望 screenError", m.screen)
	}
	out := m.View()
	if !strings.Contains(out, "出错了") {
		t.Errorf("错误界面没有标题:\n%s", out)
	}
	if !strings.Contains(out, "没有可测试的 DNS 服务器") {
		t.Errorf("错误界面没有显示原因:\n%s", out)
	}
	if !strings.Contains(out, "代理") {
		t.Errorf("错误界面没有给出排查建议:\n%s", out)
	}

	m = pressSpecial(t, m, tea.KeyEsc)
	if m.screen != screenMenu {
		t.Errorf("按 Esc 后界面 = %v, 期望返回菜单", m.screen)
	}
}

// TestCancelMarksTracker verifies cancelling from the running screen marks the
// tracker and that a resulting cancellation error returns to the menu instead
// of the error screen.
func TestCancelMarksTracker(t *testing.T) {
	m, _ := sized(t, nil)
	m.cursor = 0
	_, runCmd := m.items[0].action(m)
	_ = drainBatch(t, runCmd)

	m = pressSpecial(t, m, tea.KeyEsc)
	if m.tracker == nil || !m.tracker.Cancelled() {
		t.Fatal("按 Esc 后进度跟踪器未被标记为已取消")
	}

	m.Update(runDoneMsg{err: context.Canceled})
	if m.screen != screenMenu {
		t.Fatalf("取消后界面 = %v, 期望回到菜单（而不是错误界面）", m.screen)
	}
	if !strings.Contains(m.statusMsg, "取消") {
		t.Errorf("取消后状态 = %q, 期望提到「取消」", m.statusMsg)
	}
}

// TestDependenciesNilSafe verifies the model does not panic when optional
// dependencies are missing (a host command with no web viewer, say).
func TestDependenciesNilSafe(t *testing.T) {
	m := New(Deps{Version: "test"})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})

	// View must render with no plan and no result.
	if out := m.View(); out == "" {
		t.Error("View 返回空字符串")
	}

	// Starting a run without BuildTasks must fail gracefully, not panic.
	m.cursor = 0
	next, _ := m.items[0].action(m)
	if next != screenError {
		t.Errorf("缺少 BuildTasks 时界面 = %v, 期望 screenError", next)
	}

	// Web and save actions with no result must be no-ops.
	if cmd := m.startWeb(); cmd != nil {
		t.Error("没有结果时 startWeb 应返回 nil")
	}
	if cmd := m.saveReport(); cmd != nil {
		t.Error("没有结果时 saveReport 应返回 nil")
	}
}

// TestWebURLLifecycle verifies the viewer URL is shown, that the stop function
// is remembered, and that stopping clears it.
func TestWebURLLifecycle(t *testing.T) {
	m, _ := sized(t, nil)
	stopped := false
	m.deps.StartWeb = func(*engine.Result) (string, func(), error) {
		return "http://127.0.0.1:9999", func() { stopped = true }, nil
	}
	m.result = &engine.Result{}

	cmd := m.startWeb()
	if cmd == nil {
		t.Fatal("startWeb 返回 nil")
	}
	m.Update(cmd())
	if m.webURL != "http://127.0.0.1:9999" {
		t.Fatalf("webURL = %q", m.webURL)
	}
	if !strings.Contains(m.statusMsg, "http://127.0.0.1:9999") {
		t.Errorf("状态栏没有显示地址: %q", m.statusMsg)
	}

	m.stopWeb()
	if !stopped {
		t.Error("stopWeb 没有调用停止函数")
	}
	if m.webURL != "" {
		t.Errorf("停止后 webURL = %q, 期望空", m.webURL)
	}
}

// TestWrapTextHandlesCJKAndSpaces verifies the line wrapper used by the help
// and menu screens.
func TestWrapTextHandlesCJKAndSpaces(t *testing.T) {
	// A long unbroken CJK run must be hard-wrapped, never truncated.
	cjk := strings.Repeat("延迟", 20)
	lines := wrapText(cjk, 10)
	if len(lines) < 2 {
		t.Fatalf("长中文串没有被折行: %v", lines)
	}
	for i, l := range lines {
		if n := len([]rune(l)); n > 10 {
			t.Errorf("第 %d 行宽度 %d 超过 10: %q", i, n, l)
		}
	}
	if got := strings.Join(lines, ""); got != cjk {
		t.Errorf("折行后内容不一致:\n got %q\nwant %q", got, cjk)
	}

	// A space-separated string should prefer breaking at the space.
	lines = wrapText("hello wonderful world", 12)
	if len(lines) == 0 {
		t.Fatal("wrapText 返回空")
	}
	for _, l := range lines {
		if n := len([]rune(l)); n > 12 {
			t.Errorf("行宽 %d 超过 12: %q", n, l)
		}
	}
}

// TestCycleAndSelectors covers the option-cycling helpers directly.
func TestCycleAndSelectors(t *testing.T) {
	steps := []int{1, 2, 3}
	if got := cycle(steps, 1, 1); got != 2 {
		t.Errorf("cycle(1,+1) = %d, 期望 2", got)
	}
	if got := cycle(steps, 3, 1); got != 1 {
		t.Errorf("cycle(3,+1) = %d, 期望回绕到 1", got)
	}
	if got := cycle(steps, 1, -1); got != 3 {
		t.Errorf("cycle(1,-1) = %d, 期望回绕到 3", got)
	}
	// An unknown current value falls back to the head of the list.
	if got := cycle(steps, 99, 1); got != 2 {
		t.Errorf("cycle(未知值,+1) = %d, 期望 2", got)
	}
	if got := cycle([]int{}, 5, 1); got != 5 {
		t.Errorf("cycle(空表) = %d, 期望原值 5", got)
	}

	// nextDomainMode covers all four modes and wraps.
	if got := nextDomainMode("cn"); got != "intl" {
		t.Errorf("nextDomainMode(cn) = %q, 期望 intl", got)
	}
	if got := nextDomainMode("intl"); got != "all" {
		t.Errorf("nextDomainMode(intl) = %q, 期望 all", got)
	}
	if got := nextDomainMode("all"); got != "mixed" {
		t.Errorf("nextDomainMode(all) = %q, 期望 mixed", got)
	}
	if got := nextDomainMode("mixed"); got != "cn" {
		t.Errorf("nextDomainMode(mixed) = %q, 期望 cn（回到起点）", got)
	}

	// nextProtocolSelection always returns a copy of a known set.
	got, combo := nextProtocolSelection([]model.Protocol{model.ProtocolUDP}, "")
	if len(got) == 0 || len(got) < 2 {
		t.Errorf("nextProtocolSelection(UDP) = %v, 期望进入多协议组合", got)
	}
	if combo != "" {
		t.Errorf("nextProtocolSelection(UDP) 的组合选择器 = %q, 期望空", combo)
	}
	// The returned slice must not alias the table.
	got[0] = model.ProtocolDoH3
	if again, _ := nextProtocolSelection([]model.Protocol{model.ProtocolUDP}, ""); again[0] == model.ProtocolDoH3 {
		t.Error("nextProtocolSelection 返回了内部表的别名，修改它会污染后续调用")
	}

	// 组合模式必须能被循环到，并且带上配对选择器。
	sawCombo := false
	protos := []model.Protocol{model.ProtocolUDP}
	sel := ""
	for i := 0; i < len(protocolSets); i++ {
		protos, sel = nextProtocolSelection(protos, sel)
		if sel == model.ComboUDPDoH {
			sawCombo = true
			break
		}
	}
	if !sawCombo {
		t.Errorf("循环一遍协议预设都没能选到 %s 组合模式", model.ComboUDPDoH)
	}
	// 组合模式之后必须回到普通协议集，否则用户会被困在组合模式里。
	protos, sel = nextProtocolSelection(protos, sel)
	if sel != "" {
		t.Errorf("组合模式之后的选择器 = %q, 期望回到普通协议集", sel)
	}
	if len(protos) == 0 {
		t.Error("组合模式之后返回了空协议集")
	}

	// 未收录的组合必须回落到第一个预设而不是崩溃。
	protos, sel = nextProtocolSelection([]model.Protocol{model.ProtocolUDP}, "udp+dot")
	if len(protos) == 0 {
		t.Error("未知组合模式回落时返回了空协议集")
	}
	if sel != "" {
		t.Errorf("未知组合模式回落后的选择器 = %q, 期望空", sel)
	}

	// nextIPVersion 覆盖三种取值并回绕。
	if got := nextIPVersion(model.IPAny); got != model.IPv4 {
		t.Errorf("nextIPVersion(两者) = %q, 期望 %q", got, model.IPv4)
	}
	if got := nextIPVersion(model.IPv4); got != model.IPv6 {
		t.Errorf("nextIPVersion(IPv4) = %q, 期望 %q", got, model.IPv6)
	}
	if got := nextIPVersion(model.IPv6); got != model.IPAny {
		t.Errorf("nextIPVersion(IPv6) = %q, 期望回绕到 %q", got, model.IPAny)
	}

	// nextFormula cycles all four and wraps.
	seen := map[config.Formula]bool{}
	f := config.FormulaSpeed
	for i := 0; i < 4; i++ {
		seen[f] = true
		f = nextFormula(f)
	}
	if len(seen) != 4 {
		t.Errorf("nextFormula 只覆盖 %d 套公式", len(seen))
	}
	if f != config.FormulaSpeed {
		t.Errorf("nextFormula 循环一圈后 = %q, 期望回到 %q", f, config.FormulaSpeed)
	}
}

// TestRegionPresetsAreWellFormed verifies the menu's region cycle is usable:
// it starts with "all", every preset is labelled, and each preset's codes are
// normalised so the cycle can recognise the current filter again.
func TestRegionPresetsAreWellFormed(t *testing.T) {
	presets := regionPresets()
	if len(presets) < 2 {
		t.Fatalf("地区预设只有 %d 项，期望至少包含「全部地区」与若干分组", len(presets))
	}
	if presets[0].codes != nil {
		t.Fatalf("地区预设的第一项应是「全部地区」（空筛选），实际 %v", presets[0].codes)
	}
	for i, p := range presets {
		if strings.TrimSpace(p.label) == "" {
			t.Errorf("地区预设 [%d] 缺少名称", i)
		}
		for j, code := range p.codes {
			if code != region.Normalize(code) {
				t.Errorf("地区预设 [%d].codes[%d] = %q 未归一化", i, j, code)
			}
		}
	}
}

// TestCycleRegionPresetAdvancesAndWraps verifies the region filter cycles
// through every preset and returns to "all", and that the current filter is
// recognised so cycling continues rather than restarting.
func TestCycleRegionPresetAdvancesAndWraps(t *testing.T) {
	m := &Model{}
	presets := regionPresets()

	if len(m.cfg.Regions) != 0 {
		t.Fatalf("新建模型的地区筛选应为空，实际 %v", m.cfg.Regions)
	}

	seen := map[string]bool{}
	for i := 0; i < len(presets); i++ {
		m.cycleRegionPreset()
		key := strings.Join(m.cfg.Regions, ",")
		seen[key] = true
	}
	if len(seen) != len(presets) {
		t.Errorf("循环 %d 次只见到 %d 种筛选状态，期望 %d 种",
			len(presets), len(seen), len(presets))
	}
	// 循环一整圈后应回到「全部地区」。
	if len(m.cfg.Regions) != 0 {
		t.Errorf("循环一整圈后地区筛选 = %v，期望回到空（全部地区）", m.cfg.Regions)
	}
}

// TestCycleRegionPresetRecognisesCurrentFilter verifies that a filter which is
// not a preset (e.g. one set on the command line) starts the cycle at the
// beginning instead of getting stuck.
func TestCycleRegionPresetRecognisesCurrentFilter(t *testing.T) {
	m := &Model{cfg: config.Options{Regions: []string{"CN", "HK", "TW"}}}

	// 这一组正好是「中国」预设的前三项，但不是完整的预设，因此应从头开始。
	m.cycleRegionPreset()
	presets := regionPresets()
	if len(m.cfg.Regions) != len(presets[0].codes) {
		t.Errorf("非预设筛选之后 cycleRegionPreset 得到 %v，期望从头开始（%v）",
			m.cfg.Regions, presets[0].codes)
	}
}

// TestCycleRegionPresetDoesNotAliasPreset verifies the model never holds the
// shared preset slice, so editing the filter cannot corrupt later cycles.
func TestCycleRegionPresetDoesNotAliasPreset(t *testing.T) {
	m := &Model{}
	m.cycleRegionPreset()
	if len(m.cfg.Regions) == 0 {
		t.Skip("第一个预设就是「全部地区」，无法验证别名")
	}
	m.cfg.Regions[0] = "TAMPERED"

	again := &Model{}
	again.cycleRegionPreset()
	if len(again.cfg.Regions) > 0 && again.cfg.Regions[0] == "TAMPERED" {
		t.Fatal("cycleRegionPreset 返回了预设表的别名，修改它会污染后续调用")
	}
}

// TestSetProtocolSelectionKeepsComboInSync verifies protocols and the combined
// selector are always stored together.
func TestSetProtocolSelectionKeepsComboInSync(t *testing.T) {
	m := &Model{}
	m.setProtocolSelection([]model.Protocol{model.ProtocolUDP, model.ProtocolDoH}, model.ComboUDPDoH)
	if !m.cfg.IsUDPDoHCombo() {
		t.Fatalf("协议与组合选择器未同步: %+v", m.cfg)
	}
	if m.cfg.ComboLabel() != model.ComboUDPDoHLabel {
		t.Fatalf("ComboLabel = %q，期望 %q", m.cfg.ComboLabel(), model.ComboUDPDoHLabel)
	}

	m.setProtocolSelection([]model.Protocol{model.ProtocolUDP}, "")
	if m.cfg.IsCombo() {
		t.Fatalf("切回普通协议后仍未清除组合选择器: %+v", m.cfg)
	}
}

// TestDescribeRegionsLabels verifies the menu text names the selected regions
// rather than showing bare codes, and that the empty case says "全部地区".
func TestDescribeRegionsLabels(t *testing.T) {
	empty := &Model{}
	if got := empty.describeRegions(); !strings.Contains(got, "全部地区") {
		t.Errorf("无筛选时的描述 = %q，期望包含「全部地区」", got)
	}

	m := &Model{cfg: config.Options{Regions: []string{"CN", "US"}}}
	got := m.describeRegions()
	for _, want := range []string{region.Label("CN"), region.Label("US"), "2"} {
		if !strings.Contains(got, want) {
			t.Errorf("地区描述 %q 缺少 %q", got, want)
		}
	}
}

// TestDescribeConfigShowsCombo verifies the run summary makes the combined mode
// visible, since it changes what the result contains.
func TestDescribeConfigShowsCombo(t *testing.T) {
	m := &Model{
		cfg: config.Options{
			Domains:   "cn",
			Protocols: []model.Protocol{model.ProtocolUDP, model.ProtocolDoH},
			Combo:     model.ComboUDPDoH,
		},
		plan: &engine.Plan{Servers: 3, Domains: 2, Attempts: 1, Total: 6},
	}
	got := m.describeConfig()
	if !strings.Contains(got, model.ComboUDPDoHLabel) {
		t.Errorf("组合模式下的运行摘要 = %q，期望包含 %q", got, model.ComboUDPDoHLabel)
	}

	plain := &Model{
		cfg:  config.Options{Domains: "cn", Protocols: []model.Protocol{model.ProtocolUDP}},
		plan: &engine.Plan{Servers: 3, Domains: 2, Attempts: 1, Total: 6},
	}
	if p := plain.describeConfig(); strings.Contains(p, model.ComboUDPDoHLabel) {
		t.Errorf("普通模式的运行摘要 = %q，不应出现组合模式名称", p)
	}
}

// TestReportPath verifies the report file name is derived from the result path.
func TestReportPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"result.json", "result_report.txt"},
		{"a/b/c.json", "a/b/c_report.txt"},
		{"", ""},
	}
	for _, c := range cases {
		got := reportPath(c.in)
		if c.in == "" {
			if !strings.HasPrefix(got, "dns-opti_report_") || !strings.HasSuffix(got, ".txt") {
				t.Errorf("reportPath(%q) = %q, 期望带时间戳的默认名", c.in, got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("reportPath(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// TestFmtPlanSummarizes verifies the workload description includes the counts
// and the per-protocol / per-group breakdown.
func TestFmtPlanSummarizes(t *testing.T) {
	p := &engine.Plan{
		Servers: 4, Domains: 10, Attempts: 3, Total: 120,
		ByProto: map[model.Protocol]int{model.ProtocolUDP: 2, model.ProtocolDoT: 2},
		ByGroup: map[string]int{model.GroupCN: 6, model.GroupIntl: 4},
	}
	got := fmtPlan(p)
	for _, want := range []string{"4 台服务器", "10 个域名", "120 次查询", "UDP 2", "DoT 2", "国内域名 6", "国外域名 4"} {
		if !strings.Contains(got, want) {
			t.Errorf("fmtPlan 缺少 %q:\n%s", want, got)
		}
	}
}

// TestDomainModeLabel covers the display labels.
func TestDomainModeLabel(t *testing.T) {
	cases := map[string]string{
		"cn": "仅国内域名", "intl": "仅国外域名", "all": "国内 + 国外域名", "": "国内 + 国外域名",
	}
	for in, want := range cases {
		if got := domainModeLabel(in); got != want {
			t.Errorf("domainModeLabel(%q) = %q, 期望 %q", in, got, want)
		}
	}
	if got := domainModeLabel("a.com,b.com"); !strings.Contains(got, "自定义域名") {
		t.Errorf("domainModeLabel(自定义) = %q, 期望提到自定义域名", got)
	}
}

// drainBatch executes a tea.Batch command and returns every message it yields
// that is not a timer/progress wait, so a run's outcome can be inspected.
func drainBatch(t *testing.T, cmd tea.Cmd) []tea.Msg {
	t.Helper()
	if cmd == nil {
		return nil
	}
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		return []tea.Msg{msg}
	}
	var out []tea.Msg
	for _, c := range batch {
		if c == nil {
			continue
		}
		got := c()
		switch got.(type) {
		case runDoneMsg, planMsg, webStartedMsg, savedMsg, tea.QuitMsg:
			out = append(out, got)
		}
	}
	return out
}

// findRunDone extracts the runDoneMsg from a batch's messages.
func findRunDone(msgs []tea.Msg) (runDoneMsg, bool) {
	for _, m := range msgs {
		if d, ok := m.(runDoneMsg); ok {
			return d, true
		}
	}
	return runDoneMsg{}, false
}
