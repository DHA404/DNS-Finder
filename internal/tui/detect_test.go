package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dns-opti/internal/model"
	"dns-opti/internal/policy"
)

// stubDetect returns a DetectTypes implementation that reports a fixed result
// set without touching the network.
func stubDetect(t *testing.T, results []policy.Detection) (Deps, *int) {
	t.Helper()
	deps, _ := stubDeps(t, nil)
	calls := 0
	deps.DetectTypes = func(ctx context.Context, servers []model.Server, timeout time.Duration, progress policy.ProgressFunc) []policy.Detection {
		calls++
		if progress != nil {
			for i, d := range results {
				progress(i+1, len(results), d)
			}
		}
		return results
	}
	return deps, &calls
}

// detectionFixture is a small result set covering every verdict and both
// agreement outcomes.
func detectionFixture() []policy.Detection {
	return []policy.Detection{
		{
			Server: "94.140.14.14", Curated: policy.Security, Observed: policy.VerdictSecurity,
			Answers: []policy.AnswerState{policy.AnswerNormal, policy.AnswerBlocked, policy.AnswerBlocked},
		},
		{
			Server: "223.5.5.5", Curated: policy.Native, Observed: policy.VerdictNative,
			Answers: []policy.AnswerState{policy.AnswerNormal, policy.AnswerNormal, policy.AnswerNormal},
		},
		{
			Server: "9.9.9.9", Curated: policy.Security, Observed: policy.VerdictNative,
			Answers: []policy.AnswerState{policy.AnswerNormal, policy.AnswerNormal, policy.AnswerNormal},
		},
		{
			Server: "203.0.113.7", Curated: policy.Unknown, Observed: policy.VerdictUnknown,
			Answers: []policy.AnswerState{policy.AnswerUnusable, policy.AnswerUnusable, policy.AnswerUnusable},
		},
	}
}

// TestDetectReportShowsVerdictsAndEvidence checks the report carries both the
// verdict and the evidence behind it, since the verdict alone is not auditable.
func TestDetectReportShowsVerdictsAndEvidence(t *testing.T) {
	lines := detectReport(detectionFixture())
	text := strings.Join(lines, "\n")

	for _, want := range []string{
		"DNS 类型检测",
		"94.140.14.14",
		"223.5.5.5",
		"9.9.9.9",
		"203.0.113.7",
		// The probe domains must be named, so a reader knows what was asked.
		"malware.testcategory.com",
		"advertising.filterdns.net",
		// The caveat about timeouts is essential to reading the result.
		"无应答不等于不过滤",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("检测报告缺少 %q", want)
		}
	}
}

// TestDetectReportFlagsDisagreements is the report's whole purpose: surfacing
// where observation contradicts the hardcoded table.
func TestDetectReportFlagsDisagreements(t *testing.T) {
	lines := detectReport(detectionFixture())
	text := strings.Join(lines, "\n")

	if !strings.Contains(text, "与内置表不一致") {
		t.Error("报告未给出「与内置表不一致」小节")
	}
	// Isolate the disagreement section: it runs from its heading to the
	// "全部结果" heading that follows it.
	idx := strings.Index(text, "与内置表不一致")
	end := strings.Index(text[idx:], "全部结果")
	if end < 0 {
		t.Fatalf("不一致小节之后没有「全部结果」小节:\n%s", text)
	}
	section := text[idx : idx+end]
	if !strings.Contains(section, "9.9.9.9") {
		t.Errorf("不一致小节未列出 9.9.9.9:\n%s", section)
	}
	if strings.Contains(section, "94.140.14.14") {
		t.Errorf("一致的服务商被误列入不一致小节:\n%s", section)
	}

	// The summary must count both sides.
	if !strings.Contains(text, "一致") || !strings.Contains(text, "不一致") {
		t.Error("摘要未同时给出一致与不一致的数量")
	}
}

// TestDetectReportGroupsAllVerdicts ensures nothing is silently dropped.
func TestDetectReportGroupsAllVerdicts(t *testing.T) {
	results := detectionFixture()
	lines := detectReport(results)
	text := strings.Join(lines, "\n")

	for _, d := range results {
		if !strings.Contains(text, d.Server) {
			t.Errorf("报告遗漏了 %s", d.Server)
		}
	}
	for _, want := range []string{"[安全]", "[原生]", "[未确认]"} {
		if !strings.Contains(text, want) {
			t.Errorf("报告缺少分组 %s", want)
		}
	}
}

// TestDetectReportHandlesEmptyInput must not panic on a run that produced
// nothing (an immediate cancel, or an empty inventory).
func TestDetectReportHandlesEmptyInput(t *testing.T) {
	lines := detectReport(nil)
	if len(lines) == 0 {
		t.Fatal("空结果没有产生任何输出")
	}
	if !strings.Contains(strings.Join(lines, "\n"), "检测目标 0 个") {
		t.Errorf("空结果的目标数不正确: %v", lines)
	}
}

// TestDetectScreenReachesFindings drives the real flow: menu entry → running
// screen → findings.
func TestDetectScreenReachesFindings(t *testing.T) {
	results := detectionFixture()
	deps, calls := stubDetect(t, results)
	m := New(deps)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	idx := menuIndex(t, m, "检测内置 DNS 类型")
	m.cursor = idx

	next, cmd := m.items[idx].action(m)
	m.screen = next
	if m.screen != screenDetect {
		t.Fatalf("进入检测后屏幕 = %v, 期望 screenDetect", m.screen)
	}
	if cmd == nil {
		t.Fatal("检测未返回命令，探测不会运行")
	}
	if !m.detect.running {
		t.Error("检测未标记为运行中")
	}
	if m.detect.total != len(detectTargets()) {
		t.Errorf("检测目标数 = %d, 期望 %d", m.detect.total, len(detectTargets()))
	}

	// Run the commands until the model settles on the findings.
	settle(t, m, cmd)

	if *calls != 1 {
		t.Errorf("DetectTypes 被调用 %d 次, 期望 1 次", *calls)
	}
	if m.detect.running {
		t.Error("检测结束后仍标记为运行中")
	}
	if !m.detect.finished {
		t.Error("检测未标记为已完成")
	}
	if len(m.detectLines) == 0 {
		t.Fatal("检测完成后没有可显示的报告")
	}
	if !strings.Contains(strings.Join(m.detectLines, "\n"), "94.140.14.14") {
		t.Error("报告缺少检测结果")
	}
	// The screen must render without panicking and mention the findings.
	view := m.View()
	if !strings.Contains(view, "DNS 类型检测") {
		t.Errorf("检测结果界面标题缺失:\n%s", view)
	}
}

// settle feeds command results into the model until the detection finishes.
//
// tea.Batch returns a BatchMsg holding each command, so the loop has to expand
// batches rather than feed them to Update (Update has no case for a BatchMsg,
// which is why a naive loop never starts the probe at all). The iteration bound
// keeps a broken implementation from hanging the suite instead of failing it.
func settle(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	queue := []tea.Cmd{cmd}

	for i := 0; i < 1000 && len(queue) > 0; i++ {
		next := queue[0]
		queue = queue[1:]
		if next == nil {
			continue
		}
		msg := next()
		if msg == nil {
			continue
		}
		if batch, ok := msg.(tea.BatchMsg); ok {
			queue = append(queue, batch...)
			continue
		}
		updated, more := m.Update(msg)
		m = updated.(*Model)
		if more != nil {
			queue = append(queue, more)
		}
		if m.detect.finished {
			return
		}
	}
	if !m.detect.finished {
		t.Fatalf("检测在 %d 次迭代后仍未结束（done=%d/%d）", 1000, m.detect.done, m.detect.total)
	}
}

// TestDetectMenuDescriptionReflectsState covers the three states the entry can
// be in, since it is the only place the user learns what happened.
func TestDetectMenuDescriptionReflectsState(t *testing.T) {
	deps, _ := stubDetect(t, detectionFixture())
	m := New(deps)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	// Never run.
	desc := m.describeDetect()
	if !strings.Contains(desc, "手动启动") {
		t.Errorf("未检测时的描述应说明需手动启动: %q", desc)
	}

	// Running.
	m.detect = detectState{running: true, done: 3, total: 72}
	if desc := m.describeDetect(); !strings.Contains(desc, "正在检测") || !strings.Contains(desc, "3/72") {
		t.Errorf("运行中的描述不正确: %q", desc)
	}

	// Finished.
	m.detect = detectState{finished: true, results: detectionFixture()}
	desc = m.describeDetect()
	if !strings.Contains(desc, "上次检测") {
		t.Errorf("完成后的描述不正确: %q", desc)
	}
	for _, want := range []string{"安全 1", "原生 2", "未确认 1"} {
		if !strings.Contains(desc, want) {
			t.Errorf("完成后的描述缺少 %q: %q", want, desc)
		}
	}
}

// TestDetectEscapeCancelsWhileRunning checks the cancel path.
func TestDetectEscapeCancelsWhileRunning(t *testing.T) {
	deps, _ := stubDetect(t, detectionFixture())
	m := New(deps)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	cancelled := false
	m.detect = detectState{running: true, total: 10, cancel: func() { cancelled = true }}
	m.screen = screenDetect

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(*Model)

	if !cancelled {
		t.Error("Esc 未取消进行中的检测")
	}
	if m.screen != screenDetect {
		t.Errorf("取消后离开了检测界面: %v", m.screen)
	}
	if !strings.Contains(m.statusMsg, "中止") {
		t.Errorf("取消后未给出提示: %q", m.statusMsg)
	}
}

// TestDetectEscapeReturnsWhenIdle checks that Esc leaves the screen once the
// run is over, so the user is not trapped.
func TestDetectEscapeReturnsWhenIdle(t *testing.T) {
	deps, _ := stubDetect(t, detectionFixture())
	m := New(deps)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	m.detect = detectState{finished: true, results: detectionFixture()}
	m.detectLines = detectReport(m.detect.results)
	m.screen = screenDetect

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(*Model)

	if m.screen != screenMenu {
		t.Errorf("空闲时按 Esc 未返回菜单: %v", m.screen)
	}
}

// TestDetectScrollClamps checks the findings screen scrolls within its bounds.
func TestDetectScrollClamps(t *testing.T) {
	deps, _ := stubDetect(t, detectionFixture())
	m := New(deps)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	m.detectLines = detectReport(detectionFixture())
	m.screen = screenDetect

	// Scrolling up at the top must not go negative.
	m = pressSpecial(t, m, tea.KeyUp)
	if m.detectY != 0 {
		t.Errorf("在顶部向上滚动后 detectY = %d, 期望 0", m.detectY)
	}
	// End jumps to the bottom, and further presses stay clamped.
	m = press(t, m, "G")
	if m.detectY != m.maxDetectScroll() {
		t.Errorf("按 G 后 detectY = %d, 期望 %d", m.detectY, m.maxDetectScroll())
	}
	m = press(t, m, "j")
	if m.detectY != m.maxDetectScroll() {
		t.Errorf("在底部继续向下后 detectY = %d, 期望保持 %d", m.detectY, m.maxDetectScroll())
	}
}

// TestDetectWithoutDepsIsSafe covers a host that did not inject the detector.
func TestDetectWithoutDepsIsSafe(t *testing.T) {
	deps, _ := stubDeps(t, nil)
	deps.DetectTypes = nil
	m := New(deps)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	next, cmd := m.startDetect()
	m.screen = next

	if m.screen != screenError {
		t.Errorf("缺少 DetectTypes 时屏幕 = %v, 期望 screenError", m.screen)
	}
	if cmd != nil {
		t.Error("缺少 DetectTypes 时不应返回命令")
	}
	if !m.statusErr || !strings.Contains(m.statusMsg, "DetectTypes") {
		t.Errorf("未给出明确错误: %q", m.statusMsg)
	}
}

// TestDetectTargetsAreBuiltInInventory documents what gets probed: the whole
// built-in UDP inventory, not the user's current filter selection.
func TestDetectTargetsAreBuiltInInventory(t *testing.T) {
	targets := detectTargets()
	if len(targets) == 0 {
		t.Fatal("检测目标为空")
	}
	for _, s := range targets {
		if s.Protocol != model.ProtocolUDP {
			t.Errorf("%s 的协议 = %q, 期望只探测 UDP 明文地址", s.Address, s.Protocol)
		}
		if s.Region == "" {
			t.Errorf("%s 缺少地区码，说明未经 MarkSpecial 处理", s.Address)
		}
	}
}

// TestSummarizeDetectCountsAgreement verifies the summary arithmetic the menu
// line and the report header both depend on.
func TestSummarizeDetectCountsAgreement(t *testing.T) {
	s := summarizeDetect(detectionFixture())
	if s.Security != 1 || s.Native != 2 || s.Unknown != 1 {
		t.Errorf("类型计数 = 安全%d 原生%d 未确认%d, 期望 安全1 原生2 未确认1",
			s.Security, s.Native, s.Unknown)
	}
	// Three entries carry a documented policy; two agree, one does not.
	if s.Agree != 2 {
		t.Errorf("一致数 = %d, 期望 2", s.Agree)
	}
	if s.Disagree != 1 {
		t.Errorf("不一致数 = %d, 期望 1", s.Disagree)
	}
}

// TestDisagreementsExcludeUnknowns keeps the review list honest: entries with
// no documented policy, and entries that established nothing, are not
// disagreements.
func TestDisagreementsExcludeUnknowns(t *testing.T) {
	got := disagreementsForTest(detectionFixture())
	if len(got) != 1 {
		t.Fatalf("不一致条目 = %d, 期望 1：%+v", len(got), got)
	}
	if got[0].Server != "9.9.9.9" {
		t.Errorf("不一致条目 = %q, 期望 9.9.9.9", got[0].Server)
	}
}
