package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"dns-opti/internal/config"
	"dns-opti/internal/domainlist"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/scorer"
	"dns-opti/internal/ui"
)

// View renders the whole screen.
func (m *Model) View() string {
	if m.width == 0 && m.height == 0 {
		// The first frame may arrive before the size message; keep it terse.
		return "正在初始化…"
	}
	switch m.screen {
	case screenAdvanced:
		return m.viewAdvanced()
	case screenRunning:
		return m.viewRunning()
	case screenResult:
		return m.viewResult()
	case screenHelp:
		return m.viewHelp()
	case screenError:
		return m.viewError()
	case screenDetect:
		return m.viewDetect()
	default:
		return m.viewMenu()
	}
}

// viewDetect renders the resolver-type detection: its progress while it runs,
// then its findings.
func (m *Model) viewDetect() string {
	var b strings.Builder

	if m.detect.running {
		b.WriteString(m.header("正在检测 DNS 类型"))
		b.WriteString("\n\n")
		b.WriteString("  " + ui.Muted("按 Esc 中止检测") + "\n\n")

		b.WriteString("  " + m.detectBar() + "\n")
		fmt.Fprintf(&b, "  %s\n\n", ui.Bold.Render(
			fmt.Sprintf("%d / %d 个服务器", m.detect.done, m.detect.total)))

		b.WriteString("  " + ui.Muted("逐个探测分类测试域，判断该解析器属「安全」还是「原生」") + "\n")
		b.WriteString("  " + ui.Muted("拦截应答与「不可达」会被区分：无应答不计为不过滤") + "\n\n")
		if m.statusMsg != "" {
			b.WriteString("  " + m.renderStatus() + "\n")
		}
		b.WriteString(m.footer("Esc 中止检测"))
		return b.String()
	}

	b.WriteString(m.header("DNS 类型检测结果"))
	b.WriteString("\n")

	body := m.bodyHeight()
	start, end := m.detectY, m.detectY+body
	if end > len(m.detectLines) {
		end = len(m.detectLines)
	}
	if start > len(m.detectLines) {
		start = len(m.detectLines)
	}
	for _, line := range m.detectLines[start:end] {
		b.WriteString(line + "\n")
	}
	if shown := end - start; shown < body {
		b.WriteString(strings.Repeat("\n", body-shown))
	}

	if m.statusMsg != "" {
		b.WriteString(m.renderStatus() + "\n")
	} else {
		b.WriteString("\n")
	}
	b.WriteString(m.footer("↑/↓ 滚动 · 回车返回菜单"))
	return b.String()
}

// detectBar renders the detection progress bar.
func (m *Model) detectBar() string {
	if m.detect.total <= 0 {
		return ui.Muted("准备中…")
	}
	fraction := float64(m.detect.done) / float64(m.detect.total)
	return ui.ProgressBar(fraction, 30)
}

// viewMenu renders the main menu.
func (m *Model) viewMenu() string {
	var b strings.Builder
	b.WriteString(m.header("主菜单"))
	b.WriteString("\n\n")
	b.WriteString("  " + ui.Muted("使用 ↑/↓ 选择，回车确认；按 r 直接开始测试，Esc 退出") + "\n\n")

	for i, item := range m.items {
		selected := i == m.cursor
		cursor := "  "
		style := ui.Normal
		if selected {
			cursor = ui.Accent("❯ ")
			style = ui.Bold
		}
		b.WriteString(cursor + style.Render(item.title) + "\n")
		wrap := m.width_() - 6
		if wrap < 20 {
			wrap = 20
		}
		for _, line := range wrapText(item.desc, wrap) {
			b.WriteString("    " + ui.Muted(line) + "\n")
		}
	}

	if m.statusMsg != "" {
		b.WriteString("\n" + m.renderStatus() + "\n")
	}
	for _, n := range m.notices {
		b.WriteString("  " + ui.Warn("⚠ "+n) + "\n")
	}
	b.WriteString("\n")
	b.WriteString(m.footer("↑/↓ 选择 · 回车确认 · r 开始 · Esc 退出"))
	return b.String()
}

// viewAdvanced renders the advanced options screen.
func (m *Model) viewAdvanced() string {
	conc := m.cfg.EffectiveConcurrency()
	concNote := fmt.Sprintf("（跟随 CPU 线程数 × %d）", config.DefaultConcurrencyMultiplier)
	if m.adv.concurrency > 0 {
		concNote = "（手动指定）"
	}

	rows := []struct{ name, value, note string }{
		{"单次查询超时", m.adv.timeout.String(), "网络较慢时可调大"},
		{"每个域名的查询次数", strconv.Itoa(m.adv.attempts), "次数越多，结果越稳定"},
		{"同时测试的服务器数", strconv.Itoa(conc), concNote},
		{"预热域名", m.adv.warmup, "仅用于建立连接，不计入统计"},
	}

	var b strings.Builder
	b.WriteString(m.header("高级选项"))
	b.WriteString("\n\n")
	b.WriteString("  " + ui.Muted("使用 ↑/↓ 选择，←/→ 调整数值，Esc 返回") + "\n\n")

	for i, r := range rows {
		selected := i == m.advCursor
		cursor := "  "
		if selected {
			cursor = ui.Accent("❯ ")
		}
		line := fmt.Sprintf("%-22s %s", r.name, ui.Bold.Render(r.value))
		if selected {
			line = fmt.Sprintf("%-22s %s", ui.Normal.Render(r.name), ui.Accent("◀ ")+ui.Bold.Render(r.value)+ui.Accent(" ▶"))
		}
		b.WriteString(cursor + line + "\n")
		b.WriteString("    " + ui.Muted(r.note) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(m.footer("↑/↓ 选择 · ←/→ 调整 · Esc 返回并保存"))
	return b.String()
}

// viewRunning renders the live progress panel plus the menu's own chrome.
func (m *Model) viewRunning() string {
	var b strings.Builder
	b.WriteString(m.header("正在测试"))
	b.WriteString("\n")

	if m.statusMsg != "" {
		b.WriteString("  " + m.renderStatus() + "\n\n")
	} else {
		b.WriteString("  " + ui.Muted("按 Esc 或 Ctrl+C 可中止测试") + "\n\n")
	}

	// Reuse the standalone panel so both entry points render identically, but
	// without its own headline: this screen already draws a header.
	inner := m.width_() - 2
	if inner < 40 {
		inner = 40
	}
	panel := ui.PanelViewBare(m.tracker, inner, false)
	for _, line := range strings.Split(panel, "\n") {
		b.WriteString(" " + line + "\n")
	}
	return b.String()
}

// viewResult renders the scrollable report.
func (m *Model) viewResult() string {
	var b strings.Builder
	b.WriteString(m.header("测试结果"))
	b.WriteString("\n")

	body := m.bodyHeight()
	start := m.scroll
	end := start + body
	if end > len(m.resultLines) {
		end = len(m.resultLines)
	}
	if start > len(m.resultLines) {
		start = len(m.resultLines)
	}

	for _, line := range m.resultLines[start:end] {
		b.WriteString(line + "\n")
	}

	// Keep a fixed-height body so the footer does not jump while scrolling.
	if shown := end - start; shown < body {
		b.WriteString(strings.Repeat("\n", body-shown))
	}

	if m.statusMsg != "" {
		b.WriteString(m.renderStatus() + "\n")
	} else {
		b.WriteString("\n")
	}

	hint := "↑/↓ 滚动 · o 打开 Web 页面 · s 保存报告 · 回车返回菜单"
	if m.webURL != "" {
		hint = "Web: " + m.webURL + " · w 关闭 · " + hint
	}
	b.WriteString(m.footer(hint))
	return b.String()
}

// viewHelp renders the formula catalogue, one formula per page.
func (m *Model) viewHelp() string {
	f := scorer.Formulas[m.helpPage]

	var b strings.Builder
	b.WriteString(m.header(fmt.Sprintf("评分公式 %d/%d", m.helpPage+1, len(scorer.Formulas))))
	b.WriteString("\n\n")

	b.WriteString("  " + ui.Heading.Render(f.Name) + "  " + ui.Muted("("+string(f.ID)+")") + "\n\n")
	b.WriteString("  " + ui.Muted("公式") + "\n")
	b.WriteString("    " + ui.Bold.Render(f.Expr) + "\n\n")
	b.WriteString("  " + ui.Muted("说明") + "\n")
	for _, line := range wrapText(f.Desc, m.contentWidth()) {
		b.WriteString("    " + line + "\n")
	}
	b.WriteString("\n  " + ui.Muted("适用场景") + "\n")
	for _, line := range wrapText(f.Scenario, m.contentWidth()) {
		b.WriteString("    " + line + "\n")
	}

	b.WriteString("\n  " + ui.Warn("提示：同一 DNS 在不同公式下排名可能变化，请结合使用场景选择。") + "\n")
	b.WriteString("\n")
	b.WriteString(m.footer("←/→ 切换公式 · Esc 返回菜单"))
	return b.String()
}

// viewError renders a failure with the underlying message.
func (m *Model) viewError() string {
	var b strings.Builder
	b.WriteString(m.header("出错了"))
	b.WriteString("\n\n")
	b.WriteString("  " + ui.Bad("✖ "+m.statusMsg) + "\n\n")

	for _, hint := range m.errorHints() {
		b.WriteString("  " + ui.Muted("· "+hint) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(m.footer("回车或 Esc 返回菜单"))
	return b.String()
}

// errorHints translates a failure into actionable advice.
func (m *Model) errorHints() []string {
	msg := m.statusMsg
	var hints []string
	switch {
	case strings.Contains(msg, "没有可测试的 DNS 服务器"):
		hints = append(hints, "请减少协议筛选，或确认协议列表不为空。")
	case strings.Contains(msg, "域名"):
		hints = append(hints, "请检查域名范围设置。")
	case strings.Contains(msg, "临时文件"), strings.Contains(msg, "输出文件"), strings.Contains(msg, "创建输出目录"):
		hints = append(hints, "请检查当前目录是否可写，或改用其他目录运行。")
	}
	hints = append(hints,
		"若网络较慢，可在「高级选项」里调大单次查询超时。",
		"若启用了系统代理或加速器，请先关闭后重试。",
	)
	return hints
}

// header renders the shared title bar: the app name once, then the screen
// title, with the version right-aligned.
func (m *Model) header(title string) string {
	line := ui.Title.Render("DNS 优选工具") + ui.Muted(" · ") + ui.Bold.Render(title)
	right := ui.Muted(m.deps.Version)
	pad := m.width_() - lipglossWidth(line) - lipglossWidth(right) - 2
	if pad < 1 {
		return " " + line
	}
	return " " + line + strings.Repeat(" ", pad) + right + " "
}

// footer renders the key hint bar.
func (m *Model) footer(hint string) string {
	width := m.width_()
	rule := ui.Muted(strings.Repeat("─", width))
	return rule + "\n " + ui.Muted(hint)
}

// renderStatus renders the status line with the right colour.
func (m *Model) renderStatus() string {
	if m.statusErr {
		return ui.Bad("✖ " + m.statusMsg)
	}
	return ui.Good("✔ " + m.statusMsg)
}

// contentWidth is the usable text width inside the layout.
func (m *Model) contentWidth() int {
	w := m.width_() - 8
	if w < 30 {
		w = 30
	}
	return w
}

// lipglossWidth measures the printable width of a styled string, so the header
// stays aligned even when the title or version contain wide characters.
func lipglossWidth(s string) int { return lipgloss.Width(s) }

// --- small formatting helpers ---

// domainModeLabel renders the --domains mode for display.
func domainModeLabel(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case domainlist.ModeCN:
		return "仅国内域名"
	case domainlist.ModeIntl:
		return "仅国外域名"
	case domainlist.ModeMixed:
		return "国内外域名混合"
	case domainlist.ModeAll, "":
		return "国内 + 国外域名"
	default:
		return "自定义域名: " + mode
	}
}

// nextDomainMode cycles cn -> intl -> all -> mixed.
//
// Mixed is last rather than second so the three grouping modes keep their
// existing one-keypress relationships; a user who wants pooling will reach it
// after passing the grouped views, which is the safer direction given that
// pooling is the destructive-of-detail choice.
func nextDomainMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case domainlist.ModeCN:
		return domainlist.ModeIntl
	case domainlist.ModeIntl:
		return domainlist.ModeAll
	case domainlist.ModeAll:
		return domainlist.ModeMixed
	default:
		return domainlist.ModeCN
	}
}

// protocolList renders a protocol slice for the menu, showing a combined mode
// by its own name rather than as an unexplained pair of protocols.
func protocolList(protocols []model.Protocol) string {
	return ui.ProtocolSummary(protocols)
}

// protocolSelectionLabel renders the current protocol configuration, honouring
// the combined-mode name when one is selected.
func protocolSelectionLabel(protocols []model.Protocol, combo string) string {
	if combo == model.ComboUDPDoH {
		return model.ComboUDPDoHLabel
	}
	return protocolList(protocols)
}

// protocolSets are the protocol combinations the menu cycles through, ordered
// from the fast common case to the complete set, with the combined UDP+DoH mode
// last.
//
// Each entry carries the combined-mode selector it stands for (empty for a
// plain protocol set), so choosing "UDP + DoH" also turns on the side-by-side
// comparison rather than merely selecting two protocols.
var protocolSets = []protocolSet{
	{protocols: []model.Protocol{model.ProtocolUDP}},
	{protocols: []model.Protocol{model.ProtocolUDP, model.ProtocolDoT, model.ProtocolDoH}},
	{protocols: []model.Protocol{model.ProtocolUDP, model.ProtocolDoT, model.ProtocolDoH, model.ProtocolDoH3}},
	{protocols: []model.Protocol{model.ProtocolDoT, model.ProtocolDoH, model.ProtocolDoH3}},
	{
		protocols: []model.Protocol{model.ProtocolUDP, model.ProtocolDoH},
		combo:     model.ComboUDPDoH,
		label:     model.ComboUDPDoHLabel,
	},
}

// protocolSet is one selectable protocol configuration.
type protocolSet struct {
	protocols []model.Protocol
	// combo is the combined-mode selector, empty for a plain set.
	combo string
	// label overrides the rendered name for a combined mode.
	label string
}

// nextProtocolSelection advances to the next protocol configuration, returning
// the protocols and the combined-mode selector that go with them.
func nextProtocolSelection(cur []model.Protocol, combo string) ([]model.Protocol, string) {
	for i, set := range protocolSets {
		if set.combo == combo && sameProtocols(set.protocols, cur) {
			next := protocolSets[(i+1)%len(protocolSets)]
			return append([]model.Protocol(nil), next.protocols...), next.combo
		}
	}
	// The current selection is not one of the presets (it came from the CLI, or
	// from a custom --servers run): start from the first preset.
	return append([]model.Protocol(nil), protocolSets[0].protocols...), protocolSets[0].combo
}

// nextIPVersion cycles the address family restriction.
func nextIPVersion(cur model.IPVersion) model.IPVersion {
	return cycle([]model.IPVersion{model.IPAny, model.IPv4, model.IPv6}, cur, 1)
}

// sameProtocols reports whether two protocol slices hold the same set.
func sameProtocols(a, b []model.Protocol) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[model.Protocol]int, len(a))
	for _, p := range a {
		seen[p]++
	}
	for _, p := range b {
		seen[p]--
		if seen[p] < 0 {
			return false
		}
	}
	return true
}

// nextFormula advances to the next scoring formula.
func nextFormula(cur config.Formula) config.Formula {
	for i, f := range scorer.Formulas {
		if f.ID == cur {
			return scorer.Formulas[(i+1)%len(scorer.Formulas)].ID
		}
	}
	return scorer.Formulas[0].ID
}

// onOff renders a boolean as 开 / 关.
func onOff(v bool) string {
	if v {
		return "开"
	}
	return "关"
}

// fmtPlan renders a resolved workload as a one-line summary.
func fmtPlan(p *engine.Plan) string {
	protos := make([]string, 0, len(p.ByProto))
	for _, proto := range model.AllProtocols {
		if n := p.ByProto[proto]; n > 0 {
			protos = append(protos, fmt.Sprintf("%s %d", proto.Label(), n))
		}
	}
	groups := make([]string, 0, len(p.ByGroup))
	for _, g := range []string{model.GroupCN, model.GroupIntl, model.GroupCustom, model.GroupImported} {
		if n := p.ByGroup[g]; n > 0 {
			groups = append(groups, fmt.Sprintf("%s %d", model.GroupLabel(g), n))
		}
	}

	parts := []string{
		fmt.Sprintf("约 %d 台服务器", p.Servers),
		fmt.Sprintf("%d 个域名", p.Domains),
		fmt.Sprintf("共 %d 次查询", p.Total),
	}
	if len(protos) > 0 {
		parts = append(parts, strings.Join(protos, " / "))
	}
	if len(groups) > 0 {
		parts = append(parts, strings.Join(groups, " / "))
	}
	return strings.Join(parts, " · ")
}

// cycle returns the neighbouring value of cur in steps, wrapping around. It
// backs every "←/→ changes the value" row on the advanced screen, so the
// option tables only ever need to list their values in one direction.
func cycle[T comparable](steps []T, cur T, dir int) T {
	if len(steps) == 0 {
		return cur
	}
	idx := 0
	for i, v := range steps {
		if v == cur {
			idx = i
			break
		}
	}
	n := len(steps)
	idx = ((idx+dir)%n + n) % n
	return steps[idx]
}

// itoa is a tiny integer helper.
func itoa(v int) string { return strconv.Itoa(v) }

// concat joins strings without a separator.
func concat(parts ...string) string { return strings.Join(parts, "") }

// wrapText breaks a string into lines of at most width runes, preferring to
// break at spaces but falling back to a hard break for unbroken CJK runs.
func wrapText(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		runes := []rune(para)
		if len(runes) == 0 {
			lines = append(lines, "")
			continue
		}
		for len(runes) > width {
			cut := width
			// Prefer the last space inside the window.
			for i := width - 1; i > width/2; i-- {
				if runes[i] == ' ' {
					cut = i
					break
				}
			}
			lines = append(lines, strings.TrimRight(string(runes[:cut]), " "))
			runes = []rune(strings.TrimLeft(string(runes[cut:]), " "))
		}
		lines = append(lines, string(runes))
	}
	return lines
}

// splitLines splits a rendered report into lines.
func splitLines(s string) []string { return strings.Split(s, "\n") }

// Ensure the time import is used even if tick changes.
var _ = time.Second
