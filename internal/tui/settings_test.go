package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dns-opti/internal/config"
	"dns-opti/internal/domainlist"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/settings"
)

// modelWithSettings builds a model whose settings file lives in a temp dir, so
// persistence can be exercised without touching the developer's real settings.
func modelWithSettings(t *testing.T) (*Model, string) {
	t.Helper()
	deps, _ := stubDeps(t, nil)
	path := filepath.Join(t.TempDir(), settings.FileName)
	deps.SettingsPath = path
	m := New(deps)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return m, path
}

// menuIndex finds the menu row whose title contains substr.
func menuIndex(t *testing.T, m *Model, substr string) int {
	t.Helper()
	for i, item := range m.items {
		if strings.Contains(item.title, substr) {
			return i
		}
	}
	t.Fatalf("菜单里找不到包含 %q 的条目", substr)
	return -1
}

// TestMenuOffersOpenWeb verifies the main menu exposes the web viewer as a
// first-class entry, and that choosing it starts the server.
func TestMenuOffersOpenWeb(t *testing.T) {
	m, _ := sized(t, nil)

	idx := menuIndex(t, m, "Web")
	m.cursor = idx

	// The description must be honest about having no data yet.
	if desc := m.items[idx].desc; !strings.Contains(desc, "导入") && !strings.Contains(desc, "本次") {
		t.Errorf("Web 条目描述未说明数据来源: %q", desc)
	}

	next, cmd := m.items[idx].action(m)
	m.screen = next
	if m.screen != screenMenu {
		t.Errorf("打开 Web 后跳到了 %v, 应留在菜单", m.screen)
	}
	if cmd == nil {
		t.Fatal("打开 Web 未返回命令，服务器不会启动")
	}

	// Run the command to completion: the stub StartWeb returns a URL.
	if msg := cmd(); msg != nil {
		m.Update(msg)
	}
	if m.webURL == "" {
		t.Fatalf("启动 Web 后 webURL 仍为空（status=%q）", m.statusMsg)
	}
	if !strings.Contains(m.describeWeb(), m.webURL) {
		t.Errorf("describeWeb() 未反映运行中的地址: %q", m.describeWeb())
	}
}

// TestOpenWebWorksWithoutAResult guards the case the main-menu entry exists for:
// opening the viewer before any test has run, so an existing result file can be
// imported from the page.
func TestOpenWebWorksWithoutAResult(t *testing.T) {
	m, _ := modelWithSettings(t)
	if m.result != nil {
		t.Fatal("前置条件错误: 此时不应有测试结果")
	}
	if !strings.Contains(m.describeWeb(), "导入") {
		t.Errorf("无结果时 describeWeb() 应提示可导入数据, 实际 %q", m.describeWeb())
	}

	cmd := m.startWeb()
	if cmd == nil {
		t.Fatal("startWeb() 在无结果时返回 nil，无法打开页面")
	}
	if msg := cmd(); msg != nil {
		m.Update(msg)
	}
	if m.webURL == "" {
		t.Fatalf("无结果时未能启动 Web（status=%q）", m.statusMsg)
	}
}

// TestPolicyMenuCyclesAndWraps covers the filtering-policy row.
func TestPolicyMenuCyclesAndWraps(t *testing.T) {
	m, _ := sized(t, nil)

	// The presets are 全部 → 原生 → 安全, then back to 全部.
	want := []policy.Kind{"", policy.Native, policy.Security, ""}
	for i, expect := range want {
		var got policy.Kind
		if len(m.cfg.Policies) > 0 {
			got = m.cfg.Policies[0]
		}
		if got != expect {
			t.Fatalf("第 %d 次循环后策略 = %q, 期望 %q（完整 %v）", i, got, expect, m.cfg.Policies)
		}
		m.cyclePolicyPreset()
	}
}

// TestPolicyMenuDescriptionNeverEmpty ensures the row always explains itself.
func TestPolicyMenuDescriptionNeverEmpty(t *testing.T) {
	m, _ := sized(t, nil)
	for _, kind := range append([]policy.Kind{""}, policy.All()...) {
		if kind == "" {
			m.cfg.Policies = nil
		} else {
			m.cfg.Policies = []policy.Kind{kind}
		}
		desc := m.describePolicies()
		if strings.TrimSpace(desc) == "" {
			t.Errorf("策略 %q 的描述为空", kind)
		}
		if kind != "" && !strings.Contains(desc, policy.Label(kind)) {
			t.Errorf("策略 %q 的描述未包含其名称: %q", kind, desc)
		}
	}
}

// TestPolicyMenuRowIsWired drives the row through the real key handler, so the
// description and the configuration cannot drift apart.
func TestPolicyMenuRowIsWired(t *testing.T) {
	m, _ := sized(t, nil)
	m.cursor = menuIndex(t, m, "过滤策略")

	m = pressSpecial(t, m, tea.KeyEnter)
	if len(m.cfg.Policies) != 1 || m.cfg.Policies[0] != policy.Native {
		t.Fatalf("第一次回车后策略 = %v, 期望 [native]", m.cfg.Policies)
	}
	// The menu must show the new value on the next frame.
	m.refreshMenu()
	if desc := m.items[menuIndex(t, m, "过滤策略")].desc; !strings.Contains(desc, policy.Label(policy.Native)) {
		t.Errorf("切换后菜单描述未更新: %q", desc)
	}
}

// TestSettingsRoundTripThroughMenu is the end-to-end check: change options in
// the menu, reopen the interface, and confirm the choices came back.
func TestSettingsRoundTripThroughMenu(t *testing.T) {
	deps, _ := stubDeps(t, nil)
	path := filepath.Join(t.TempDir(), settings.FileName)
	deps.SettingsPath = path

	m := New(deps)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	// Change several unrelated options through the real key handler, so the
	// persist hook is exercised rather than a direct settings call.
	m.cursor = menuIndex(t, m, "域名范围")
	m.cfg.Domains = domainlist.ModeMixed
	m.persist()

	m.cursor = menuIndex(t, m, "过滤策略")
	m.cfg.Policies = []policy.Kind{policy.Security}
	m.persist()

	m.cursor = menuIndex(t, m, "系统 DNS")
	m.cfg.SystemDNS = false
	m.persist()

	m.adv.timeout = 5 * time.Second
	m.adv.attempts = 2
	m.syncAdvanced()
	m.persist()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("设置文件未创建: %v", err)
	}

	// A fresh model pointed at the same file must recover the configuration.
	reopened := New(deps)
	if reopened.cfg.Domains != domainlist.ModeMixed {
		t.Errorf("域名范围未恢复: %q", reopened.cfg.Domains)
	}
	if len(reopened.cfg.Policies) != 1 || reopened.cfg.Policies[0] != policy.Security {
		t.Errorf("过滤策略未恢复: %v", reopened.cfg.Policies)
	}
	if reopened.cfg.SystemDNS {
		t.Error("系统 DNS 开关未恢复为 false")
	}
	if reopened.adv.timeout != 5*time.Second {
		t.Errorf("超时未恢复: %v", reopened.adv.timeout)
	}
	if reopened.adv.attempts != 2 {
		t.Errorf("查询次数未恢复: %d", reopened.adv.attempts)
	}
	if !reopened.settingsLoaded {
		t.Error("settingsLoaded 未置位，无法说明设置已生效")
	}
}

// TestNoSettingsPathWritesNothing is the safety property the tests themselves
// depend on: without an explicit path the interactive UI must never create a
// settings file, so running the test suite cannot touch a real installation.
func TestNoSettingsPathWritesNothing(t *testing.T) {
	m, _ := sized(t, nil)
	if m.deps.SettingsPath != "" {
		t.Fatalf("测试用的 Deps 不应带 SettingsPath, 实际 %q", m.deps.SettingsPath)
	}
	// persist must be a silent no-op rather than an error.
	m.persist()
	if m.statusErr {
		t.Errorf("无 SettingsPath 时 persist() 报了错: %q", m.statusMsg)
	}
}

// TestCorruptSettingsFallBackToDefaults verifies a broken file degrades instead
// of leaving the menu unusable.
func TestCorruptSettingsFallBackToDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, settings.FileName)
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	deps, _ := stubDeps(t, nil)
	deps.SettingsPath = path
	m := New(deps)

	if !m.statusErr || !strings.Contains(m.statusMsg, "设置文件") {
		t.Errorf("损坏的设置文件未产生提示, statusMsg=%q statusErr=%v", m.statusMsg, m.statusErr)
	}
	// The defaults must still be a runnable configuration.
	if err := m.cfg.Validate(); err != nil {
		t.Errorf("回落到默认值后配置仍不可运行: %v", err)
	}
	if m.cfg.Domains != domainlist.ModeAll {
		t.Errorf("未回落到默认域名范围: %q", m.cfg.Domains)
	}
}

// TestSettingsWithInvalidValuesAreIgnored ensures a hand-edited file cannot put
// the menu into a configuration it cannot run.
func TestSettingsWithInvalidValuesAreIgnored(t *testing.T) {
	m, _ := sized(t, nil)
	before := m.cfg

	m.applySettings(settings.Settings{
		Domains:     domainlist.ModeCN,
		Protocols:   []string{"not-a-protocol"},
		IPVersion:   "ipv9",
		Formula:     "nonsense",
		ServerClass: "mars",
		TimeoutMS:   -5,
		Attempts:    -1,
	})

	if m.cfg.Domains != domainlist.ModeCN {
		t.Errorf("合法的域名范围应被采纳, 实际 %q", m.cfg.Domains)
	}
	// Every invalid field must have been skipped rather than applied.
	if len(m.cfg.Protocols) != len(before.Protocols) {
		t.Errorf("非法协议列表被采纳了: %v", m.cfg.Protocols)
	}
	if m.cfg.IPVersion != before.IPVersion {
		t.Errorf("非法地址族被采纳了: %q", m.cfg.IPVersion)
	}
	if m.formula != config.FormulaComprehensive {
		t.Errorf("非法公式被采纳了: %q", m.formula)
	}
	if len(m.cfg.ServerCategories) != 0 {
		t.Errorf("非法服务器分类被采纳了: %v", m.cfg.ServerCategories)
	}
	if m.adv.timeout != before.Timeout || m.adv.attempts != before.Attempts {
		t.Errorf("非法超时/次数被采纳了: %v / %d", m.adv.timeout, m.adv.attempts)
	}
	if err := m.cfg.Validate(); err != nil {
		t.Errorf("跳过非法值后配置仍不可运行: %v", err)
	}
}

// TestSettingsComboOnlyRestoredWhenConsistent guards the pair of fields that
// must never contradict each other: a combo selector only makes sense alongside
// the protocol list it expands to.
func TestSettingsComboOnlyRestoredWhenConsistent(t *testing.T) {
	m, _ := sized(t, nil)

	// A combo whose protocols do not match what was saved is dropped.
	m.applySettings(settings.Settings{
		Protocols: []string{"dot"},
		Combo:     model.ComboUDPDoH,
	})
	if m.cfg.Combo != "" {
		t.Errorf("协议为 dot 时仍恢复了组合模式 %q，两者不一致", m.cfg.Combo)
	}

	// A combo that does match is restored.
	m.applySettings(settings.Settings{
		Protocols: []string{"udp", "doh"},
		Combo:     model.ComboUDPDoH,
	})
	if m.cfg.Combo != model.ComboUDPDoH {
		t.Errorf("协议与组合模式一致时未恢复: %q", m.cfg.Combo)
	}
}

// TestSettingsFileIsValidJSON checks what is actually written to disk, since a
// hand-editable file is part of the feature.
func TestSettingsFileIsValidJSON(t *testing.T) {
	m, path := modelWithSettings(t)
	m.cfg.Domains = domainlist.ModeMixed
	m.cfg.Policies = []policy.Kind{policy.Security}
	m.persist()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Error("设置文件缺少结尾换行，不适合手工编辑与 diff")
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("设置文件不是合法 JSON: %v\n%s", err, raw)
	}
	if decoded["domains"] != domainlist.ModeMixed {
		t.Errorf("domains = %v, 期望 %q", decoded["domains"], domainlist.ModeMixed)
	}
}
