package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dns-opti/internal/config"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/scheduler"
	"dns-opti/internal/ui"
)

// selectItem moves the cursor to the menu entry whose title contains needle and
// activates it, returning the resulting model.
func selectItem(t *testing.T, m *Model, needle string) *Model {
	t.Helper()
	for i, item := range m.items {
		if strings.Contains(item.title, needle) {
			m.cursor = i
			return pressSpecial(t, m, tea.KeyEnter)
		}
	}
	t.Fatalf("菜单里找不到包含 %q 的项", needle)
	return m
}

// TestDumpScreens is a development aid: setting DNS_OPTI_DUMP_SCREENS=1 makes it
// print every screen so the layout can be reviewed without a TTY. It always
// passes, so it never breaks a normal `go test ./...`.
func TestDumpScreens(t *testing.T) {
	if os.Getenv("DNS_OPTI_DUMP_SCREENS") != "1" {
		t.Skip("设置 DNS_OPTI_DUMP_SCREENS=1 可输出各界面预览")
	}

	m := dumpModel(t)
	dump(t, "1. 主菜单（双击 exe 后看到的界面）", m)

	m = selectItem(t, m, "高级选项")
	dump(t, "2. 高级选项", m)
	m = pressSpecial(t, m, tea.KeyEsc)

	m = selectItem(t, m, "公式说明")
	dump(t, "3. 公式说明 · 第 1 页", m)
	m = pressSpecial(t, m, tea.KeyRight)
	dump(t, "4. 公式说明 · 第 2 页", m)
	m = pressSpecial(t, m, tea.KeyEsc)

	// Running + result.
	m2, _ := sized(t, nil)
	m2.cursor = 0
	_, runCmd := m2.items[0].action(m2)
	for _, msg := range drainBatch(t, runCmd) {
		if d, ok := msg.(runDoneMsg); ok {
			// Show the running screen mid-flight first.
			dump(t, "5. 测试进行中", m2)
			m2.Update(d)
			break
		}
	}
	dump(t, "6. 测试结果（报告）", m2)

	// Error screen.
	m3, _ := sized(t, nil)
	m3.Update(runDoneMsg{err: fmt.Errorf("没有可测试的 DNS 服务器（请检查 --protocols / --servers 参数）")})
	dump(t, "7. 出错界面", m3)
}

// dumpModel builds a model with a realistic stub run for the screen dump.
func dumpModel(t *testing.T) *Model {
	t.Helper()
	deps := Deps{
		Version: "v1.0.0",
		Run: func(ctx context.Context, cfg config.Options, progress ui.ProgressFunc) (*engine.Result, error) {
			servers := []model.Server{
				{Name: "AliDNS 1", Address: "223.5.5.5", Protocol: model.ProtocolUDP},
				{Name: "AliDNS 2", Address: "223.6.6.6", Protocol: model.ProtocolUDP},
				{Name: "DNSPod", Address: "119.29.29.29", Protocol: model.ProtocolUDP},
				{Name: "AliDNS", Address: "dns.alidns.com", Protocol: model.ProtocolDoT},
				{Name: "AliDNS", Address: "https://dns.alidns.com/dns-query", Protocol: model.ProtocolDoH},
			}
			total := len(servers) * 10
			n := 0
			for _, s := range servers {
				for i := 0; i < 10; i++ {
					n++
					progress(scheduler.ProgressEvent{
						Server: s, Domain: "baidu.com", Group: model.GroupCN,
						Success: !(s.Address == "119.29.29.29" && i > 6),
						Latency: time.Duration(9+len(s.Address)%11+i) * time.Millisecond,
						Done:    n, Total: total,
					})
				}
			}
			return &engine.Result{
				Meta: model.Meta{Version: "1.0", Concurrency: 12, WarmupDomain: "example.com"},
				Summaries: []model.Summary{
					{DNS: "223.5.5.5", Name: "AliDNS 1", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 12.2, P95MS: 16.8, StdDevMS: 1.9},
					{DNS: "dns.alidns.com", Name: "AliDNS", Protocol: model.ProtocolDoT, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 12.4, P95MS: 22.7, StdDevMS: 3.4},
					{DNS: "119.29.29.29", Name: "DNSPod", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 7, SuccessRate: 0.7, AvgMS: 16.7, P95MS: 24.3, StdDevMS: 3.0},
				},
				Path: "dns-opti_result_demo.json", Total: 30, Failed: 3,
			}, nil
		},
		StartWeb: func(*engine.Result) (string, func(), error) {
			return "http://127.0.0.1:38200", func() {}, nil
		},
		BuildTasks: func(cfg config.Options) ([]model.Server, []model.Domain, []string, error) {
			servers := []model.Server{}
			for _, p := range cfg.Protocols {
				switch p {
				case model.ProtocolUDP:
					servers = append(servers,
						model.Server{Name: "AliDNS 1", Address: "223.5.5.5", Protocol: model.ProtocolUDP},
						model.Server{Name: "DNSPod", Address: "119.29.29.29", Protocol: model.ProtocolUDP},
					)
				case model.ProtocolDoT:
					servers = append(servers, model.Server{Name: "AliDNS", Address: "dns.alidns.com", Protocol: model.ProtocolDoT})
				case model.ProtocolDoH:
					servers = append(servers, model.Server{Name: "AliDNS", Address: "https://dns.alidns.com/dns-query", Protocol: model.ProtocolDoH})
				case model.ProtocolDoH3:
					servers = append(servers, model.Server{Name: "Cloudflare", Address: "https://cloudflare-dns.com/dns-query", Protocol: model.ProtocolDoH3})
				}
			}
			domains := []model.Domain{}
			if cfg.Domains != "cn" {
				domains = append(domains, model.Domain{Name: "google.com", Group: model.GroupIntl})
			}
			if cfg.Domains != "intl" {
				domains = append(domains, model.Domain{Name: "baidu.com", Group: model.GroupCN}, model.Domain{Name: "qq.com", Group: model.GroupCN})
			}
			return servers, domains, nil, nil
		},
	}
	m := New(deps)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if cmd := m.Init(); cmd != nil {
		m.Update(cmd())
	}
	return m
}

// dump prints one screen.
func dump(t *testing.T, title string, m *Model) {
	t.Helper()
	var b strings.Builder
	b.WriteString("\n" + strings.Repeat("=", 96) + "\n")
	b.WriteString("### " + title + "\n")
	b.WriteString(strings.Repeat("=", 96) + "\n")
	b.WriteString(m.View() + "\n")
	t.Log(b.String())
}
