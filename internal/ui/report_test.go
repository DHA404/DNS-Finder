package ui

import (
	"strings"
	"testing"

	"dns-opti/internal/config"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/scorer"
)

// rankedRow builds a scored row for the advice tests.
func rankedRow(dns string, avg, p95, stddev, rateMS float64, success, total int, system bool) scorer.Ranked {
	s := model.Summary{
		DNS:         dns,
		Name:        dns,
		Protocol:    model.ProtocolUDP,
		Group:       model.GroupCN,
		Total:       total,
		Success:     success,
		SuccessRate: rateMS,
		AvgMS:       avg,
		P95MS:       p95,
		StdDevMS:    stddev,
		IsSystem:    system,
	}
	return scorer.Ranked{Summary: s}
}

// TestSystemAdviceSlowSystemDNSIsNotCloseEnough is a regression test for an
// inverted comparison: the "within the error margin" branch used to be
// evaluated as best-sys < tolerance, which is negative (and therefore true)
// whenever the system DNS is *slower* than the best. A resolver that was 300ms
// slower than the best was consequently reported as "差距在误差范围内".
func TestSystemAdviceSlowSystemDNSIsNotCloseEnough(t *testing.T) {
	sys := rankedRow("156.154.71.22", 314, 400, 40, 1.0, 71, 71, true)
	best := rankedRow("https://dns.alidns.com/dns-query", 11, 12, 1.6, 1.0, 71, 71, false)

	got := systemAdvice(sys, best)

	if strings.Contains(got, "误差范围内") {
		t.Fatalf("系统 DNS 比最优慢 303ms，却被判定为差距可忽略:\n%s", got)
	}
	if !strings.Contains(got, "建议切换") {
		t.Fatalf("系统 DNS 明显更慢，应建议切换:\n%s", got)
	}
	// The reported saving must be the positive gap.
	if !strings.Contains(got, "303") {
		t.Errorf("未报告可降低的延迟（约 303ms）:\n%s", got)
	}
}

// TestSystemAdviceCloseEnough verifies that a genuinely negligible gap keeps
// the current configuration.
func TestSystemAdviceCloseEnough(t *testing.T) {
	sys := rankedRow("192.168.1.1", 24, 30, 2, 0.99, 99, 100, true)
	best := rankedRow("223.5.5.5", 20, 25, 2, 1.0, 100, 100, false)

	got := systemAdvice(sys, best)
	if !strings.Contains(got, "误差范围内") {
		t.Fatalf("差距 4ms 应判定为误差范围内:\n%s", got)
	}
	if strings.Contains(got, "建议切换") {
		t.Errorf("差距 4ms 不应建议切换:\n%s", got)
	}
}

// TestSystemAdviceBestIsKept verifies the top-ranked case.
func TestSystemAdviceBestIsKept(t *testing.T) {
	sys := rankedRow("223.5.5.5", 10, 12, 1, 1.0, 10, 10, true)
	sys.Rank = 1
	best := sys

	got := systemAdvice(sys, best)
	if !strings.Contains(got, "已是本组最优") {
		t.Fatalf("最优的系统 DNS 应被保留:\n%s", got)
	}
}

// TestSystemAdviceAllFailed verifies the total-failure case.
func TestSystemAdviceAllFailed(t *testing.T) {
	sys := rankedRow("10.0.0.1", 0, 0, 0, 0, 0, 20, true)
	best := rankedRow("223.5.5.5", 12, 15, 1, 1.0, 20, 20, false)

	got := systemAdvice(sys, best)
	if !strings.Contains(got, "全部查询失败") {
		t.Fatalf("全部失败应明确提示:\n%s", got)
	}
}

// TestSystemAdviceWarnsAboutPrivateDNS verifies that an internal resolver is
// flagged, because replacing it can break internal name resolution.
func TestSystemAdviceWarnsAboutPrivateDNS(t *testing.T) {
	sys := rankedRow("192.168.1.1", 300, 400, 50, 1.0, 20, 20, true)
	sys.IsPrivate = true
	best := rankedRow("223.5.5.5", 12, 15, 1, 1.0, 20, 20, false)

	got := systemAdvice(sys, best)
	if !strings.Contains(got, "内网") {
		t.Fatalf("内网 / 环回地址应被警告:\n%s", got)
	}
	if !strings.Contains(got, "无法解析") {
		t.Errorf("应提示可能无法解析内部域名:\n%s", got)
	}
}

// TestSystemAdviceSuccessOnlyGap verifies that a success-rate gap alone can
// trigger the switch advice even when the latencies are close.
func TestSystemAdviceSuccessOnlyGap(t *testing.T) {
	sys := rankedRow("9.9.9.9", 20, 25, 2, 0.80, 80, 100, true)
	best := rankedRow("223.5.5.5", 21, 25, 2, 1.0, 100, 100, false)

	got := systemAdvice(sys, best)
	if !strings.Contains(got, "建议切换") {
		t.Fatalf("成功率低 20%% 应建议切换:\n%s", got)
	}
	if !strings.Contains(got, "成功率可提升") {
		t.Errorf("应报告成功率的提升空间:\n%s", got)
	}
}

// TestRendererTableWidthsStable checks the table renderer aligns columns.
func TestRendererTableWidthsStable(t *testing.T) {
	rows := [][]string{
		{"#", "DNS", "得分"},
		{"1", "1.1.1.1", "10.00"},
		{"10", "very-long-server-name.example.com", "5.00"},
	}
	out := renderTable(rows)
	lines := strings.Split(out, "\n")
	if len(lines) != 4 {
		t.Fatalf("renderTable 返回 %d 行, 期望 4 行（表头 + 分隔线 + 2 行数据）:\n%s", len(lines), out)
	}
	if !strings.Contains(out, "very-long-server-name.example.com") {
		t.Errorf("长服务器名被截断:\n%s", out)
	}
}

// TestPrintNetworkVerdictRendersRecordedVerdict verifies the report states which
// families were usable and how many servers that excluded, instead of leaving
// the reader to wonder why IPv6 servers are absent.
func TestPrintNetworkVerdictRendersRecordedVerdict(t *testing.T) {
	tests := []struct {
		name   string
		probe  *model.NetworkProbe
		want   []string
		absent []string
	}{
		{
			name:   "无判定信息时不输出",
			probe:  nil,
			absent: []string{"地址族实测"},
		},
		{
			name:  "IPv6 不可用",
			probe: &model.NetworkProbe{IPv4: true, IPv6: false, Skipped: 8},
			want:  []string{"地址族实测", "IPv4", "可用", "IPv6", "不可用", "8"},
		},
		{
			name:  "IPv4 不可用",
			probe: &model.NetworkProbe{IPv4: false, IPv6: true, Skipped: 3},
			want:  []string{"地址族实测", "IPv4", "不可用", "IPv6", "可用", "3"},
		},
		{
			name:  "强制地址族的措辞不同",
			probe: &model.NetworkProbe{IPv4: true, IPv6: true, Skipped: 4, Forced: true},
			want:  []string{"--ip-version", "4"},
		},
		{
			name:  "两族都不可用",
			probe: &model.NetworkProbe{IPv4: false, IPv6: false},
			want:  []string{"地址族实测", "不可用"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &engine.Result{Meta: model.Meta{Network: tt.probe}}
			var b strings.Builder
			printNetworkVerdict(&b, res)
			got := b.String()

			if tt.probe == nil {
				if got != "" {
					t.Fatalf("无判定信息时输出了 %q", got)
				}
				return
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("判定行缺少 %q:\n%s", want, got)
				}
			}
			for _, absent := range tt.absent {
				if strings.Contains(got, absent) {
					t.Errorf("判定行不应包含 %q:\n%s", absent, got)
				}
			}
		})
	}
}

// TestPrintReportOmitsAlreadyShownWarnings verifies the report can suppress
// warnings the caller already displayed.
//
// The one-shot CLI prints the plan warnings before the run — the moment they are
// actually useful — so repeating the identical sentences at the end would show
// the user the same text twice.
func TestPrintReportOmitsAlreadyShownWarnings(t *testing.T) {
	const verdict = "本机 IPv6 实测无响应"
	const systemNote = "已跳过 2 个地址族不可用的系统 DNS"
	const regionNote = "地区筛选只作用于内置服务器"

	res := &engine.Result{
		Meta: model.Meta{
			Network: &model.NetworkProbe{IPv4: true, IPv6: false, Skipped: 10, Label: verdict},
		},
		Warned: []string{verdict, systemNote, regionNote},
	}

	t.Run("全部已显示过则一条都不重复", func(t *testing.T) {
		var b strings.Builder
		PrintReport(&b, res, ReportOptions{
			Formula:      config.FormulaComprehensive,
			AlreadyShown: []string{verdict, systemNote, regionNote},
		})
		got := b.String()

		for _, s := range []string{verdict, systemNote, regionNote} {
			if strings.Contains(got, s) {
				t.Errorf("已显示过的警告 %q 被重复打印:\n%s", s, got)
			}
		}
		// 判定摘要仍然要在，它是事实陈述而不是重复的提示。
		if !strings.Contains(got, "地址族实测") {
			t.Errorf("报告缺少地址族判定摘要:\n%s", got)
		}
	})

	t.Run("未显示过的警告仍然保留", func(t *testing.T) {
		var b strings.Builder
		PrintReport(&b, res, ReportOptions{
			Formula:      config.FormulaComprehensive,
			AlreadyShown: []string{verdict},
		})
		got := b.String()

		if strings.Contains(got, verdict) {
			t.Errorf("已显示过的判定被重复打印:\n%s", got)
		}
		for _, want := range []string{systemNote, regionNote} {
			if !strings.Contains(got, want) {
				t.Errorf("未显示过的警告 %q 被吞掉了:\n%s", want, got)
			}
		}
	})

	t.Run("未指定已显示集合时报告自包含", func(t *testing.T) {
		// 交互式菜单保存的报告要能独立阅读，因此默认必须打印全部警告。
		var b strings.Builder
		PrintResult(&b, res, config.FormulaComprehensive)
		got := b.String()

		for _, want := range []string{systemNote, regionNote} {
			if !strings.Contains(got, want) {
				t.Errorf("自包含报告缺少警告 %q:\n%s", want, got)
			}
		}
	})
}
