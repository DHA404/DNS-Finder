package scorer

import (
	"math"
	"testing"

	"dns-opti/internal/config"
	"dns-opti/internal/model"
)

// approxEqual 比较两个浮点数，tolerance 为相对误差。
func approxEqual(got, want float64) bool {
	if got == want {
		return true
	}
	scale := math.Max(math.Abs(want), 1)
	return math.Abs(got-want) <= 1e-9*scale
}

// sampleRow 是手工计算的固定输入行：成功率 90%、平均 20ms、P95 50ms、标准差 10ms。
func sampleRow() model.Summary {
	return model.Summary{
		DNS:         "8.8.8.8",
		Protocol:    model.ProtocolUDP,
		Group:       model.GroupCN,
		Total:       10,
		Success:     9,
		SuccessRate: 0.9,
		AvgMS:       20,
		P95MS:       50,
		StdDevMS:    10,
	}
}

// TestScoreMatchesPlanFormulas 用固定输入行核对 PLAN 第五节的四套公式。
//
// 手工推导（success_rate=0.9, avg=20, p95=50, stddev=10）：
//
//	极速优先: 1000*0.9/20                       = 45
//	稳定优先: 1000*0.9²/20 * 1/(1+10/20)        = 40.5 / 1.5 = 27
//	综合体验: 1000*0.9/(0.5*20+0.5*50)          = 900/35 ≈ 25.714285714285715
//	抗抖动:   1000*0.9/(20+2*10)                = 900/40 = 22.5
func TestScoreMatchesPlanFormulas(t *testing.T) {
	row := sampleRow()

	tests := []struct {
		name    string
		formula config.Formula
		want    float64
	}{
		{name: "公式1 极速优先", formula: config.FormulaSpeed, want: 45},
		{name: "公式2 稳定优先", formula: config.FormulaStable, want: 27},
		{name: "公式3 综合体验", formula: config.FormulaComprehensive, want: 900.0 / 35.0},
		{name: "公式4 抗抖动优先", formula: config.FormulaJitter, want: 22.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Score(row, tt.formula)
			if !approxEqual(got, tt.want) {
				t.Fatalf("Score(%+v, %q) = %v, 期望 %v（手工推导值）", row, tt.formula, got, tt.want)
			}
		})
	}
}

// TestScoreMatchesPlanFormulasSecondRow 用第二组数值再次核对公式，避免只对上一种巧合。
//
// 手工推导（success_rate=0.5, avg=100, p95=200, stddev=50）：
//
//	极速优先: 1000*0.5/100                        = 5
//	稳定优先: 1000*0.25/100 * 1/(1+50/100)        = 2.5/1.5 ≈ 1.6666666666666667
//	综合体验: 1000*0.5/(0.5*100+0.5*200)          = 500/150 ≈ 3.3333333333333335
//	抗抖动:   1000*0.5/(100+2*50)                 = 500/200 = 2.5
func TestScoreMatchesPlanFormulasSecondRow(t *testing.T) {
	row := model.Summary{
		DNS: "1.1.1.1", Protocol: model.ProtocolDoH, Group: model.GroupIntl,
		Total: 4, Success: 2, SuccessRate: 0.5,
		AvgMS: 100, P95MS: 200, StdDevMS: 50,
	}

	tests := []struct {
		name    string
		formula config.Formula
		want    float64
	}{
		{name: "公式1 极速优先", formula: config.FormulaSpeed, want: 5},
		{name: "公式2 稳定优先", formula: config.FormulaStable, want: 2.5 / 1.5},
		{name: "公式3 综合体验", formula: config.FormulaComprehensive, want: 500.0 / 150.0},
		{name: "公式4 抗抖动优先", formula: config.FormulaJitter, want: 2.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Score(row, tt.formula)
			if !approxEqual(got, tt.want) {
				t.Fatalf("Score(%+v, %q) = %v, 期望 %v", row, tt.formula, got, tt.want)
			}
		})
	}
}

func TestScoreZeroSuccessIsZeroForEveryFormula(t *testing.T) {
	rows := []model.Summary{
		{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 0, SuccessRate: 0, AvgMS: 12, P95MS: 20, StdDevMS: 3},
		// 只有失败记录时不会有延迟统计，字段全为 0。
		{DNS: "1.1.1.1", Protocol: model.ProtocolUDP, Group: model.GroupIntl, Total: 5, Success: 0},
		// Success 与 Total 都缺失的畸形行也必须为 0。
		{DNS: "9.9.9.9", Protocol: model.ProtocolUDP, Group: model.GroupCN},
		// Total 为 0 但 Success 非零，属于不一致数据，同样按 0 处理。
		{DNS: "149.112.112.112", Success: 3, Total: 0, SuccessRate: 1},
	}

	formulas := []config.Formula{
		config.FormulaSpeed, config.FormulaStable, config.FormulaComprehensive, config.FormulaJitter,
	}

	for _, row := range rows {
		for _, f := range formulas {
			got := Score(row, f)
			if got != 0 {
				t.Fatalf("零成功行 Score(%+v, %q) = %v, 期望 0", row, f, got)
			}
		}
	}
}

func TestScoreNeverReturnsNaNOrInf(t *testing.T) {
	// 回归测试：稳定优先曾写成 avg*(1+stddev/avg)，当 avg == 0 时 stddev/avg 为
	// NaN，乘积保持 NaN，而 `NaN < minDenominator` 为 false，兜底逻辑形同虚设，
	// 于是得分变成 NaN 并污染整张排名表。这里对退化输入做穷举，确保任何组合都
	// 只产生有限值。
	degenerate := []float64{0, 0.0001, 1, 1000}
	formulas := []config.Formula{
		config.FormulaSpeed, config.FormulaStable, config.FormulaComprehensive,
		config.FormulaJitter, config.Formula("unknown"),
	}

	for _, avgMS := range degenerate {
		for _, p95 := range degenerate {
			for _, sd := range degenerate {
				row := model.Summary{
					DNS: "degenerate", Protocol: model.ProtocolUDP, Group: model.GroupCN,
					Total: 1, Success: 1, SuccessRate: 1,
					AvgMS: avgMS, P95MS: p95, StdDevMS: sd,
				}
				for _, f := range formulas {
					got := Score(row, f)
					if math.IsNaN(got) {
						t.Fatalf("Score(avg=%v p95=%v stddev=%v, %q) = NaN, 期望有限值", avgMS, p95, sd, f)
					}
					if math.IsInf(got, 0) {
						t.Fatalf("Score(avg=%v p95=%v stddev=%v, %q) = %v, 期望有限值", avgMS, p95, sd, f, got)
					}
				}
			}
		}
	}
}

// TestStableFormulaDegenerateInputs 单独盯住稳定优先的退化输入。
func TestStableFormulaDegenerateInputs(t *testing.T) {
	tests := []struct {
		name string
		row  model.Summary
		want float64
	}{
		{
			name: "平均延迟为 0：分母被兜底为 minDenominator",
			row:  model.Summary{Total: 1, Success: 1, SuccessRate: 1, AvgMS: 0, StdDevMS: 0},
			want: 1000 / minDenominator,
		},
		{
			name: "平均延迟为 0 但标准差非 0：分母为 0+stddev，不产生 NaN",
			row:  model.Summary{Total: 1, Success: 1, SuccessRate: 1, AvgMS: 0, StdDevMS: 5},
			want: 1000 / 5,
		},
		{
			name: "正常输入：分母为 avg+stddev",
			row:  model.Summary{Total: 10, Success: 10, SuccessRate: 1, AvgMS: 20, StdDevMS: 5},
			want: 1000 * 1 / 25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Score(tt.row, config.FormulaStable)
			if math.IsNaN(got) {
				t.Fatalf("Score(%+v, stable) = NaN, 期望 %v", tt.row, tt.want)
			}
			if !approxEqual(got, tt.want) {
				t.Fatalf("Score(%+v, stable) = %v, 期望 %v", tt.row, got, tt.want)
			}
		})
	}
}

func TestScoreDerivesSuccessRateWhenMissing(t *testing.T) {
	// SuccessRate 缺失时按 Success/Total 现算，结果应与显式给出的完全一致。
	implicit := model.Summary{DNS: "8.8.8.8", Total: 10, Success: 9, AvgMS: 20, P95MS: 50, StdDevMS: 10}
	explicit := sampleRow()
	for _, f := range []config.Formula{config.FormulaSpeed, config.FormulaStable, config.FormulaComprehensive, config.FormulaJitter} {
		a, b := Score(implicit, f), Score(explicit, f)
		if !approxEqual(a, b) {
			t.Fatalf("缺失 SuccessRate 时 Score(..., %q) = %v, 显式给出时为 %v, 期望一致", f, a, b)
		}
	}
}

func TestScoreUnknownFormulaFallsBackToComprehensive(t *testing.T) {
	row := sampleRow()
	got := Score(row, config.Formula("made-up"))
	want := Score(row, config.FormulaComprehensive)
	if !approxEqual(got, want) {
		t.Fatalf("未知公式的得分 = %v, 期望回落为综合体验的 %v", got, want)
	}
}

func TestScoreGuardsDivisionByZero(t *testing.T) {
	// 所有延迟字段为 0 时不能得到 Inf / NaN，分母兜底为 minDenominator。
	row := model.Summary{DNS: "127.0.0.1", Total: 1, Success: 1, SuccessRate: 1}
	for _, f := range []config.Formula{config.FormulaSpeed, config.FormulaStable, config.FormulaComprehensive, config.FormulaJitter} {
		got := Score(row, f)
		if math.IsNaN(got) || math.IsInf(got, 0) {
			t.Fatalf("零延迟行 Score(..., %q) = %v, 期望有限值", f, got)
		}
		if got <= 0 {
			t.Fatalf("零延迟行 Score(..., %q) = %v, 期望正数（被 minDenominator 保护）", f, got)
		}
		want := 1000 * 1.0 / minDenominator
		if !approxEqual(got, want) {
			t.Fatalf("零延迟行 Score(..., %q) = %v, 期望 %v", f, got, want)
		}
	}
}

func TestFormulasCatalogue(t *testing.T) {
	wantIDs := []config.Formula{
		config.FormulaSpeed, config.FormulaStable, config.FormulaComprehensive, config.FormulaJitter,
	}
	if len(Formulas) != len(wantIDs) {
		t.Fatalf("Formulas 共 %d 条, 期望 %d 条", len(Formulas), len(wantIDs))
	}
	for i, want := range wantIDs {
		f := Formulas[i]
		if f.ID != want {
			t.Fatalf("Formulas[%d].ID = %q, 期望 %q", i, f.ID, want)
		}
		if f.Name == "" || f.Expr == "" || f.Desc == "" || f.Scenario == "" {
			t.Fatalf("Formulas[%d] 的展示字段不完整: %+v", i, f)
		}
		info, ok := FormulaByID(want)
		if !ok {
			t.Fatalf("FormulaByID(%q) 未找到", want)
		}
		if info != f {
			t.Fatalf("FormulaByID(%q) = %+v, 与 Formulas[%d] = %+v 不一致", want, info, i, f)
		}
	}
	if _, ok := FormulaByID(config.Formula("nope")); ok {
		t.Fatal("FormulaByID(\"nope\") 本应返回 false")
	}
}

// rankSample 构造一组覆盖多个分组、多个协议的汇总行。
func rankSample() []model.Summary {
	return []model.Summary{
		// 0: 国内 UDP，最快但抖动大
		{DNS: "223.5.5.5", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 10, P95MS: 80, StdDevMS: 40},
		// 1: 国内 UDP，较慢但非常稳
		{DNS: "119.29.29.29", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 20, P95MS: 22, StdDevMS: 2},
		// 2: 国内 DoH
		{DNS: "https://doh.pub/dns-query", Protocol: model.ProtocolDoH, Group: model.GroupCN, Total: 10, Success: 9, SuccessRate: 0.9, AvgMS: 30, P95MS: 60, StdDevMS: 8},
		// 3: 国外 UDP
		{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Group: model.GroupIntl, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 15, P95MS: 40, StdDevMS: 12},
		// 4: 国外 DoT
		{DNS: "dns.google", Protocol: model.ProtocolDoT, Group: model.GroupIntl, Total: 10, Success: 8, SuccessRate: 0.8, AvgMS: 25, P95MS: 45, StdDevMS: 6},
	}
}

func TestRankOrderDescendingAndContiguous(t *testing.T) {
	rows := rankSample()
	for _, f := range []config.Formula{config.FormulaSpeed, config.FormulaStable, config.FormulaComprehensive, config.FormulaJitter} {
		t.Run(string(f), func(t *testing.T) {
			ranked := Rank(rows, f, Filter{})
			if len(ranked) != len(rows) {
				t.Fatalf("Rank 返回 %d 行, 期望 %d 行（无过滤条件时不应丢行）", len(ranked), len(rows))
			}
			for i, r := range ranked {
				want := i + 1
				if r.Rank != want {
					t.Fatalf("ranked[%d].Rank = %d, 期望 %d（名次必须从 1 开始且连续）", i, r.Rank, want)
				}
				if i > 0 && ranked[i-1].Score < r.Score {
					t.Fatalf("ranked[%d].Score = %v 大于前一行 %v, 期望降序（公式 %q）",
						i, r.Score, ranked[i-1].Score, f)
				}
			}
			// 每行都必须能在输入中找到对应记录，且 Score 与单独计算一致。
			for i, r := range ranked {
				if got := Score(r.Summary, f); !approxEqual(r.Score, got) {
					t.Fatalf("ranked[%d].Score = %v, 但 Score(%+v, %q) = %v", i, r.Score, r.Summary, f, got)
				}
			}
		})
	}
}

func TestRankFilterByGroupAndProtocol(t *testing.T) {
	rows := rankSample()

	tests := []struct {
		name   string
		filter Filter
		want   []string // 期望的 DNS 集合（顺序无关，用集合比较）
	}{
		{
			name:   "不限制",
			filter: Filter{},
			want:   []string{"223.5.5.5", "119.29.29.29", "https://doh.pub/dns-query", "8.8.8.8", "dns.google"},
		},
		{
			name:   "只取国内分组",
			filter: Filter{Group: model.GroupCN},
			want:   []string{"223.5.5.5", "119.29.29.29", "https://doh.pub/dns-query"},
		},
		{
			name:   "只取国外分组",
			filter: Filter{Group: model.GroupIntl},
			want:   []string{"8.8.8.8", "dns.google"},
		},
		{
			name:   "只取 UDP 协议",
			filter: Filter{Protocol: model.ProtocolUDP},
			want:   []string{"223.5.5.5", "119.29.29.29", "8.8.8.8"},
		},
		{
			name:   "国内 + UDP",
			filter: Filter{Group: model.GroupCN, Protocol: model.ProtocolUDP},
			want:   []string{"223.5.5.5", "119.29.29.29"},
		},
		{
			name:   "国外 + DoT",
			filter: Filter{Group: model.GroupIntl, Protocol: model.ProtocolDoT},
			want:   []string{"dns.google"},
		},
		{
			name:   "国内 + DoH3 无匹配",
			filter: Filter{Group: model.GroupCN, Protocol: model.ProtocolDoH3},
			want:   nil,
		},
		{
			name:   "不存在的分组",
			filter: Filter{Group: "nope"},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranked := Rank(rows, config.FormulaComprehensive, tt.filter)
			if len(ranked) != len(tt.want) {
				t.Fatalf("Rank(..., %+v) 返回 %d 行（%v）, 期望 %d 行（%v）",
					tt.filter, len(ranked), dnsList(ranked), len(tt.want), tt.want)
			}
			got := map[string]bool{}
			for _, r := range ranked {
				got[r.DNS] = true
				if tt.filter.Group != "" && r.Group != tt.filter.Group {
					t.Fatalf("过滤 %+v 后仍出现分组 %q 的行 %q", tt.filter, r.Group, r.DNS)
				}
				if tt.filter.Protocol != "" && r.Protocol != tt.filter.Protocol {
					t.Fatalf("过滤 %+v 后仍出现协议 %q 的行 %q", tt.filter, r.Protocol, r.DNS)
				}
			}
			for _, want := range tt.want {
				if !got[want] {
					t.Fatalf("Rank(..., %+v) 缺少 %q（实际 %v）", tt.filter, want, dnsList(ranked))
				}
			}
			// 过滤后的名次同样必须从 1 开始连续编号。
			for i, r := range ranked {
				if r.Rank != i+1 {
					t.Fatalf("过滤后 ranked[%d].Rank = %d, 期望 %d", i, r.Rank, i+1)
				}
			}
		})
	}
}

func TestRankEmptyInput(t *testing.T) {
	ranked := Rank(nil, config.FormulaComprehensive, Filter{})
	if len(ranked) != 0 {
		t.Fatalf("Rank(nil, ...) = %v, 期望空结果", ranked)
	}
	if _, ok := Best(nil, config.FormulaComprehensive, Filter{}); ok {
		t.Fatal("Best(nil, ...) 本应返回 false")
	}
	if _, ok := Best(rankSample(), config.FormulaComprehensive, Filter{Group: "nope"}); ok {
		t.Fatal("Best 在过滤无匹配时本应返回 false")
	}
}

func TestRankTieBreakIsDeterministic(t *testing.T) {
	// 得分完全相同的两行按平均延迟升序排列，重复调用结果必须一致。
	rows := []model.Summary{
		{DNS: "b.example", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 1, Success: 1, SuccessRate: 1, AvgMS: 20, P95MS: 20},
		{DNS: "a.example", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 1, Success: 1, SuccessRate: 1, AvgMS: 20, P95MS: 20},
		{DNS: "c.example", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 1, Success: 1, SuccessRate: 1, AvgMS: 10, P95MS: 10},
	}
	for run := 0; run < 5; run++ {
		ranked := Rank(rows, config.FormulaComprehensive, Filter{})
		want := []string{"c.example", "a.example", "b.example"}
		for i, w := range want {
			if ranked[i].DNS != w {
				t.Fatalf("第 %d 次 Rank 的 ranked[%d].DNS = %q, 期望 %q（同分时按地址升序，结果必须稳定）",
					run, i, ranked[i].DNS, w)
			}
		}
	}
}

// TestSameRowRanksDifferentlyPerFormula 证明“同一 DNS 在不同公式下排名可能变化”。
func TestSameRowRanksDifferentlyPerFormula(t *testing.T) {
	// A：极快但抖动极大；B：慢一些但非常稳定。
	rows := []model.Summary{
		{DNS: "fast-jittery.example", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 10, P95MS: 80, StdDevMS: 40},
		{DNS: "slow-stable.example", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 20, P95MS: 22, StdDevMS: 2},
	}

	speed := Rank(rows, config.FormulaSpeed, Filter{})
	if speed[0].DNS != "fast-jittery.example" {
		t.Fatalf("极速优先应让 fast-jittery 排第一, 实际第一是 %q（%v）", speed[0].DNS, dnsList(speed))
	}

	comprehensive := Rank(rows, config.FormulaComprehensive, Filter{})
	if comprehensive[0].DNS != "slow-stable.example" {
		t.Fatalf("综合体验应让 slow-stable 排第一, 实际第一是 %q（%v）", comprehensive[0].DNS, dnsList(comprehensive))
	}

	jitter := Rank(rows, config.FormulaJitter, Filter{})
	if jitter[0].DNS != "slow-stable.example" {
		t.Fatalf("抗抖动优先应让 slow-stable 排第一, 实际第一是 %q（%v）", jitter[0].DNS, dnsList(jitter))
	}

	stable := Rank(rows, config.FormulaStable, Filter{})
	if stable[0].DNS != "slow-stable.example" {
		t.Fatalf("稳定优先应让 slow-stable 排第一, 实际第一是 %q（%v）", stable[0].DNS, dnsList(stable))
	}

	// 断言两行在两种公式下的名次确实互换了。
	fastRankUnderSpeed := rankOf(speed, "fast-jittery.example")
	fastRankUnderComprehensive := rankOf(comprehensive, "fast-jittery.example")
	if fastRankUnderSpeed != 1 || fastRankUnderComprehensive != 2 {
		t.Fatalf("fast-jittery 在极速优先下名次 %d、在综合体验下名次 %d, 期望 1 和 2",
			fastRankUnderSpeed, fastRankUnderComprehensive)
	}
}

func TestGroupKeysCanonicalOrder(t *testing.T) {
	tests := []struct {
		name      string
		summaries []model.Summary
		want      []string
	}{
		{
			name:      "空输入",
			summaries: nil,
			want:      nil,
		},
		{
			name: "输入顺序为 intl 在前，输出仍强制 cn 优先",
			summaries: []model.Summary{
				{Group: model.GroupIntl}, {Group: model.GroupCN},
			},
			want: []string{model.GroupCN, model.GroupIntl},
		},
		{
			name: "只有 intl",
			summaries: []model.Summary{
				{Group: model.GroupIntl}, {Group: model.GroupIntl},
			},
			want: []string{model.GroupIntl},
		},
		{
			name: "只有 cn",
			summaries: []model.Summary{
				{Group: model.GroupCN},
			},
			want: []string{model.GroupCN},
		},
		{
			name: "自定义与导入分组排在规范分组之后",
			summaries: []model.Summary{
				{Group: model.GroupImported}, {Group: model.GroupCustom},
				{Group: model.GroupIntl}, {Group: model.GroupCN},
			},
			want: []string{model.GroupCN, model.GroupIntl, model.GroupImported, model.GroupCustom},
		},
		{
			name: "自定义分组去重",
			summaries: []model.Summary{
				{Group: model.GroupCustom}, {Group: model.GroupCustom},
			},
			want: []string{model.GroupCustom},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GroupKeys(tt.summaries)
			if len(got) != len(tt.want) {
				t.Fatalf("GroupKeys(%v) = %v, 期望 %v", tt.summaries, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("GroupKeys(%v)[%d] = %q, 期望 %q（完整 %v）", tt.summaries, i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

func TestProtocolKeysCanonicalOrder(t *testing.T) {
	tests := []struct {
		name      string
		summaries []model.Summary
		want      []model.Protocol
	}{
		{name: "空输入", summaries: nil, want: nil},
		{
			name: "输入乱序，输出按 udp/dot/doh/doh3",
			summaries: []model.Summary{
				{Protocol: model.ProtocolDoH3}, {Protocol: model.ProtocolUDP},
				{Protocol: model.ProtocolDoH}, {Protocol: model.ProtocolDoT},
			},
			want: []model.Protocol{model.ProtocolUDP, model.ProtocolDoT, model.ProtocolDoH, model.ProtocolDoH3},
		},
		{
			name: "去重",
			summaries: []model.Summary{
				{Protocol: model.ProtocolUDP}, {Protocol: model.ProtocolUDP},
			},
			want: []model.Protocol{model.ProtocolUDP},
		},
		{
			name: "只保留出现的协议",
			summaries: []model.Summary{
				{Protocol: model.ProtocolDoT}, {Protocol: model.ProtocolDoH3},
			},
			want: []model.Protocol{model.ProtocolDoT, model.ProtocolDoH3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProtocolKeys(tt.summaries)
			if len(got) != len(tt.want) {
				t.Fatalf("ProtocolKeys(%v) = %v, 期望 %v", tt.summaries, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("ProtocolKeys(%v)[%d] = %q, 期望 %q（完整 %v）", tt.summaries, i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

func TestBest(t *testing.T) {
	rows := rankSample()

	tests := []struct {
		name      string
		formula   config.Formula
		filter    Filter
		wantDNS   string
		wantFound bool
	}{
		{
			name:    "国内 UDP 综合体验最优",
			formula: config.FormulaComprehensive,
			filter:  Filter{Group: model.GroupCN, Protocol: model.ProtocolUDP},
			// 223.5.5.5: 1000/(5+40)≈22.22；119.29.29.29: 1000/(10+11)≈47.62
			wantDNS:   "119.29.29.29",
			wantFound: true,
		},
		{
			name:    "国内 UDP 极速优先最优",
			formula: config.FormulaSpeed,
			filter:  Filter{Group: model.GroupCN, Protocol: model.ProtocolUDP},
			// 223.5.5.5: 1000/10=100；119.29.29.29: 1000/20=50
			wantDNS:   "223.5.5.5",
			wantFound: true,
		},
		{
			name:      "无匹配返回 false",
			formula:   config.FormulaSpeed,
			filter:    Filter{Protocol: model.ProtocolDoH3},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Best(rows, tt.formula, tt.filter)
			if ok != tt.wantFound {
				t.Fatalf("Best(..., %q, %+v) 的 found = %v, 期望 %v", tt.formula, tt.filter, ok, tt.wantFound)
			}
			if !ok {
				if got.Rank != 0 || got.DNS != "" {
					t.Fatalf("Best 未找到时返回了 %+v, 期望零值", got)
				}
				return
			}
			if got.DNS != tt.wantDNS {
				t.Fatalf("Best(..., %q, %+v).DNS = %q, 期望 %q", tt.formula, tt.filter, got.DNS, tt.wantDNS)
			}
			if got.Rank != 1 {
				t.Fatalf("Best(...).Rank = %d, 期望 1", got.Rank)
			}
		})
	}
}

func TestRankDoesNotMutateInput(t *testing.T) {
	rows := rankSample()
	before := make([]model.Summary, len(rows))
	copy(before, rows)
	Rank(rows, config.FormulaSpeed, Filter{})
	for i := range rows {
		if rows[i] != before[i] {
			t.Fatalf("Rank 修改了输入切片第 %d 行: %+v -> %+v", i, before[i], rows[i])
		}
	}
}

func TestRoundScore(t *testing.T) {
	tests := []struct {
		in   float64
		want float64
	}{
		{in: 1.234, want: 1.23},
		{in: 1.235, want: 1.24},
		{in: 45, want: 45},
		{in: 0, want: 0},
		{in: 22.5, want: 22.5},
		{in: 25.714285714, want: 25.71},
	}
	for _, tt := range tests {
		got := RoundScore(tt.in)
		if math.Abs(got-tt.want) > 1e-9 {
			t.Fatalf("RoundScore(%v) = %v, 期望 %v", tt.in, got, tt.want)
		}
	}
}

// rankOf 返回指定 DNS 在排名中的名次，找不到返回 0。
func rankOf(ranked []Ranked, dns string) int {
	for _, r := range ranked {
		if r.DNS == dns {
			return r.Rank
		}
	}
	return 0
}

// dnsList 提取排名中的 DNS 序列，用于失败信息。
func dnsList(ranked []Ranked) []string {
	out := make([]string, 0, len(ranked))
	for _, r := range ranked {
		out = append(out, r.DNS)
	}
	return out
}
