// Package scorer implements the four ranking formulas of the tool and the
// ranking itself.
//
// Every formula is computed from the aggregated data of one
// (dns, protocol, group) row, so a resolver can rank differently for domestic
// and international domains — and that is intentional: the two groups are
// never mixed (see PLAN 五).
package scorer

import (
	"cmp"
	"math"
	"slices"
	"strings"

	"dns-opti/internal/config"
	"dns-opti/internal/model"
)

// minDenominator guards the formulas against a division by zero when a server
// answers in under a microsecond (a local cache, say). Without it such a
// server would score zero despite being the fastest.
const minDenominator = 0.001

// FormulaInfo describes one scoring formula for the CLI help and the web UI:
// what it computes, what it favours and when to use it.
type FormulaInfo struct {
	ID       config.Formula `json:"id"`
	Name     string         `json:"name"`
	Expr     string         `json:"expr"`
	Desc     string         `json:"desc"`
	Scenario string         `json:"scenario"`
}

// Formulas lists the four built-in formulas in presentation order.
var Formulas = []FormulaInfo{
	{
		ID:       config.FormulaSpeed,
		Name:     "极速优先",
		Expr:     "Score = 1000 × 成功率 ÷ 平均延迟(ms)",
		Desc:     "只关心平均延迟，成功率线性计入权重。任何一次成功都很值钱，于是它偏爱离你最近、命中缓存最快的服务器。",
		Scenario: "对延迟极度敏感、能接受偶尔失败的场景：快速打开网页、短连接小请求、抢票类操作。",
	},
	{
		ID:       config.FormulaStable,
		Name:     "稳定优先",
		Expr:     "Score = 1000 × 成功率² ÷ 平均延迟(ms) × 1 ÷ (1 + 标准差 ÷ 平均延迟)",
		Desc:     "成功率取平方，放大失败的代价；再用变异系数（标准差 ÷ 平均延迟）惩罚延迟抖动。两头都稳才拿高分。",
		Scenario: "视频会议、在线游戏、长时间保持连接的场景，偶发卡顿比平均慢几毫秒更难受。",
	},
	{
		ID:       config.FormulaComprehensive,
		Name:     "综合体验",
		Expr:     "Score = 1000 × 成功率 ÷ (0.5 × 平均延迟(ms) + 0.5 × P95延迟(ms))",
		Desc:     "平均延迟与 P95 各占一半。P95 代表最慢的那 5% 请求，把“大部分很快、偶尔很慢”的服务器拉下马，同时不至于像稳定优先那样极端。",
		Scenario: "日常网页浏览与综合场景，也是默认公式：既看常态速度，也看尾部延迟。",
	},
	{
		ID:       config.FormulaJitter,
		Name:     "抗抖动优先",
		Expr:     "Score = 1000 × 成功率 ÷ (平均延迟(ms) + 2 × 标准差(ms))",
		Desc:     "把标准差按两倍权重直接加进延迟里。抖动越大惩罚越重，比稳定优先更激进地淘汰忽快忽慢的服务器。",
		Scenario: "移动网络、Wi-Fi 信号差、网络波动大的环境，宁可整体慢一点也要少断流。",
	},
}

// FormulaByID returns the metadata of a formula.
func FormulaByID(id config.Formula) (FormulaInfo, bool) {
	for _, f := range Formulas {
		if f.ID == id {
			return f, true
		}
	}
	return FormulaInfo{}, false
}

// Score computes the score of a summary row under the given formula. A row
// with no successful query scores zero under every formula.
func Score(s model.Summary, f config.Formula) float64 {
	if s.Success <= 0 || s.Total <= 0 {
		return 0
	}
	sr := s.SuccessRate
	if sr <= 0 {
		sr = float64(s.Success) / float64(s.Total)
	}
	avg := s.AvgMS
	if avg <= 0 {
		avg = 0
	}

	var denom float64
	switch f {
	case config.FormulaSpeed:
		denom = avg
	case config.FormulaStable:
		// 1000 * sr² / avg * 1/(1 + stddev/avg) folds into the single
		// denominator avg + stddev. It must be written as that sum rather than
		// as the algebraically equal avg*(1+stddev/avg): with avg == 0 the
		// ratio is +Inf (or NaN when stddev is also 0), the product stays
		// non-finite, and "NaN < minDenominator" is false — so the guard below
		// would not fire and the formula would return NaN. A NaN score then
		// corrupts the whole ordering, because cmp.Compare does not order NaN.
		sr *= sr
		denom = avg + s.StdDevMS
	case config.FormulaComprehensive:
		denom = 0.5*avg + 0.5*s.P95MS
	case config.FormulaJitter:
		denom = avg + 2*s.StdDevMS
	default:
		// Unknown formulas fall back to the default so a hand-edited result
		// file can never produce a NaN ranking.
		denom = 0.5*avg + 0.5*s.P95MS
	}

	if denom < minDenominator {
		denom = minDenominator
	}
	return 1000 * sr / denom
}

// Ranked is one row of a ranking: the aggregate plus its computed score and
// 1-based position.
type Ranked struct {
	model.Summary
	Score float64 `json:"score"`
	Rank  int     `json:"rank"`
}

// Filter selects the rows of one domain group and, optionally, one protocol.
// An empty protocol or group means "no restriction on that dimension".
type Filter struct {
	Group    string
	Protocol model.Protocol
}

// Rank filters the summaries, scores them under the formula and returns them
// sorted by descending score. Rows with identical scores keep a stable order
// (by average latency, then by address) so the table does not jitter between
// refreshes.
func Rank(summaries []model.Summary, f config.Formula, filter Filter) []Ranked {
	out := make([]Ranked, 0, len(summaries))
	for _, s := range summaries {
		if filter.Group != "" && s.Group != filter.Group {
			continue
		}
		if filter.Protocol != "" && s.Protocol != filter.Protocol {
			continue
		}
		out = append(out, Ranked{Summary: s, Score: Score(s, f)})
	}

	slices.SortStableFunc(out, func(a, b Ranked) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c
		}
		if c := cmp.Compare(a.AvgMS, b.AvgMS); c != 0 {
			return c
		}
		if c := cmp.Compare(a.SuccessRate, b.SuccessRate); c != 0 {
			return -c
		}
		return strings.Compare(a.DNS, b.DNS)
	})

	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

// GroupKeys returns the distinct domain groups present in the summaries. The
// canonical groups come first (cn, then intl, then the pooled mixed group),
// followed by any other group in first-seen order.
//
// Mixed is placed after the two split groups rather than before them because a
// run can only ever produce one of the two arrangements — mixed *or* cn+intl —
// so the order only has to be stable, and putting the split pair first keeps
// the more informative arrangement leading when a file somehow holds both.
func GroupKeys(summaries []model.Summary) []string {
	seen := make(map[string]struct{}, len(summaries))
	var extra []string
	for _, s := range summaries {
		if _, ok := seen[s.Group]; ok {
			continue
		}
		seen[s.Group] = struct{}{}
		switch s.Group {
		case model.GroupCN, model.GroupIntl, model.GroupMixed:
			// handled below
		default:
			extra = append(extra, s.Group)
		}
	}

	var out []string
	for _, g := range []string{model.GroupCN, model.GroupIntl, model.GroupMixed} {
		if _, ok := seen[g]; ok {
			out = append(out, g)
		}
	}
	return append(out, extra...)
}

// ProtocolKeys returns the distinct protocols present in the summaries, in the
// canonical protocol order.
func ProtocolKeys(summaries []model.Summary) []model.Protocol {
	seen := make(map[model.Protocol]struct{}, len(summaries))
	for _, s := range summaries {
		seen[s.Protocol] = struct{}{}
	}
	var out []model.Protocol
	for _, p := range model.AllProtocols {
		if _, ok := seen[p]; ok {
			out = append(out, p)
		}
	}
	return out
}

// Best returns the highest scoring row of a filtered ranking, or false when
// the filter matches nothing.
func Best(summaries []model.Summary, f config.Formula, filter Filter) (Ranked, bool) {
	ranked := Rank(summaries, f, filter)
	if len(ranked) == 0 {
		return Ranked{}, false
	}
	return ranked[0], true
}

// RoundScore rounds a score for display.
func RoundScore(v float64) float64 { return math.Round(v*100) / 100 }
