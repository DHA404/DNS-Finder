package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"dns-opti/internal/config"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/scorer"
)

// ReportOptions controls how a report is rendered.
type ReportOptions struct {
	// Formula selects the ranking formula.
	Formula config.Formula
	// AlreadyShown lists warnings the caller has already displayed to the user,
	// which the report then omits.
	//
	// The one-shot CLI prints the plan warnings before the run, because they
	// explain what is about to happen — and for a run that takes minutes, that
	// is the moment they are useful. Repeating the identical sentences at the
	// end adds nothing. The interactive menu, by contrast, shows them as a
	// transient notice and the report is also what gets saved to a file, so
	// there the report must stay self-contained and AlreadyShown is left empty.
	AlreadyShown []string
}

// PrintResult renders the complete CLI report of a finished run: the per-group
// rankings, the recommendation for the current system DNS, and where the
// result file went.
func PrintResult(w io.Writer, res *engine.Result, formula config.Formula) {
	PrintReport(w, res, ReportOptions{Formula: formula})
}

// PrintReport is PrintResult with explicit rendering options.
func PrintReport(w io.Writer, res *engine.Result, opts ReportOptions) {
	formula := opts.Formula
	info, ok := scorer.FormulaByID(formula)
	if !ok {
		info = scorer.Formulas[0]
	}
	skip := make(map[string]struct{}, len(opts.AlreadyShown))
	for _, s := range opts.AlreadyShown {
		skip[s] = struct{}{}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, styleTitle.Render("测试完成"))
	fmt.Fprintln(w, styleMuted.Render(strings.Repeat("─", 78)))
	fmt.Fprintf(w, " 查询总数 %d   成功率 %s   用时 %s\n",
		res.Total,
		successStyle(rate(res.Total-res.Failed, res.Total)).Render(pct(rate(res.Total-res.Failed, res.Total))),
		elapsed(res.Duration),
	)
	fmt.Fprintf(w, " 并发数 %d   预热域名 %s   参考公式 %s\n",
		res.Meta.Concurrency, res.Meta.WarmupDomain, styleBold.Render(info.Name))
	printNetworkVerdict(w, res)
	for _, warn := range res.Warned {
		if _, dup := skip[warn]; dup {
			continue
		}
		fmt.Fprintln(w, styleWarn.Render(" ⚠ "+warn))
	}

	groups := scorer.GroupKeys(res.Summaries)
	for _, group := range groups {
		ranked := scorer.Rank(res.Summaries, formula, scorer.Filter{Group: group})
		if len(ranked) == 0 {
			continue
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s  %s\n", styleTitle.Render(model.GroupLabel(group)),
			styleMuted.Render(fmt.Sprintf("（%d 条记录）", len(ranked))))
		fmt.Fprintf(w, "%s\n", styleMuted.Render(" 公式: "+info.Expr))
		fmt.Fprintln(w, RankedTable(ranked))
		printGroupAdvice(w, ranked, group)
	}

	fmt.Fprintln(w)
	printTransportComparison(w, res.Comparisons)
	fmt.Fprintln(w, styleMuted.Render(formulaNotice))
	fmt.Fprintln(w, styleMuted.Render(riskNotice))
	if res.Path != "" {
		fmt.Fprintf(w, "\n 结果已导出: %s\n", styleBold.Render(res.Path))
	}
}

// ResultView renders the CLI report into a string instead of a writer. The
// interactive menu needs the report as a scrollable block of lines.
func ResultView(res *engine.Result, formula config.Formula) string {
	var b strings.Builder
	PrintResult(&b, res, formula)
	return b.String()
}

// printNetworkVerdict states which address families the run found usable, and
// how many servers that excluded.
//
// It is a one-line factual summary rather than a warning: by the time the
// report is printed the run is over, so "consider --ip-version=ipv6" is no
// longer actionable — but a reader still needs to know why IPv6 servers are
// missing from the ranking.
func printNetworkVerdict(w io.Writer, res *engine.Result) {
	n := res.Meta.Network
	if n == nil {
		return
	}

	mark := func(ok bool) string {
		if ok {
			return styleGood.Render("可用")
		}
		return styleWarn.Render("不可用")
	}

	line := fmt.Sprintf(" 地址族实测: IPv4 %s · IPv6 %s", mark(n.IPv4), mark(n.IPv6))
	if n.Skipped > 0 {
		if n.Forced {
			line += fmt.Sprintf("   已按 --ip-version 排除 %d 个服务器", n.Skipped)
		} else {
			line += fmt.Sprintf("   已排除 %d 个不可用地址族的服务器", n.Skipped)
		}
	}
	fmt.Fprintln(w, line)
}

// printGroupAdvice prints the top picks of a group plus, when the current
// system DNS took part in the run, whether switching away from it is worth it.
func printGroupAdvice(w io.Writer, ranked []scorer.Ranked, group string) {
	if len(ranked) == 0 {
		return
	}

	top := ranked
	if len(top) > maxPicks {
		top = top[:maxPicks]
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, " 推荐 %s:\n", model.GroupLabel(group))
	for i, r := range top {
		fmt.Fprintf(w, "   %s %s\n", styleGood.Render(fmt.Sprintf("#%d", i+1)),
			fmt.Sprintf("%s (%s · %s) 得分 %.2f · 平均 %s · 成功率 %s",
				ServerIdentity(r.Summary), r.Protocol.Label(), policy.Label(r.Policy),
				r.Score, ms(r.AvgMS), pct(r.SuccessRate)))
	}

	// The system DNS verdict is printed whenever it took part in the run, even
	// if it did not make the top picks — that is exactly the case the user
	// needs to know about.
	if sys, ok := findSystem(ranked); ok {
		fmt.Fprintln(w)
		fmt.Fprintln(w, systemAdvice(sys, ranked[0]))
	}
}

// maxPicks caps how many servers are listed per group in the CLI report.
const maxPicks = 3

// findSystem locates the system DNS row in a ranking.
func findSystem(ranked []scorer.Ranked) (scorer.Ranked, bool) {
	for _, r := range ranked {
		if r.IsSystem {
			return r, true
		}
	}
	return scorer.Ranked{}, false
}

// systemAdvice compares the system DNS against the best server of the group.
//
// A switch is only suggested when the gap is meaningful: a few milliseconds on
// a single measurement is not a reason to reconfigure a machine. Private and
// loopback resolvers (routers, corporate or VPN DNS) are additionally flagged,
// because replacing them usually breaks internal name resolution (PLAN 九).
func systemAdvice(sys, best scorer.Ranked) string {
	const (
		latencyTolerance = 15.0 // ms
		rateTolerance    = 0.05
	)

	var b strings.Builder
	fmt.Fprintf(&b, " 当前系统 DNS: %s（第 %d 名，成功率 %s，平均 %s）",
		displayAddress(sys.Summary), sys.Rank, pct(sys.SuccessRate), ms(sys.AvgMS))

	if sys.IsPrivate {
		b.WriteString("\n")
		b.WriteString(styleWarn.Render(" ⚠ 该地址属于内网 / 环回 / 链路本地保留网段，通常用于路由器、公司或 VPN 内部解析。"))
		b.WriteString("\n")
		b.WriteString(styleWarn.Render("   换成公共 DNS 可能导致内部域名（如 .local、公司内网域名）无法解析，请谨慎。"))
	}

	// latencyGap is how much slower the system DNS is than the best server; it
	// is negative when the system DNS is actually the faster one.
	latencyGap := sys.AvgMS - best.AvgMS
	rateGap := best.SuccessRate - sys.SuccessRate

	switch {
	case sys.Success == 0:
		fmt.Fprintf(&b, "\n → 系统 DNS 全部查询失败，建议切换到 %s。", ConfigureHint(best.Summary))
	case sys.Rank == 1:
		b.WriteString("\n → 系统 DNS 已是本组最优，无需更换。")
	case latencyGap < latencyTolerance && rateGap <= rateTolerance:
		b.WriteString("\n → 与最优相比差距在误差范围内，保留当前设置即可。")
	default:
		fmt.Fprintf(&b, "\n → 建议切换到 %s", ConfigureHint(best.Summary))
		if latencyGap > 0 {
			fmt.Fprintf(&b, "，平均延迟可降低约 %s", ms(latencyGap))
		}
		if rateGap > 0 {
			fmt.Fprintf(&b, "，成功率可提升约 %s", pct(rateGap))
		}
		b.WriteString("。")
	}
	return b.String()
}

// WriteJSONReport prints the machine-readable variant of the report, used by
// --json. It is stable for scripted consumers: the ranking arrays are always
// present and the formulas are always described in full.
func WriteJSONReport(w io.Writer, res *engine.Result, formula config.Formula) error {
	type groupReport struct {
		Group    string          `json:"group"`
		Label    string          `json:"label"`
		Rankings []scorer.Ranked `json:"rankings"`
	}

	groups := scorer.GroupKeys(res.Summaries)
	reports := make([]groupReport, 0, len(groups))
	for _, group := range groups {
		reports = append(reports, groupReport{
			Group:    group,
			Label:    model.GroupLabel(group),
			Rankings: scorer.Rank(res.Summaries, formula, scorer.Filter{Group: group}),
		})
	}

	doc := struct {
		Meta      model.Meta           `json:"meta"`
		Formula   scorer.FormulaInfo   `json:"formula"`
		Formulas  []scorer.FormulaInfo `json:"formulas"`
		Output    string               `json:"output"`
		Total     int                  `json:"total"`
		Failed    int                  `json:"failed"`
		DurationS float64              `json:"duration_seconds"`
		Warnings  []string             `json:"warnings,omitempty"`
		Groups    []groupReport        `json:"groups"`
	}{
		Meta:      res.Meta,
		Formula:   mustFormula(formula),
		Formulas:  scorer.Formulas,
		Output:    res.Path,
		Total:     res.Total,
		Failed:    res.Failed,
		DurationS: res.Duration.Seconds(),
		Warnings:  res.Warned,
		Groups:    reports,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// mustFormula resolves a formula, falling back to the default.
func mustFormula(f config.Formula) scorer.FormulaInfo {
	if info, ok := scorer.FormulaByID(f); ok {
		return info
	}
	return scorer.Formulas[0]
}
