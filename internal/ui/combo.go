package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"dns-opti/internal/engine"
	"dns-opti/internal/region"
)

// printTransportComparison renders the UDP-vs-DoH section of a combined run.
//
// The two transports are shown side by side rather than folded into one score,
// because they measure different things: a UDP query is one round trip, while a
// DoH query pays for a TLS and HTTP exchange on top. Collapsing them would hide
// exactly the difference this mode exists to expose — usually that DoH costs a
// few milliseconds more but is not usable on a network that blocks UDP.
func printTransportComparison(w io.Writer, comparisons []engine.TransportComparison) {
	if len(comparisons) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, styleTitle.Render("UDP 与 DoH 对比"))
	fmt.Fprintln(w, styleMuted.Render(strings.Repeat("─", 78)))
	fmt.Fprintln(w, styleMuted.Render(" 同一服务商的两种传输并排比较；两部分分别统计，不合并成一个分数。"))

	headers := []string{"服务商", "地区", "UDP 成功率", "UDP 平均", "DoH 成功率", "DoH 平均", "DoH − UDP"}
	table := make([][]string, 0, len(comparisons)+1)
	table = append(table, headers)

	comparable := 0
	var totalDelta float64
	for _, c := range comparisons {
		regionText := c.Region
		if label := regionLabel(c.Region); label != "" {
			regionText = label
		}

		// Mark an aggregated side, so a row that folds two resolvers together
		// is never read as a single server.
		name := c.Name
		if n := maxEndpoints(c.UDP, c.DoH); n > 1 {
			name = fmt.Sprintf("%s (%d 个端点)", name, n)
		}

		udpRate, udpAvg := sideCells(c.UDP)
		dohRate, dohAvg := sideCells(c.DoH)

		delta := styleMuted.Render("—")
		if c.Comparable {
			comparable++
			totalDelta += c.AvgDeltaMS
			delta = deltaStyle(c.AvgDeltaMS).Render(signed(c.AvgDeltaMS))
		}

		table = append(table, []string{
			name, regionText, udpRate, udpAvg, dohRate, dohAvg, delta,
		})
	}
	fmt.Fprintln(w, renderTable(table))

	fmt.Fprintln(w)
	if comparable == 0 {
		fmt.Fprintln(w, styleWarn.Render(" ⚠ 没有任何服务商的两种传输都成功，无法给出对比结论。"))
		fmt.Fprintln(w, styleMuted.Render("   常见原因：本机到 DoH 端点的 443 端口被阻断，或测试超时过短。"))
		return
	}
	fmt.Fprintf(w, " 可对比 %d 组；DoH 平均比 UDP %s（平均差 %s）。\n",
		comparable, describeDelta(totalDelta/float64(comparable)), signed(totalDelta/float64(comparable)))

	// A short, actionable verdict: users pick a transport, not a table row.
	fmt.Fprintln(w)
	slower, faster := 0, 0
	for _, c := range comparisons {
		if !c.Comparable {
			continue
		}
		if c.AvgDeltaMS > 0 {
			slower++
		} else {
			faster++
		}
	}
	// With a single comparable pair, "普遍" (generally) would overstate the
	// evidence: one provider is an anecdote, not a trend.
	if comparable == 1 {
		fmt.Fprintln(w, styleMuted.Render(" 结论：只有一组可对比数据，仅供参考——多测几个地区或服务商再下结论。"))
		return
	}
	switch {
	case slower > 0 && faster == 0:
		fmt.Fprintln(w, styleMuted.Render(" 结论：DoH 在本机普遍比 UDP 慢（需额外握手），但对延迟不敏感的场景更安全。"))
	case faster > 0 && slower == 0:
		fmt.Fprintln(w, styleMuted.Render(" 结论：DoH 在本机反而更快，通常说明 UDP 路径被限速或干扰。"))
	default:
		fmt.Fprintln(w, styleMuted.Render(" 结论：DoH 与 UDP 互有胜负，建议对延迟敏感的服务保持 UDP，其余可用 DoH。"))
	}
}

// regionLabel renders a region code for display, falling back to the code.
func regionLabel(code string) string {
	if code == "" {
		return ""
	}
	return region.Label(code)
}

// maxEndpoints returns the largest endpoint count among the given sides.
func maxEndpoints(sides ...*engine.TransportSide) int {
	best := 0
	for _, s := range sides {
		if s != nil && s.Endpoints > best {
			best = s.Endpoints
		}
	}
	return best
}

// sideCells renders the two rate/latency cells of one transport side.
func sideCells(side *engine.TransportSide) (rate, avg string) {
	if side == nil || side.Total == 0 {
		return styleMuted.Render("—"), styleMuted.Render("—")
	}
	rateText := successStyle(side.SuccessRate).Render(pct(side.SuccessRate))
	if side.Success == 0 {
		return rateText, styleMuted.Render("—")
	}
	return rateText, ms(side.AvgMS)
}

// signed renders a millisecond delta with an explicit sign.
func signed(v float64) string {
	if v > 0 {
		return fmt.Sprintf("+%s", ms(v))
	}
	if v < 0 {
		return "-" + ms(-v)
	}
	return ms(0)
}

// describeDelta words a latency delta so the direction is unmistakable.
func describeDelta(v float64) string {
	switch {
	case v > 1:
		return "慢 " + ms(v)
	case v < -1:
		return "快 " + ms(-v)
	default:
		return "基本持平"
	}
}

// deltaStyle colours a delta by whether the encrypted transport costs much.
func deltaStyle(v float64) lipgloss.Style {
	switch {
	case v > 15:
		return styleWarn
	case v < -1:
		return styleGood
	default:
		return styleMuted
	}
}
