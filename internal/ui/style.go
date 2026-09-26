// Package ui renders the two command-line presentations of a run: the live
// progress panel (bubbletea + lipgloss, modelled on dnspick) and the final
// ranked report. It contains no benchmarking logic.
package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/scorer"
)

// Palette and shared styles.
var (
	colorAccent  = lipgloss.Color("39")  // blue
	colorGood    = lipgloss.Color("42")  // green
	colorWarn    = lipgloss.Color("214") // orange
	colorBad     = lipgloss.Color("203") // red
	colorMuted   = lipgloss.Color("244")
	colorHeading = lipgloss.Color("213")

	styleTitle   = lipgloss.NewStyle().Bold(true).Foreground(colorHeading)
	styleHeading = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleMuted   = lipgloss.NewStyle().Foreground(colorMuted)
	styleGood    = lipgloss.NewStyle().Foreground(colorGood)
	styleWarn    = lipgloss.NewStyle().Foreground(colorWarn)
	styleBad     = lipgloss.NewStyle().Foreground(colorBad)
	styleBold    = lipgloss.NewStyle().Bold(true)
)

// Exported styles and colour helpers, so the interactive menu (internal/tui)
// can render with the exact same look as the one-shot CLI output.
var (
	// Title styles a screen title.
	Title = styleTitle
	// Heading styles a section heading.
	Heading = styleHeading
	// Bold styles emphasised text.
	Bold = styleBold
	// Normal is the default, unstyled text.
	Normal = lipgloss.NewStyle()

	// Muted renders secondary text.
	Muted = styleMuted.Render
	// Good renders a success message.
	Good = styleGood.Render
	// Warn renders a warning.
	Warn = styleWarn.Render
	// Bad renders an error.
	Bad = styleBad.Render
	// Accent renders a highlighted fragment (cursor, selection).
	Accent = lipgloss.NewStyle().Foreground(colorAccent).Render
)

// ColorAccent exposes the accent colour for composed styles.
var ColorAccent = colorAccent

// barWidth is the width of a progress bar in characters.
const barWidth = 22

// The progress bar glyphs. Both are three bytes long in UTF-8, which is why the
// bar must never be split by byte offset: doing so cuts a glyph in half and the
// terminal renders the remaining bytes as U+FFFD ("�").
const (
	barFull  = "█"
	barEmpty = "░"
)

// ProgressBar renders a progress bar for the fraction done (0..1). It is the
// exported form of renderBar, used by the interactive type-detection screen so
// both progress displays are drawn by the same code.
func ProgressBar(fraction float64, width int) string { return renderBar(fraction, width) }

// renderBar draws a progress bar for the fraction done (0..1).
//
// The filled and empty halves are always built as separate strings. Slicing one
// combined string at a byte index equal to the number of filled cells would be
// wrong, because each cell occupies three bytes.
func renderBar(fraction float64, width int) string {
	if width <= 0 {
		width = barWidth
	}
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	filled := int(fraction*float64(width) + 0.5)
	if filled > width {
		filled = width
	}

	switch {
	case filled >= width:
		return styleGood.Render(strings.Repeat(barFull, width))
	case filled <= 0:
		return styleMuted.Render(strings.Repeat(barEmpty, width))
	default:
		return styleAccentBar(filled, width)
	}
}

// styleAccentBar renders a part-filled bar: the completed part in the accent
// colour, the remainder muted.
func styleAccentBar(filled, width int) string {
	if filled >= width {
		return styleGood.Render(strings.Repeat(barFull, width))
	}
	return lipgloss.NewStyle().Foreground(colorAccent).Render(strings.Repeat(barFull, filled)) +
		styleMuted.Render(strings.Repeat(barEmpty, width-filled))
}

// pct renders a fraction as a fixed-width percentage.
func pct(fraction float64) string {
	return fmt.Sprintf("%5.1f%%", fraction*100)
}

// successStyle picks the colour for a success rate.
func successStyle(rate float64) lipgloss.Style {
	switch {
	case rate >= 0.99:
		return styleGood
	case rate >= 0.9:
		return styleWarn
	default:
		return styleBad
	}
}

// ms renders a millisecond value.
func ms(v float64) string {
	switch {
	case v <= 0:
		return "-"
	case v < 10:
		return fmt.Sprintf("%.1fms", v)
	default:
		return fmt.Sprintf("%.0fms", v)
	}
}

// elapsed renders a duration as mm:ss.
func elapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d", total/60, total%60)
}

// ConfigureHint renders a row the way a user would have to enter it into their
// system settings: the IP plus the protocol, and — for an encrypted transport —
// the endpoint URL as well.
//
// The URL is kept only where it is genuinely needed. A plain resolver is
// configured by IP alone, so repeating "udp://223.5.5.5:53" would be noise; a
// DoH endpoint cannot be configured from an IP at all, because the certificate
// is issued to the name. Printing just the IP there would give the user
// something they cannot type in.
func ConfigureHint(s model.Summary) string {
	id := ServerIdentity(s)
	switch s.Protocol {
	case model.ProtocolDoH, model.ProtocolDoH3, model.ProtocolDoT:
		return fmt.Sprintf("%s (%s %s)", id, s.Protocol.Label(), displayAddress(s))
	default:
		return fmt.Sprintf("%s (%s)", id, s.Protocol.Label())
	}
}

// serverLabel renders a server for a single-line status message. The identity
// is the address, because that is what the user configures and recognises.
func serverLabel(s model.Server) string {
	return fmt.Sprintf("%s (%s)", s.DisplayIP(), s.Protocol.Label())
}

// ServerIdentity is the primary identity of a summary row: its IP literal.
//
// The whole tool identifies a resolver by address rather than by a vendor name,
// for two reasons. An address is unambiguous — "AliDNS" covers eight endpoints
// across two families and four transports — and it is the thing a user actually
// types into their network settings, so a row can be copied straight out of the
// report. The vendor name still travels in the exported meta block, where it is
// useful provenance, but it is no longer the label a reader has to translate.
//
// When an endpoint could not be resolved the configured address is returned, so
// a row is never left without an identity.
func ServerIdentity(s model.Summary) string {
	if ip := s.DisplayIP(); ip != "" {
		return ip
	}
	return s.DNS
}

// stateTags renders the bracketed markers that qualify an identity, so a caller
// can append them without duplicating the wording.
func stateTags(s model.Summary) string {
	var b strings.Builder
	if s.IsSystem {
		b.WriteString(styleHeading.Render(" [当前系统]"))
		if s.IsPrivate {
			b.WriteString(styleWarn.Render(" [内网地址]"))
		}
	} else if s.IsPrivate {
		b.WriteString(styleWarn.Render(" [内网地址]"))
	}
	return b.String()
}

// displayAddress renders a row's configured endpoint with the protocol scheme.
// It is the *dial target* rather than the identity, so it is used where the
// exact endpoint matters (a DoH URL, a tls:// host); the ranking tables show
// ServerIdentity instead.
func displayAddress(s model.Summary) string {
	addr := s.DNS
	switch s.Protocol {
	case model.ProtocolDoT:
		addr = "tls://" + addr
	case model.ProtocolDoH, model.ProtocolDoH3:
		if !strings.HasPrefix(addr, "http") {
			addr = "https://" + addr
		}
	}
	return addr
}

// formulaNotice is shown whenever a ranking is printed, so the numbers are
// never mistaken for an absolute ordering.
const formulaNotice = "提示：同一 DNS 在不同评分公式下的排名可能不同，切换公式即可对比。"

// riskNotice reminds the user about the two environmental factors the tool
// deliberately does not detect (see PLAN 六 / 十三).
const riskNotice = "提示：请先关闭系统代理与加速器，否则加密协议（DoT/DoH/DoH3）的延迟会被代理与本地缓存干扰。"

// RankedTable renders the ranking of one domain group as an aligned table.
//
// The identity column is the server's IP, not its vendor name: an address is
// what the user configures and what stays unique across the eight endpoints one
// vendor may publish. The filtering policy is its own column rather than part
// of the name, so rows can be compared down a column.
func RankedTable(rows []scorer.Ranked) string {
	if len(rows) == 0 {
		return styleMuted.Render("（无数据）")
	}

	headers := []string{"#", "DNS 服务器 (IP)", "协议", "策略", "成功率", "平均", "P95", "标准差", "得分"}
	table := make([][]string, 0, len(rows)+1)
	table = append(table, headers)

	for _, r := range rows {
		rate := r.SuccessRate
		rateCell := successStyle(rate).Render(pct(rate))
		if r.Success < r.Total {
			rateCell = successStyle(rate).Render(fmt.Sprintf("%s (%d/%d)", pct(rate), r.Success, r.Total))
		}

		name := ServerIdentity(r.Summary) + stateTags(r.Summary)

		table = append(table, []string{
			fmt.Sprintf("%d", r.Rank),
			name,
			r.Protocol.Label(),
			policyStyle(r.Policy).Render(policy.Label(r.Policy)),
			rateCell,
			ms(r.AvgMS),
			ms(r.P95MS),
			ms(r.StdDevMS),
			styleBold.Render(fmt.Sprintf("%.2f", r.Score)),
		})
	}

	return renderTable(table)
}

// policyStyle colours a filtering policy: an unfiltered resolver is neutral, a
// filtering one is flagged. The colour is a hint, not a verdict on quality —
// whether filtering is desirable depends entirely on what the user wants.
func policyStyle(k policy.Kind) lipgloss.Style {
	switch policy.CanonicalKind(k) {
	case policy.Security:
		return styleHeading
	case policy.Native:
		return styleMuted
	}
	return styleMuted
}

// renderTable lays out a table with two leading spaces and single-space
// padding. Cell 1 (the server identity) is left-aligned; the rest are
// right-aligned except the protocol and policy columns.
func renderTable(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	cols := len(rows[0])
	widths := make([]int, cols)
	for _, row := range rows {
		for i, cell := range row {
			if w := lipgloss.Width(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}

	// The numeric columns are right-aligned so magnitudes line up: columns 4
	// (成功率) through 8 (得分) in RankedTable.
	alignRight := map[int]bool{4: true, 5: true, 6: true, 7: true, 8: true}

	var b strings.Builder
	for r, row := range rows {
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			if i > 0 {
				b.WriteString("  ")
			}
			pad := widths[i] - lipgloss.Width(cell)
			if alignRight[i] {
				b.WriteString(strings.Repeat(" ", pad))
				b.WriteString(cell)
			} else {
				b.WriteString(cell)
				b.WriteString(strings.Repeat(" ", pad))
			}
		}
		line := strings.TrimRight(b.String(), " ")
		b.Reset()
		b.WriteString(line)
		if r == 0 {
			b.WriteString("\n")
			b.WriteString(styleMuted.Render(strings.Repeat("─", sum(widths)+2*(cols-1))))
		}
		if r != len(rows)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// sum adds up the column widths.
func sum(values []int) int {
	total := 0
	for _, v := range values {
		total += v
	}
	return total
}
