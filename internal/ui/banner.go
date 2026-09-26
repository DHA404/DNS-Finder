package ui

import (
	"fmt"
	"strings"

	"dns-opti/internal/config"
	"dns-opti/internal/model"
)

// RunBanner is the one-line summary printed before a run starts.
func RunBanner(version string, servers, domains int, cfg config.Options) string {
	return fmt.Sprintf("%s  待测服务器 %d 个 · 测试域名 %d 个 · 每域名 %d 次 · 并发 %d",
		styleTitle.Render(version), servers, domains, cfg.Attempts, cfg.EffectiveConcurrency())
}

// WarningLine renders a non-fatal remark.
func WarningLine(msg string) string { return styleWarn.Render("⚠ " + msg) }

// ErrorLine renders an error message.
func ErrorLine(msg string) string { return styleBad.Render("✖ " + msg) }

// ProtocolSummary renders a protocol slice, e.g. "UDP, DoT, DoH".
func ProtocolSummary(protocols []model.Protocol) string {
	parts := make([]string, 0, len(protocols))
	for _, p := range protocols {
		parts = append(parts, p.Label())
	}
	return strings.Join(parts, ", ")
}
