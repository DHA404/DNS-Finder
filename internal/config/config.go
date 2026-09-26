// Package config defines the options shared by the CLI commands and provides
// the parsing helpers for the flag values that accept compound syntax.
package config

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"dns-opti/internal/domainlist"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/region"
)

// Defaults for the run options.
const (
	DefaultAttempts     = 3
	DefaultTimeout      = 2 * time.Second
	DefaultWarmupDomain = "example.com"
	DefaultFormula      = "comprehensive"
	// DefaultConcurrencyMultiplier is how many servers are tested at once per
	// CPU thread when --concurrency is not given.
	//
	// One worker per server, and each server is queried by at most
	// DefaultPerServerConcurrency connections, so a query's latency is a round
	// trip rather than a queueing delay. Three per thread keeps enough servers
	// in flight to hide the network wait without making the workers contend for
	// the CPU while they parse responses.
	DefaultConcurrencyMultiplier = 3
	// DefaultPerServerConcurrency is how many connections one server is tested
	// with: its domain list is split across that many workers, each owning its
	// own Querier, so the queries of one server overlap instead of running
	// strictly one after another.
	//
	// Two is the value that measurement supports: interleaved runs of 19
	// servers showed no success-rate or latency difference against a fully
	// serial run (the spread was the same as repeating the serial run), while
	// halving the time a single slow server contributes to the wall clock.
	// Raising it is not free — past roughly 8 concurrent queries per server the
	// local socket/NAT budget starts dropping replies and the measured success
	// rate falls with it — so it stays at 2.
	DefaultPerServerConcurrency = 2
	// DefaultConcurrency is the sentinel meaning "resolve automatically"; it is
	// the flag default and is turned into a real count by
	// EffectiveConcurrency.
	DefaultConcurrency = 0
)

// AutoConcurrency returns the worker count used when none was configured:
// DefaultConcurrencyMultiplier per CPU thread, never less than one.
func AutoConcurrency() int {
	n := runtime.NumCPU() * DefaultConcurrencyMultiplier
	if n < 1 {
		return 1
	}
	return n
}

// ServerCategory is one origin filter for the built-in server list.
type ServerCategory = string

// Options is the fully resolved configuration of a "test" run, and the subset
// used by the "web" command.
type Options struct {
	// Domains is a group keyword (cn|intl|all) or an explicit domain list.
	Domains string
	// Protocols to test, in priority order.
	Protocols []model.Protocol
	// Combo is set when the protocol selection was a combined mode such as
	// "udp+doh". Protocols then holds the transports that combo implies, and
	// Combo additionally marks the two transports of one provider as a
	// pair so the report can compare them side by side.
	Combo string
	// ServerCategories limits the built-in server list to 国内 / 国外 entries.
	ServerCategories []ServerCategory
	// Regions limits the built-in server list to the given region codes (ISO
	// 3166-1 alpha-2, or CDN / PRIVATE / UNKNOWN). Empty means no filter.
	Regions []string
	// Policies limits the built-in server list to the given filtering
	// behaviours (原生 / 安全). Empty means no filter.
	Policies []policy.Kind
	// IPVersion restricts testing to one address family.
	IPVersion model.IPVersion
	// Servers is an explicit comma-separated server list, used instead of the
	// built-in inventory when non-empty.
	Servers string
	// Output is the path of the exported result JSON.
	Output string
	// Web starts the local web UI once the run finishes.
	Web bool
	// NoWeb explicitly forbids the web UI (takes precedence over Web).
	NoWeb bool
	// Timeout bounds a single query.
	Timeout time.Duration
	// Attempts is how many times each domain is queried on each server.
	Attempts int
	// SystemDNS adds the machine's configured resolvers to the comparison.
	SystemDNS bool
	// Concurrency is the number of DNS servers tested at the same time.
	Concurrency int
	// WarmupDomain is queried once per server before measurement starts.
	WarmupDomain string
	// Formula selects the ranking formula used for the CLI table.
	Formula string
	// JSON prints machine-readable output to stdout instead of the TUI.
	JSON bool

	// --- web command (populated when the web UI is started) ---
	// Port is the loopback port; 0 selects a free port.
	Port int
	// NoOpenBrowser suppresses opening the browser automatically.
	NoOpenBrowser bool
}

// IsCombo reports whether the protocol selection names a combined mode (such as
// "udp+doh") rather than a plain protocol list.
func (o Options) IsCombo() bool { return o.Combo != "" }

// ComboName returns the combined-mode selector, if any.
func (o Options) ComboName() string { return o.Combo }

// ComboLabel renders the combined mode for display, falling back to the
// ordinary protocol list when the run is not a combined one.
func (o Options) ComboLabel() string {
	if o.Combo == "" {
		return ""
	}
	if o.Combo == model.ComboUDPDoH {
		return model.ComboUDPDoHLabel
	}
	return o.Combo
}

// EffectiveConcurrency resolves the concurrency, defaulting to
// DefaultConcurrencyMultiplier workers per CPU thread.
func (o Options) EffectiveConcurrency() int {
	if o.Concurrency > 0 {
		return o.Concurrency
	}
	return AutoConcurrency()
}

// ShouldOpenWeb reports whether the web UI should be started after the run.
func (o Options) ShouldOpenWeb() bool { return o.Web && !o.NoWeb }

// Validate checks the option set for contradictions and out-of-range values.
func (o Options) Validate() error {
	if o.Timeout <= 0 {
		return fmt.Errorf("超时时间必须大于 0")
	}
	if o.Attempts < 1 {
		return fmt.Errorf("尝试次数至少为 1")
	}
	if o.Concurrency < 0 {
		return fmt.Errorf("并发数不能为负数")
	}
	if len(o.Protocols) == 0 {
		return fmt.Errorf("至少选择一种协议")
	}
	// A protocol that this build cannot speak is a configuration error, not a
	// run that happens to fail: reporting it up front stops a nodoh3 binary
	// from producing a table of 0% rows that looks like the servers' fault.
	if reason := model.UnsupportedProtocols(o.Protocols); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	if o.IPVersion != "" && !o.IPVersion.IsLiteral() {
		return fmt.Errorf("未知地址族 %q（可选: ipv4, ipv6, both）", o.IPVersion)
	}
	if _, err := ParseFormula(o.Formula); err != nil {
		return err
	}
	if _, err := domainlist.Select(o.Domains); err != nil {
		return err
	}
	return nil
}

// IsUDPDoHCombo reports whether this run pairs UDP with DoH.
func (o Options) IsUDPDoHCombo() bool { return o.Combo == model.ComboUDPDoH }

// ParseProtocolSelection parses the protocol flag, accepting both an ordinary
// comma-separated protocol list and the combined modes ("udp+doh").
//
// The combined mode is a selector rather than a transport: it expands to the
// two protocols it names *and* sets Combo, which is what turns on the
// side-by-side comparison of one provider's two transports.
func ParseProtocolSelection(raw string) (protocols []model.Protocol, combo string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return append([]model.Protocol(nil), model.AllProtocols...), "", nil
	}

	// A combined mode is recognised as a whole value, so it cannot be confused
	// with a protocol list that happens to contain "udp" and "doh" separately.
	if expanded, ok := model.ComboProtocols(trimmed); ok {
		return expanded, model.ComboUDPDoH, nil
	}

	// Reject a combo name that is written with different spacing or ordering
	// but is not a known mode, so a typo does not silently become a plain list.
	if looksLikeCombo(trimmed) {
		return nil, "", fmt.Errorf("未知组合模式 %q（可选: %s）", trimmed, model.ComboUDPDoH)
	}

	protocols, err = ParseProtocols(trimmed)
	return protocols, "", err
}

// looksLikeCombo reports whether a selector is clearly meant to be a combined
// mode: it contains a '+' or an '&', which no protocol name does.
func looksLikeCombo(raw string) bool {
	return strings.ContainsAny(raw, "+&")
}

// ParseProtocols parses a comma-separated protocol list such as
// "udp,dot,doh", preserving the given order and rejecting unknown names.
func ParseProtocols(raw string) ([]model.Protocol, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return append([]model.Protocol(nil), model.AllProtocols...), nil
	}
	seen := make(map[model.Protocol]struct{})
	var out []model.Protocol
	for item := range strings.SplitSeq(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		p, ok := model.ParseProtocol(item)
		if !ok {
			return nil, fmt.Errorf("未知协议 %q（可选: udp, dot, doh, doh3）", item)
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("协议列表为空")
	}
	return out, nil
}

// ParseServerCategories parses a comma-separated origin filter for the built-in
// server list. Empty means "no filter".
func ParseServerCategories(raw string) ([]ServerCategory, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []ServerCategory
	for item := range strings.SplitSeq(raw, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		switch item {
		case "cn", "intl":
			out = append(out, item)
		case "all", "":
			// no filter
		default:
			return nil, fmt.Errorf("未知服务器分类 %q（可选: cn, intl, all）", item)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// ParsePolicies parses a comma-separated resolver-policy filter. Each entry is
// one of the keywords "native" / "security" / "adblock" (or their Chinese
// spellings 原生 / 安全). Empty or "all" means "no filter".
//
// Unlike regions, the keywords ARE validated: the set of policies is closed and
// defined by this tool, so a typo is a mistake worth reporting rather than a
// value to pass through.
func ParsePolicies(raw string) ([]policy.Kind, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []policy.Kind
	for item := range strings.SplitSeq(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.EqualFold(item, "all") {
			continue
		}
		kind, ok := policy.ParseKind(item)
		if !ok {
			return nil, fmt.Errorf("未知过滤策略 %q（可选: native/原生, security/安全）", item)
		}
		if kind == policy.Unknown {
			return nil, fmt.Errorf("过滤策略 %q 不能用于筛选（未确认的策略无法预先选定）", item)
		}
		out = append(out, kind)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return policy.NormalizeAll(out), nil
}

// ParseRegions parses a comma-separated region filter. Each entry is an ISO
// 3166-1 alpha-2 country code ("CN", "US", ...) or one of the special codes
// "CDN" / "PRIVATE" / "UNKNOWN". Case and surrounding space are ignored, and
// duplicates collapse.
//
// The codes are deliberately *not* validated against a list of countries: an
// imported result file may carry a code this build has no label for, and
// rejecting it would make that data unfilterable.
func ParseRegions(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []string
	for item := range strings.SplitSeq(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		// "all" is a convenience spelling for "no filter".
		if strings.EqualFold(item, "all") {
			continue
		}
		if !isRegionCode(item) {
			return nil, fmt.Errorf("未知地区码 %q（应为 ISO 3166-1 两位国家码，或 CDN / PRIVATE / UNKNOWN）", item)
		}
		out = append(out, region.Normalize(item))
	}
	return region.NormalizeAll(out), nil
}

// isRegionCode validates the shape of a region code: two or three letters, or
// one of the special codes.
func isRegionCode(code string) bool {
	code = region.Normalize(code)
	switch code {
	case region.CDN, region.Private, region.Unknown:
		return true
	}
	if len(code) != 2 {
		return false
	}
	for _, r := range code {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// ParseIPVersion parses the --ip-version flag.
func ParseIPVersion(raw string) (model.IPVersion, error) {
	v, ok := model.ParseIPVersion(raw)
	if !ok {
		return "", fmt.Errorf("未知地址族 %q（可选: ipv4, ipv6, both）", raw)
	}
	return v, nil
}

// Formula identifies one of the four ranking formulas.
type Formula string

// The four scoring formulas (see PLAN 五).
const (
	// FormulaSpeed = 1000 * success_rate / avg_latency_ms —— 极速优先
	FormulaSpeed Formula = "speed"
	// FormulaStable = 1000 * success_rate² / avg_latency_ms * 1/(1+stddev/avg) —— 稳定优先
	FormulaStable Formula = "stable"
	// FormulaComprehensive = 1000 * success_rate / (0.5*avg + 0.5*p95) —— 综合体验
	FormulaComprehensive Formula = "comprehensive"
	// FormulaJitter = 1000 * success_rate / (avg + 2*stddev) —— 抗抖动优先
	FormulaJitter Formula = "jitter"
)

// ParseFormula resolves a formula keyword.
func ParseFormula(raw string) (Formula, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(FormulaComprehensive):
		return FormulaComprehensive, nil
	case string(FormulaSpeed), "fast", "latency":
		return FormulaSpeed, nil
	case string(FormulaStable), "stability":
		return FormulaStable, nil
	case string(FormulaJitter), "anti-jitter":
		return FormulaJitter, nil
	}
	return "", fmt.Errorf("未知评分公式 %q（可选: speed, stable, comprehensive, jitter）", raw)
}
