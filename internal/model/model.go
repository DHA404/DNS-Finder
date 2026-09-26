// Package model defines the shared data model of the DNS 优选 tool: DNS
// transports, servers, domain groups, the raw JSON Lines records produced
// during a run and the aggregated summary rows used for ranking.
//
// The structures here are the serialization contract of the exported result
// file (meta / raw / summary) and are shared by the engine, the store, the
// scorer, the CLI and the local web server.
package model

import (
	"net/netip"
	"strings"
	"time"

	"dns-opti/internal/policy"
)

// Protocol identifies the DNS transport used by a server.
type Protocol string

// Supported protocols. DoH3 is DNS-over-HTTPS carried over HTTP/3 (QUIC); it
// uses the same RFC 8484 /dns-query endpoint as DoH and differs only in the
// transport underneath.
const (
	ProtocolUDP  Protocol = "udp"
	ProtocolDoT  Protocol = "dot"
	ProtocolDoH  Protocol = "doh"
	ProtocolDoH3 Protocol = "doh3"
)

// AllProtocols is the canonical protocol order used in meta data, help text
// and the progress panel.
var AllProtocols = []Protocol{ProtocolUDP, ProtocolDoT, ProtocolDoH, ProtocolDoH3}

// ComboUDPDoH is the identifier of the "UDP + DoH" combined mode: each provider
// is measured twice, once over plain UDP and once over DoH, and the two results
// are reported side by side. It is a *selector*, not a Protocol value — a run
// in this mode produces ordinary UDP and DoH records.
const ComboUDPDoH = "udp+doh"

// ComboUDPDoHLabel is the display name of the combined mode.
const ComboUDPDoHLabel = "UDP + DoH"

// ComboProtocols returns the protocols a selector implies. A selector that is
// not a known combo yields a single-element list holding the value itself
// parsed as a protocol, so an ordinary protocol name works in its place.
func ComboProtocols(selector string) ([]Protocol, bool) {
	switch strings.ToLower(strings.TrimSpace(selector)) {
	case ComboUDPDoH:
		return []Protocol{ProtocolUDP, ProtocolDoH}, true
	}
	return nil, false
}

// IsCombo reports whether a selector names a combined mode.
func IsCombo(selector string) bool {
	_, ok := ComboProtocols(selector)
	return ok
}

// ParseProtocol converts a user-supplied protocol name to a Protocol. The
// aliases cover the spellings people commonly type.
func ParseProtocol(s string) (Protocol, bool) {
	switch s {
	case "udp", "UDP":
		return ProtocolUDP, true
	case "dot", "DOT", "tls", "DoT":
		return ProtocolDoT, true
	case "doh", "DOH", "DoH":
		return ProtocolDoH, true
	case "doh3", "DOH3", "DoH3", "h3":
		return ProtocolDoH3, true
	}
	return "", false
}

// Label returns the human-facing name of the protocol.
func (p Protocol) Label() string {
	switch p {
	case ProtocolUDP:
		return "UDP"
	case ProtocolDoT:
		return "DoT"
	case ProtocolDoH:
		return "DoH"
	case ProtocolDoH3:
		return "DoH3"
	}
	return string(p)
}

// IPVersion identifies the address family of a resolver endpoint.
type IPVersion string

// Address families. The empty value is meaningful: it marks a hostname-based
// endpoint, whose family is only decided when the name is resolved.
const (
	// IPAny is a hostname endpoint; the family is chosen at resolve time
	// according to the requested family and what the network can route.
	IPAny IPVersion = ""
	// IPv4 is an endpoint pinned to an IPv4 literal.
	IPv4 IPVersion = "ipv4"
	// IPv6 is an endpoint pinned to an IPv6 literal.
	IPv6 IPVersion = "ipv6"
)

// ParseIPVersion resolves a user-supplied address-family keyword. "both",
// "any" and "auto" all mean "no restriction", which is the same as IPAny.
func ParseIPVersion(s string) (IPVersion, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "both", "any", "auto", "all":
		return IPAny, true
	case "ipv4", "v4", "4":
		return IPv4, true
	case "ipv6", "v6", "6":
		return IPv6, true
	}
	return "", false
}

// Label returns the human-facing name of the address family.
func (v IPVersion) Label() string {
	switch v {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	}
	return "IPv4/IPv6"
}

// IsLiteral reports whether the family is pinned to a literal address.
func (v IPVersion) IsLiteral() bool { return v == IPv4 || v == IPv6 }

// Domain group keys. Domestic and international domains are strictly kept
// apart: they are never mixed into one score.
const (
	GroupCN   = "cn"   // 国内域名
	GroupIntl = "intl" // 国外域名
	// GroupMixed is the 国内 + 国外 domains measured as ONE group. It is
	// deliberately distinct from GroupAll: "all" keeps the two groups apart and
	// reports them separately, while "mixed" pools their queries so a single
	// score describes how a resolver behaves across both. Pooling loses the
	// per-group detail, which is why it is opt-in rather than the default.
	GroupMixed = "mixed"
	// GroupCustom marks a user-supplied domain list (--domains with explicit
	// domain names).
	GroupCustom = "custom"
	// GroupImported marks summary rows reconstructed from a foreign result
	// file (e.g. xxnuo/dns-benchmark), where the original domain split is
	// unknown. It is never produced by this tool's own test runs.
	GroupImported = "imported"
)

// GroupLabel returns the Chinese display label of a domain group.
func GroupLabel(g string) string {
	switch g {
	case GroupCN:
		return "国内域名"
	case GroupIntl:
		return "国外域名"
	case GroupMixed:
		return "国内外混合"
	case GroupCustom:
		return "自定义域名"
	case GroupImported:
		return "导入数据"
	}
	return g
}

// GroupShortLabel returns a compact form of the group name, used where a table
// cell is too narrow for the full label.
func GroupShortLabel(g string) string {
	switch g {
	case GroupCN:
		return "国内"
	case GroupIntl:
		return "国外"
	case GroupMixed:
		return "混合"
	case GroupCustom:
		return "自定义"
	case GroupImported:
		return "导入"
	}
	return g
}

// Server describes one DNS server endpoint to be tested.
type Server struct {
	Name     string   `json:"name"`
	Address  string   `json:"address"`
	Protocol Protocol `json:"protocol"`
	// IP is the literal address the endpoint is actually reached at: the
	// endpoint itself for a bare IP, or the address a hostname resolved to.
	//
	// It exists because the tool identifies a server by its IP everywhere the
	// user reads it, while the *configuration* identifier has to stay the
	// address: "" and a DoH URL are not interchangeable as dial targets. For a
	// hostname endpoint the value is only known after resolution, so it is
	// empty until the run has started (see Querier.ResolvedIP).
	IP string `json:"ip,omitempty"`
	// Region is the ISO 3166-1 alpha-2 code of the resolver, or one of the
	// special codes CDN / PRIVATE / UNKNOWN (see internal/region). It is the
	// dimension the viewer's region filter operates on.
	Region string `json:"region,omitempty"`
	// Policy is the resolver's documented filtering behaviour (see
	// internal/policy): 原生 / 安全. It is a separate axis from
	// Region, because where a resolver sits says nothing about what it filters.
	Policy policy.Kind `json:"policy,omitempty"`
	// Family is the address family of the endpoint: IPv4 or IPv6 for a literal
	// address, empty for a hostname. It is derived, not configured.
	Family IPVersion `json:"family,omitempty"`
	// IsSystem marks the resolver currently configured on this machine.
	IsSystem bool `json:"is_system"`
	// IsPrivate marks RFC 1918 / RFC 4193 / loopback / link-local resolvers,
	// which usually serve internal names and should not be swapped out.
	IsPrivate bool `json:"is_private,omitempty"`
	// Combo is the identifier of the "UDP + DoH" pairing this entry belongs to,
	// when the run was configured in combined mode. Entries sharing a Combo
	// value are the same underlying provider measured over two transports.
	Combo string `json:"combo,omitempty"`
}

// Key identifies a server unambiguously inside a run.
func (s Server) Key() string { return string(s.Protocol) + "|" + s.Address }

// DisplayIP is the address the user sees this server by.
//
// It prefers the resolved literal address and falls back to the host of the
// configured address, so a row is identifiable by IP even before the run has
// resolved its hostname endpoints. The fallback is the host of the *address*
// rather than the name: for a DoH URL that is the authority, and for every
// other shape it is the address itself, which is what makes the result stable
// across a run's lifetime.
func (s Server) DisplayIP() string {
	if s.IP != "" {
		return s.IP
	}
	return HostOf(s.Address)
}

// HostOf extracts the host of an endpoint of any accepted shape: a bare IP, a
// bare hostname, a bracketed IPv6 literal, "host:port", or a DoH URL. It is the
// single implementation the whole tool uses, so a display name can never be
// derived two different ways.
func HostOf(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if i := strings.Index(endpoint, "://"); i >= 0 {
		endpoint = endpoint[i+3:]
	}
	if i := strings.IndexAny(endpoint, "/?#"); i >= 0 {
		endpoint = endpoint[:i]
	}
	if i := strings.LastIndexByte(endpoint, '@'); i >= 0 {
		endpoint = endpoint[i+1:]
	}
	// A bracketed IPv6 literal: the host is what is inside the brackets.
	if strings.HasPrefix(endpoint, "[") {
		if i := strings.IndexByte(endpoint, ']'); i >= 0 {
			return endpoint[1:i]
		}
		return strings.TrimPrefix(endpoint, "[")
	}
	// A bare IPv6 literal is recognised by parsing, which is unambiguous. Only
	// when it is not an address may a trailing ":port" be stripped; a colon
	// count test would cut the last group off "2400:3200::1".
	if isIPLiteral(endpoint) {
		return endpoint
	}
	if i := strings.LastIndexByte(endpoint, ':'); i >= 0 && isPort(endpoint[i+1:]) {
		endpoint = endpoint[:i]
	}
	return endpoint
}

// isIPLiteral reports whether s parses as an IP address.
func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// isPort reports whether s is a plausible port number. An empty value is not a
// port, so a trailing colon is left in place rather than silently truncated.
func isPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ComboKey identifies the "UDP + DoH" pairing a server belongs to. It is the
// provider identity (name plus region) rather than the address, because the two
// transports of one provider are reached at different addresses. Servers
// without a Combo are never paired, so each becomes its own group.
func (s Server) ComboKey() string {
	if s.Combo == "" {
		return ""
	}
	return s.Combo
}

// Domain is a test domain together with the group it belongs to.
type Domain struct {
	Name  string `json:"name"`
	Group string `json:"group"`
}

// Meta is the "meta" block of an exported result file.
type Meta struct {
	Version      string    `json:"version"`
	Timestamp    time.Time `json:"timestamp"`
	Platform     string    `json:"platform"`
	Concurrency  int       `json:"concurrency"`
	WarmupDomain string    `json:"warmup_domain"`
	DomainGroups []string  `json:"domain_groups"`
	Protocols    []string  `json:"protocols"`
	DNSServers   []Server  `json:"dns_servers"`
	SystemDNS    []string  `json:"system_dns"`
	// Combo records the combined mode a run used ("udp+doh"), if any.
	Combo string `json:"combo,omitempty"`
	// Regions is the region filter that was applied, if any.
	Regions []string `json:"regions,omitempty"`
	// Policies is the resolver-policy filter that was applied, if any.
	Policies []string `json:"policies,omitempty"`
	// Domains records the domain selection the run used, so a reader can tell
	// a 分组 run from a 混合 one without having to infer it from the groups
	// present in the rows.
	Domains string `json:"domains,omitempty"`
	// IPVersion is the address family the run was restricted to ("ipv4" /
	// "ipv6"), or empty for both.
	IPVersion string `json:"ip_version,omitempty"`
	// Network records what the reachability probe found, so an exported file
	// explains on its own why IPv6 (or IPv4) servers are absent instead of
	// leaving the reader to guess.
	Network *NetworkProbe `json:"network,omitempty"`
	// Note carries a short human-readable remark, e.g. that some servers were
	// skipped because the host has no usable IPv6 route.
	Note string `json:"note,omitempty"`
}

// NetworkProbe records the result of the address-family reachability probe.
//
// It exists because "servers are missing from this file" is otherwise
// indistinguishable from "the run was configured that way": the verdict used to
// survive only as a transient console warning, so a file shared or re-read
// later could not explain its own contents.
type NetworkProbe struct {
	// IPv4 / IPv6 report whether a real query to that family was answered.
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`
	// Skipped counts the servers dropped by the family rule.
	Skipped int `json:"skipped,omitempty"`
	// Forced is true when an explicit --ip-version overrode the probe, in which
	// case Skipped counts the servers dropped for contradicting the request
	// rather than for being unreachable.
	Forced bool `json:"forced,omitempty"`
	// Label is the human-readable summary shown in reports.
	Label string `json:"label,omitempty"`
}

// RawRecord is one measured query. Every query is recorded, successful or not;
// failures are uniformly success=false and the reason is deliberately not
// distinguished (See PLAN 4.2).
type RawRecord struct {
	DNS       string   `json:"dns"`
	Name      string   `json:"name,omitempty"`
	Protocol  Protocol `json:"protocol"`
	Domain    string   `json:"domain"`
	Group     string   `json:"group"`
	Attempt   int      `json:"attempt"`
	Success   bool     `json:"success"`
	LatencyMS float64  `json:"latency_ms"`
	TS        int64    `json:"ts"`
}

// Summary is the aggregated row for one (dns, protocol, group) triple.
type Summary struct {
	DNS      string   `json:"dns"`
	Name     string   `json:"name,omitempty"`
	Protocol Protocol `json:"protocol"`
	Group    string   `json:"group"`
	// IP is the literal address the server was reached at, mirroring
	// Server.IP. It is the row's display identity: every surface identifies a
	// row by its IP plus its protocol, never by a vendor name.
	IP          string  `json:"ip,omitempty"`
	Total       int     `json:"total"`
	Success     int     `json:"success"`
	SuccessRate float64 `json:"success_rate"`
	AvgMS       float64 `json:"avg_ms"`
	P95MS       float64 `json:"p95_ms"`
	StdDevMS    float64 `json:"stddev_ms"`
	// Region and Family mirror the Server fields so the viewer can filter on
	// them without a second lookup (see internal/region).
	Region string    `json:"region,omitempty"`
	Family IPVersion `json:"family,omitempty"`
	// Policy mirrors Server.Policy: the resolver's documented filtering
	// behaviour, which the viewer filters on independently of region.
	Policy policy.Kind `json:"policy,omitempty"`
	// IsSystem / IsPrivate mirror the Server flags for display purposes.
	IsSystem  bool `json:"is_system,omitempty"`
	IsPrivate bool `json:"is_private,omitempty"`
	// Combo mirrors Server.Combo: the "UDP + DoH" pairing this row belongs to.
	Combo string `json:"combo,omitempty"`
}

// Key identifies the aggregation bucket of a summary row.
func (s Summary) Key() string { return s.DNS + "|" + string(s.Protocol) + "|" + s.Group }

// DisplayIP is the address the row is shown by, mirroring Server.DisplayIP.
func (s Summary) DisplayIP() string {
	if s.IP != "" {
		return s.IP
	}
	return HostOf(s.DNS)
}

// File is the top-level structure of an exported result file. Raw is streamed
// out of the temporary JSON Lines file at export time so that a long run never
// has to hold every record in memory.
type File struct {
	Meta    Meta        `json:"meta"`
	Raw     []RawRecord `json:"raw"`
	Summary []Summary   `json:"summary"`
}
