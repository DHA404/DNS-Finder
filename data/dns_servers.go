// Package data holds the built-in, hard-coded test data of the tool: the DNS
// server list and the domestic / international domain lists.
//
// The lists ship inside the binary so a run never depends on external files.
// They are updated by editing this package, not through a configuration file
// (see PLAN 八).
package data

import (
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/region"
)

// Category describes where a built-in server list entry comes from, which is
// what the CLI's --server-class filter operates on.
type Category string

// Server categories.
const (
	CategoryCN   Category = "cn"   // 国内公共 DNS
	CategoryIntl Category = "intl" // 国外公共 DNS
)

// entry pairs a server with its origin category and its region code.
//
// The region is declared here rather than derived because this list is curated
// by hand: every entry's home country is known exactly, and a hand-written
// answer beats a heuristic for the servers the tool ships. Derivation (see
// internal/region) is used for everything that is *not* in this list — explicit
// --servers entries, system resolvers and imported rows.
//
// The filtering policy is deliberately *not* a field here. It is looked up per
// endpoint in internal/policy, so one curated verdict covers the plain and the
// encrypted endpoint of the same service and two lines can never contradict
// each other. A per-line field would let "Cloudflare 安全版" and a future
// "Cloudflare" line disagree about 1.1.1.2.
type entry struct {
	server   model.Server
	category Category
	region   string
}

// serverList is the built-in server inventory in display order: domestic
// plain-DNS resolvers first, then international ones, then the encrypted
// transports (DoT / DoH / DoH3). IPv6 endpoints are listed next to their IPv4
// counterpart of the same provider, so --ip-version ipv4|ipv6 selects a
// coherent slice of the list.
var serverList = []entry{
	// ---------- 国内公共 DNS (UDP / IPv4) ----------
	{model.Server{Name: "AliDNS 1", Address: "223.5.5.5", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "AliDNS 2", Address: "223.6.6.6", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "DNSPod 1", Address: "119.29.29.29", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "DNSPod 2", Address: "119.28.28.28", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "114DNS 1", Address: "114.114.114.114", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "114DNS 2", Address: "114.114.115.115", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	// The filtering variant of 114DNS. It is a distinct address rather than a
	// profile, which is exactly the case the endpoint-keyed policy table
	// exists for: 114.114.114.114 and .119 are one vendor and two policies.
	{model.Server{Name: "114DNS 安全版", Address: "114.114.114.119", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "BaiduDNS", Address: "180.76.76.76", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "Bytedance 1", Address: "180.184.1.1", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "Bytedance 2", Address: "180.184.2.2", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "OneDNS 1", Address: "117.50.10.10", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "OneDNS 2", Address: "52.80.52.52", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "USTC", Address: "202.38.93.153", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "TUNA", Address: "101.6.6.6", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "DNS 派", Address: "101.226.4.6", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},

	// ---------- 国内公共 DNS (UDP / IPv6) ----------
	{model.Server{Name: "AliDNS 1 (IPv6)", Address: "2400:3200::1", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "AliDNS 2 (IPv6)", Address: "2400:3200:baba::1", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "DNSPod 1 (IPv6)", Address: "2402:4e00::", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "DNSPod 2 (IPv6)", Address: "2402:4e00:1::", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "下一代互联网 (IPv6)", Address: "240c::6666", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "腾讯云 (IPv6)", Address: "2400:da00::6666", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "USTC (IPv6)", Address: "2001:da8:d800::1", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},
	{model.Server{Name: "TUNA (IPv6)", Address: "2001:da8::666", Protocol: model.ProtocolUDP}, CategoryCN, "CN"},

	// ---------- 国外公共 DNS (UDP / IPv4) ----------
	{model.Server{Name: "Google 1", Address: "8.8.8.8", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Google 2", Address: "8.8.4.4", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Cloudflare 1", Address: "1.1.1.1", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Cloudflare 2", Address: "1.0.0.1", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Cloudflare 安全版", Address: "1.1.1.2", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Quad9 1", Address: "9.9.9.9", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Quad9 2", Address: "149.112.112.112", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	// Quad9's deliberately unfiltered service: a separate address with the
	// opposite policy to the .9 above, under the same vendor name.
	{model.Server{Name: "Quad9 无过滤", Address: "9.9.9.10", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "OpenDNS 1", Address: "208.67.222.222", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "OpenDNS 2", Address: "208.67.220.220", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	// AdGuard's public DNS blocks ads and trackers by default, so all of its
	// endpoints are 拦截广告 rather than 安全.
	{model.Server{Name: "AdGuard 1", Address: "94.140.14.14", Protocol: model.ProtocolUDP}, CategoryIntl, "CY"},
	{model.Server{Name: "AdGuard 2", Address: "94.140.15.15", Protocol: model.ProtocolUDP}, CategoryIntl, "CY"},
	{model.Server{Name: "DNS.SB 1", Address: "185.222.222.222", Protocol: model.ProtocolUDP}, CategoryIntl, "DE"},
	{model.Server{Name: "DNS.SB 2", Address: "45.11.45.11", Protocol: model.ProtocolUDP}, CategoryIntl, "DE"},
	{model.Server{Name: "Level3 1", Address: "4.2.2.1", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Level3 2", Address: "4.2.2.2", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Verisign 1", Address: "64.6.64.6", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Verisign 2", Address: "64.6.65.6", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Neustar 1", Address: "156.154.70.1", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Neustar 2", Address: "156.154.71.1", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "CleanBrowsing", Address: "185.228.168.9", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Control D", Address: "76.76.2.0", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Mullvad", Address: "194.242.2.2", Protocol: model.ProtocolUDP}, CategoryIntl, "SE"},
	{model.Server{Name: "Hurricane Electric", Address: "74.82.42.42", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Yandex", Address: "77.88.8.8", Protocol: model.ProtocolUDP}, CategoryIntl, "RU"},
	{model.Server{Name: "UncensoredDNS", Address: "91.239.100.100", Protocol: model.ProtocolUDP}, CategoryIntl, "DE"},
	{model.Server{Name: "TWNIC Quad101", Address: "101.101.101.101", Protocol: model.ProtocolUDP}, CategoryIntl, "TW"},
	{model.Server{Name: "HiNet", Address: "168.95.1.1", Protocol: model.ProtocolUDP}, CategoryIntl, "TW"},
	{model.Server{Name: "Nawala", Address: "180.131.144.144", Protocol: model.ProtocolUDP}, CategoryIntl, "ID"},

	// ---------- 国外公共 DNS (UDP / IPv6) ----------
	{model.Server{Name: "Google 1 (IPv6)", Address: "2001:4860:4860::8888", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Google 2 (IPv6)", Address: "2001:4860:4860::8844", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Cloudflare 1 (IPv6)", Address: "2606:4700:4700::1111", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Cloudflare 2 (IPv6)", Address: "2606:4700:4700::1001", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Quad9 1 (IPv6)", Address: "2620:fe::fe", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "Quad9 2 (IPv6)", Address: "2620:fe::9", Protocol: model.ProtocolUDP}, CategoryIntl, region.CDN},
	{model.Server{Name: "OpenDNS 1 (IPv6)", Address: "2620:119:35::35", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "OpenDNS 2 (IPv6)", Address: "2620:119:53::53", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "AdGuard 1 (IPv6)", Address: "2a10:50c0::ad1:ff", Protocol: model.ProtocolUDP}, CategoryIntl, "CY"},
	{model.Server{Name: "AdGuard 2 (IPv6)", Address: "2a10:50c0::ad2:ff", Protocol: model.ProtocolUDP}, CategoryIntl, "CY"},
	{model.Server{Name: "DNS.SB (IPv6)", Address: "2a09::", Protocol: model.ProtocolUDP}, CategoryIntl, "DE"},
	{model.Server{Name: "Neustar 1 (IPv6)", Address: "2610:a1:1018::1", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Neustar 2 (IPv6)", Address: "2610:a1:1019::1", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Hurricane Electric (IPv6)", Address: "2001:470:20::2", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Yandex (IPv6)", Address: "2a02:6b8::feed:0ff", Protocol: model.ProtocolUDP}, CategoryIntl, "RU"},
	{model.Server{Name: "UncensoredDNS (IPv6)", Address: "2001:67c:28a4::", Protocol: model.ProtocolUDP}, CategoryIntl, "DE"},
	{model.Server{Name: "TWNIC Quad101 (IPv6)", Address: "2001:de4::101", Protocol: model.ProtocolUDP}, CategoryIntl, "TW"},
	{model.Server{Name: "CleanBrowsing (IPv6)", Address: "2a0d:2a00:1::", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Control D (IPv6)", Address: "2606:1a40::", Protocol: model.ProtocolUDP}, CategoryIntl, "US"},
	{model.Server{Name: "Mullvad (IPv6)", Address: "2a07:e340::2", Protocol: model.ProtocolUDP}, CategoryIntl, "SE"},

	// ---------- DoT ----------
	// A DoT endpoint is a hostname; the address family is chosen when the name
	// is resolved, so these entries serve --ip-version ipv4 and ipv6 alike.
	{model.Server{Name: "AliDNS", Address: "dns.alidns.com", Protocol: model.ProtocolDoT}, CategoryCN, "CN"},
	{model.Server{Name: "DNSPod", Address: "dot.pub", Protocol: model.ProtocolDoT}, CategoryCN, "CN"},
	{model.Server{Name: "360", Address: "dot.360.cn", Protocol: model.ProtocolDoT}, CategoryCN, "CN"},
	{model.Server{Name: "Google", Address: "dns.google", Protocol: model.ProtocolDoT}, CategoryIntl, region.CDN},
	{model.Server{Name: "Cloudflare", Address: "one.one.one.one", Protocol: model.ProtocolDoT}, CategoryIntl, region.CDN},
	{model.Server{Name: "Quad9", Address: "dns.quad9.net", Protocol: model.ProtocolDoT}, CategoryIntl, region.CDN},
	{model.Server{Name: "AdGuard", Address: "dns.adguard-dns.com", Protocol: model.ProtocolDoT}, CategoryIntl, "CY"},
	{model.Server{Name: "DNS.SB", Address: "dot.sb", Protocol: model.ProtocolDoT}, CategoryIntl, "DE"},
	{model.Server{Name: "Mullvad", Address: "dns.mullvad.net", Protocol: model.ProtocolDoT}, CategoryIntl, "SE"},
	{model.Server{Name: "OpenDNS", Address: "doh.opendns.com", Protocol: model.ProtocolDoT}, CategoryIntl, "US"},
	{model.Server{Name: "Control D", Address: "p2.freedns.controld.com", Protocol: model.ProtocolDoT}, CategoryIntl, "US"},

	// ---------- DoH (RFC 8484 wire format) ----------
	{model.Server{Name: "AliDNS", Address: "https://dns.alidns.com/dns-query", Protocol: model.ProtocolDoH}, CategoryCN, "CN"},
	{model.Server{Name: "DNSPod", Address: "https://doh.pub/dns-query", Protocol: model.ProtocolDoH}, CategoryCN, "CN"},
	{model.Server{Name: "360", Address: "https://doh.360.cn/dns-query", Protocol: model.ProtocolDoH}, CategoryCN, "CN"},
	{model.Server{Name: "Cloudflare", Address: "https://cloudflare-dns.com/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, region.CDN},
	{model.Server{Name: "Google", Address: "https://dns.google/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, region.CDN},
	{model.Server{Name: "Quad9", Address: "https://dns.quad9.net/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, region.CDN},
	{model.Server{Name: "AdGuard", Address: "https://dns.adguard-dns.com/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, "CY"},
	{model.Server{Name: "DNS.SB", Address: "https://doh.sb/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, "DE"},
	{model.Server{Name: "OpenDNS", Address: "https://doh.opendns.com/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, "US"},
	{model.Server{Name: "Mullvad", Address: "https://dns.mullvad.net/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, "SE"},
	// Control D's "p2" profile is explicitly labelled Ads & Tracking, so this
	// endpoint is 拦截广告 rather than native.
	{model.Server{Name: "Control D", Address: "https://freedns.controld.com/p2", Protocol: model.ProtocolDoH}, CategoryIntl, "US"},
	{model.Server{Name: "CleanBrowsing", Address: "https://doh.cleanbrowsing.org/doh/family-filter/", Protocol: model.ProtocolDoH}, CategoryIntl, "US"},
	{model.Server{Name: "dnsforge.de", Address: "https://dnsforge.de/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, "DE"},

	// ---------- DoH over an IPv6 literal ----------
	// These three providers publish IP SANs in their TLS certificates, so a
	// DoH request addressed to the IPv6 literal still verifies. They are the
	// only way to measure DoH over IPv6 without depending on the system
	// resolver's family preference.
	{model.Server{Name: "Cloudflare (IPv6)", Address: "https://[2606:4700:4700::1111]/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, region.CDN},
	{model.Server{Name: "Google (IPv6)", Address: "https://[2001:4860:4860::8888]/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, region.CDN},
	{model.Server{Name: "Quad9 (IPv6)", Address: "https://[2620:fe::fe]/dns-query", Protocol: model.ProtocolDoH}, CategoryIntl, region.CDN},

	// ---------- DoH3 (DNS-over-HTTP/3) ----------
	{model.Server{Name: "AliDNS", Address: "https://dns.alidns.com/dns-query", Protocol: model.ProtocolDoH3}, CategoryCN, "CN"},
	{model.Server{Name: "Cloudflare", Address: "https://cloudflare-dns.com/dns-query", Protocol: model.ProtocolDoH3}, CategoryIntl, region.CDN},
	{model.Server{Name: "Google", Address: "https://dns.google/dns-query", Protocol: model.ProtocolDoH3}, CategoryIntl, region.CDN},
	{model.Server{Name: "Quad9", Address: "https://dns.quad9.net/dns-query", Protocol: model.ProtocolDoH3}, CategoryIntl, region.CDN},
	{model.Server{Name: "AdGuard", Address: "https://dns.adguard-dns.com/dns-query", Protocol: model.ProtocolDoH3}, CategoryIntl, "CY"},
	{model.Server{Name: "DNS.SB", Address: "https://doh.sb/dns-query", Protocol: model.ProtocolDoH3}, CategoryIntl, "DE"},
	{model.Server{Name: "Mullvad", Address: "https://dns.mullvad.net/dns-query", Protocol: model.ProtocolDoH3}, CategoryIntl, "SE"},
}

// Servers returns the built-in server list filtered by the requested protocol
// set, origin categories, region codes and resolver policies, preserving the
// declaration order and skipping duplicates. An empty slice means "no filter"
// for that dimension, and the filters combine with AND.
//
// Every returned server carries its curated Region and its documented Policy;
// the address family is left empty and filled in by the engine once the
// endpoint has been classified.
//
// The policy filter is applied here rather than by the caller because the
// policy is a curated property of each entry: an entry with no documented
// policy is 未确认 and is therefore excluded by any policy filter, which is the
// honest outcome. Selecting "原生" must not silently include servers whose
// behaviour nobody documented.
func Servers(protocols []model.Protocol, categories []Category, regions []string, policies []policy.Kind) []model.Server {
	protoSet := make(map[model.Protocol]struct{}, len(protocols))
	for _, p := range protocols {
		protoSet[p] = struct{}{}
	}
	catSet := make(map[Category]struct{}, len(categories))
	for _, c := range categories {
		catSet[c] = struct{}{}
	}
	regionSet := make(map[string]struct{}, len(regions))
	for _, r := range regions {
		regionSet[region.Normalize(r)] = struct{}{}
	}
	policySet := make(map[policy.Kind]struct{}, len(policies))
	for _, p := range policies {
		if k := policy.CanonicalKind(p); k != policy.Unknown {
			policySet[k] = struct{}{}
		}
	}

	seen := make(map[string]struct{}, len(serverList))
	out := make([]model.Server, 0, len(serverList))
	for _, e := range serverList {
		if len(protoSet) > 0 {
			if _, ok := protoSet[e.server.Protocol]; !ok {
				continue
			}
		}
		if len(catSet) > 0 {
			if _, ok := catSet[e.category]; !ok {
				continue
			}
		}
		if _, dup := seen[e.server.Key()]; dup {
			continue
		}

		s := e.server
		// The curated region is authoritative: it is why the table carries one
		// per entry at all. Derivation is only a fallback for an entry that has
		// none, so a newly added line is never left unattributed.
		s.Region = e.region
		if s.Region == "" {
			s.Region = region.Of(s.Address, false)
		}
		if len(regionSet) > 0 {
			if _, ok := regionSet[region.Normalize(s.Region)]; !ok {
				continue
			}
		}
		// The policy comes from the curated endpoint table, not from the
		// inventory line, so one entry cannot contradict another endpoint of
		// the same vendor.
		s.Policy = e.policy()
		if len(policySet) > 0 {
			if _, ok := policySet[s.Policy]; !ok {
				continue
			}
		}

		seen[s.Key()] = struct{}{}
		out = append(out, s)
	}
	return out
}

// policy resolves an entry's documented filtering behaviour from the curated
// endpoint table (see internal/policy).
//
// The display name is passed as a secondary signal because a filtering variant
// is often named as such ("Cloudflare 安全版"), and for a hostname endpoint the
// name is what the inventory actually curates. The address always wins, so a
// line cannot talk the table out of its verdict.
func (e entry) policy() policy.Kind {
	return policy.OfServer(e.server.Address, e.server.Name)
}

// AllServers returns the full built-in server list. It is used when the
// protocol/category filters are not applied (e.g. for counting how many
// servers a filter dropped).
func AllServers() []model.Server { return Servers(nil, nil, nil, nil) }

// PolicyCounts returns how many built-in servers carry each policy, so the CLI
// can report a filter that matched nothing before it is applied.
func PolicyCounts() map[policy.Kind]int {
	counts := map[policy.Kind]int{}
	for _, s := range AllServers() {
		counts[s.Policy]++
	}
	return counts
}

// RegionCodes returns the distinct region codes of the built-in inventory, in
// the order they first appear. It is what the CLI's --regions help lists.
func RegionCodes() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range serverList {
		code := e.region
		if code == "" {
			code = region.Of(e.server.Address, false)
		}
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out
}
