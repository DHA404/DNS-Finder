// Package region maps a DNS resolver endpoint to a region code, and provides
// the region groups the viewer offers as quick filters.
//
// A region code is an upper-case ISO 3166-1 alpha-2 country code ("CN", "DE",
// "US", ...) or one of three special codes:
//
//	CDN      任播 / 全球网络，无法归属单一国家
//	PRIVATE  内网 / 回环 / 链路本地保留网段
//	UNKNOWN  未能归属
//
// The built-in server inventory carries its region explicitly, because that
// list is curated by hand and the exact answer is known for every entry. This
// package therefore only has to *derive* a region for endpoints that are not in
// the inventory: --servers entries, the machine's own resolvers, and rows
// imported from a foreign result file.
//
// Derivation is deliberately a small curated network table rather than a GeoIP
// database. A GeoIP lookup is actively misleading for this use case — every
// large resolver is anycast, so the database reports whichever datacentre the
// vendor registered, not where the query is answered. The curated table knows
// the two things that actually matter here: which networks belong to a single
// country, and which ones are globally anycast.
package region

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
)

// Special region codes.
const (
	// CDN marks a globally anycast network. The same address is answered from
	// many countries, so attributing it to one of them would be wrong.
	CDN = "CDN"
	// Private marks an RFC 1918 / RFC 4193 / loopback / link-local resolver.
	Private = "PRIVATE"
	// Unknown marks an address no rule could attribute.
	Unknown = "UNKNOWN"
)

// regionPrefix pairs a network with its region. The table covers the resolver
// networks this tool ships plus the other well-known public resolvers a user is
// likely to pass through --servers. It is intentionally small and hand-checked.
type regionPrefix struct {
	prefix netip.Prefix
	region string
}

// mustPrefix builds a prefix, panicking on a programming error in the table
// below (which is a compile-time constant list).
func mustPrefix(cidr, region string) regionPrefix {
	return regionPrefix{prefix: netip.MustParsePrefix(cidr), region: region}
}

// networks is consulted longest-prefix-first, so a more specific entry always
// wins over a broader one.
var networks = []regionPrefix{
	// ---------- 中国 ----------
	mustPrefix("223.5.5.0/24", "CN"),        // AliDNS
	mustPrefix("223.6.6.0/24", "CN"),        // AliDNS
	mustPrefix("2400:3200::/32", "CN"),      // AliDNS IPv6
	mustPrefix("119.29.29.0/24", "CN"),      // DNSPod
	mustPrefix("119.28.28.0/24", "CN"),      // DNSPod
	mustPrefix("114.114.114.0/24", "CN"),    // 114DNS
	mustPrefix("114.114.115.0/24", "CN"),    // 114DNS
	mustPrefix("180.76.76.0/24", "CN"),      // BaiduDNS
	mustPrefix("180.184.0.0/16", "CN"),      // Bytedance
	mustPrefix("117.50.10.0/24", "CN"),      // OneDNS
	mustPrefix("52.80.52.0/24", "CN"),       // OneDNS
	mustPrefix("202.38.93.0/24", "CN"),      // USTC
	mustPrefix("101.6.6.0/24", "CN"),        // TUNA
	mustPrefix("101.226.4.0/24", "CN"),      // DNS 派
	mustPrefix("240c::6666/128", "CN"),      // 下一代互联网 IPv6
	mustPrefix("2400:da00::6666/128", "CN"), // 腾讯云 IPv6
	mustPrefix("2402:4e00::/32", "CN"),      // DNSPod IPv6

	// ---------- 中国台湾 / 香港 ----------
	mustPrefix("101.101.101.0/24", "TW"), // TWNIC Quad101
	mustPrefix("168.95.1.0/24", "TW"),    // HiNet
	mustPrefix("168.95.192.0/24", "TW"),  // HiNet
	mustPrefix("203.80.96.0/24", "HK"),   // HKIX

	// ---------- 亚洲其它 ----------
	mustPrefix("103.86.96.0/24", "ID"),   // Nawala
	mustPrefix("103.86.99.0/24", "ID"),   // Nawala
	mustPrefix("202.12.27.0/24", "JP"),   // M-root (WIDE)
	mustPrefix("101.102.0.0/16", "KR"),   // KT
	mustPrefix("168.126.63.0/24", "KR"),  // KT
	mustPrefix("218.2.2.0/24", "JP"),     // IIJ
	mustPrefix("202.181.224.0/24", "SG"), // 新加坡

	// ---------- 美洲 ----------
	mustPrefix("208.67.220.0/24", "US"), // OpenDNS
	mustPrefix("208.67.222.0/24", "US"), // OpenDNS
	mustPrefix("146.112.41.0/24", "US"), // OpenDNS FamilyShield
	mustPrefix("4.2.2.0/24", "US"),      // Level3
	mustPrefix("64.6.64.0/24", "US"),    // Verisign
	mustPrefix("64.6.65.0/24", "US"),    // Verisign
	mustPrefix("156.154.70.0/24", "US"), // Neustar UltraDNS
	mustPrefix("156.154.71.0/24", "US"), // Neustar UltraDNS
	mustPrefix("76.76.2.0/24", "US"),    // Control D
	mustPrefix("76.76.10.0/24", "US"),   // Control D
	mustPrefix("205.171.2.0/24", "US"),  // CenturyLink
	mustPrefix("205.171.3.0/24", "US"),  // CenturyLink
	mustPrefix("8.20.247.0/24", "US"),   // Comodo
	mustPrefix("64.6.0.0/16", "US"),     // Verisign 兜底

	// ---------- 欧洲 ----------
	mustPrefix("84.200.69.0/24", "DE"),     // DNS.WATCH
	mustPrefix("94.140.14.0/24", "CY"),     // AdGuard
	mustPrefix("94.140.15.0/24", "CY"),     // AdGuard
	mustPrefix("185.222.222.0/24", "DE"),   // DNS.SB
	mustPrefix("45.11.45.0/24", "DE"),      // DNS.SB
	mustPrefix("84.200.70.0/24", "DE"),     // DNS.WATCH
	mustPrefix("5.1.66.0/24", "DE"),        // dnsforge.de
	mustPrefix("89.233.43.0/24", "DE"),     // UncensoredDNS
	mustPrefix("91.239.100.0/24", "DE"),    // UncensoredDNS
	mustPrefix("194.242.2.0/24", "SE"),     // Mullvad
	mustPrefix("77.88.8.0/24", "RU"),       // Yandex
	mustPrefix("2a02:6b8::feed/128", "RU"), // Yandex IPv6
	mustPrefix("146.255.56.0/24", "AT"),    // IPA
	mustPrefix("86.54.11.0/24", "AT"),      // DNS4EU
	mustPrefix("193.110.81.0/24", "MD"),    // AdGuard DNS (Moldova anycast)
	mustPrefix("86.106.0.0/16", "NL"),      // OpenNIC NL
	mustPrefix("185.121.177.0/24", "NL"),   // OpenNIC NL
	mustPrefix("169.239.202.0/24", "ZA"),   // OpenNIC ZA

	// ---------- 全球任播 ----------
	mustPrefix("1.1.1.0/24", CDN),          // Cloudflare
	mustPrefix("1.0.0.0/24", CDN),          // Cloudflare
	mustPrefix("162.159.0.0/16", CDN),      // Cloudflare
	mustPrefix("2606:4700::/32", CDN),      // Cloudflare IPv6
	mustPrefix("8.8.8.0/24", CDN),          // Google
	mustPrefix("8.8.4.0/24", CDN),          // Google
	mustPrefix("2001:4860:4860::/48", CDN), // Google IPv6
	mustPrefix("9.9.9.0/24", CDN),          // Quad9
	mustPrefix("149.112.112.0/24", CDN),    // Quad9
	mustPrefix("2620:fe::/32", CDN),        // Quad9 IPv6
	mustPrefix("185.228.168.0/24", "US"),   // CleanBrowsing
	mustPrefix("185.228.169.0/24", "US"),   // CleanBrowsing
}

// hostRegions attributes a resolver *hostname* (not an IP) to a region. This is
// the second half of derivation: most encrypted endpoints are published under a
// name rather than a bare IP.
var hostRegions = []struct {
	suffix string
	region string
}{
	{"dns.alidns.com", "CN"},
	{"alidns.com", "CN"},
	{"doh.pub", "CN"},
	{"dot.pub", "CN"},
	{"dns.pub", "CN"},
	{"dnspod.cn", "CN"},
	{"doh.360.cn", "CN"},
	{"dot.360.cn", "CN"},
	{"360.cn", "CN"},
	{"qq.com", "CN"},
	{"dnspod.com", "CN"},
	{"tencent.com", "CN"},
	{"baidu.com", "CN"},
	{"bytedance.com", "CN"},
	{"onedns.net", "CN"},
	{"ustc.edu.cn", "CN"},
	{"tuna.tsinghua.edu.cn", "CN"},
	{"tsinghua.edu.cn", "CN"},
	{"iij.ad.jp", "JP"},
	{"quad101.tw", "TW"},
	{"twnic.net.tw", "TW"},
	{"hinet.net", "TW"},
	{"nawala.id", "ID"},
	{"adguard-dns.com", "CY"},
	{"adguard-dns.io", "CY"},
	{"adguard.com", "CY"},
	{"dns.sb", "DE"},
	{"doh.sb", "DE"},
	{"dot.sb", "DE"},
	{"dnsforge.de", "DE"},
	{"digitalcourage.de", "DE"},
	{"uncensoreddns.org", "DE"},
	{"dns.watch", "DE"},
	{"opendns.com", "US"},
	{"cisco.com", "US"},
	{"controld.com", "US"},
	{"cleanbrowsing.org", "US"},
	{"level3.net", "US"},
	{"verisign.com", "US"},
	{"ultradns.com", "US"},
	{"neustar.biz", "US"},
	{"comodo.com", "US"},
	{"mullvad.net", "SE"},
	{"yandex.ru", "RU"},
	{"yandex.net", "RU"},
	{"opennic.org", "NL"},
	{"cloudflare-dns.com", CDN},
	{"cloudflare.com", CDN},
	{"one.one.one.one", CDN},
	{"dns.google", CDN},
	{"google.com", CDN},
	{"dns.quad9.net", CDN},
	{"quad9.net", CDN},
	{"dns4eu.eu", "AT"},
}

// Group is one quick-filter group of region codes, modelled on the reference
// site's 亚太 / 美洲 / 欧洲 / 中国 / CDN buttons.
type Group struct {
	// ID is the stable key used by the viewer.
	ID string `json:"id"`
	// Label is the Chinese display name.
	Label string `json:"label"`
	// Codes are the region codes the group selects.
	Codes []string `json:"codes"`
}

// Groups returns the quick-filter groups in presentation order. A group
// matches a row when the row's region code is one of its codes.
func Groups() []Group {
	return []Group{
		{ID: "cn", Label: "中国", Codes: []string{"CN", "HK", "TW", "MO"}},
		{
			ID:    "asia",
			Label: "亚太",
			Codes: []string{"CN", "HK", "TW", "MO", "JP", "KR", "SG", "ID", "MY", "TH", "VN", "IN", "AU", "NZ", "BD", "AE", "PH"},
		},
		{ID: "americas", Label: "美洲", Codes: []string{"US", "CA", "BR", "MX", "AR", "CL"}},
		{
			ID:    "europe",
			Label: "欧洲",
			Codes: []string{"DE", "FR", "GB", "NL", "SE", "CH", "RU", "CY", "AT", "FI", "NO", "PL", "IT", "ES", "CZ", "IE", "RO", "MD", "LV", "LT", "EE", "SI", "HU", "BG", "LU", "UA", "GR", "PT", "DK", "BE", "SK", "HR", "RS", "IS", "TR", "IL"},
		},
		{ID: "global", Label: "CDN / 任播", Codes: []string{CDN}},
		{ID: "special", Label: "内网 / 未知", Codes: []string{Private, Unknown}},
	}
}

// labels holds the Chinese display names of the region codes this tool can
// produce. A code without an entry falls back to the code itself, which is the
// right behaviour for an imported file carrying a country the table predates.
var labels = map[string]string{
	CDN:     "CDN 任播",
	Private: "内网地址",
	Unknown: "未知地区",

	"CN": "中国", "HK": "中国香港", "TW": "中国台湾", "MO": "中国澳门",
	"JP": "日本", "KR": "韩国", "SG": "新加坡", "ID": "印度尼西亚",
	"MY": "马来西亚", "TH": "泰国", "VN": "越南", "IN": "印度",
	"PH": "菲律宾", "BD": "孟加拉", "AE": "阿联酋", "IL": "以色列",
	"TR": "土耳其", "KZ": "哈萨克斯坦", "PK": "巴基斯坦",
	"AU": "澳大利亚", "NZ": "新西兰",
	"US": "美国", "CA": "加拿大", "BR": "巴西", "MX": "墨西哥",
	"AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁",
	"DE": "德国", "FR": "法国", "GB": "英国", "NL": "荷兰",
	"SE": "瑞典", "CH": "瑞士", "RU": "俄罗斯", "CY": "塞浦路斯",
	"AT": "奥地利", "FI": "芬兰", "NO": "挪威", "PL": "波兰",
	"IT": "意大利", "ES": "西班牙", "CZ": "捷克", "IE": "爱尔兰",
	"RO": "罗马尼亚", "MD": "摩尔多瓦", "LV": "拉脱维亚", "LT": "立陶宛",
	"EE": "爱沙尼亚", "SI": "斯洛文尼亚", "HU": "匈牙利", "BG": "保加利亚",
	"LU": "卢森堡", "UA": "乌克兰", "GR": "希腊", "PT": "葡萄牙",
	"DK": "丹麦", "BE": "比利时", "SK": "斯洛伐克", "HR": "克罗地亚",
	"RS": "塞尔维亚", "IS": "冰岛", "ZA": "南非", "EU": "欧盟",
}

// vendorCodes maps the non-ISO "geocode" values that foreign result files
// carry onto this tool's region codes.
//
// xxnuo/dns-benchmark labels an anycast resolver with the vendor's name rather
// than a country ("CLOUDFLARE", "GOOGLE", "AKAMAI", "FASTLY", and even
// "TWITTER" / "FACEBOOK" for addresses announced by those networks). Those are
// all globally anycast, which is exactly what CDN means here, so they are
// folded into it instead of appearing as a bogus one-off "country" that the
// viewer could not label or group.
var vendorCodes = map[string]string{
	"CLOUDFLARE":    CDN,
	"GOOGLE":        CDN,
	"AKAMAI":        CDN,
	"FASTLY":        CDN,
	"TWITTER":       CDN,
	"FACEBOOK":      CDN,
	"META":          CDN,
	"AMAZON":        CDN,
	"AWS":           CDN,
	"MICROSOFT":     CDN,
	"AZURE":         CDN,
	"QUAD9":         CDN,
	"OPENDNS":       "US",
	"CISCO":         "US",
	"NEUSTAR":       "US",
	"VERISIGN":      "US",
	"LEVEL3":        "US",
	"ALIBABA":       "CN",
	"ALIDNS":        "CN",
	"TENCENT":       "CN",
	"DNSPOD":        "CN",
	"BAIDU":         "CN",
	"360":           "CN",
	"YANDEX":        "RU",
	"ADGUARD":       "CY",
	"MULLVAD":       "SE",
	"CONTROLD":      "US",
	"CONTROL D":     "US",
	"DNS.SB":        "DE",
	"DNSSB":         "DE",
	"CLEANBROWSING": "US",
	"HINET":         "TW",
	"TWNIC":         "TW",
	"NAWALA":        "ID",
	"IIJ":           "JP",
	"LOCAL":         Private,
	"INTERNAL":      Private,
	"RESERVED":      Private,
}

// Canonical turns a region value from any supported source into this tool's
// canonical form. A known vendor name becomes the region it belongs to, a
// country code is upper-cased, and anything unrecognised is passed through
// upper-cased so it stays visible and filterable rather than being discarded.
func Canonical(raw string) string {
	code := Normalize(raw)
	if code == "" {
		return ""
	}
	if mapped, ok := vendorCodes[code]; ok {
		return mapped
	}
	return code
}

// Label returns the Chinese display name of a region code. A vendor name is
// resolved first, so a label is never the raw "CLOUDFLARE".
func Label(code string) string {
	code = Canonical(code)
	if name, ok := labels[code]; ok {
		return name
	}
	if code == "" {
		return ""
	}
	return code
}

// Labels returns a copy of the code -> display-name table, so the viewer can
// render a region it has never seen with the same wording as the CLI.
func Labels() map[string]string {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}

// Normalize canonicalises a region code: surrounding space is trimmed and the
// code is upper-cased, so "de", " DE " and "DE" all denote the same region.
// The alphabetical form is preserved rather than validated against a list of
// countries, because an imported result file may legitimately carry a code this
// build has no label for.
//
// Normalize is deliberately a pure spelling fix; use Canonical to also fold a
// vendor name such as "CLOUDFLARE" onto its region.
func Normalize(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

// NormalizeAll normalises and de-duplicates a list of region codes, preserving
// the input order so a user-supplied filter keeps its meaning. Vendor names are
// resolved through Canonical first, so a filter written as "cloudflare" and one
// written as "CDN" select the same rows and collapse into one entry.
func NormalizeAll(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		code := Canonical(item)
		if code == "" {
			continue
		}
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	return out
}

// IsSpecial reports whether a code is one of the non-country codes.
func IsSpecial(code string) bool {
	switch Canonical(code) {
	case CDN, Private, Unknown:
		return true
	}
	return false
}

// Of derives the region of a resolver endpoint. endpoint may be a bare
// hostname, a bare IP literal, a bracketed IPv6 literal, or a DoH URL
// ("https://dns.google/dns-query"); isPrivate is the verdict of the same
// private-range check the rest of the tool uses, so the two can never disagree.
// An empty result is never returned: an unplaceable endpoint is attributed to
// Unknown so that it stays visible and filterable.
func Of(endpoint string, isPrivate bool) string {
	host := hostOfEndpoint(endpoint)
	if host == "" {
		return Unknown
	}
	if isPrivate {
		return Private
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if region, ok := lookupNetworks(addr); ok {
			return region
		}
		// A literal address that no rule covers. Private ranges have already
		// been handled by the caller's flag, but guard the case where the
		// caller passed false by mistake.
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			return Private
		}
		return Unknown
	}
	// A hostname: match the curated suffix table, longest suffix first.
	lower := strings.ToLower(host)
	best := ""
	bestLen := -1
	for _, entry := range hostRegions {
		if lower == entry.suffix || strings.HasSuffix(lower, "."+entry.suffix) {
			if len(entry.suffix) > bestLen {
				best, bestLen = entry.region, len(entry.suffix)
			}
		}
	}
	if best != "" {
		return best
	}
	return Unknown
}

// hostOfEndpoint reduces an endpoint of any accepted shape to its host. It
// mirrors the tool's own endpoint parser closely enough for region derivation,
// without importing the transport package (which would be an import cycle).
func hostOfEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	// Strip a scheme ("https://", "udp://", ...).
	if i := strings.Index(endpoint, "://"); i >= 0 {
		endpoint = endpoint[i+3:]
	}
	// Strip userinfo, path, query and fragment.
	if i := strings.IndexAny(endpoint, "/?#"); i >= 0 {
		endpoint = endpoint[:i]
	}
	// Strip a port, handling the bracketed IPv6 form first because a bare IPv6
	// literal contains colons that are not a port separator.
	if strings.HasPrefix(endpoint, "[") {
		if i := strings.IndexByte(endpoint, ']'); i >= 0 {
			return endpoint[1:i]
		}
		return strings.TrimPrefix(endpoint, "[")
	}
	// A bare IPv6 literal is recognised by parsing it, which is unambiguous.
	// Only when it is not an address is a trailing ":port" stripped; a colon
	// count test would cut the last group off "2400:3200::1".
	if _, err := netip.ParseAddr(endpoint); err == nil {
		return endpoint
	}
	if i := strings.LastIndexByte(endpoint, ':'); i >= 0 && isDigits(endpoint[i+1:]) {
		endpoint = endpoint[:i]
	}
	return endpoint
}

// isDigits reports whether s is a non-empty run of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// lookupNetworks finds the region of a literal address using the longest
// matching prefix in the curated table.
func lookupNetworks(addr netip.Addr) (string, bool) {
	addr = addr.Unmap()
	best := ""
	bestBits := -1
	for _, entry := range networks {
		if !entry.prefix.Contains(addr) {
			continue
		}
		if bits := entry.prefix.Bits(); bits > bestBits {
			best, bestBits = entry.region, bits
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// Order returns the distinct region codes of the given rows in a stable
// presentation order: the codes with the most rows first, ties broken
// alphabetically, with the special codes always last. Counts are keyed by
// canonical code, so a row labelled "CLOUDFLARE" and one labelled "CDN" are
// counted together rather than producing two chips for the same thing.
func Order(counts map[string]int) []string {
	normalized := make(map[string]int, len(counts))
	for code, n := range counts {
		normalized[Canonical(code)] += n
	}

	out := make([]string, 0, len(normalized))
	for code := range normalized {
		out = append(out, code)
	}
	slices.SortFunc(out, func(a, b string) int {
		// Country codes sort before the special codes, so CDN / PRIVATE /
		// UNKNOWN always sit at the end of the chip list.
		if c := cmp.Compare(specialWeight(a), specialWeight(b)); c != 0 {
			return c
		}
		// More rows first: the regions that actually have data lead.
		if c := cmp.Compare(normalized[b], normalized[a]); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})
	return out
}

// specialWeight orders the special codes after every country code.
func specialWeight(code string) int {
	if IsSpecial(code) {
		return 1
	}
	return 0
}
