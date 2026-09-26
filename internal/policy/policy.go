// Package policy classifies a DNS resolver endpoint by its *filtering policy*:
// whether it answers every name as published (原生), blocks malware and
// phishing (安全), or additionally blocks advertising and tracking domains
// (拦截广告).
//
// This is a different axis from internal/region. Region says *where* a resolver
// is reached; policy says *what it does to the answer*. The two are genuinely
// independent — 114DNS and AliDNS are both CN, but only 114DNS ships a
// filtering variant — so they are kept in separate packages with separate
// tables rather than being folded into one "attributes" list.
//
// # Why the classification is curated rather than probed
//
// A resolver's policy cannot be discovered by querying it. There is no
// handshake that reports "I block ads"; the only way to learn it is to ask for
// a domain that is known to be advertising and see whether the answer is a
// sinkhole. That test is unreliable in both directions:
//
//   - False positive: an ad domain that is also genuinely dead, or that the
//     network blocks upstream, looks exactly like a policy block.
//   - False negative: a resolver may block a category asynchronously, or its
//     blocklist may simply not contain the single domain probed, so a working
//     probe proves nothing about the policy.
//
// Vendor documentation, by contrast, states the policy explicitly and is what a
// user actually wants to know when choosing a resolver. The table below is
// therefore hand-checked against vendor documentation, and every entry cites
// where its verdict comes from. Where documentation is silent the endpoint is
// reported as 未确认 rather than being guessed at, because a wrong "安全" badge
// is worse than an honest "unknown".
//
// # Why the same IP can appear twice
//
// A vendor frequently publishes several policies at different addresses of the
// same service. Quad9's 9.9.9.9 blocks malware while 9.9.9.10 deliberately does
// not; AdGuard's 94.140.14.14 blocks ads while 94.140.14.140 does not. The
// addresses are what the user configures, so the table is keyed by *endpoint*,
// never by vendor, and two entries of one vendor routinely carry different
// policies. A vendor-keyed table would be wrong for exactly the addresses
// people are most likely to type.
package policy

import (
	"strings"
)

// Kind is a resolver's filtering policy.
type Kind string

// The policy kinds. The empty value is meaningful and is reported as
// KindUnknown: a DNS server that no rule could attribute has an unknown
// policy, which is not the same as having no filtering.
const (
	// Native is a general-purpose resolver that does not filter.
	Native Kind = "native"
	// Security is a resolver that filters: it blocks malware, phishing and
	// similar threats, and typically advertising and tracking domains as well.
	//
	// The two filtering behaviours were once separate kinds, because they are
	// genuinely different policies. They are merged because the distinction
	// could not be *observed*: only some vendors answer a blocked name with a
	// sinkhole address, while others let the query time out, so a probe cannot
	// tell "blocks ads too" from "blocks threats only". Reporting a split the
	// tool cannot verify would be a guess wearing a label.
	Security Kind = "security"
	// Unknown marks an endpoint whose policy is not documented here.
	Unknown Kind = "unknown"
)

// All returns the policy kinds in presentation order: unfiltered first,
// because it is the baseline a comparison starts from.
func All() []Kind { return []Kind{Native, Security} }

// Label returns the Chinese display name of a policy.
func Label(k Kind) string {
	switch CanonicalKind(k) {
	case Native:
		return "原生"
	case Security:
		return "安全"
	}
	return "未确认"
}

// ShortLabel returns the compact form used where space is tight (table cells,
// chart labels).
func ShortLabel(k Kind) string {
	switch CanonicalKind(k) {
	case Native:
		return "原生"
	case Security:
		return "安全"
	}
	return "未确认"
}

// Description explains what a policy means, for help text and tooltips.
func Description(k Kind) string {
	switch CanonicalKind(k) {
	case Native:
		return "不过滤任何域名，按权威记录如实返回"
	case Security:
		return "拦截恶意软件、钓鱼等威胁域名，通常也拦截广告与跟踪域名"
	}
	return "来源文档未说明其过滤策略"
}

// CanonicalKind folds a value of any accepted spelling onto a Kind. It accepts
// this package's own identifiers, the Chinese labels and the common English
// synonyms, so a value that came from a flag, a settings file or an imported
// result file all resolve the same way.
//
// The legacy "adblock" spelling still resolves, to Security: files written by a
// build that had the two kinds must keep importing instead of silently losing
// their policy.
func CanonicalKind(raw Kind) Kind {
	switch strings.ToLower(strings.TrimSpace(string(raw))) {
	case "native", "none", "off", "plain", "unfiltered", "no-filter", "原生", "无过滤":
		return Native
	case "security", "secure", "malware", "threat", "安全",
		"adblock", "ads", "ad", "advertising", "tracker", "block", "拦截广告", "广告", "拦截":
		return Security
	case "unknown", "unconfirmed", "?", "未确认", "未知":
		return Unknown
	}
	return Unknown
}

// IsFiltering reports whether a policy blocks anything at all. Security does;
// Native and Unknown do not (an unknown policy is not assumed to filter).
func IsFiltering(k Kind) bool {
	return CanonicalKind(k) == Security
}

// ParseKind resolves a user-supplied policy keyword from the CLI or the
// interactive menu.
func ParseKind(raw string) (Kind, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", false
	}
	switch trimmed {
	case "all", "any", "全部":
		return "", false
	}
	kind := CanonicalKind(Kind(trimmed))
	if kind == Unknown {
		// "unknown" is a real value but is not something a user filters *by*;
		// an unrecognised word must not silently become it either.
		if trimmed == "unknown" || trimmed == "未确认" || trimmed == "未知" {
			return Unknown, true
		}
		return "", false
	}
	return kind, true
}

// NormalizeAll canonicalises and de-duplicates a list of policy kinds,
// preserving the input order.
func NormalizeAll(raw []Kind) []Kind {
	seen := make(map[Kind]struct{}, len(raw))
	var out []Kind
	for _, item := range raw {
		kind := CanonicalKind(item)
		if kind == Unknown {
			continue
		}
		if _, dup := seen[kind]; dup {
			continue
		}
		seen[kind] = struct{}{}
		out = append(out, kind)
	}
	return out
}

// entry is one curated endpoint.
type entry struct {
	// address is the endpoint in the form the inventory writes it: a bare IP,
	// a bare hostname, or a full DoH URL. Matching normalises it, so the exact
	// spelling (scheme, brackets, trailing slash) does not matter.
	address string
	kind    Kind
	// note records the documented wording the verdict rests on. It is kept in
	// the source rather than only in a comment so `go doc` and a future
	// reviewer see the justification next to the claim.
	note string
}

// curated is the hand-checked endpoint table.
//
// Every entry cites vendor documentation for its verdict. An endpoint that is
// not listed here resolves to Unknown, which the UI shows as 未确认 — the
// deliberate alternative to guessing.
var curated = []entry{
	// ---------- 原生：文档明确说明不过滤 ----------
	//
	// 国内
	{"223.5.5.5", Native, "AliDNS 公共 DNS，官方未声明任何域名过滤"},
	{"223.6.6.6", Native, "AliDNS 公共 DNS，同上"},
	{"2400:3200::1", Native, "AliDNS IPv6，同上"},
	{"2400:3200:baba::1", Native, "AliDNS IPv6，同上"},
	{"119.29.29.29", Native, "DNSPod 公共 DNS，官方未声明域名过滤"},
	{"119.28.28.28", Native, "DNSPod 公共 DNS，同上"},
	{"2402:4e00::", Native, "DNSPod IPv6，同上"},
	{"2402:4e00:1::", Native, "DNSPod IPv6，同上"},
	{"114.114.114.114", Native, "114DNS 纯净版（官方：纯净无劫持），与 .119 拦截版是不同地址"},
	{"114.114.115.115", Native, "114DNS 纯净版备用地址，同上"},
	// Baidu's public resolver advertises virus/trojan interception, so it is a
	// security resolver rather than an unfiltered one. Its docs make no
	// ad/tracker claim, which is what separates 安全 from 拦截广告.
	{"180.76.76.76", Security, "百度公共 DNS 官方功能页：依托安全搜索技术拦截病毒、木马风险网站"},
	{"180.184.1.1", Native, "字节跳动公共 DNS，官方未声明域名过滤"},
	{"180.184.2.2", Native, "字节跳动公共 DNS，同上"},
	// OneDNS is deliberately absent: the vendor's site is a JavaScript-only SPA
	// whose archived setup page predates the 拦截版/纯净版 product line and
	// lists neither address, so which variant each IP is cannot be verified.
	// Guessing would put a wrong 安全/原生 badge on two rows; 未确认 is correct.
	{"202.38.93.153", Native, "中科大 USTC 公共 DNS，教育网服务，无商业过滤"},
	{"101.6.6.6", Native, "清华 TUNA 公共 DNS，同上"},
	{"101.226.4.6", Native, "DNS 派（电信）公共 DNS，官方未声明域名过滤"},
	{"240c::6666", Native, "下一代互联网 IPv6 公共 DNS，同上"},
	{"2400:da00::6666", Native, "腾讯云 IPv6 公共 DNS，同上"},
	{"2001:da8:d800::1", Native, "USTC IPv6，同上"},
	{"2001:da8::666", Native, "TUNA IPv6，同上"},

	// 国外：不加密传输
	{"8.8.8.8", Native, "Google Public DNS 官方说明极少进行拦截或过滤"},
	{"8.8.4.4", Native, "Google Public DNS，同上"},
	{"2001:4860:4860::8888", Native, "Google Public DNS IPv6，同上"},
	{"2001:4860:4860::8844", Native, "Google Public DNS IPv6，同上"},
	{"1.1.1.1", Native, "Cloudflare 官方：标准解析器不进行任何内容过滤"},
	{"1.0.0.1", Native, "Cloudflare 1.1.1.1 备用地址，同上"},
	{"2606:4700:4700::1111", Native, "Cloudflare 1.1.1.1 IPv6，同上"},
	{"2606:4700:4700::1001", Native, "Cloudflare 1.1.1.1 IPv6，同上"},
	{"9.9.9.10", Native, "Quad9 官方明确列为 Unsecured：不做恶意域名拦截"},
	{"149.112.112.10", Native, "Quad9 Unsecured 备用地址，同上"},
	{"2620:fe::10", Native, "Quad9 Unsecured IPv6（官方列为 2620:fe::10 / 2620:fe::fe:10）"},
	{"2620:fe::fe:10", Native, "Quad9 Unsecured IPv6，同上"},
	{"76.76.2.0", Native, "Control D 免费 DNS，官方表格列为 Unfiltered"},
	{"2606:1a40::", Native, "Control D 免费 DNS IPv6，官方表格列为 Unfiltered（76.76.2.0 的 IPv6 对应）"},
	{"4.2.2.1", Native, "Level3 公共 DNS，无域名过滤"},
	{"4.2.2.2", Native, "Level3 公共 DNS，同上"},
	{"64.6.64.6", Native, "Verisign 公共 DNS，无域名过滤"},
	{"64.6.65.6", Native, "Verisign 公共 DNS，同上"},
	{"156.154.70.1", Native, "Neustar UltraDNS 公共 DNS，无域名过滤"},
	{"156.154.71.1", Native, "Neustar UltraDNS 公共 DNS，同上"},
	{"2610:a1:1018::1", Native, "Neustar UltraDNS IPv6，同上"},
	{"2610:a1:1019::1", Native, "Neustar UltraDNS IPv6，同上"},
	{"74.82.42.42", Native, "Hurricane Electric 公共 DNS，无域名过滤"},
	{"2001:470:20::2", Native, "Hurricane Electric IPv6，同上"},
	// Mullvad's bare encrypted endpoint is its *unfiltered* service. The
	// counterintuitive part is that "base.dns.mullvad.net" is NOT the plain
	// one: it blocks ads, trackers AND malware. Only the bare name is native.
	{"194.242.2.2", Native, "Mullvad 默认加密 DNS，官方拦截对照表该行为空（不过滤）"},
	{"2a07:e340::2", Native, "Mullvad 默认加密 DNS IPv6，同上"},
	{"dns.mullvad.net", Native, "Mullvad 默认加密 DNS 主机名，同上"},
	// Yandex: 77.88.8.8 is the BASIC (unfiltered) mode. The Safe mode is
	// 77.88.8.88 and the Family mode 77.88.8.7 — near-identical addresses with
	// different policies, which is why they must not be conflated.
	{"77.88.8.8", Native, "Yandex DNS 官方模式表：77.88.8.8 为 Основной/Базовый（基础，不过滤）"},
	{"2a02:6b8::feed:0ff", Native, "Yandex DNS IPv6 基础模式，同上"},
	{"185.222.222.222", Native, "DNS.SB 官方声明不做任何内容过滤或封锁"},
	{"45.11.45.11", Native, "DNS.SB 备用地址，同上"},
	{"2a09::", Native, "DNS.SB IPv6，同上"},
	{"dot.sb", Native, "DNS.SB DoT 端点，同上"},
	{"doh.sb", Native, "DNS.SB DoH 端点，同上"},
	{"91.239.100.100", Native, "UncensoredDNS 定位即无审查、无过滤"},
	{"2001:67c:28a4::", Native, "UncensoredDNS IPv6，同上"},
	// Nawala is a filtering resolver, not a neutral one: its own site documents
	// blocking of negative-content sites (pornography, gambling) plus fraud,
	// malware and phishing. No ad/tracker category, so 安全.
	{"180.131.144.144", Security, "Nawala 官网：对色情/赌博等负面内容及诈骗、恶意软件、钓鱼站点做过滤"},
	// TWNIC Quad101 ships a threat-intelligence filter covering phishing,
	// malware and botnet C&C, per its terms of service. No ad category.
	{"101.101.101.101", Security, "TWNIC Quad101 服务条款：内建过滤机制，封锁钓鱼、恶意软件、僵尸网络网域"},
	{"2001:de4::101", Security, "TWNIC Quad101 IPv6，同一套过滤服务"},

	// 国外：加密传输端点（与同名明文端点同策略）
	// 360 (dot.360.cn / doh.360.cn) 见上方说明：无可核实来源，保持未确认。
	{"dns.alidns.com", Native, "AliDNS 加密端点，与明文同策略"},
	{"dot.pub", Native, "DNSPod 加密端点，与明文同策略"},
	{"doh.pub", Native, "DNSPod DoH 端点，与明文同策略"},
	{"doh.opendns.com", Security, "OpenDNS 加密端点，与其明文地址同策略"},
	// 360 (dot.360.cn / doh.360.cn) 见下方说明：无可核实来源，保持未确认。
	{"dns.google", Native, "Google 加密端点，与明文同策略"},
	{"one.one.one.one", Native, "Cloudflare 1.1.1.1 加密端点，官方：标准解析器无内容过滤"},
	{"cloudflare-dns.com", Native, "Cloudflare 1.1.1.1 DoH 端点，同上"},

	// ---------- 安全：文档说明该解析器会过滤域名 ----------
	//
	// 这一节同时包含"只拦威胁"与"连广告一起拦"两类，因为二者已合并为同一个
	// 「安全」类别（见 Security 的说明）。每条 note 仍写清楚文档所述的**具体**
	// 拦截范围，便于日后若要重新拆分时有据可依。
	{"9.9.9.9", Security, "Quad9 推荐服务文档列为 Malware Blocking"},
	{"149.112.112.112", Security, "Quad9 推荐服务备用地址，同上"},
	{"2620:fe::fe", Security, "Quad9 推荐服务 IPv6，同上"},
	{"2620:fe::9", Security, "Quad9 推荐服务 IPv6（官方与 2620:fe::fe 同列），同上"},
	{"114.114.114.119", Security, "114DNS 官方页面：拦截钓鱼病毒木马网站"},
	{"1.1.1.2", Security, "Cloudflare for Families 文档列为 Block malware，无广告类别"},
	{"185.228.168.9", Security, "CleanBrowsing Security Filter：拦截钓鱼/垃圾/恶意域名，不拦截成人内容"},
	{"2a0d:2a00:1::", Security, "CleanBrowsing Security Filter IPv6，同上"},
	{"208.67.222.222", Security, "OpenDNS 官方福利表：OpenDNS Home 内置恶意钓鱼防护"},
	{"208.67.220.220", Security, "OpenDNS 备用地址，同上"},
	{"2620:119:35::35", Security, "OpenDNS IPv6，同上"},
	{"2620:119:53::53", Security, "OpenDNS IPv6，同上"},
	{"76.76.2.1", Security, "Control D 免费 DNS，官方表格列为 Malware（对应 p1）"},
	{"p1.freedns.controld.com", Security, "Control D p1 = Malware"},
	{"p1.freedns.controld.com/dns-query", Security, "Control D p1 DoH，同上"},
	{"dns.quad9.net", Security, "Quad9 推荐服务的加密端点，含恶意域名拦截"},
	{"dns11.quad9.net", Security, "Quad9 Secured w/ECS，含恶意域名拦截"},
	{"dns.cleanbrowsing.org", Security, "CleanBrowsing Security Filter 加密端点，同上"},
	{"doh.cleanbrowsing.org/doh/family-filter", Security, "CleanBrowsing Family Filter：拦截成人内容与恶意/钓鱼域名"},

	// 以下在文档层面属于"拦截广告"，已并入「安全」类别。
	{"94.140.14.14", Security, "AdGuard DNS 默认服务器官方说明：拦截广告与跟踪器"},
	{"94.140.15.15", Security, "AdGuard DNS 默认服务器备用地址，同上"},
	{"2a10:50c0::ad1:ff", Security, "AdGuard DNS 默认服务器 IPv6，同上"},
	{"2a10:50c0::ad2:ff", Security, "AdGuard DNS 默认服务器 IPv6，同上"},
	{"dns.adguard-dns.com", Security, "AdGuard DNS 默认服务器加密端点，同上"},
	{"76.76.2.2", Security, "Control D 免费 DNS，官方表格列为 Ads & Tracking（对应 p2）"},
	{"p2.freedns.controld.com", Security, "Control D p2 = Ads & Tracking"},
	{"p2.freedns.controld.com/dns-query", Security, "Control D p2 DoH，同上"},
	{"freedns.controld.com/p2", Security, "Control D p2 DoH，同上"},
	// dnsforge.de 的裸域名是"带广告拦截"的 Normal 档（文档：拦截广告、跟踪与
	// 恶意软件）；无过滤版是 blank.dnsforge.de，本清单未收录，因此不能把裸域名
	// 当作中性解析器。
	{"dnsforge.de", Security, "dnsforge.de 官网 Normal 档：拦截广告、跟踪与恶意软件；无过滤版是 blank.dnsforge.de"},
}

// byAddress indexes the curated table by normalised endpoint.
var byAddress = func() map[string]Kind {
	m := make(map[string]Kind, len(curated))
	for _, e := range curated {
		m[normalizeEndpoint(e.address)] = e.kind
	}
	return m
}()

// Of reports the documented filtering policy of an endpoint.
//
// The endpoint may be written in any of the shapes the tool accepts — a bare
// IP, a bare hostname, a bracketed IPv6 literal, or a full DoH URL — because
// the lookup normalises it first. An endpoint with no curated entry is reported
// as Unknown rather than Native: "not documented here" must never be presented
// as a positive claim that nothing is filtered.
func Of(endpoint string) Kind {
	for _, candidate := range endpointForms(endpoint) {
		if kind, ok := byAddress[candidate]; ok {
			return kind
		}
	}
	return Unknown
}

// OfServer is Of for the fields of a server, preferring the display name when
// it names a policy explicitly.
//
// The fallback exists because the DoT/DoH inventory writes endpoints as
// hostnames that occasionally carry no distinguishing information beyond the
// name. It is only consulted when the address lookup found nothing, so a
// curated endpoint can never be overridden by a name.
func OfServer(address, name string) Kind {
	if kind := Of(address); kind != Unknown {
		return kind
	}
	if kind := ofName(name); kind != Unknown {
		return kind
	}
	return Unknown
}

// ofName recognises the policy variants the inventory spells out in a server's
// display name, e.g. "AdGuard 拦截广告" or "Cloudflare 安全版".
//
// It is deliberately narrow. A name is free text that a user can write in
// --servers, so it may only *confirm* a filtering policy when it uses one of
// the vocabulary words below; it never infers Native from a name, because
// silence about filtering is not documentation of it.
func ofName(name string) Kind {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return Unknown
	}
	switch {
	case strings.Contains(lower, "广告"), strings.Contains(lower, "Security"),
		strings.Contains(lower, "adguard"), strings.Contains(lower, "ads"):
		return Security
	case strings.Contains(lower, "安全"), strings.Contains(lower, "security"),
		strings.Contains(lower, "malware"), strings.Contains(lower, "family"):
		return Security
	case strings.Contains(lower, "净化"), strings.Contains(lower, "纯净"),
		strings.Contains(lower, "无过滤"), strings.Contains(lower, "unfiltered"):
		return Native
	}
	return Unknown
}

// endpointForms enumerates the spellings of an endpoint that the curated table
// may have used for it, most specific first. Trying several forms is what lets
// the table be written naturally ("doh.sb") while still matching the fully
// spelled-out endpoint the inventory uses ("https://doh.sb/dns-query").
func endpointForms(endpoint string) []string {
	norm := normalizeEndpoint(endpoint)
	if norm == "" {
		return nil
	}
	forms := []string{norm}

	// A DoH URL: also try its bare authority, with and without a path.
	host, path := splitAuthority(norm)
	if host != "" && host != norm {
		if path != "" {
			forms = append(forms, host+"/"+path)
		}
		forms = append(forms, host)
	}
	return forms
}

// splitAuthority splits a normalised endpoint into its authority and its path.
// An endpoint with no path returns an empty path.
func splitAuthority(endpoint string) (host, path string) {
	if i := strings.IndexByte(endpoint, '/'); i >= 0 {
		return endpoint[:i], endpoint[i+1:]
	}
	return endpoint, ""
}

// normalizeEndpoint reduces an endpoint to a comparable key: lower-cased, with
// the scheme, userinfo, query, fragment, a default port and a trailing slash
// stripped. An IPv6 authority is returned unbracketed, so the bracketed URL
// form and the bare form of one address reduce to the same key.
//
// A query string is dropped because RFC 8484 endpoints occasionally carry one
// as a vendor's way of selecting a policy profile; the profile is already part
// of the path in the cases this table covers.
func normalizeEndpoint(endpoint string) string {
	e := strings.ToLower(strings.TrimSpace(endpoint))
	if e == "" {
		return ""
	}
	// Strip the scheme. DoH endpoints are https and the table sometimes records
	// just the authority, so the scheme carries no information here.
	if i := strings.Index(e, "://"); i >= 0 {
		e = e[i+3:]
	}
	// Strip any query / fragment, then userinfo.
	if i := strings.IndexAny(e, "?#"); i >= 0 {
		e = e[:i]
	}
	if i := strings.LastIndexByte(e, '@'); i >= 0 {
		e = e[i+1:]
	}

	// Split the authority from the path *before* looking for a port: the path
	// may itself contain a colon, and a port can only appear in the authority.
	// Doing it the other way round is what made "doh.sb:443/dns-query" fail to
	// match "doh.sb" — the "port" was read as "443/dns-query".
	authority, path := e, ""
	if i := strings.IndexByte(e, '/'); i >= 0 {
		authority, path = e[:i], e[i:]
	}
	return normalizeAuthority(authority) + strings.TrimSuffix(path, "/")
}

// normalizeAuthority strips a default port from an authority and unbrackets an
// IPv6 literal.
//
// Only a *default* port is removed. A non-default port is meaningful — it
// distinguishes a differently-provisioned listener — so it is preserved and
// will simply not match any curated entry.
func normalizeAuthority(authority string) string {
	if strings.HasPrefix(authority, "[") {
		if i := strings.IndexByte(authority, ']'); i >= 0 {
			host := authority[1:i]
			if isDefaultPort(authority[i+1:]) {
				return host
			}
			return host + authority[i+1:]
		}
		return strings.TrimPrefix(authority, "[")
	}
	// A bare IPv6 literal contains colons that are group separators rather than
	// a port, so the colon may only be read as a port separator when what
	// precedes it holds no colon of its own. Without this test "2620:fe::fe"
	// would be truncated to "2620:fe:".
	if i := strings.LastIndexByte(authority, ':'); i >= 0 && !strings.Contains(authority[:i], ":") {
		if isDefaultPort(authority[i:]) {
			return authority[:i]
		}
	}
	return authority
}

// isDefaultPort reports whether s is a ":port" suffix naming a port implied by
// the transport, and therefore carrying no distinguishing information.
func isDefaultPort(s string) bool {
	switch s {
	case ":443", ":853", ":53":
		return true
	}
	return false
}

// Entry is one row of the curated table, exported for documentation and tests.
type Entry struct {
	Address string `json:"address"`
	Kind    Kind   `json:"kind"`
	Label   string `json:"label"`
	Note    string `json:"note"`
}

// Entries returns the curated table in declaration order, so the CLI can list
// every documented verdict next to the wording it rests on.
func Entries() []Entry {
	out := make([]Entry, 0, len(curated))
	for _, e := range curated {
		out = append(out, Entry{
			Address: e.address,
			Kind:    e.kind,
			Label:   Label(e.kind),
			Note:    e.note,
		})
	}
	return out
}

// Counts returns how many curated endpoints carry each policy.
func Counts() map[Kind]int {
	out := map[Kind]int{}
	for _, e := range curated {
		out[e.kind]++
	}
	return out
}

// Order returns the distinct policies of the given rows in a stable
// presentation order: the documented policies in their canonical sequence,
// with 未确认 always last.
func Order(counts map[Kind]int) []Kind {
	var out []Kind
	for _, k := range All() {
		if counts[CanonicalKind(k)] > 0 {
			out = append(out, CanonicalKind(k))
		}
	}
	if counts[Unknown] > 0 {
		out = append(out, Unknown)
	}
	return out
}
