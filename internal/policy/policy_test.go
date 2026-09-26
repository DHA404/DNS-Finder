package policy

import "testing"

func TestLabelAndDescription(t *testing.T) {
	tests := []struct {
		kind      Kind
		wantLabel string
		wantShort string
	}{
		{Native, "原生", "原生"},
		{Security, "安全", "安全"},
		{Unknown, "未确认", "未确认"},
		{"", "未确认", "未确认"},
		// 旧的 adblock 取值在合并后仍须渲染为「安全」，否则导入旧文件会出现
		// 一个没有名称的策略。
		{"adblock", "安全", "安全"},
	}
	for _, tt := range tests {
		if got := Label(tt.kind); got != tt.wantLabel {
			t.Errorf("Label(%q) = %q, 期望 %q", tt.kind, got, tt.wantLabel)
		}
		if got := ShortLabel(tt.kind); got != tt.wantShort {
			t.Errorf("ShortLabel(%q) = %q, 期望 %q", tt.kind, got, tt.wantShort)
		}
		if got := Description(tt.kind); got == "" {
			t.Errorf("Description(%q) 不应为空", tt.kind)
		}
	}
}

func TestCanonicalKindAcceptsAliases(t *testing.T) {
	tests := []struct {
		raw  Kind
		want Kind
	}{
		{"native", Native},
		{"NONE", Native},
		{"unfiltered", Native},
		{"原生", Native},
		{"无过滤", Native},
		{"security", Security},
		{"Malware", Security},
		{"安全", Security},
		// 合并前写入文件的 "adblock" 必须继续解析为「安全」，
		// 否则旧结果文件会丢掉整条策略信息。
		{"adblock", Security},
		{"ads", Security},
		{"拦截广告", Security},
		{"广告", Security},
		{"unknown", Unknown},
		{"未确认", Unknown},
		{"something-else", Unknown},
		{"", Unknown},
	}
	for _, tt := range tests {
		if got := CanonicalKind(tt.raw); got != tt.want {
			t.Errorf("CanonicalKind(%q) = %q, 期望 %q", tt.raw, got, tt.want)
		}
	}
}

func TestIsFiltering(t *testing.T) {
	tests := []struct {
		kind Kind
		want bool
	}{
		{Native, false},
		{Security, true},
		{Security, true},
		// An undocumented policy must never be presented as filtering: the
		// badge would be an unearned claim.
		{Unknown, false},
	}
	for _, tt := range tests {
		if got := IsFiltering(tt.kind); got != tt.want {
			t.Errorf("IsFiltering(%q) = %v, 期望 %v", tt.kind, got, tt.want)
		}
	}
}

func TestParseKind(t *testing.T) {
	tests := []struct {
		raw     string
		want    Kind
		wantOK  bool
		comment string
	}{
		{"native", Native, true, ""},
		{"安全", Security, true, ""},
		{"Security", Security, true, ""},
		{"unknown", Unknown, true, "unknown 是合法值，只是不用于筛选"},
		{"", "", false, "空值表示不过滤"},
		{"all", "", false, "all 表示不过滤"},
		{"bogus", "", false, "未知词不得静默变成 unknown"},
	}
	for _, tt := range tests {
		got, ok := ParseKind(tt.raw)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("ParseKind(%q) = (%q, %v), 期望 (%q, %v) %s",
				tt.raw, got, ok, tt.want, tt.wantOK, tt.comment)
		}
	}
}

func TestOfAcceptsEveryEndpointShape(t *testing.T) {
	// The same curated endpoint must be recognised whatever shape the caller
	// wrote it in, because the inventory, --servers and imported files all use
	// slightly different spellings.
	tests := []struct {
		endpoint string
		want     Kind
	}{
		{"1.1.1.2", Security}, // Cloudflare malware-blocking variant
		{" 1.1.1.2 ", Security},
		{"https://dns.adguard-dns.com/dns-query", Security},
		{"dns.adguard-dns.com", Security},
		{"DNS.ADGUARD-DNS.COM", Security},
		{"https://[2606:4700:4700::1111]/dns-query", Native}, // bracketed URL form reduces to the bare literal
		{"https://203.0.113.9/dns-query", Unknown},           // not curated -> unknown, not native
		{"[2620:fe::fe]", Security},
		{"2620:fe::fe", Security},
		{"https://doh.sb/dns-query", Native},
		{"https://doh.sb", Native},
		{"https://doh.sb:443/dns-query", Native},
	}
	for _, tt := range tests {
		if got := Of(tt.endpoint); got != tt.want {
			t.Errorf("Of(%q) = %q, 期望 %q", tt.endpoint, got, tt.want)
		}
	}
}

// TestQuad9IPv6VariantsAreNotConfused guards the single most easily botched
// pair in the whole table. Quad9's 2620:fe::9 belongs to the *Recommended*
// (malware-blocking) service and 2620:fe::10 to the Unsecured one; noting only
// the ::fe spelling would mislabel the other two.
func TestQuad9IPv6VariantsAreNotConfused(t *testing.T) {
	tests := []struct {
		endpoint string
		want     Kind
		why      string
	}{
		{"2620:fe::fe", Security, "推荐服务 IPv6"},
		{"2620:fe::9", Security, "推荐服务 IPv6 第二个地址"},
		{"2620:fe::10", Native, "Unsecured IPv6"},
		{"2620:fe::fe:10", Native, "Unsecured IPv6 第二个地址"},
		{"9.9.9.9", Security, "推荐服务 IPv4"},
		{"9.9.9.10", Native, "Unsecured IPv4"},
	}
	for _, tt := range tests {
		if got := Of(tt.endpoint); got != tt.want {
			t.Errorf("Of(%q) = %q, 期望 %q（%s）", tt.endpoint, got, tt.want, tt.why)
		}
	}
}

// TestVendorVariantsDifferWithinOneVendor documents the reason the table is
// keyed by endpoint rather than by vendor: the same vendor ships several
// policies at different addresses, and the addresses are what users configure.
func TestVendorVariantsDifferWithinOneVendor(t *testing.T) {
	groups := []struct {
		vendor   string
		native   string
		filtered string
		kind     Kind
	}{
		{"Quad9", "9.9.9.10", "9.9.9.9", Security},
		{"Cloudflare", "1.1.1.1", "1.1.1.2", Security},
		{"AdGuard", "94.140.14.140", "94.140.14.14", Security},
		{"Control D", "76.76.2.0", "76.76.2.2", Security},
		{"114DNS", "114.114.114.114", "114.114.114.119", Security},
	}
	for _, g := range groups {
		gotNative := Of(g.native)
		if g.native == "94.140.14.140" {
			// AdGuard's non-filtering server is deliberately *not* curated:
			// the tool does not ship it, so it must stay 未确认 rather than
			// being asserted to be unfiltered.
			if gotNative != Unknown {
				t.Errorf("%s 的 %s = %q, 期望 %q（未收录即未确认）", g.vendor, g.native, gotNative, Unknown)
			}
			continue
		}
		if gotNative != Native {
			t.Errorf("%s 的 %s = %q, 期望 %q", g.vendor, g.native, gotNative, Native)
		}
		if got := Of(g.filtered); got != g.kind {
			t.Errorf("%s 的 %s = %q, 期望 %q", g.vendor, g.filtered, got, g.kind)
		}
	}
}

// TestCounterintuitiveVendorMappings pins the verdicts that research showed are
// easy to get backwards. Each of these looks like it should be the *other*
// category, so a future edit that "tidies up" the table would silently
// reintroduce a wrong badge without failing any other test.
func TestCounterintuitiveVendorMappings(t *testing.T) {
	tests := []struct {
		endpoint string
		want     Kind
		why      string
	}{
		// The bare Mullvad name is the unfiltered service; the sibling named
		// "base" is the one that blocks ads, trackers AND malware.
		{"dns.mullvad.net", Native, "裸域名才是无过滤版，base.* 反而拦截广告与恶意域名"},
		{"194.242.2.2", Native, "同上，IPv4"},
		// Yandex: .8 is the Basic (unfiltered) mode; .88 is Safe, .7 is Family.
		{"77.88.8.8", Native, "77.88.8.8 是基础模式；安全模式是 77.88.8.88、家庭模式是 77.88.8.7"},
		// dnsforge.de's bare hostname is its Securitying "Normal" profile.
		{"dnsforge.de", Security, "裸域名为 Normal 档（含广告拦截），无过滤版是 blank.dnsforge.de"},
		{"https://dnsforge.de/dns-query", Security, "同上，DoH 端点"},
		// Baidu and Nawala both filter threats, so neither is a neutral resolver.
		{"180.76.76.76", Security, "百度公共 DNS 拦截病毒/木马"},
		{"180.131.144.144", Security, "Nawala 过滤负面内容与恶意站点"},
		{"101.101.101.101", Security, "Quad101 内建威胁情报过滤"},
		// AdGuard's default server blocks ads, so it is not merely 安全.
		{"dns.adguard-dns.com", Security, "AdGuard 默认服务器拦截广告与跟踪器"},
	}
	for _, tt := range tests {
		if got := Of(tt.endpoint); got != tt.want {
			t.Errorf("Of(%q) = %q, 期望 %q（%s）", tt.endpoint, got, tt.want, tt.why)
		}
	}
}

// TestUnconfirmedEndpointsStayUnknown records the endpoints that research could
// not pin down. They must remain 未确认: promoting any of them to a real policy
// would assert something no vendor page supports.
func TestUnconfirmedEndpointsStayUnknown(t *testing.T) {
	for _, endpoint := range []string{
		"117.50.10.10", // OneDNS：站点为纯 JS SPA，无法确认是拦截版还是纯净版
		"52.80.52.52",  // OneDNS 同上
		"168.95.1.1",   // HiNet：无可达的官方策略说明
		"dot.360.cn",   // 360：无可核实的默认过滤策略说明
		"doh.360.cn",   // 360 同上
	} {
		if got := Of(endpoint); got != Unknown {
			t.Errorf("Of(%q) = %q, 期望 %q（缺少可核实的文档依据）", endpoint, got, Unknown)
		}
	}
}

func TestOfUnknownForUncuratedEndpoint(t *testing.T) {
	// The distinction that matters: an endpoint nobody documented must be
	// reported as Unknown, never silently as Native.
	for _, endpoint := range []string{
		"203.0.113.7",
		"https://example.invalid/dns-query",
		"this-is-not-a-resolver.example",
		"",
	} {
		if got := Of(endpoint); got != Unknown {
			t.Errorf("Of(%q) = %q, 期望 %q", endpoint, got, Unknown)
		}
	}
}

func TestOfServerPrefersAddressThenName(t *testing.T) {
	tests := []struct {
		address string
		name    string
		want    Kind
	}{
		// A curated address always wins, even if the name suggests otherwise:
		// the address is the documented fact.
		{"9.9.9.9", "看起来像广告拦截", Security},
		// An uncurated address may be resolved through an explicit name.
		{"203.0.113.7", "AdGuard 拦截广告", Security},
		{"203.0.113.7", "Quad9 安全版", Security},
		{"203.0.113.7", "无过滤纯净版", Native},
		// Neither is curated -> unknown.
		{"203.0.113.7", "某公共 DNS", Unknown},
		{"203.0.113.7", "", Unknown},
	}
	for _, tt := range tests {
		if got := OfServer(tt.address, tt.name); got != tt.want {
			t.Errorf("OfServer(%q, %q) = %q, 期望 %q", tt.address, tt.name, got, tt.want)
		}
	}
}

// TestOfNameNeverInfersNativeFromSilence guards the conservative half of the
// name fallback: a name that says nothing about filtering must not be read as
// a promise that nothing is filtered.
func TestOfNameNeverInfersNativeFromSilence(t *testing.T) {
	for _, name := range []string{
		"AliDNS", "Cloudflare", "Google 1", "某地公共 DNS", "Quad9",
	} {
		if got := ofName(name); got != Unknown {
			t.Errorf("ofName(%q) = %q, 期望 %q（名称未说明策略时不得推断为原生）", name, got, Unknown)
		}
	}
}

func TestNormalizeEndpointStripsOnlyTheRightPort(t *testing.T) {
	tests := []struct {
		endpoint string
		want     string
	}{
		{"https://doh.sb:443/dns-query", "doh.sb/dns-query"},
		{"doh.sb:443", "doh.sb"},
		{"doh.sb:8443", "doh.sb:8443"}, // a non-default port is meaningful
		// A bare IPv6 literal must keep every group: stripping at the last
		// colon would truncate "2620:fe::fe" to "2620:fe:".
		{"2620:fe::fe", "2620:fe::fe"},
		{"[2620:fe::fe]", "2620:fe::fe"},
		{"[2620:fe::fe]:443", "2620:fe::fe"},
		{"[2620:fe::fe]:8443", "2620:fe::fe:8443"},
		// The bracketed URL form and the bare form must reduce to one key, so
		// the table only ever needs one of them.
		{"https://[2620:fe::fe]/dns-query", "2620:fe::fe/dns-query"},
		{"https://user:pw@doh.sb/dns-query", "doh.sb/dns-query"},
		{"https://doh.sb/dns-query?x=1", "doh.sb/dns-query"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeEndpoint(tt.endpoint); got != tt.want {
			t.Errorf("normalizeEndpoint(%q) = %q, 期望 %q", tt.endpoint, got, tt.want)
		}
	}
}

func TestNormalizeAllDropsUnknownAndDuplicates(t *testing.T) {
	// 合并后「安全」与旧的 "adblock" 是同一个类别，因此必须去重成一项。
	got := NormalizeAll([]Kind{"native", "NATIVE", "安全", Unknown, "adblock", "", "安全"})
	want := []Kind{Native, Security}
	if len(got) != len(want) {
		t.Fatalf("NormalizeAll = %v, 期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("NormalizeAll[%d] = %q, 期望 %q（完整 %v）", i, got[i], want[i], got)
		}
	}
}

func TestOrderPutsUnknownLast(t *testing.T) {
	counts := map[Kind]int{Native: 3, Security: 2, Unknown: 5}
	got := Order(counts)
	want := []Kind{Native, Security, Unknown}
	if len(got) != len(want) {
		t.Fatalf("Order = %v, 期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Order[%d] = %q, 期望 %q（完整 %v）", i, got[i], want[i], got)
		}
	}
}

// TestCuratedTableIsWellFormed checks the invariants the table itself must
// hold. A duplicated address with two different verdicts is the failure mode
// that would make Of() order-dependent and silently wrong.
func TestCuratedTableIsWellFormed(t *testing.T) {
	seen := make(map[string]Kind, len(curated))
	for _, e := range curated {
		key := normalizeEndpoint(e.address)
		if key == "" {
			t.Errorf("条目 %+v 的地址归一化后为空", e)
			continue
		}
		if prev, dup := seen[key]; dup {
			t.Errorf("地址 %q 重复收录：%q 与 %q", e.address, prev, e.kind)
			continue
		}
		seen[key] = e.kind

		if e.kind != Native && e.kind != Security {
			t.Errorf("条目 %q 的策略 %q 不是可展示的策略", e.address, e.kind)
		}
		// Every claim must cite the wording it rests on; an uncited verdict is
		// a guess, which is exactly what this package exists to avoid.
		if len([]rune(e.note)) < 8 {
			t.Errorf("条目 %q 的说明过短，无法作为依据: %q", e.address, e.note)
		}
	}
}

func TestEntriesAndCountsAreConsistent(t *testing.T) {
	entries := Entries()
	if len(entries) != len(curated) {
		t.Fatalf("Entries() 返回 %d 条, 期望 %d 条", len(entries), len(curated))
	}

	counts := Counts()
	total := 0
	for _, n := range counts {
		total += n
	}
	if total != len(curated) {
		t.Fatalf("Counts() 合计 %d, 期望 %d", total, len(curated))
	}

	// Every entry's Of() must agree with the table it came from, so the
	// exported listing cannot drift from the lookup.
	for _, e := range entries {
		if got := Of(e.Address); got != e.Kind {
			t.Errorf("Entries() 中 %q 标为 %q, 但 Of() 返回 %q", e.Address, e.Kind, got)
		}
		if e.Label != Label(e.Kind) {
			t.Errorf("Entries() 中 %q 的标签 = %q, 期望 %q", e.Address, e.Label, Label(e.Kind))
		}
	}
}

// TestEveryCuratedPolicyKindIsUsed makes sure a whole category never silently
// empties out, which would leave the viewer's filter with a dead chip.
func TestEveryCuratedPolicyKindIsUsed(t *testing.T) {
	counts := Counts()
	for _, k := range All() {
		if counts[k] == 0 {
			t.Errorf("策略 %q 在收录表中没有任何条目", k)
		}
	}
}
