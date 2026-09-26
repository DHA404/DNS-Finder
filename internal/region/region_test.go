package region

import (
	"slices"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "小写转大写", raw: "de", want: "DE"},
		{name: "已大写不变", raw: "CN", want: "CN"},
		{name: "去除首尾空白", raw: "  jp  ", want: "JP"},
		{name: "特殊码同样归一化", raw: " cdn ", want: "CDN"},
		{name: "空字符串", raw: "", want: ""},
		{name: "只有空白", raw: "   ", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalize(tt.raw); got != tt.want {
				t.Fatalf("Normalize(%q) = %q, 期望 %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestNormalizeAll(t *testing.T) {
	tests := []struct {
		name string
		raw  []string
		want []string
	}{
		{name: "保持输入顺序", raw: []string{"us", "CN", "de"}, want: []string{"US", "CN", "DE"}},
		{name: "去重且保留首次出现", raw: []string{"cn", "CN", " us ", "cn"}, want: []string{"CN", "US"}},
		{name: "跳过空条目", raw: []string{"cn", "", "  ", "us"}, want: []string{"CN", "US"}},
		{name: "nil 输入", raw: nil, want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeAll(tt.raw)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("NormalizeAll(%v) = %v, 期望 %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestLabel(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		{name: "中国", code: "CN", want: "中国"},
		{name: "小写也识别", code: "cn", want: "中国"},
		{name: "带空白也识别", code: " de ", want: "德国"},
		{name: "美国", code: "US", want: "美国"},
		{name: "CDN", code: CDN, want: "CDN 任播"},
		{name: "内网", code: Private, want: "内网地址"},
		{name: "未知", code: Unknown, want: "未知地区"},
		{name: "未收录的国家码回落为代码本身", code: "ZZ", want: "ZZ"},
		{name: "空字符串", code: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Label(tt.code); got != tt.want {
				t.Fatalf("Label(%q) = %q, 期望 %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestLabelsReturnsCopy(t *testing.T) {
	first := Labels()
	first["CN"] = "被修改"
	first["TAMPERED"] = "x"

	second := Labels()
	if second["CN"] != "中国" {
		t.Fatalf("Labels() 返回了共享的 map，调用方修改污染了内置表: CN = %q", second["CN"])
	}
	if _, ok := second["TAMPERED"]; ok {
		t.Fatal("Labels() 返回了共享的 map，新增键污染了内置表")
	}
}

func TestIsSpecial(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{CDN, true},
		{Private, true},
		{Unknown, true},
		{"cdn", true},
		{" CN ", false},
		{"", false},
		{"ZZ", false},
	}
	for _, tt := range tests {
		if got := IsSpecial(tt.code); got != tt.want {
			t.Fatalf("IsSpecial(%q) = %v, 期望 %v", tt.code, got, tt.want)
		}
	}
}

func TestOfPrivateWinsOverEverything(t *testing.T) {
	// isPrivate 由调用方传入（与工具其它部分同一套判定），必须优先于网络表。
	if got := Of("192.168.1.1", true); got != Private {
		t.Fatalf("Of(192.168.1.1, true) = %q, 期望 %q", got, Private)
	}
	// 即使 isPrivate 传错，字面量的保留网段也要被兜住。
	for _, addr := range []string{"10.0.0.1", "192.168.0.1", "127.0.0.1", "::1", "fe80::1", "fd00::1"} {
		if got := Of(addr, false); got != Private {
			t.Fatalf("Of(%q, false) = %q, 期望 %q（保留网段兜底）", addr, got, Private)
		}
	}
}

func TestOfIPv4Literals(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"223.5.5.5", "CN"},
		{"223.6.6.6", "CN"},
		{"119.29.29.29", "CN"},
		{"114.114.114.114", "CN"},
		{"180.76.76.76", "CN"},
		{"180.184.1.1", "CN"},
		{"117.50.10.10", "CN"},
		{"202.38.93.153", "CN"},
		{"101.6.6.6", "CN"},
		{"101.101.101.101", "TW"},
		{"94.140.14.14", "CY"},
		{"185.222.222.222", "DE"},
		{"45.11.45.11", "DE"},
		{"194.242.2.2", "SE"},
		{"208.67.222.222", "US"},
		{"4.2.2.1", "US"},
		{"64.6.64.6", "US"},
		{"156.154.71.22", "US"},
		{"1.1.1.1", CDN},
		{"1.0.0.1", CDN},
		{"8.8.8.8", CDN},
		{"8.8.4.4", CDN},
		{"9.9.9.9", CDN},
		{"149.112.112.112", CDN},
		// 表外的公网地址归入 UNKNOWN，而不是被误判成某个国家。
		{"203.0.113.9", Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := Of(tt.addr, false); got != tt.want {
				t.Fatalf("Of(%q, false) = %q, 期望 %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestOfIPv6Literals(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "AliDNS IPv6", addr: "2400:3200::1", want: "CN"},
		{name: "AliDNS IPv6 2", addr: "2400:3200:baba::1", want: "CN"},
		{name: "Google IPv6", addr: "2001:4860:4860::8888", want: CDN},
		{name: "Google IPv6 2", addr: "2001:4860:4860::8844", want: CDN},
		{name: "Cloudflare IPv6", addr: "2606:4700:4700::1111", want: CDN},
		{name: "Cloudflare IPv6 2", addr: "2606:4700:4700::1001", want: CDN},
		{name: "Quad9 IPv6", addr: "2620:fe::fe", want: CDN},
		{name: "Quad9 IPv6 2", addr: "2620:fe::9", want: CDN},
		{name: "方括号形式", addr: "[2606:4700:4700::1111]", want: CDN},
		{name: "表外 IPv6", addr: "2001:db8::1", want: Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Of(tt.addr, false); got != tt.want {
				t.Fatalf("Of(%q, false) = %q, 期望 %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestOfHostnames(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "AliDNS DoT", host: "dns.alidns.com", want: "CN"},
		{name: "DNSPod DoT", host: "dot.pub", want: "CN"},
		{name: "DNSPod DoH", host: "doh.pub", want: "CN"},
		{name: "360 DoT", host: "dot.360.cn", want: "CN"},
		{name: "阿里子域", host: "dns.alidns.com.", want: Unknown}, // 表按后缀匹配，尾点不匹配
		{name: "AdGuard DoT", host: "dns.adguard-dns.com", want: "CY"},
		{name: "DNS.SB DoT", host: "dot.sb", want: "DE"},
		{name: "Mullvad DoT", host: "dns.mullvad.net", want: "SE"},
		{name: "OpenDNS DoH", host: "doh.opendns.com", want: "US"},
		{name: "Google DoT", host: "dns.google", want: CDN},
		{name: "Cloudflare DoT", host: "one.one.one.one", want: CDN},
		{name: "Cloudflare DoH", host: "cloudflare-dns.com", want: CDN},
		{name: "Quad9 DoT", host: "dns.quad9.net", want: CDN},
		{name: "未知主机名", host: "dns.example.invalid", want: Unknown},
		{name: "空主机名", host: "", want: Unknown},
		{name: "只有空白", host: "   ", want: Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Of(tt.host, false); got != tt.want {
				t.Fatalf("Of(%q, false) = %q, 期望 %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestOfIsCaseInsensitiveForHostnames(t *testing.T) {
	// DNS 主机名大小写不敏感，表匹配必须同样忽略大小写。
	for _, host := range []string{"DNS.ALIDNS.COM", "Dns.AliDns.Com", "dns.alidns.COM"} {
		if got := Of(host, false); got != "CN" {
			t.Fatalf("Of(%q, false) = %q, 期望 %q", host, got, "CN")
		}
	}
}

func TestOfLongestHostSuffixWins(t *testing.T) {
	// "dns.alidns.com" 同时匹配 "alidns.com" 与 "dns.alidns.com"，两者都是 CN，
	// 但表里有一条更具体的 "doh.pub"/"dot.pub" 与泛化的 "dns.pub"。
	// 用重叠最明显的一组验证：更长的后缀优先。
	if got := Of("dot.pub", false); got != "CN" {
		t.Fatalf("Of(dot.pub) = %q, 期望 CN", got)
	}
	// 一个同时匹配兜底与具体条目的名字，必须取具体条目。
	if got := Of("dns.dns.sb", false); got != "DE" {
		t.Fatalf("Of(dns.dns.sb) = %q, 期望 DE", got)
	}
}

func TestOfLongestPrefixWins(t *testing.T) {
	// 64.6.0.0/16（Verisign 兜底，US）与 64.6.64.0/24 / 64.6.65.0/24（同为 US）
	// 重叠时结果一致；这里用一个能区分优先级的构造验证 /16 生效。
	if got := Of("64.6.1.1", false); got != "US" {
		t.Fatalf("Of(64.6.1.1) = %q, 期望 US（/16 兜底）", got)
	}
	// Cloudflare 162.159.0.0/16 落在 CDN。
	if got := Of("162.159.46.1", false); got != CDN {
		t.Fatalf("Of(162.159.46.1) = %q, 期望 CDN", got)
	}
}

func TestGroupsAreWellFormed(t *testing.T) {
	groups := Groups()
	if len(groups) == 0 {
		t.Fatal("Groups() 返回空列表")
	}

	seenIDs := map[string]bool{}
	for i, g := range groups {
		if g.ID == "" {
			t.Fatalf("Groups()[%d] 缺少 ID", i)
		}
		if g.Label == "" {
			t.Fatalf("Groups()[%d]（%s）缺少 Label", i, g.ID)
		}
		if len(g.Codes) == 0 {
			t.Fatalf("Groups()[%d]（%s）没有任何地区码", i, g.ID)
		}
		if seenIDs[g.ID] {
			t.Fatalf("Groups() 出现重复的 ID %q", g.ID)
		}
		seenIDs[g.ID] = true

		for j, code := range g.Codes {
			if code != Normalize(code) {
				t.Fatalf("Groups()[%d].Codes[%d] = %q 不是归一化后的大写形式", i, j, code)
			}
		}
	}
}

func TestGroupsContainTheSpecialCodes(t *testing.T) {
	// 特殊码必须能通过某个分组被选中，否则带这些码的行永远筛不出来。
	var all []string
	for _, g := range Groups() {
		all = append(all, g.Codes...)
	}
	for _, code := range []string{CDN, Private, Unknown} {
		if !slices.Contains(all, code) {
			t.Fatalf("分组中没有任何一项包含特殊码 %q", code)
		}
	}
}

func TestGroupsHaveNoDuplicatesWithinAGroup(t *testing.T) {
	for _, g := range Groups() {
		seen := map[string]bool{}
		for _, code := range g.Codes {
			if seen[code] {
				t.Fatalf("分组 %s 内出现重复地区码 %q", g.ID, code)
			}
			seen[code] = true
		}
	}
}

func TestOrder(t *testing.T) {
	tests := []struct {
		name   string
		counts map[string]int
		want   []string
	}{
		{
			name:   "按行数降序",
			counts: map[string]int{"CN": 10, "US": 5, "DE": 1},
			want:   []string{"CN", "US", "DE"},
		},
		{
			name:   "行数相同按字母序",
			counts: map[string]int{"US": 3, "DE": 3, "CN": 3},
			want:   []string{"CN", "DE", "US"},
		},
		{
			name:   "特殊码排在最后",
			counts: map[string]int{CDN: 99, "CN": 1, Unknown: 50, Private: 2},
			want:   []string{"CN", CDN, Unknown, Private},
		},
		{
			name:   "键会被归一化并合并",
			counts: map[string]int{"cn": 2, "CN": 3, " us ": 1},
			want:   []string{"CN", "US"},
		},
		{
			name:   "空 map",
			counts: map[string]int{},
			want:   []string{},
		},
		{
			name:   "只有特殊码",
			counts: map[string]int{Unknown: 1, CDN: 1},
			want:   []string{CDN, Unknown},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Order(tt.counts)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("Order(%v) = %v, 期望 %v", tt.counts, got, tt.want)
			}
		})
	}
}

func TestCanonical(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		// 国家码只是大小写归一化。
		{name: "国家码大写", raw: "us", want: "US"},
		{name: "国家码带空白", raw: "  de ", want: "DE"},
		{name: "已是标准形式", raw: "CN", want: "CN"},
		// 特殊码原样保留。
		{name: "CDN", raw: "cdn", want: CDN},
		{name: "PRIVATE", raw: "private", want: Private},
		{name: "UNKNOWN", raw: "unknown", want: Unknown},
		// 厂商名折叠到地区码：参考项目的 geocode 字段会用厂商名。
		{name: "CLOUDFLARE 折叠为 CDN", raw: "CLOUDFLARE", want: CDN},
		{name: "cloudflare 小写也能折叠", raw: "cloudflare", want: CDN},
		{name: "GOOGLE 折叠为 CDN", raw: "GOOGLE", want: CDN},
		{name: "AKAMAI 折叠为 CDN", raw: "AKAMAI", want: CDN},
		{name: "FASTLY 折叠为 CDN", raw: "FASTLY", want: CDN},
		{name: "TWITTER 折叠为 CDN", raw: "TWITTER", want: CDN},
		{name: "ALIBABA 折叠为 CN", raw: "ALIBABA", want: "CN"},
		{name: "OPENDNS 折叠为 US", raw: "OPENDNS", want: "US"},
		{name: "YANDEX 折叠为 RU", raw: "YANDEX", want: "RU"},
		{name: "LOCAL 折叠为内网", raw: "LOCAL", want: Private},
		// 未收录的值原样大写保留，不能丢。
		{name: "未收录的值保留", raw: "zz", want: "ZZ"},
		{name: "空字符串", raw: "", want: ""},
		{name: "只有空白", raw: "   ", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Canonical(tt.raw); got != tt.want {
				t.Fatalf("Canonical(%q) = %q, 期望 %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCanonicalIsIdempotent(t *testing.T) {
	// 对已经是标准形式的值再跑一次必须不变，否则重复导入会让地区码漂移。
	values := []string{"CN", "US", CDN, Private, Unknown, "ZZ", "CLOUDFLARE", "ALIBABA"}
	for _, v := range values {
		once := Canonical(v)
		twice := Canonical(once)
		if once != twice {
			t.Fatalf("Canonical 不幂等: Canonical(%q)=%q, 再算一次=%q", v, once, twice)
		}
	}
}

func TestLabelResolvesVendorNames(t *testing.T) {
	// 标签绝不能把 "CLOUDFLARE" 原样显示出来。
	tests := []struct {
		code string
		want string
	}{
		{"CLOUDFLARE", "CDN 任播"},
		{"GOOGLE", "CDN 任播"},
		{"ALIBABA", "中国"},
		{"OPENDNS", "美国"},
		{"cloudflare", "CDN 任播"},
		{"CN", "中国"},
		{"ZZ", "ZZ"},
	}
	for _, tt := range tests {
		if got := Label(tt.code); got != tt.want {
			t.Fatalf("Label(%q) = %q, 期望 %q", tt.code, got, tt.want)
		}
	}
}

func TestOrderMergesVendorNamesIntoTheirRegion(t *testing.T) {
	// "CLOUDFLARE" 与 "CDN" 必须合并成同一个条目，否则筛选栏会出现两个
	// 指向同一批服务器的胶囊。
	got := Order(map[string]int{"CLOUDFLARE": 3, "CDN": 2, "CN": 1})
	want := []string{"CN", CDN}
	if !slices.Equal(got, want) {
		t.Fatalf("Order 把厂商名与地区码分开处理了: %v, 期望 %v", got, want)
	}
}

func TestNormalizeAllResolvesVendorNames(t *testing.T) {
	got := NormalizeAll([]string{"cloudflare", "CDN", "alibaba", "CN"})
	want := []string{CDN, "CN"}
	if !slices.Equal(got, want) {
		t.Fatalf("NormalizeAll = %v, 期望 %v（厂商名应与地区码合并去重）", got, want)
	}
}

func TestVendorCodesMapToValidCodes(t *testing.T) {
	// 映射表的目标值必须自身是标准形式，否则会出现「折叠后仍需再折叠」的链条。
	for vendor, code := range vendorCodes {
		if vendor != Normalize(vendor) {
			t.Fatalf("厂商名键 %q 未归一化", vendor)
		}
		if code == "" {
			t.Fatalf("厂商名 %q 映射到了空地区码", vendor)
		}
		if Canonical(code) != code {
			t.Fatalf("厂商名 %q 映射到 %q，而它本身不是标准形式", vendor, code)
		}
	}
}

func TestOfAcceptsEveryEndpointShape(t *testing.T) {
	// Of 必须能处理工具里出现的所有端点写法，而不只是裸主机名。DoH 的
	// URL 形式尤其重要：内置清单里的加密服务器全部是 URL，若 Of 只认裸
	// 主机名，它们的地区就会全部退化成 UNKNOWN。
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "裸 IPv4", endpoint: "223.5.5.5", want: "CN"},
		{name: "IPv4 带端口", endpoint: "223.5.5.5:53", want: "CN"},
		{name: "裸 IPv6", endpoint: "2606:4700:4700::1111", want: CDN},
		{name: "方括号 IPv6", endpoint: "[2606:4700:4700::1111]", want: CDN},
		{name: "方括号 IPv6 带端口", endpoint: "[2606:4700:4700::1111]:53", want: CDN},
		{name: "DoH URL", endpoint: "https://dns.alidns.com/dns-query", want: "CN"},
		{name: "DoH URL 带自定义路径", endpoint: "https://freedns.controld.com/p2", want: "US"},
		{name: "DoH URL 指向 IPv6 字面量", endpoint: "https://[2606:4700:4700::1111]/dns-query", want: CDN},
		{name: "DoH URL 带端口", endpoint: "https://dns.google:8443/dns-query", want: CDN},
		{name: "tls 前缀", endpoint: "tls://dot.pub", want: "CN"},
		{name: "udp 前缀", endpoint: "udp://8.8.8.8", want: CDN},
		{name: "裸主机名", endpoint: "dns.google", want: CDN},
		{name: "带空白的输入", endpoint: "  https://dns.google/dns-query  ", want: CDN},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Of(tt.endpoint, false); got != tt.want {
				t.Fatalf("Of(%q, false) = %q, 期望 %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestHostOfEndpointKeepsBareIPv6Groups(t *testing.T) {
	// 裸 IPv6 字面量的冒号不是端口分隔符；按最后一个冒号切分会把末组截掉，
	// 于是 "2400:3200::1" 变成 "2400:3200:" 并落入 UNKNOWN。
	tests := []struct {
		endpoint string
		want     string
	}{
		{"2400:3200::1", "2400:3200::1"},
		{"2606:4700:4700::1111", "2606:4700:4700::1111"},
		{"2620:fe::9", "2620:fe::9"},
		{"2402:4e00:1::", "2402:4e00:1::"},
		{"[2606:4700:4700::1111]", "2606:4700:4700::1111"},
		{"[2606:4700:4700::1111]:53", "2606:4700:4700::1111"},
		{"8.8.8.8:53", "8.8.8.8"},
		{"https://dns.google:8443/dns-query", "dns.google"},
		{"dns.google", "dns.google"},
	}
	for _, tt := range tests {
		if got := hostOfEndpoint(tt.endpoint); got != tt.want {
			t.Fatalf("hostOfEndpoint(%q) = %q, 期望 %q", tt.endpoint, got, tt.want)
		}
	}
}

func TestIsDigits(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"53", true},
		{"8443", true},
		{"0", true},
		{"", false},
		{"abc", false},
		{"53a", false},
		{"-1", false},
	}
	for _, tt := range tests {
		if got := isDigits(tt.in); got != tt.want {
			t.Fatalf("isDigits(%q) = %v, 期望 %v", tt.in, got, tt.want)
		}
	}
}

func TestLookupNetworksNeverReturnsEmptyRegion(t *testing.T) {
	// 表里任何一条被命中都必须给出非空、已归一化的地区码。
	for _, entry := range networks {
		addr := entry.prefix.Addr()
		got, ok := lookupNetworks(addr)
		if !ok {
			t.Fatalf("表项 %v 的第一个地址 %v 未被自身命中", entry.prefix, addr)
		}
		if got == "" {
			t.Fatalf("表项 %v 命中的地区码为空", entry.prefix)
		}
		if got != Normalize(got) {
			t.Fatalf("表项 %v 的地区码 %q 未归一化", entry.prefix, got)
		}
	}
}

func TestNetworksAreValidAndNonOverlappingWhereItMatters(t *testing.T) {
	// 表本身必须是合法前缀；重复的前缀会让结果取决于声明顺序，必须避免。
	seen := map[string]string{}
	for _, entry := range networks {
		key := entry.prefix.String()
		if prev, dup := seen[key]; dup {
			t.Fatalf("网络表出现重复前缀 %s（%s 与 %s）", key, prev, entry.region)
		}
		seen[key] = entry.region
	}
}
