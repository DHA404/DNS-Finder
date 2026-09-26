package data

import (
	"strings"
	"testing"

	"dns-opti/internal/model"
	"dns-opti/internal/region"
)

// knownProtocols 是模型层认可的全部协议。
var knownProtocols = []model.Protocol{
	model.ProtocolUDP, model.ProtocolDoT, model.ProtocolDoH, model.ProtocolDoH3,
}

func isKnownProtocol(p model.Protocol) bool {
	for _, k := range knownProtocols {
		if p == k {
			return true
		}
	}
	return false
}

// keysOf 计算服务器列表的 Key 序列。
func keysOf(servers []model.Server) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		out = append(out, s.Key())
	}
	return out
}

// assertNoDuplicateKeys 断言结果中没有重复的 Key。
func assertNoDuplicateKeys(t *testing.T, servers []model.Server, context string) {
	t.Helper()
	seen := map[string]int{}
	for i, s := range servers {
		if prev, dup := seen[s.Key()]; dup {
			t.Fatalf("%s 出现重复的 Key %q（下标 %d 与 %d）", context, s.Key(), prev, i)
		}
		seen[s.Key()] = i
	}
}

func TestServersNoFilter(t *testing.T) {
	got := Servers(nil, nil, nil, nil)
	if len(got) == 0 {
		t.Fatal("Servers(nil, nil, nil, nil) 返回空列表")
	}
	if len(got) != len(AllServers()) {
		t.Fatalf("Servers(nil, nil, nil, nil) 返回 %d 个, 与 AllServers() 的 %d 个不一致", len(got), len(AllServers()))
	}
	assertNoDuplicateKeys(t, got, "Servers(nil, nil, nil, nil)")
}

func TestServersProtocolFilter(t *testing.T) {
	for _, proto := range knownProtocols {
		t.Run(string(proto), func(t *testing.T) {
			got := Servers([]model.Protocol{proto}, nil, nil, nil)
			if len(got) == 0 {
				t.Fatalf("Servers([%s], nil) 返回空列表", proto)
			}
			assertNoDuplicateKeys(t, got, "Servers(["+string(proto)+"], nil)")

			wantCount := 0
			for _, s := range AllServers() {
				if s.Protocol == proto {
					wantCount++
				}
			}
			if len(got) != wantCount {
				t.Fatalf("Servers([%s], nil) 返回 %d 个, 期望 %d 个", proto, len(got), wantCount)
			}
			for i, s := range got {
				if s.Protocol != proto {
					t.Fatalf("Servers([%s], nil)[%d] 的协议 = %q, 期望 %q", proto, i, s.Protocol, proto)
				}
			}
		})
	}
}

func TestServersCategoryFilter(t *testing.T) {
	for _, cat := range []Category{CategoryCN, CategoryIntl} {
		t.Run(string(cat), func(t *testing.T) {
			got := Servers(nil, []Category{cat}, nil, nil)
			if len(got) == 0 {
				t.Fatalf("Servers(nil, [%s]) 返回空列表", cat)
			}
			assertNoDuplicateKeys(t, got, "Servers(nil, ["+string(cat)+"])")

			// 结果必须与无过滤列表中的同分类条目一致。
			want := map[string]bool{}
			for _, e := range serverList {
				if e.category == cat {
					want[e.server.Key()] = true
				}
			}
			if len(got) != len(want) {
				t.Fatalf("Servers(nil, [%s]) 返回 %d 个, 期望 %d 个", cat, len(got), len(want))
			}
			for i, s := range got {
				if !want[s.Key()] {
					t.Fatalf("Servers(nil, [%s])[%d] = %q 不属于分类 %s", cat, i, s.Key(), cat)
				}
			}
		})
	}
}

func TestServersBothFilters(t *testing.T) {
	tests := []struct {
		name       string
		protocols  []model.Protocol
		categories []Category
	}{
		{name: "UDP + 国内", protocols: []model.Protocol{model.ProtocolUDP}, categories: []Category{CategoryCN}},
		{name: "UDP + 国外", protocols: []model.Protocol{model.ProtocolUDP}, categories: []Category{CategoryIntl}},
		{name: "DoH + 国内", protocols: []model.Protocol{model.ProtocolDoH}, categories: []Category{CategoryCN}},
		{name: "DoH + 国外", protocols: []model.Protocol{model.ProtocolDoH}, categories: []Category{CategoryIntl}},
		{name: "DoT + 国内", protocols: []model.Protocol{model.ProtocolDoT}, categories: []Category{CategoryCN}},
		{name: "DoH3 + 国外", protocols: []model.Protocol{model.ProtocolDoH3}, categories: []Category{CategoryIntl}},
		{name: "全部协议 + 两个分类", protocols: knownProtocols, categories: []Category{CategoryCN, CategoryIntl}},
		{
			name:       "多协议 + 多分类",
			protocols:  []model.Protocol{model.ProtocolUDP, model.ProtocolDoT},
			categories: []Category{CategoryCN, CategoryIntl},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Servers(tt.protocols, tt.categories, nil, nil)
			assertNoDuplicateKeys(t, got, "Servers("+tt.name+")")

			protoSet := map[model.Protocol]bool{}
			for _, p := range tt.protocols {
				protoSet[p] = true
			}
			catSet := map[Category]bool{}
			for _, c := range tt.categories {
				catSet[c] = true
			}

			// 逐条与内置清单比对，确保过滤条件是正确的“与”关系。
			wantCount := 0
			for _, e := range serverList {
				if protoSet[e.server.Protocol] && catSet[e.category] {
					wantCount++
				}
			}
			if len(got) != wantCount {
				t.Fatalf("Servers(%v, %v) 返回 %d 个, 期望 %d 个", tt.protocols, tt.categories, len(got), wantCount)
			}
			for i, s := range got {
				if !protoSet[s.Protocol] {
					t.Fatalf("结果 [%d] = %q 的协议不在过滤集合内", i, s.Key())
				}
			}
		})
	}
}

func TestServersReturnsCopies(t *testing.T) {
	first := Servers(nil, nil, nil, nil)
	first[0].Name = "被修改"
	first[0].IsPrivate = true

	second := Servers(nil, nil, nil, nil)
	if second[0].Name == "被修改" || second[0].IsPrivate {
		t.Fatalf("Servers 返回的不是副本，调用方修改污染了内置清单: %+v", second[0])
	}
}

func TestServersPreservesDeclarationOrder(t *testing.T) {
	// 过滤只做筛选，不重排：结果必须是内置清单的子序列。
	all := AllServers()
	allIndex := map[string]int{}
	for i, s := range all {
		allIndex[s.Key()] = i
	}

	for _, proto := range knownProtocols {
		got := Servers([]model.Protocol{proto}, nil, nil, nil)
		prev := -1
		for i, s := range got {
			idx, ok := allIndex[s.Key()]
			if !ok {
				t.Fatalf("协议 %s 的结果 [%d] = %q 不在完整清单中", proto, i, s.Key())
			}
			if idx <= prev {
				t.Fatalf("协议 %s 的结果顺序与内置清单不一致: [%d] 的下标 %d 不大于前一行的 %d", proto, i, idx, prev)
			}
			prev = idx
		}
	}
}

func TestBuiltInServersAreWellFormed(t *testing.T) {
	all := AllServers()
	if len(all) == 0 {
		t.Fatal("AllServers() 返回空列表")
	}

	for i, s := range all {
		if strings.TrimSpace(s.Name) == "" {
			t.Fatalf("内置服务器 [%d]（%q）缺少 Name", i, s.Address)
		}
		if strings.TrimSpace(s.Address) == "" {
			t.Fatalf("内置服务器 [%d]（%q）缺少 Address", i, s.Name)
		}
		if !isKnownProtocol(s.Protocol) {
			t.Fatalf("内置服务器 %q（%q）的协议 %q 不是已知协议", s.Name, s.Address, s.Protocol)
		}
		// DoH / DoH3 必须使用 https 地址，UDP / DoT 必须是裸主机名或 IP。
		switch s.Protocol {
		case model.ProtocolDoH, model.ProtocolDoH3:
			if !strings.HasPrefix(s.Address, "https://") {
				t.Fatalf("%q 的地址 %q 不是 https:// 开头", s.Name, s.Address)
			}
		case model.ProtocolUDP, model.ProtocolDoT:
			if strings.Contains(s.Address, "://") {
				t.Fatalf("%q 的地址 %q 不应带协议前缀", s.Name, s.Address)
			}
		}
		// 内置条目默认不带标记位。
		if s.IsSystem {
			t.Fatalf("内置服务器 %q 不应预设 IsSystem", s.Name)
		}
	}
}

func TestServerListEntriesHaveValidCategory(t *testing.T) {
	for i, e := range serverList {
		switch e.category {
		case CategoryCN, CategoryIntl:
		default:
			t.Fatalf("内置服务器清单 [%d]（%q）的分类 %q 不是 cn/intl", i, e.server.Key(), e.category)
		}
	}
}

func TestEveryBuiltInServerCarriesACuratedRegion(t *testing.T) {
	// 地区码是查看器筛选与 UDP+DoH 配对的基础。若某条目漏写，它会静默退化成
	// 派生结果（加密端点会变成 UNKNOWN），从而在任何地区筛选下都消失。
	for i, e := range serverList {
		if strings.TrimSpace(e.region) == "" {
			t.Fatalf("内置服务器清单 [%d]（%q, %s）缺少地区码", i, e.server.Key(), e.server.Name)
		}
		if e.region != region.Normalize(e.region) {
			t.Fatalf("内置服务器清单 [%d]（%q）的地区码 %q 未归一化为大写", i, e.server.Key(), e.region)
		}
	}
}

func TestServersAssignCuratedRegion(t *testing.T) {
	// Servers 必须把条目自带的地区码传给返回值，而不是丢掉它去重新派生。
	// 这正是 DoH/DoH3 之前全被筛掉的原因：它们的 URL 地址无法被派生出地区。
	got := Servers(nil, nil, nil, nil)
	want := map[string]string{}
	for _, e := range serverList {
		want[e.server.Key()] = e.region
	}

	for _, s := range got {
		if s.Region != want[s.Key()] {
			t.Fatalf("服务器 %q（%s）的地区 = %q, 期望清单里的 %q",
				s.Address, s.Protocol.Label(), s.Region, want[s.Key()])
		}
	}
}

func TestServersRegionFilterCoversEveryProtocol(t *testing.T) {
	// 每个协议在每个出现的地区码下都必须能被筛出来。这是对上面那条 bug 的
	// 直接回归：之前按地区筛选时 DoH/DoH3 恒为 0。
	for _, code := range RegionCodes() {
		t.Run(code, func(t *testing.T) {
			filtered := Servers(nil, nil, []string{code}, nil)
			if len(filtered) == 0 {
				t.Fatalf("地区码 %q 筛出 0 个服务器", code)
			}
			got := map[model.Protocol]bool{}
			want := map[model.Protocol]bool{}
			for _, s := range filtered {
				got[s.Protocol] = true
			}
			for _, e := range serverList {
				if e.region == code {
					want[e.server.Protocol] = true
				}
			}
			for proto := range want {
				if !got[proto] {
					t.Fatalf("地区码 %q 下协议 %s 的服务器全部丢失", code, proto.Label())
				}
			}
		})
	}
}

func TestServersRegionFilterIsCaseInsensitive(t *testing.T) {
	upper := Servers(nil, nil, []string{"CN"}, nil)
	lower := Servers(nil, nil, []string{"cn"}, nil)
	mixed := Servers(nil, nil, []string{" cn "}, nil)

	if len(upper) == 0 {
		t.Fatal("地区筛选 CN 返回空列表")
	}
	if len(lower) != len(upper) || len(mixed) != len(upper) {
		t.Fatalf("地区筛选大小写/空白处理不一致: CN=%d, cn=%d, \" cn \"=%d",
			len(upper), len(lower), len(mixed))
	}
}

func TestServersRegionFilterRejectsUnknownCode(t *testing.T) {
	// 不存在的地区码返回空结果，而不是被当成「无过滤」而返回全部。
	if got := Servers(nil, nil, []string{"ZZ"}, nil); len(got) != 0 {
		t.Fatalf("地区码 ZZ 筛出 %d 个服务器, 期望 0 个（不得当作无过滤）", len(got))
	}
}

func TestServersRegionFilterCombinesWithProtocol(t *testing.T) {
	// 地区与协议是「与」关系。
	got := Servers([]model.Protocol{model.ProtocolDoH}, nil, []string{"CN"}, nil)
	if len(got) == 0 {
		t.Fatal("DoH + CN 筛出 0 个服务器")
	}
	for _, s := range got {
		if s.Protocol != model.ProtocolDoH {
			t.Fatalf("协议过滤失效: %+v", s)
		}
		if s.Region != "CN" {
			t.Fatalf("地区过滤失效: %+v", s)
		}
	}
}

func TestRegionCodesAreWellFormed(t *testing.T) {
	codes := RegionCodes()
	if len(codes) == 0 {
		t.Fatal("RegionCodes() 返回空列表")
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if code == "" {
			t.Fatal("RegionCodes() 含空地区码")
		}
		if code != region.Normalize(code) {
			t.Fatalf("RegionCodes() 含未归一化的地区码 %q", code)
		}
		if seen[code] {
			t.Fatalf("RegionCodes() 出现重复地区码 %q", code)
		}
		seen[code] = true
	}
}

func TestBuiltInInventoryHasIPv6Endpoints(t *testing.T) {
	// IPv6 支持必须由内置清单真正覆盖：每个协议都应至少有一个 IPv6 端点，
	// 否则 --ip-version=ipv6 在某些协议下会无服务器可测。
	byProto := map[model.Protocol]int{}
	for _, e := range serverList {
		// 主机名端点（DoT）在解析时按所选地址族取地址，本身不固定族。
		if familyOfAddress(e.server.Address) == model.IPv6 {
			byProto[e.server.Protocol]++
		}
	}

	// UDP 与 DoH 必须有可直接寻址的 IPv6 端点。
	for _, proto := range []model.Protocol{model.ProtocolUDP, model.ProtocolDoH} {
		if byProto[proto] == 0 {
			t.Fatalf("内置清单没有任何 %s 的 IPv6 端点", proto.Label())
		}
	}
}

// familyOfAddress 判定地址的地址族，测试内的小工具。
func familyOfAddress(address string) model.IPVersion {
	host := address
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.Count(host, ":") >= 2 {
		return model.IPv6
	}
	return model.IPAny
}

// assertCleanDomainList 校验域名列表不含注释、空行与重复项。
func assertCleanDomainList(t *testing.T, name string, domains []string) {
	t.Helper()
	if len(domains) == 0 {
		t.Fatalf("%s 为空", name)
	}
	seen := map[string]int{}
	for i, d := range domains {
		if strings.TrimSpace(d) == "" {
			t.Fatalf("%s[%d] 是空白条目", name, i)
		}
		if strings.HasPrefix(d, "#") {
			t.Fatalf("%s[%d] = %q 是注释行，未被过滤", name, i, d)
		}
		if strings.ContainsAny(d, " \t") {
			t.Fatalf("%s[%d] = %q 仍含空白字符，未做裁剪", name, i, d)
		}
		if strings.Contains(d, "://") {
			t.Fatalf("%s[%d] = %q 不是域名", name, i, d)
		}
		if prev, dup := seen[d]; dup {
			t.Fatalf("%s 出现重复域名 %q（下标 %d 与 %d）", name, d, prev, i)
		}
		seen[d] = i
	}
}

func TestDomainListsAreClean(t *testing.T) {
	assertCleanDomainList(t, "CNDomains()", CNDomains())
	assertCleanDomainList(t, "IntlDomains()", IntlDomains())
}

func TestDomainListsHaveNoOverlap(t *testing.T) {
	// 国内外域名必须严格分开，同一个域名不能同时出现在两个列表里。
	cn := map[string]bool{}
	for _, d := range CNDomains() {
		cn[d] = true
	}
	for _, d := range IntlDomains() {
		if cn[d] {
			t.Fatalf("域名 %q 同时出现在国内与国外列表中", d)
		}
	}
}

func TestDomainListsReturnFreshSlices(t *testing.T) {
	first := CNDomains()
	first[0] = "tampered.example"

	second := CNDomains()
	if second[0] == "tampered.example" {
		t.Fatal("CNDomains() 返回了共享底层数组，调用方修改污染了内置列表")
	}
}

func TestParseDomainList(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "空字符串", raw: "", want: nil},
		{name: "只有注释与空行", raw: "# 注释\n\n   \n# 又一行注释\n", want: nil},
		{name: "基本解析", raw: "a.com\nb.com\n", want: []string{"a.com", "b.com"}},
		{name: "跳过注释与空行", raw: "# 头部\na.com\n\n# 中间\nb.com\n  \n", want: []string{"a.com", "b.com"}},
		{name: "去除首尾空白与 CR", raw: "  a.com  \r\n\tb.com\r\n", want: []string{"a.com", "b.com"}},
		{name: "只有行内井号不视为注释", raw: "a.com # 行内说明\n", want: []string{"a.com # 行内说明"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDomainList(tt.raw)
			if len(got) != len(tt.want) {
				t.Fatalf("parseDomainList(%q) = %v, 期望 %v", tt.raw, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("parseDomainList(%q)[%d] = %q, 期望 %q", tt.raw, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestServersEmptyFilterResultIsEmptyNotNil(t *testing.T) {
	// 不存在的协议组合应返回空结果（而不是把过滤当作无过滤）。
	got := Servers([]model.Protocol{model.Protocol("quic")}, nil, nil, nil)
	if len(got) != 0 {
		t.Fatalf("Servers 用未知协议过滤 = %v, 期望空结果", keysOf(got))
	}
	got = Servers(nil, []Category{Category("mars")}, nil, nil)
	if len(got) != 0 {
		t.Fatalf("Servers 用未知分类过滤 = %v, 期望空结果", keysOf(got))
	}
}
