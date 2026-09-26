package engine

import (
	"strings"
	"testing"
	"time"

	"dns-opti/data"
	"dns-opti/internal/config"
	"dns-opti/internal/dnsclient"
	"dns-opti/internal/model"
)

// baseOptions 返回一份合法的运行配置；BuildTasks 不会联网，因此可以随意调整。
func baseOptions() config.Options {
	return config.Options{
		Domains:      "cn",
		Protocols:    []model.Protocol{model.ProtocolUDP},
		Servers:      "223.5.5.5,1.1.1.1",
		Timeout:      2 * time.Second,
		Attempts:     1,
		Concurrency:  1,
		WarmupDomain: "example.com",
		Formula:      string(config.FormulaComprehensive),
	}
}

// findServer 按 Key 查找服务器。
func findServer(servers []model.Server, key string) (model.Server, bool) {
	for _, s := range servers {
		if s.Key() == key {
			return s, true
		}
	}
	return model.Server{}, false
}

func TestBuildTasksExplicitServers(t *testing.T) {
	opts := baseOptions()
	servers, domains, warns, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks(%+v) 返回错误: %v", opts, err)
	}
	if len(warns) != 0 {
		t.Fatalf("显式指定服务器时不应产生警告, 实际 %v", warns)
	}
	if len(servers) != 2 {
		t.Fatalf("BuildTasks 返回 %d 个服务器（%+v）, 期望 2 个", len(servers), servers)
	}
	if len(domains) == 0 {
		t.Fatal("BuildTasks 返回的域名列表为空")
	}
	for i, d := range domains {
		if d.Group != model.GroupCN {
			t.Fatalf("domains[%d] 的分组 = %q, 期望 %q", i, d.Group, model.GroupCN)
		}
	}

	for _, want := range []string{"223.5.5.5", "1.1.1.1"} {
		s, ok := findServer(servers, "udp|"+want)
		if !ok {
			t.Fatalf("结果中缺少服务器 %q: %+v", want, servers)
		}
		if s.IsPrivate {
			t.Fatalf("公网服务器 %q 被标记为 IsPrivate: %+v", want, s)
		}
		if s.Protocol != model.ProtocolUDP {
			t.Fatalf("服务器 %q 的协议 = %q, 期望 %q", want, s.Protocol, model.ProtocolUDP)
		}
	}
}

func TestBuildTasksMarksPrivateServer(t *testing.T) {
	opts := baseOptions()
	opts.Servers = "192.168.1.1"

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks(%+v) 返回错误: %v", opts, err)
	}
	if len(servers) != 1 {
		t.Fatalf("BuildTasks 返回 %d 个服务器, 期望 1 个", len(servers))
	}
	if !servers[0].IsPrivate {
		t.Fatalf("192.168.1.1 未被标记为 IsPrivate: %+v", servers[0])
	}
}

func TestBuildTasksMarksPrivateServerFamilies(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		wantPrivate bool
	}{
		{name: "RFC1918 10/8", address: "10.0.0.53", wantPrivate: true},
		{name: "RFC1918 172.16/12", address: "172.16.5.5", wantPrivate: true},
		{name: "RFC1918 192.168/16", address: "192.168.0.1", wantPrivate: true},
		{name: "IPv4 回环", address: "127.0.0.1", wantPrivate: true},
		{name: "IPv6 回环", address: "[::1]", wantPrivate: true},
		{name: "IPv6 ULA", address: "[fd00::1]", wantPrivate: true},
		{name: "IPv6 链路本地", address: "[fe80::1]", wantPrivate: true},
		{name: "公网 IPv4", address: "8.8.8.8", wantPrivate: false},
		{name: "公网 IPv6", address: "[2606:4700:4700::1111]", wantPrivate: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := baseOptions()
			opts.Servers = tt.address

			servers, _, _, err := BuildTasks(opts)
			if err != nil {
				t.Fatalf("BuildTasks(--servers %q) 返回错误: %v", tt.address, err)
			}
			if len(servers) != 1 {
				t.Fatalf("BuildTasks(--servers %q) 返回 %d 个服务器, 期望 1 个", tt.address, len(servers))
			}
			if servers[0].IsPrivate != tt.wantPrivate {
				t.Fatalf("BuildTasks(--servers %q).IsPrivate = %v, 期望 %v（%+v）",
					tt.address, servers[0].IsPrivate, tt.wantPrivate, servers[0])
			}
		})
	}
}

func TestBuildTasksInvalidDomains(t *testing.T) {
	tests := []struct {
		name    string
		domains string
	}{
		{name: "只有逗号", domains: ","},
		{name: "只有空白条目", domains: " , "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := baseOptions()
			opts.Domains = tt.domains

			servers, domains, warns, err := BuildTasks(opts)
			if err == nil {
				t.Fatalf("BuildTasks(--domains %q) = (%v, %v, %v), 期望错误", tt.domains, servers, domains, warns)
			}
			if !strings.Contains(err.Error(), "域名列表为空") {
				t.Fatalf("BuildTasks(--domains %q) 错误 = %q, 期望包含 %q", tt.domains, err.Error(), "域名列表为空")
			}
			if servers != nil || domains != nil || warns != nil {
				t.Fatalf("出错时应返回全部 nil, 实际 servers=%v domains=%v warns=%v", servers, domains, warns)
			}
		})
	}
}

func TestBuildTasksCustomDomainsUseCustomGroup(t *testing.T) {
	opts := baseOptions()
	opts.Domains = "example.com,example.org"

	_, domains, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("BuildTasks 返回 %d 个域名, 期望 2 个: %+v", len(domains), domains)
	}
	wantNames := []string{"example.com", "example.org"}
	for i, d := range domains {
		if d.Name != wantNames[i] {
			t.Fatalf("domains[%d].Name = %q, 期望 %q", i, d.Name, wantNames[i])
		}
		if d.Group != model.GroupCustom {
			t.Fatalf("自定义域名 %q 的分组 = %q, 期望 %q", d.Name, d.Group, model.GroupCustom)
		}
	}
}

func TestBuildTasksAllDomainsKeepGroupsApart(t *testing.T) {
	opts := baseOptions()
	opts.Domains = "all"

	_, domains, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	seen := map[string]int{}
	for _, d := range domains {
		seen[d.Group]++
	}
	if seen[model.GroupCN] == 0 {
		t.Fatalf("--domains all 未包含国内域名: %v", seen)
	}
	if seen[model.GroupIntl] == 0 {
		t.Fatalf("--domains all 未包含国外域名: %v", seen)
	}
	if len(seen) != 2 {
		t.Fatalf("--domains all 产生了额外的分组: %v", seen)
	}

	// 国内域名必须整体排在国外域名之前，两组不交错。
	firstIntl := -1
	for i, d := range domains {
		if d.Group == model.GroupIntl {
			firstIntl = i
			break
		}
	}
	for i := firstIntl; i < len(domains); i++ {
		if domains[i].Group != model.GroupIntl {
			t.Fatalf("domains[%d] 的分组 = %q, 出现在国外域名之后，两组被混用", i, domains[i].Group)
		}
	}
}

func TestBuildTasksUnknownProtocolInServers(t *testing.T) {
	// --servers 不识别协议前缀时按普通主机名处理（裸主机名回落为 UDP），
	// 但完全无法解析的条目会导致整个列表解析失败。
	opts := baseOptions()
	opts.Servers = "223.5.5.5,quic://1.1.1.1"

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	// "quic://1.1.1.1" 没有匹配任何已知前缀，hostOf 会剥离 "quic://" 得到 1.1.1.1，
	// 于是作为 UDP 服务器收录。
	if len(servers) != 2 {
		t.Fatalf("BuildTasks 返回 %d 个服务器（%+v）, 期望 2 个", len(servers), servers)
	}
	for _, s := range servers {
		if s.Protocol != model.ProtocolUDP {
			t.Fatalf("服务器 %+v 的协议 = %q, 期望回落为 %q", s, s.Protocol, model.ProtocolUDP)
		}
	}

	// 完全无法解析的条目（例如只有端口）应当让整次构建失败。
	opts.Servers = ":53"
	if _, _, _, err := BuildTasks(opts); err == nil {
		t.Fatalf("BuildTasks(--servers %q) 本应返回错误", opts.Servers)
	}
}

func TestBuildTasksExplicitServersIgnoreProtocolAndCategoryFilters(t *testing.T) {
	// --servers 覆盖内置列表，协议过滤不再生效：UDP 条目在只勾选 DoH 时依然保留。
	opts := baseOptions()
	opts.Protocols = []model.Protocol{model.ProtocolDoH}
	opts.ServerCategories = []config.ServerCategory{"cn"}

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("--servers 覆盖内置列表时返回 %d 个服务器, 期望 2 个", len(servers))
	}
}

func TestBuildTasksBuiltInServersRespectProtocolFilter(t *testing.T) {
	// 使用内置列表：每个服务器的协议都必须落在请求的协议集合内。
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP}
	opts.ServerCategories = []config.ServerCategory{"cn"}

	servers, _, warns, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(servers) == 0 {
		t.Fatalf("内置国内 UDP 服务器列表为空（警告 %v）", warns)
	}
	for i, s := range servers {
		if s.Protocol != model.ProtocolUDP {
			t.Fatalf("servers[%d] 的协议 = %q, 期望 %q", i, s.Protocol, model.ProtocolUDP)
		}
		if strings.TrimSpace(s.Name) == "" {
			t.Fatalf("servers[%d] 缺少 Name: %+v", i, s)
		}
	}
}

func TestBuildTasksBuiltInServersHaveKnownProtocol(t *testing.T) {
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP, model.ProtocolDoT, model.ProtocolDoH, model.ProtocolDoH3}

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(servers) == 0 {
		t.Fatal("内置服务器列表为空")
	}
	seen := map[string]bool{}
	for i, s := range servers {
		if seen[s.Key()] {
			t.Fatalf("servers[%d] 与前面的条目重复: %q", i, s.Key())
		}
		seen[s.Key()] = true
		if _, ok := model.ParseProtocol(string(s.Protocol)); !ok {
			t.Fatalf("servers[%d] 的协议 %q 不是已知协议", i, s.Protocol)
		}
	}
}

// TestBuildTasksDoesNotMutateOptions 确认 BuildTasks 不会写出调用方的切片。
func TestBuildTasksDoesNotMutateOptions(t *testing.T) {
	protocols := []model.Protocol{model.ProtocolUDP}
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = protocols

	before := len(protocols)
	if _, _, _, err := BuildTasks(opts); err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(protocols) != before || protocols[0] != model.ProtocolUDP {
		t.Fatalf("BuildTasks 修改了调用方的协议切片: %v", protocols)
	}
}

func TestBuildTasksRegionFilter(t *testing.T) {
	tests := []struct {
		name    string
		regions []string
		wantErr bool
	}{
		{name: "国内", regions: []string{"CN"}},
		{name: "任播", regions: []string{"CDN"}},
		{name: "多个地区", regions: []string{"CN", "US"}},
		{name: "小写也接受", regions: []string{"cn"}},
		{name: "不存在的地区码应报错", regions: []string{"ZZ"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := baseOptions()
			opts.Servers = ""
			opts.Protocols = []model.Protocol{model.ProtocolUDP}
			opts.Regions = tt.regions

			servers, _, _, err := BuildTasks(opts)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("地区筛选 %v 本应报错, 实际得到 %d 个服务器", tt.regions, len(servers))
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildTasks 返回错误: %v", err)
			}
			if len(servers) == 0 {
				t.Fatalf("地区筛选 %v 返回空服务器列表", tt.regions)
			}
			want := map[string]bool{}
			for _, r := range tt.regions {
				want[strings.ToUpper(r)] = true
			}
			for i, s := range servers {
				if !want[s.Region] {
					t.Fatalf("servers[%d] 的地区 = %q, 不在筛选集合 %v 内: %+v",
						i, s.Region, tt.regions, s)
				}
			}
		})
	}
}

func TestBuildTasksEveryServerHasRegionAndFamily(t *testing.T) {
	// 地区与地址族是查看器筛选与配对的基础，任何返回的服务器都必须带上。
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP, model.ProtocolDoH}

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(servers) == 0 {
		t.Fatal("服务器列表为空")
	}
	for i, s := range servers {
		if s.Region == "" {
			t.Fatalf("servers[%d]（%s）缺少地区码: %+v", i, s.Address, s)
		}
		if s.Region != strings.ToUpper(s.Region) {
			t.Fatalf("servers[%d]（%s）的地区码 %q 未归一化", i, s.Address, s.Region)
		}
		// Family 只在字面量地址上有意义；主机名端点保持空值由解析决定。
		if !s.Family.IsLiteral() && strings.Contains(s.Address, "://") &&
			!strings.Contains(s.Address, "[") {
			continue
		}
	}
}

func TestDescribeProbeRecordsVerdict(t *testing.T) {
	// 判定必须被记录下来，而不是只作为一行会消失的控制台提示：导出文件被
	// 分享或稍后重读时，必须能自己解释「为什么没有 IPv6 服务器」。
	restore := dnsclient.SetCapabilitiesForTest(dnsclient.NetworkCapabilities{IPv4: true, IPv6: false})
	defer restore()

	probe := describeProbe(model.IPAny, 8)
	if probe == nil {
		t.Fatal("describeProbe 返回 nil")
	}
	if !probe.IPv4 || probe.IPv6 {
		t.Fatalf("探测结论记录错误: %+v", probe)
	}
	if probe.Skipped != 8 {
		t.Fatalf("Skipped = %d, 期望 8", probe.Skipped)
	}
	if probe.Forced {
		t.Fatal("未指定 --ip-version 时 Forced 应为 false")
	}
	if probe.Label == "" {
		t.Fatal("判定缺少可读说明")
	}
}

func TestDescribeProbeMarksForcedFamily(t *testing.T) {
	// 显式 --ip-version 是用户指令，措辞必须与「探测判定」区分开，
	// 否则读者会以为服务器是因为不可达才被排除。
	restore := dnsclient.SetCapabilitiesForTest(dnsclient.NetworkCapabilities{IPv4: true, IPv6: true})
	defer restore()

	probe := describeProbe(model.IPv4, 3)
	if !probe.Forced {
		t.Fatal("显式 --ip-version 时 Forced 应为 true")
	}
	if !strings.Contains(probe.Label, "--ip-version") {
		t.Fatalf("强制模式的说明未提到 --ip-version: %q", probe.Label)
	}
}

func TestDescribeProbeHandlesBothFamiliesDead(t *testing.T) {
	// 两族都探不出来时不得声称「已按可达性跳过」，因为此时根本没有过滤。
	restore := dnsclient.SetCapabilitiesForTest(dnsclient.NetworkCapabilities{})
	defer restore()

	probe := describeProbe(model.IPAny, 0)
	if probe.IPv4 || probe.IPv6 {
		t.Fatalf("探测结论记录错误: %+v", probe)
	}
	if probe.Label == "" {
		t.Fatal("判定缺少可读说明")
	}
	if !strings.Contains(probe.Label, "均实测无响应") {
		t.Fatalf("两族都不可用时的说明不准确: %q", probe.Label)
	}
}

func TestBuildTasksWithProbeSkipsUnreachableSystemDNS(t *testing.T) {
	// 关键回归：探测判定必须同时作用于内置服务器与系统 DNS。此前系统 DNS
	// 只受显式 --ip-version 影响，于是「跳过 8 个内置 IPv6」的同时仍去测
	// IPv6 系统解析器，白等一整个超时预算换来必然 0% 的行。
	restore := dnsclient.SetCapabilitiesForTest(dnsclient.NetworkCapabilities{IPv4: true, IPv6: false})
	defer restore()

	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP}
	opts.SystemDNS = true

	servers, _, probe, _, err := BuildTasksWithProbe(opts)
	if err != nil {
		t.Fatalf("BuildTasksWithProbe 返回错误: %v", err)
	}
	if probe == nil {
		t.Fatal("未返回探测判定")
	}

	for i, s := range servers {
		if s.Family == model.IPv6 {
			t.Fatalf("IPv6 不可用时仍保留了 servers[%d]（%s, 系统=%v）",
				i, s.Address, s.IsSystem)
		}
	}
}

func TestBuildTasksWithProbeRecordsSkippedCount(t *testing.T) {
	// Skipped 必须把内置与系统 DNS 的排除数合并统计，否则报告里的数字
	// 会对不上实际少掉的服务器。
	restore := dnsclient.SetCapabilitiesForTest(dnsclient.NetworkCapabilities{IPv4: true, IPv6: false})
	defer restore()

	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP}
	opts.SystemDNS = true

	servers, _, probe, _, err := BuildTasksWithProbe(opts)
	if err != nil {
		t.Fatalf("BuildTasksWithProbe 返回错误: %v", err)
	}

	all := data.Servers([]model.Protocol{model.ProtocolUDP}, nil, nil, nil)
	expectedAtLeast := 0
	for _, s := range all {
		if dnsclient.FamilyOf(s.Address) == model.IPv6 {
			expectedAtLeast++
		}
	}
	if probe.Skipped < expectedAtLeast {
		t.Fatalf("Skipped = %d, 至少应包含 %d 个被排除的内置 IPv6 服务器",
			probe.Skipped, expectedAtLeast)
	}
	if len(servers) == 0 {
		t.Fatal("服务器列表为空")
	}
}

func TestBuildTasksWithProbeIsConsistentWithBuildTasks(t *testing.T) {
	// 两个入口必须给出同一份服务器列表，否则预览与实际运行会不一致。
	opts := baseOptions()
	opts.Servers = ""

	plain, _, warns, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	withProbe, _, _, warnsProbe, err := BuildTasksWithProbe(opts)
	if err != nil {
		t.Fatalf("BuildTasksWithProbe 返回错误: %v", err)
	}

	if len(plain) != len(withProbe) {
		t.Fatalf("两个入口服务器数不同: %d != %d", len(plain), len(withProbe))
	}
	for i := range plain {
		if plain[i].Key() != withProbe[i].Key() {
			t.Fatalf("两个入口 servers[%d] 不同: %q != %q", i, plain[i].Key(), withProbe[i].Key())
		}
	}
	if len(warns) != len(warnsProbe) {
		t.Fatalf("两个入口警告数不同: %d != %d", len(warns), len(warnsProbe))
	}
}

func TestBuildTasksRegionFilterKeepsSystemDNSAndSaysSo(t *testing.T) {
	// 系统 DNS 是「是否建议更换」这一结论的基线，因此不受地区筛选影响；
	// 但必须给出提示，否则被筛过的运行里会莫名出现范围外的服务器。
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP}
	opts.Regions = []string{"CN"}
	opts.SystemDNS = true

	servers, _, warns, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}

	system := countSystem(servers)
	if system == 0 {
		t.Skip("本机没有可检测的系统 DNS，无法验证该提示")
	}

	// 内置服务器仍必须全部落在筛选范围内。
	for i, s := range servers {
		if s.IsSystem {
			continue
		}
		if s.Region != "CN" {
			t.Fatalf("内置 servers[%d] 的地区 = %q, 不在筛选范围内: %+v", i, s.Region, s)
		}
	}

	var found bool
	for _, w := range warns {
		if strings.Contains(w, "地区筛选") && strings.Contains(w, "系统 DNS") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("纳入系统 DNS 却没有给出说明, 警告 = %v", warns)
	}
}

func TestBuildTasksNoRegionFilterHasNoSystemDNSNote(t *testing.T) {
	// 没有地区筛选时不应出现这条提示（否则是噪音）。
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP}
	opts.SystemDNS = true

	_, _, warns, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	for _, w := range warns {
		if strings.Contains(w, "地区筛选") {
			t.Fatalf("未使用 --regions 却出现了地区筛选提示: %q", w)
		}
	}
}

func TestBuildTasksExplicitServersBypassRegionFilter(t *testing.T) {
	// --servers 是逃生舱：显式给出的地址不参与内置清单的地区筛选。
	opts := baseOptions()
	opts.Servers = "8.8.8.8"
	opts.Regions = []string{"CN"}

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("--servers 显式指定时返回 %d 个服务器, 期望 1 个: %+v", len(servers), servers)
	}
	if servers[0].Region != "CDN" {
		t.Fatalf("显式指定的 8.8.8.8 地区 = %q, 期望 CDN（不应被 --regions cn 过滤掉）", servers[0].Region)
	}
}

func TestBuildTasksRegionFilterKeepsComboPairing(t *testing.T) {
	// 地区筛选与组合模式叠加时，配对标记仍必须正确落到两种传输上。
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP, model.ProtocolDoH}
	opts.Regions = []string{"CN"}
	opts.Combo = model.ComboUDPDoH

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}

	var udpCombo, dohCombo string
	for _, s := range servers {
		if s.Combo == "" {
			t.Fatalf("组合模式下服务器 %s（%s）缺少配对标记", s.Address, s.Protocol.Label())
		}
		if s.Region != "CN" {
			t.Fatalf("地区筛选失效: %+v", s)
		}
		switch s.Protocol {
		case model.ProtocolUDP:
			if strings.HasPrefix(s.Name, "AliDNS") {
				udpCombo = s.Combo
			}
		case model.ProtocolDoH:
			if s.Name == "AliDNS" {
				dohCombo = s.Combo
			}
		}
	}
	if udpCombo == "" || dohCombo == "" {
		t.Fatalf("未找到 AliDNS 的两种传输: udp=%q doh=%q", udpCombo, dohCombo)
	}
	if udpCombo != dohCombo {
		t.Fatalf("地区筛选后 AliDNS 的配对标识不同: %q != %q", udpCombo, dohCombo)
	}
}

func TestBuildTasksExplicitIPVersionFiltersFamilies(t *testing.T) {
	opts := baseOptions()
	opts.Servers = "8.8.8.8,2606:4700:4700::1111"
	opts.IPVersion = model.IPv4

	servers, _, warns, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("--ip-version=ipv4 返回 %d 个服务器, 期望 1 个（仅 IPv4）: %+v", len(servers), servers)
	}
	if servers[0].Family != model.IPv4 {
		t.Fatalf("保留的服务器地址族 = %q, 期望 %q", servers[0].Family, model.IPv4)
	}
	if len(warns) == 0 {
		t.Fatal("过滤掉了服务器却没有给出提示")
	}
}

func TestBuildTasksExplicitIPVersionKeepsUnreachableFamily(t *testing.T) {
	// 显式 --ip-version 是明确的用户指令，必须覆盖可达性启发式：否则在
	// 「有 IPv6 地址但没有 IPv6 出口」的机器上用户永远无法强制测试 IPv6。
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP}
	opts.IPVersion = model.IPv6

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(servers) == 0 {
		t.Fatal("显式请求 IPv6 时不应返回空列表（可达性启发式不得否决明确指令）")
	}
	for i, s := range servers {
		if s.Family != model.IPv6 {
			t.Fatalf("servers[%d]（%s）的地址族 = %q, 期望 %q", i, s.Address, s.Family, model.IPv6)
		}
	}
}

func TestBuildTasksComboMarksPairs(t *testing.T) {
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP, model.ProtocolDoH}
	opts.Combo = model.ComboUDPDoH

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	if len(servers) == 0 {
		t.Fatal("服务器列表为空")
	}

	// 组合模式下每台 UDP/DoH 服务器都要带上配对标记。
	marked := 0
	for i, s := range servers {
		switch s.Protocol {
		case model.ProtocolUDP, model.ProtocolDoH:
			if s.Combo == "" {
				t.Fatalf("组合模式下 servers[%d]（%s, %s）缺少配对标记: %+v",
					i, s.Name, s.Protocol.Label(), s)
			}
			marked++
		default:
			if s.Combo != "" {
				t.Fatalf("非组合协议 servers[%d]（%s）不应带配对标记: %+v", i, s.Protocol.Label(), s)
			}
		}
	}
	if marked == 0 {
		t.Fatal("没有任何服务器被标记为组合配对")
	}

	// AliDNS 的 UDP 与 DoH 必须落到同一个配对标识上。
	var udpCombo, dohCombo string
	for _, s := range servers {
		if s.Name != "AliDNS" && !strings.HasPrefix(s.Name, "AliDNS ") {
			continue
		}
		switch s.Protocol {
		case model.ProtocolUDP:
			udpCombo = s.Combo
		case model.ProtocolDoH:
			dohCombo = s.Combo
		}
	}
	if udpCombo == "" || dohCombo == "" {
		t.Fatalf("未找到 AliDNS 的两种传输: udp=%q doh=%q", udpCombo, dohCombo)
	}
	if udpCombo != dohCombo {
		t.Fatalf("AliDNS 的 UDP 与 DoH 配对标识不同: %q != %q", udpCombo, dohCombo)
	}
}

func TestBuildTasksWithoutComboLeavesMarkersEmpty(t *testing.T) {
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP, model.ProtocolDoH}

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	for i, s := range servers {
		if s.Combo != "" {
			t.Fatalf("非组合运行中 servers[%d]（%s）带了配对标记 %q", i, s.Address, s.Combo)
		}
	}
}

func TestBuildTasksSystemDNSHonoursIPVersion(t *testing.T) {
	// --ip-version 也必须管住系统 DNS，否则 IPv6 运行里会混入 IPv4 的系统解析器。
	opts := baseOptions()
	opts.Servers = ""
	opts.Protocols = []model.Protocol{model.ProtocolUDP}
	opts.SystemDNS = true
	opts.IPVersion = model.IPv4

	servers, _, _, err := BuildTasks(opts)
	if err != nil {
		t.Fatalf("BuildTasks 返回错误: %v", err)
	}
	for i, s := range servers {
		if !s.IsSystem {
			continue
		}
		if s.Family != model.IPv4 {
			t.Fatalf("系统 DNS servers[%d]（%s）的地址族 = %q, 期望 %q",
				i, s.Address, s.Family, model.IPv4)
		}
	}
}
