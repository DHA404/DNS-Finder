package dnsclient

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"dns-opti/internal/config"
	"dns-opti/internal/model"
)

func TestHostOf(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "裸主机名", endpoint: "dns.google", want: "dns.google"},
		{name: "裸 IP", endpoint: "8.8.8.8", want: "8.8.8.8"},
		{name: "主机名带端口", endpoint: "dns.google:853", want: "dns.google"},
		{name: "IP 带端口", endpoint: "8.8.8.8:53", want: "8.8.8.8"},
		{name: "方括号 IPv6", endpoint: "[2606:4700:4700::1111]", want: "2606:4700:4700::1111"},
		{name: "方括号 IPv6 带端口", endpoint: "[2606:4700:4700::1111]:53", want: "2606:4700:4700::1111"},
		{name: "无方括号 IPv6", endpoint: "2606:4700:4700::1111", want: "2606:4700:4700::1111"},
		{name: "https URL 无端口", endpoint: "https://dns.google/dns-query", want: "dns.google"},
		{name: "https URL 带端口", endpoint: "https://dns.google:8443/dns-query", want: "dns.google"},
		{name: "https URL 仅主机", endpoint: "https://dns.google", want: "dns.google"},
		{name: "https URL 带根路径", endpoint: "https://dns.google/", want: "dns.google"},
		{name: "https URL 带查询串", endpoint: "https://dns.google?x=1", want: "dns.google"},
		{name: "https URL 带片段", endpoint: "https://dns.google#frag", want: "dns.google"},
		{name: "带端口的 https URL 与路径", endpoint: "https://1.1.1.1:443/dns-query?ct", want: "1.1.1.1"},
		{name: "udp 前缀", endpoint: "udp://223.5.5.5", want: "223.5.5.5"},
		{name: "tls 前缀带端口", endpoint: "tls://dns.google:853", want: "dns.google"},
		{name: "首尾空白被裁剪", endpoint: "  dns.google  ", want: "dns.google"},
		{name: "空字符串", endpoint: "", want: ""},
		{name: "仅协议前缀", endpoint: "https://", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostOf(tt.endpoint); got != tt.want {
				t.Fatalf("hostOf(%q) = %q, 期望 %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		// RFC 1918 私有地址
		{name: "10.0.0.1", addr: "10.0.0.1", want: true},
		{name: "10.255.255.255", addr: "10.255.255.255", want: true},
		{name: "172.16.0.1", addr: "172.16.0.1", want: true},
		{name: "172.31.255.254", addr: "172.31.255.254", want: true},
		{name: "192.168.1.1", addr: "192.168.1.1", want: true},
		{name: "192.168.255.255", addr: "192.168.255.255", want: true},
		// 回环
		{name: "127.0.0.1", addr: "127.0.0.1", want: true},
		{name: "127.1.2.3", addr: "127.1.2.3", want: true},
		{name: "IPv6 回环", addr: "::1", want: true},
		// IPv6 链路本地
		{name: "fe80::1", addr: "fe80::1", want: true},
		{name: "fe80::abcd", addr: "fe80::abcd", want: true},
		// IPv6 唯一本地地址 fc00::/7
		{name: "fc00::1", addr: "fc00::1", want: true},
		{name: "fd12:3456::1", addr: "fd12:3456::1", want: true},
		// 公网地址
		{name: "8.8.8.8", addr: "8.8.8.8", want: false},
		{name: "1.1.1.1", addr: "1.1.1.1", want: false},
		{name: "172.15.0.1 不属于 172.16/12", addr: "172.15.0.1", want: false},
		{name: "172.32.0.1 不属于 172.16/12", addr: "172.32.0.1", want: false},
		{name: "11.0.0.1 不属于 10/8", addr: "11.0.0.1", want: false},
		{name: "2606:4700::1111", addr: "2606:4700::1111", want: false},
		{name: "2001:4860:4860::8888", addr: "2001:4860:4860::8888", want: false},
		// 非法输入
		{name: "空字符串", addr: "", want: false},
		{name: "主机名", addr: "dns.google", want: false},
		{name: "带端口", addr: "8.8.8.8:53", want: false},
		{name: "带空白的合法地址会被裁剪", addr: "  192.168.0.1  ", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPrivate(tt.addr); got != tt.want {
				t.Fatalf("IsPrivate(%q) = %v, 期望 %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestIsPrivateMatchesNetipSemantics(t *testing.T) {
	// 与 net/netip 的判定逐一对齐，避免手工实现跑偏。
	addrs := []string{
		"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "::1", "fe80::1",
		"fc00::1", "fd00::2", "8.8.8.8", "1.1.1.1", "2606:4700::1111",
	}
	for _, a := range addrs {
		ip := netip.MustParseAddr(a)
		want := ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
		if got := IsPrivate(a); got != want {
			t.Fatalf("IsPrivate(%q) = %v, netip 判定为 %v", a, got, want)
		}
	}
}

func TestParseServersBareIP(t *testing.T) {
	got, err := ParseServers("223.5.5.5")
	if err != nil {
		t.Fatalf("ParseServers 返回错误: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ParseServers(\"223.5.5.5\") 返回 %d 个, 期望 1 个: %+v", len(got), got)
	}
	s := got[0]
	if s.Address != "223.5.5.5" || s.Name != "223.5.5.5" {
		t.Fatalf("裸 IP 解析为 Name=%q Address=%q, 期望都是 223.5.5.5", s.Name, s.Address)
	}
	if s.Protocol != model.ProtocolUDP {
		t.Fatalf("裸 IP 的协议 = %q, 期望 %q", s.Protocol, model.ProtocolUDP)
	}
}

func TestParseServersPrefixes(t *testing.T) {
	tests := []struct {
		name         string
		entry        string
		wantName     string
		wantAddress  string
		wantProtocol model.Protocol
	}{
		{
			name:         "udp 前缀",
			entry:        "udp://223.5.5.5",
			wantName:     "223.5.5.5",
			wantAddress:  "223.5.5.5",
			wantProtocol: model.ProtocolUDP,
		},
		{
			name:         "tls 前缀",
			entry:        "tls://dns.google",
			wantName:     "dns.google",
			wantAddress:  "dns.google",
			wantProtocol: model.ProtocolDoT,
		},
		{
			name:         "dot 前缀",
			entry:        "dot://dns.google",
			wantName:     "dns.google",
			wantAddress:  "dns.google",
			wantProtocol: model.ProtocolDoT,
		},
		{
			name:         "tls 前缀保留端口之外的裸主机",
			entry:        "tls://dns.google:853",
			wantName:     "dns.google",
			wantAddress:  "dns.google",
			wantProtocol: model.ProtocolDoT,
		},
		{
			name:         "https URL 原样保留",
			entry:        "https://dns.google/dns-query",
			wantName:     "dns.google",
			wantAddress:  "https://dns.google/dns-query",
			wantProtocol: model.ProtocolDoH,
		},
		{
			name:         "doh 前缀归一化为 https",
			entry:        "doh://dns.google/dns-query",
			wantName:     "dns.google",
			wantAddress:  "https://dns.google/dns-query",
			wantProtocol: model.ProtocolDoH,
		},
		{
			name:         "h3 前缀改写为 https",
			entry:        "h3://dns.google/dns-query",
			wantName:     "dns.google",
			wantAddress:  "https://dns.google/dns-query",
			wantProtocol: model.ProtocolDoH3,
		},
		{
			name:         "doh3 前缀改写为 https",
			entry:        "doh3://dns.google/dns-query",
			wantName:     "dns.google",
			wantAddress:  "https://dns.google/dns-query",
			wantProtocol: model.ProtocolDoH3,
		},
		{
			name:         "h3 带端口",
			entry:        "h3://dns.google:8443/dns-query",
			wantName:     "dns.google",
			wantAddress:  "https://dns.google:8443/dns-query",
			wantProtocol: model.ProtocolDoH3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseServers(tt.entry)
			if err != nil {
				t.Fatalf("ParseServers(%q) 返回错误: %v", tt.entry, err)
			}
			if len(got) != 1 {
				t.Fatalf("ParseServers(%q) 返回 %d 个, 期望 1 个: %+v", tt.entry, len(got), got)
			}
			s := got[0]
			if s.Name != tt.wantName {
				t.Fatalf("ParseServers(%q).Name = %q, 期望 %q", tt.entry, s.Name, tt.wantName)
			}
			if s.Address != tt.wantAddress {
				t.Fatalf("ParseServers(%q).Address = %q, 期望 %q", tt.entry, s.Address, tt.wantAddress)
			}
			if s.Protocol != tt.wantProtocol {
				t.Fatalf("ParseServers(%q).Protocol = %q, 期望 %q", tt.entry, s.Protocol, tt.wantProtocol)
			}
		})
	}
}

func TestParseServersBareHTTPSHostExpandsToDNSQuery(t *testing.T) {
	tests := []struct {
		name        string
		entry       string
		wantAddress string
	}{
		{name: "https 裸主机", entry: "https://dns.google", wantAddress: "https://dns.google/dns-query"},
		{name: "https 裸主机带端口", entry: "https://dns.google:8443", wantAddress: "https://dns.google:8443/dns-query"},
		{name: "doh 裸主机", entry: "doh://dns.google", wantAddress: "https://dns.google/dns-query"},
		{name: "带路径时不改写", entry: "https://dns.google/custom", wantAddress: "https://dns.google/custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseServers(tt.entry)
			if err != nil {
				t.Fatalf("ParseServers(%q) 返回错误: %v", tt.entry, err)
			}
			if len(got) != 1 {
				t.Fatalf("ParseServers(%q) 返回 %d 个, 期望 1 个", tt.entry, len(got))
			}
			if got[0].Address != tt.wantAddress {
				t.Fatalf("ParseServers(%q).Address = %q, 期望 %q", tt.entry, got[0].Address, tt.wantAddress)
			}
			if got[0].Protocol != model.ProtocolDoH {
				t.Fatalf("ParseServers(%q).Protocol = %q, 期望 %q", tt.entry, got[0].Protocol, model.ProtocolDoH)
			}
		})
	}
}

func TestParseServersBareH3HostExpandsToDNSQuery(t *testing.T) {
	// DoH3 与 DoH 共用 RFC 8484 的 /dns-query 端点，裸主机必须同样补全路径，
	// 否则请求会打到网站根路径而不是 DNS 端点。
	got, err := ParseServers("h3://dns.google")
	if err != nil {
		t.Fatalf("ParseServers(\"h3://dns.google\") 返回错误: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ParseServers(\"h3://dns.google\") 返回 %d 个, 期望 1 个", len(got))
	}
	if got[0].Protocol != model.ProtocolDoH3 {
		t.Fatalf("协议 = %q, 期望 %q", got[0].Protocol, model.ProtocolDoH3)
	}
	if want := "https://dns.google/dns-query"; got[0].Address != want {
		t.Fatalf("ParseServers(\"h3://dns.google\").Address = %q, 期望 %q", got[0].Address, want)
	}
	if got[0].Name != "dns.google" {
		t.Fatalf("Name = %q, 期望 dns.google", got[0].Name)
	}
}

func TestParseServersDropsDuplicates(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		wantN int
	}{
		{name: "完全相同的条目", raw: "1.1.1.1,1.1.1.1", wantN: 1},
		{name: "裸 IP 与 udp:// 视为同一个", raw: "1.1.1.1,udp://1.1.1.1", wantN: 1},
		{name: "同一地址不同协议保留两条", raw: "1.1.1.1,tls://1.1.1.1", wantN: 2},
		{name: "https 与 h3 视为不同协议", raw: "https://dns.google/dns-query,h3://dns.google/dns-query", wantN: 2},
		{name: "去重后保留首次出现的位置", raw: "8.8.8.8,1.1.1.1,8.8.8.8", wantN: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseServers(tt.raw)
			if err != nil {
				t.Fatalf("ParseServers(%q) 返回错误: %v", tt.raw, err)
			}
			if len(got) != tt.wantN {
				t.Fatalf("ParseServers(%q) 返回 %d 个（%+v）, 期望 %d 个", tt.raw, len(got), got, tt.wantN)
			}
			seen := map[string]bool{}
			for _, s := range got {
				if seen[s.Key()] {
					t.Fatalf("ParseServers(%q) 出现重复 Key %q", tt.raw, s.Key())
				}
				seen[s.Key()] = true
			}
		})
	}
}

func TestParseServersOrderPreserved(t *testing.T) {
	got, err := ParseServers("8.8.8.8,1.1.1.1,9.9.9.9")
	if err != nil {
		t.Fatalf("ParseServers 返回错误: %v", err)
	}
	want := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("ParseServers 返回 %d 个, 期望 %d 个", len(got), len(want))
	}
	for i := range want {
		if got[i].Address != want[i] {
			t.Fatalf("ParseServers[%d].Address = %q, 期望 %q（顺序必须与输入一致）", i, got[i].Address, want[i])
		}
	}
}

func TestParseServersHandlesWhitespaceAndComments(t *testing.T) {
	// 空条目与仅有分隔符的条目都应被安静跳过。
	got, err := ParseServers("  8.8.8.8 ,, # 注释不是特殊语法 , 1.1.1.1  ")
	if err != nil {
		t.Fatalf("ParseServers 返回错误: %v", err)
	}
	// "# 注释不是特殊语法" 既不是 IP 也不是合法的 host:port 解析结果为空，会被丢弃。
	if len(got) != 2 {
		t.Fatalf("ParseServers 返回 %d 个（%+v）, 期望 2 个（8.8.8.8 与 1.1.1.1）", len(got), got)
	}
	if got[0].Address != "8.8.8.8" || got[1].Address != "1.1.1.1" {
		t.Fatalf("ParseServers 结果 = %+v, 期望 8.8.8.8 与 1.1.1.1", got)
	}
}

func TestParseServersEmptyErrors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "空字符串", raw: ""},
		{name: "只有空白", raw: "   "},
		{name: "只有逗号", raw: ",,,"},
		{name: "无法解析的条目", raw: "://"},
		{name: "只有端口", raw: ":53"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseServers(tt.raw)
			if err == nil {
				t.Fatalf("ParseServers(%q) = %+v, 期望错误", tt.raw, got)
			}
			if got != nil {
				t.Fatalf("ParseServers(%q) 出错时返回了 %+v, 期望 nil", tt.raw, got)
			}
		})
	}
}

func TestMarkSpecial(t *testing.T) {
	in := []model.Server{
		{Name: "路由器", Address: "192.168.1.1", Protocol: model.ProtocolUDP},
		{Name: "Google", Address: "8.8.8.8", Protocol: model.ProtocolUDP},
		{Name: "IPv6 回环", Address: "[::1]", Protocol: model.ProtocolUDP},
		{Name: "DoH", Address: "https://dns.google/dns-query", Protocol: model.ProtocolDoH},
	}
	got := MarkSpecial(in)
	if len(got) != len(in) {
		t.Fatalf("MarkSpecial 返回 %d 个, 期望 %d 个", len(got), len(in))
	}
	wantPrivate := []bool{true, false, true, false}
	for i := range got {
		if got[i].IsPrivate != wantPrivate[i] {
			t.Fatalf("MarkSpecial[%d]（%q）的 IsPrivate = %v, 期望 %v", i, got[i].Address, got[i].IsPrivate, wantPrivate[i])
		}
		if got[i].Name != in[i].Name || got[i].Address != in[i].Address || got[i].Protocol != in[i].Protocol {
			t.Fatalf("MarkSpecial[%d] 改动了原有字段: %+v -> %+v", i, in[i], got[i])
		}
	}
	// 不得就地修改入参。
	if in[0].IsPrivate {
		t.Fatalf("MarkSpecial 就地修改了入参: %+v", in[0])
	}
}

func TestSelectResolvedHost(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		cap   NetworkCapabilities
		want  model.IPVersion
		got   string
	}{
		{
			name:  "仅支持 IPv4 时选 IPv4",
			addrs: []string{"2606:4700::1111", "1.1.1.1"},
			cap:   NetworkCapabilities{IPv4: true},
			got:   "1.1.1.1",
		},
		{
			name:  "仅支持 IPv6 时选 IPv6",
			addrs: []string{"1.1.1.1", "2606:4700::1111"},
			cap:   NetworkCapabilities{IPv6: true},
			got:   "2606:4700::1111",
		},
		{
			name:  "双栈未指定地址族时优先 IPv4",
			addrs: []string{"2606:4700::1111", "1.1.1.1"},
			cap:   NetworkCapabilities{IPv4: true, IPv6: true},
			got:   "1.1.1.1",
		},
		{
			name:  "显式要求 IPv6 时优先 IPv6",
			addrs: []string{"1.1.1.1", "2606:4700::1111"},
			cap:   NetworkCapabilities{IPv4: true, IPv6: true},
			want:  model.IPv6,
			got:   "2606:4700::1111",
		},
		{
			name:  "显式要求 IPv4 时优先 IPv4",
			addrs: []string{"2606:4700::1111", "1.1.1.1"},
			cap:   NetworkCapabilities{IPv4: true, IPv6: true},
			want:  model.IPv4,
			got:   "1.1.1.1",
		},
		{
			name:  "显式要求 IPv6 但名字只有 IPv4 时回落到可达地址族",
			addrs: []string{"1.1.1.1"},
			cap:   NetworkCapabilities{IPv4: true},
			want:  model.IPv6,
			got:   "1.1.1.1",
		},
		{
			name:  "无匹配家族时回落第一条",
			addrs: []string{"2606:4700::1111"},
			cap:   NetworkCapabilities{IPv4: true},
			got:   "2606:4700::1111",
		},
		{
			name:  "空列表",
			addrs: nil,
			cap:   NetworkCapabilities{IPv4: true},
			got:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectResolvedHost(tt.addrs, tt.cap, tt.want); got != tt.got {
				t.Fatalf("selectResolvedHost(%v, %+v, %q) = %q, 期望 %q", tt.addrs, tt.cap, tt.want, got, tt.got)
			}
		})
	}
}

func TestSelectResolvedHostPrefersRequestedFamily(t *testing.T) {
	// 请求的地址族必须优先于「本机优先 IPv4」的默认策略，否则
	// --ip-version=ipv6 对主机名端点不会生效。
	addrs := []string{"1.1.1.1", "2606:4700::1111"}
	cap := NetworkCapabilities{IPv4: true, IPv6: true}

	if got := selectResolvedHost(addrs, cap, model.IPv4); got != "1.1.1.1" {
		t.Fatalf("请求 IPv4 时选中 %q, 期望 1.1.1.1", got)
	}
	if got := selectResolvedHost(addrs, cap, model.IPv6); got != "2606:4700::1111" {
		t.Fatalf("请求 IPv6 时选中 %q, 期望 2606:4700::1111", got)
	}
	// 未指定时必须保持「双栈优先 IPv4」以维持既有行为。
	if got := selectResolvedHost(addrs, cap, model.IPAny); got != "1.1.1.1" {
		t.Fatalf("未指定地址族时选中 %q, 期望 1.1.1.1", got)
	}
}

func TestSocketNetwork(t *testing.T) {
	tests := []struct {
		base   string
		family model.IPVersion
		want   string
	}{
		{"udp", model.IPv4, "udp4"},
		{"udp", model.IPv6, "udp6"},
		{"udp", model.IPAny, "udp"},
		{"tcp", model.IPv4, "tcp4"},
		{"tcp", model.IPv6, "tcp6"},
		{"tcp-tls", model.IPv4, "tcp-tls4"},
		{"tcp-tls", model.IPv6, "tcp-tls6"},
		{"tcp-tls", model.IPAny, "tcp-tls"},
	}
	for _, tt := range tests {
		if got := socketNetwork(tt.base, tt.family); got != tt.want {
			t.Fatalf("socketNetwork(%q, %q) = %q, 期望 %q", tt.base, tt.family, got, tt.want)
		}
	}
}

func TestFamilyOf(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     model.IPVersion
	}{
		{name: "IPv4 字面量", endpoint: "8.8.8.8", want: model.IPv4},
		{name: "IPv4 带端口", endpoint: "8.8.8.8:53", want: model.IPv4},
		{name: "IPv6 字面量", endpoint: "2606:4700:4700::1111", want: model.IPv6},
		{name: "方括号 IPv6", endpoint: "[2606:4700:4700::1111]", want: model.IPv6},
		{name: "方括号 IPv6 带端口", endpoint: "[2606:4700:4700::1111]:53", want: model.IPv6},
		{name: "DoH URL 主机名", endpoint: "https://dns.google/dns-query", want: model.IPAny},
		{name: "DoH URL IPv4", endpoint: "https://1.1.1.1/dns-query", want: model.IPv4},
		{name: "DoH URL 方括号 IPv6", endpoint: "https://[2606:4700:4700::1111]/dns-query", want: model.IPv6},
		{name: "裸主机名", endpoint: "dns.google", want: model.IPAny},
		{name: "空字符串", endpoint: "", want: model.IPAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FamilyOf(tt.endpoint); got != tt.want {
				t.Fatalf("FamilyOf(%q) = %q, 期望 %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestIsPrivateHost(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		{name: "内网 IPv4", endpoint: "192.168.1.1", want: true},
		{name: "内网 IPv4 带端口", endpoint: "192.168.1.1:53", want: true},
		{name: "回环 IPv6", endpoint: "[::1]", want: true},
		{name: "DoH URL 指向内网", endpoint: "https://192.168.1.1/dns-query", want: true},
		{name: "公网 IPv4", endpoint: "8.8.8.8", want: false},
		{name: "公网 IPv6", endpoint: "[2606:4700:4700::1111]", want: false},
		{name: "主机名", endpoint: "dns.google", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPrivateHost(tt.endpoint); got != tt.want {
				t.Fatalf("IsPrivateHost(%q) = %v, 期望 %v", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestResolveHostWithLiteralAddress(t *testing.T) {
	// 字面量地址不查系统解析器，原样返回（离线安全），与请求的地址族无关。
	for _, addr := range []string{"8.8.8.8", "2606:4700::1111"} {
		for _, want := range []model.IPVersion{model.IPAny, model.IPv4, model.IPv6} {
			if got := resolveHost(addr, 0, want); got != addr {
				t.Fatalf("resolveHost(%q, 0, %q) = %q, 期望原样返回", addr, want, got)
			}
		}
	}
	if got := resolveHost("", 0, model.IPAny); got != "" {
		t.Fatalf("resolveHost(\"\") = %q, 期望空字符串", got)
	}
}

func TestProbeCapabilitiesUsesProbeResult(t *testing.T) {
	// probeCapabilities 先做一次本地 UDP 拨号（不发包），只有拨号成功才发
	// 真实查询。两个地址族并发探测，因此用带互斥锁的集合记录调用，而不是
	// 依赖顺序的切片。
	var (
		mu      sync.Mutex
		dialed  = map[string]bool{}
		queried = map[string]int{}
	)
	cap := probeCapabilities(
		func(network, address string) bool {
			mu.Lock()
			dialed[network+" "+address] = true
			mu.Unlock()
			return network == "udp4"
		},
		func(_ context.Context, network, _ string, _ time.Duration) bool {
			mu.Lock()
			queried[network]++
			mu.Unlock()
			return network == "udp4"
		},
	)
	if !cap.IPv4 {
		t.Fatal("IPv4 有目标应答时能力应为 true")
	}
	if cap.IPv6 {
		t.Fatal("IPv6 拨号失败时能力应为 false")
	}

	mu.Lock()
	defer mu.Unlock()
	// 两个地址族都要拨号试探（拨号是判断「有没有路由」的廉价手段）。
	if len(dialed) != 2 {
		t.Fatalf("拨号探针被调用 %d 次, 期望 2 次（两个地址族各一次）: %v", len(dialed), dialed)
	}
	if !dialed["udp4 "+probeTargets[model.IPv4][0]] {
		t.Fatalf("未用首个 IPv4 目标拨号: %v", dialed)
	}
	if !dialed["udp6 "+probeTargets[model.IPv6][0]] {
		t.Fatalf("未用首个 IPv6 目标拨号: %v", dialed)
	}
	// 但拨号失败的地址族不应再发查询：那是纯粹浪费一次超时等待。
	if queried["udp6"] != 0 {
		t.Fatalf("IPv6 拨号失败后仍发起了 %d 次查询, 期望 0 次", queried["udp6"])
	}
	if queried["udp4"] == 0 {
		t.Fatal("IPv4 拨号成功后应至少发起一次查询")
	}
}

func TestProbeCapabilitiesCancelsRemainingTargetsOnFirstAnswer(t *testing.T) {
	// 一个地址族内只要有一个目标应答就应立即取消其余目标。否则只要有一个
	// 目标被黑洞（这在真实网络里是常态），整个地址族仍要等满超时。
	//
	// 注意每个地址族有各自的 ctx：IPv4 成功只会取消 IPv4 的其余目标，
	// IPv6 的探测不受影响（两个地址族的结论互相独立）。因此这里的桩必须像
	// 真实的 canQuery 一样既尊重取消、又尊重超时，否则它会永远挂住。
	var (
		mu       sync.Mutex
		started  int
		observed int // 观察到取消的目标数
	)
	cap := probeCapabilities(
		func(string, string) bool { return true },
		func(ctx context.Context, network, _ string, timeout time.Duration) bool {
			if network != "udp4" {
				// IPv6 在本测试中始终无响应，但要像真实实现那样带超时返回。
				select {
				case <-ctx.Done():
				case <-time.After(timeout):
				}
				return false
			}

			mu.Lock()
			started++
			n := started
			mu.Unlock()

			if n == 1 {
				return true // 第一个目标立刻成功
			}
			// 其余目标等待被取消；若取消没有传播，则退化为超时。
			select {
			case <-ctx.Done():
				mu.Lock()
				observed++
				mu.Unlock()
				return false
			case <-time.After(timeout):
				return false
			}
		},
	)

	if !cap.IPv4 {
		t.Fatal("IPv4 有一个目标应答时应为 true")
	}

	// 成功之后，其余目标的 ctx 必须被取消 —— 若没有取消，它们会一直等到
	// probeTimeout 才返回，整个探测也就会被拖满超时。
	mu.Lock()
	defer mu.Unlock()
	if started != len(probeTargets[model.IPv4]) {
		t.Fatalf("启动了 %d 个 IPv4 目标, 期望全部 %d 个（目标应并发启动）",
			started, len(probeTargets[model.IPv4]))
	}
	if observed == 0 {
		t.Fatal("没有任何目标观察到取消，取消没有传播到同族的其余目标")
	}
}

func TestProbeCapabilitiesReturnsPromptlyOnSuccess(t *testing.T) {
	// 端到端计时断言：只要有一个目标应答，探测就不应等满 probeTimeout。
	// 这里让 IPv4 立刻成功、IPv6 一直挂到超时，因此总耗时由 IPv6 决定，
	// 这恰好验证了两个地址族是并发的而不是串行的。
	start := time.Now()
	cap := probeCapabilities(
		func(string, string) bool { return true },
		func(ctx context.Context, network, _ string, timeout time.Duration) bool {
			if network == "udp4" {
				return true
			}
			select {
			case <-ctx.Done():
			case <-time.After(timeout):
			}
			return false
		},
	)
	elapsed := time.Since(start)

	if !cap.IPv4 {
		t.Fatal("IPv4 应答时应为 true")
	}
	if cap.IPv6 {
		t.Fatal("IPv6 无应答时应为 false")
	}
	// 两个地址族并发探测，所以总耗时约等于较慢的那一个（IPv6 的超时），
	// 而不是两者之和。
	if elapsed > probeTimeout+probeTimeout/2 {
		t.Fatalf("探测耗时 %v，超过单个 probeTimeout(%v) 过多，地址族可能没有并发",
			elapsed, probeTimeout)
	}
}

func TestProbeCapabilitiesRequiresAnsweredQuery(t *testing.T) {
	// 这是本次修复的核心：只要拨号成功就判定地址族可用的旧逻辑，在有 IPv6
	// 地址与默认路由、但没有 IPv6 出口的网络上是假阳性 —— 会白白为几十个
	// IPv6 服务器各等待一次超时。因此查询探针必须是否决票。
	tests := []struct {
		name     string
		canQuery bool
		want     NetworkCapabilities
	}{
		{
			name:     "拨号成功但查询无响应（假阳性网络）",
			canQuery: false,
			want:     NetworkCapabilities{IPv4: false, IPv6: false},
		},
		{
			name:     "拨号与查询都成功",
			canQuery: true,
			want:     NetworkCapabilities{IPv4: true, IPv6: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			queries := map[string]int{}
			cap := probeCapabilities(
				func(string, string) bool { return true },
				func(_ context.Context, network, _ string, _ time.Duration) bool {
					mu.Lock()
					queries[network]++
					mu.Unlock()
					return tt.canQuery
				},
			)
			if cap != tt.want {
				t.Fatalf("能力 = %+v, 期望 %+v", cap, tt.want)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, family := range []model.IPVersion{model.IPv4, model.IPv6} {
				network := socketNetwork("udp", family)
				if queries[network] == 0 {
					t.Fatalf("%s 一次都没有探测: %v", network, queries)
				}
				// 全部失败时必须把所有目标都试完（单个目标被屏蔽不能
				// 代表整个地址族）；有应答时允许提前取消，所以只断言上界。
				if want := len(probeTargets[family]); queries[network] > want {
					t.Fatalf("%s 探测了 %d 次, 超过目标总数 %d: %v",
						network, queries[network], want, queries)
				}
				if !tt.canQuery && queries[network] != len(probeTargets[family]) {
					t.Fatalf("%s 全部失败时只探测了 %d 次, 期望试完全部 %d 个目标: %v",
						network, queries[network], len(probeTargets[family]), queries)
				}
			}
		})
	}
}

func TestProbeCapabilitiesAcceptsAnyTargetOfAFamily(t *testing.T) {
	// 单个公共解析器被网络屏蔽是常态（1.1.1.1 在很多网络不可达），只探测
	// 一个目标会把健康的 IPv4 主机误判为「没有 IPv4」，静默丢掉所有 IPv4
	// 服务器。因此只要同族任一目标应答，就判定该族可用。
	var mu sync.Mutex
	answered := 0
	cap := probeCapabilities(
		func(string, string) bool { return true },
		func(_ context.Context, network, address string, _ time.Duration) bool {
			if network != "udp4" {
				return false
			}
			mu.Lock()
			defer mu.Unlock()
			answered++
			// 只有最后一个 IPv4 目标应答。
			return address == probeTargets[model.IPv4][len(probeTargets[model.IPv4])-1]
		},
	)
	if !cap.IPv4 {
		t.Fatalf("同族中有一个目标应答时 IPv4 应为 true（已尝试 %d 个）", answered)
	}
	if cap.IPv6 {
		t.Fatal("IPv6 无任何目标应答时应为 false")
	}
}

func TestProbeCapabilitiesSkipsQueryWhenDialFails(t *testing.T) {
	// 拨号失败时不必再发查询，省掉一次无谓的等待。
	var mu sync.Mutex
	queries := 0
	cap := probeCapabilities(
		func(string, string) bool { return false },
		func(_ context.Context, _, _ string, _ time.Duration) bool {
			mu.Lock()
			queries++
			mu.Unlock()
			return true
		},
	)
	if cap.IPv4 || cap.IPv6 {
		t.Fatalf("拨号全部失败时能力应为 false: %+v", cap)
	}
	mu.Lock()
	defer mu.Unlock()
	if queries != 0 {
		t.Fatalf("拨号失败后仍发起了 %d 次查询探针, 期望 0 次", queries)
	}
}

func TestSetCapabilitiesForTestOverridesVerdict(t *testing.T) {
	// 覆盖点必须生效，并且恢复之后能再次被覆盖。这里刻意不断言恢复后的具体
	// 值：真实探测结果取决于运行环境（本机可能确实没有 IPv6 出口），把它写死
	// 会让测试在正确的机器上失败。用两次不同的覆盖来证明开关是生效的。
	first := NetworkCapabilities{IPv4: true, IPv6: false}
	restoreFirst := SetCapabilitiesForTest(first)
	if got := DetectCapabilities(); got != first {
		t.Fatalf("覆盖后 DetectCapabilities() = %+v, 期望 %+v", got, first)
	}
	restoreFirst()

	second := NetworkCapabilities{IPv4: false, IPv6: true}
	restoreSecond := SetCapabilitiesForTest(second)
	defer restoreSecond()
	if got := DetectCapabilities(); got != second {
		t.Fatalf("第二次覆盖后 DetectCapabilities() = %+v, 期望 %+v（恢复未生效？）", got, second)
	}
}

func TestMatchesFamily(t *testing.T) {
	both := NetworkCapabilities{IPv4: true, IPv6: true}
	v4 := NetworkCapabilities{IPv4: true}
	v6 := NetworkCapabilities{IPv6: true}

	tests := []struct {
		name string
		cap  NetworkCapabilities
		want model.IPVersion
		ok   bool
	}{
		{name: "双栈匹配 IPv4", cap: both, want: model.IPv4, ok: true},
		{name: "双栈匹配 IPv6", cap: both, want: model.IPv6, ok: true},
		{name: "双栈匹配不限制", cap: both, want: model.IPAny, ok: true},
		{name: "仅 IPv4 匹配 IPv6", cap: v4, want: model.IPv6, ok: false},
		{name: "仅 IPv4 匹配 IPv4", cap: v4, want: model.IPv4, ok: true},
		{name: "仅 IPv6 匹配 IPv4", cap: v6, want: model.IPv4, ok: false},
		{name: "仅 IPv6 匹配 IPv6", cap: v6, want: model.IPv6, ok: true},
		{name: "无能力也不限制（不误杀）", cap: NetworkCapabilities{}, want: model.IPAny, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cap.MatchesFamily(tt.want); got != tt.ok {
				t.Fatalf("%+v.MatchesFamily(%q) = %v, 期望 %v", tt.cap, tt.want, got, tt.ok)
			}
		})
	}
}

func TestIsReachableFamily(t *testing.T) {
	tests := []struct {
		name string
		cap  NetworkCapabilities
		addr string
		want bool
	}{
		{name: "IPv4 可达", cap: NetworkCapabilities{IPv4: true}, addr: "8.8.8.8", want: true},
		{name: "IPv4 不可达", cap: NetworkCapabilities{IPv6: true}, addr: "8.8.8.8", want: false},
		{name: "IPv6 可达", cap: NetworkCapabilities{IPv6: true}, addr: "2606:4700::1111", want: true},
		{name: "IPv6 不可达", cap: NetworkCapabilities{IPv4: true}, addr: "2606:4700::1111", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			if got := tt.cap.isReachableFamily(addr); got != tt.want {
				t.Fatalf("%+v.isReachableFamily(%s) = %v, 期望 %v", tt.cap, tt.addr, got, tt.want)
			}
		})
	}
}

func TestFilterReachableKeepsHostnames(t *testing.T) {
	// 主机名永远保留（可能解析到任一地址族），因此不论本机能力如何都不得被丢弃。
	in := []model.Server{
		{Name: "DoT", Address: "dns.google", Protocol: model.ProtocolDoT},
		{Name: "DoH", Address: "https://dns.google/dns-query", Protocol: model.ProtocolDoH},
	}
	kept, skipped := filterReachable(in, model.IPAny, NetworkCapabilities{IPv4: true, IPv6: true})
	if skipped != 0 {
		t.Fatalf("跳过 %d 个主机名服务器, 期望 0 个（主机名必须保留）", skipped)
	}
	if len(kept) != len(in) {
		t.Fatalf("保留 %d 个, 期望 %d 个", len(kept), len(in))
	}
}

func TestFilterReachableHonoursRequestedFamily(t *testing.T) {
	// --ip-version 是用户的明确指令，即使地址族本身可达，也必须过滤掉另一族。
	both := NetworkCapabilities{IPv4: true, IPv6: true}
	in := []model.Server{
		{Name: "v4", Address: "8.8.8.8", Protocol: model.ProtocolUDP},
		{Name: "v6", Address: "2606:4700:4700::1111", Protocol: model.ProtocolUDP},
		{Name: "host", Address: "dns.google", Protocol: model.ProtocolDoT},
	}

	t.Run("只要 IPv4", func(t *testing.T) {
		kept, skipped := filterReachable(in, model.IPv4, both)
		if skipped != 1 {
			t.Fatalf("跳过 %d 个, 期望 1 个（IPv6 字面量）", skipped)
		}
		for _, s := range kept {
			if s.Name == "v6" {
				t.Fatalf("IPv6 字面量未被过滤: %+v", kept)
			}
		}
		if len(kept) != 2 {
			t.Fatalf("保留 %d 个, 期望 2 个（IPv4 + 主机名）: %+v", len(kept), kept)
		}
	})

	t.Run("只要 IPv6", func(t *testing.T) {
		kept, skipped := filterReachable(in, model.IPv6, both)
		if skipped != 1 {
			t.Fatalf("跳过 %d 个, 期望 1 个（IPv4 字面量）", skipped)
		}
		for _, s := range kept {
			if s.Name == "v4" {
				t.Fatalf("IPv4 字面量未被过滤: %+v", kept)
			}
		}
		if len(kept) != 2 {
			t.Fatalf("保留 %d 个, 期望 2 个（IPv6 + 主机名）: %+v", len(kept), kept)
		}
	})
}

func TestFilterReachableExplicitFamilyOverridesReachability(t *testing.T) {
	// 显式 --ip-version 是用户的明确指令，必须覆盖可达性启发式：否则在
	// 「有 IPv6 地址但没有 IPv6 出口」的机器上，用户永远无法强制测试 IPv6。
	// 测试它们并如实报告失败，比静默地什么都不测更有用。
	in := []model.Server{
		{Name: "v6", Address: "2606:4700:4700::1111", Protocol: model.ProtocolUDP},
	}
	kept, skipped := filterReachable(in, model.IPv6, NetworkCapabilities{IPv4: true, IPv6: false})
	if skipped != 0 {
		t.Fatalf("显式请求 IPv6 时跳过 %d 个, 期望 0 个（不得被可达性启发式否决）", skipped)
	}
	if len(kept) != 1 {
		t.Fatalf("保留 %d 个, 期望 1 个: %+v", len(kept), kept)
	}
}

func TestFilterReachableKeepsBracketedIPv6WithRequestedFamily(t *testing.T) {
	// 方括号形式与 DoH URL 中的 IPv6 字面量同样要被识别为 IPv6。
	in := []model.Server{
		{Name: "bracketed", Address: "[2606:4700:4700::1111]", Protocol: model.ProtocolUDP},
		{Name: "doh-v6", Address: "https://[2606:4700:4700::1111]/dns-query", Protocol: model.ProtocolDoH},
		{Name: "v4", Address: "8.8.8.8", Protocol: model.ProtocolUDP},
	}
	kept, skipped := filterReachable(in, model.IPv6, NetworkCapabilities{IPv4: true, IPv6: true})
	if skipped != 1 {
		t.Fatalf("跳过 %d 个, 期望 1 个（IPv4）: %+v", skipped, kept)
	}
	if len(kept) != 2 {
		t.Fatalf("保留 %d 个, 期望 2 个: %+v", len(kept), kept)
	}
	for _, s := range kept {
		if s.Name == "v4" {
			t.Fatalf("IPv4 未被过滤: %+v", kept)
		}
	}
}

func TestFilterReachableDropsUnreachableFamily(t *testing.T) {
	// 本机只有 IPv4 时，IPv6 字面量必须被丢弃，而不是留着每次超时。
	in := []model.Server{
		{Name: "v4", Address: "8.8.8.8", Protocol: model.ProtocolUDP},
		{Name: "v6", Address: "2606:4700:4700::1111", Protocol: model.ProtocolUDP},
		{Name: "host", Address: "dns.google", Protocol: model.ProtocolDoT},
	}
	kept, skipped := filterReachable(in, model.IPAny, NetworkCapabilities{IPv4: true})
	if skipped != 1 {
		t.Fatalf("跳过 %d 个, 期望 1 个（IPv6）: %+v", skipped, kept)
	}
	if len(kept) != 2 {
		t.Fatalf("保留 %d 个, 期望 2 个: %+v", len(kept), kept)
	}
	for _, s := range kept {
		if s.Name == "v6" {
			t.Fatalf("不可达的 IPv6 未被过滤: %+v", kept)
		}
	}
}

func TestFilterReachableKeepsEverythingWhenProbeIsInconclusive(t *testing.T) {
	// 两个地址族都探不出来（离线运行、容器无默认路由）时不能把字面量服务器
	// 全部丢掉，否则整份基准会被无声地清空。
	in := []model.Server{
		{Name: "v4", Address: "8.8.8.8", Protocol: model.ProtocolUDP},
		{Name: "v6", Address: "2606:4700:4700::1111", Protocol: model.ProtocolUDP},
	}
	kept, skipped := filterReachable(in, model.IPAny, NetworkCapabilities{})
	if skipped != 0 {
		t.Fatalf("探针无结论时跳过 %d 个, 期望 0 个（不得误杀）", skipped)
	}
	if len(kept) != len(in) {
		t.Fatalf("保留 %d 个, 期望 %d 个", len(kept), len(in))
	}
}

func TestFilterReachableIsPure(t *testing.T) {
	// 入参不得被就地修改，输出必须是新切片。
	in := []model.Server{{Name: "v4", Address: "8.8.8.8", Protocol: model.ProtocolUDP}}
	kept, _ := filterReachable(in, model.IPAny, NetworkCapabilities{IPv4: true})
	if len(kept) != 1 {
		t.Fatalf("保留 %d 个, 期望 1 个", len(kept))
	}
	kept[0].Name = "被修改"
	if in[0].Name == "被修改" {
		t.Fatal("filterReachable 返回了共享底层数组")
	}
}

func TestParseServersIPv6(t *testing.T) {
	tests := []struct {
		name         string
		entry        string
		wantName     string
		wantAddress  string
		wantProtocol model.Protocol
		wantFamily   model.IPVersion
	}{
		{
			name:         "裸 IPv6 字面量",
			entry:        "2606:4700:4700::1111",
			wantName:     "2606:4700:4700::1111",
			wantAddress:  "2606:4700:4700::1111",
			wantProtocol: model.ProtocolUDP,
			wantFamily:   model.IPv6,
		},
		{
			name:         "方括号 IPv6 字面量",
			entry:        "[2606:4700:4700::1111]",
			wantName:     "2606:4700:4700::1111",
			wantAddress:  "2606:4700:4700::1111",
			wantProtocol: model.ProtocolUDP,
			wantFamily:   model.IPv6,
		},
		{
			name:         "udp:// 前缀的方括号 IPv6",
			entry:        "udp://[2400:3200::1]",
			wantName:     "2400:3200::1",
			wantAddress:  "2400:3200::1",
			wantProtocol: model.ProtocolUDP,
			wantFamily:   model.IPv6,
		},
		{
			name:         "tls:// 前缀的方括号 IPv6",
			entry:        "tls://[2606:4700:4700::1111]",
			wantName:     "2606:4700:4700::1111",
			wantAddress:  "2606:4700:4700::1111",
			wantProtocol: model.ProtocolDoT,
			wantFamily:   model.IPv6,
		},
		{
			name:         "https URL 中的方括号 IPv6",
			entry:        "https://[2606:4700:4700::1111]/dns-query",
			wantName:     "2606:4700:4700::1111",
			wantAddress:  "https://[2606:4700:4700::1111]/dns-query",
			wantProtocol: model.ProtocolDoH,
			wantFamily:   model.IPv6,
		},
		{
			name:         "IPv4 字面量",
			entry:        "8.8.8.8",
			wantName:     "8.8.8.8",
			wantAddress:  "8.8.8.8",
			wantProtocol: model.ProtocolUDP,
			wantFamily:   model.IPv4,
		},
		{
			name:         "主机名没有固定地址族",
			entry:        "dns.google",
			wantName:     "dns.google",
			wantAddress:  "dns.google",
			wantProtocol: model.ProtocolUDP,
			wantFamily:   model.IPAny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseServers(tt.entry)
			if err != nil {
				t.Fatalf("ParseServers(%q) 返回错误: %v", tt.entry, err)
			}
			if len(got) != 1 {
				t.Fatalf("ParseServers(%q) 返回 %d 个, 期望 1 个: %+v", tt.entry, len(got), got)
			}
			s := got[0]
			if s.Name != tt.wantName {
				t.Fatalf("Name = %q, 期望 %q", s.Name, tt.wantName)
			}
			if s.Address != tt.wantAddress {
				t.Fatalf("Address = %q, 期望 %q", s.Address, tt.wantAddress)
			}
			if s.Protocol != tt.wantProtocol {
				t.Fatalf("Protocol = %q, 期望 %q", s.Protocol, tt.wantProtocol)
			}
			if s.Family != tt.wantFamily {
				t.Fatalf("Family = %q, 期望 %q", s.Family, tt.wantFamily)
			}
		})
	}
}

func TestParseServersDerivesRegion(t *testing.T) {
	tests := []struct {
		name       string
		entry      string
		wantRegion string
	}{
		{name: "国内 UDP", entry: "223.5.5.5", wantRegion: "CN"},
		{name: "国外 UDP", entry: "8.8.8.8", wantRegion: "CDN"},
		{name: "内网地址", entry: "192.168.1.1", wantRegion: "PRIVATE"},
		{name: "主机名", entry: "dns.alidns.com", wantRegion: "CN"},
		{name: "未知地址", entry: "203.0.113.9", wantRegion: "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseServers(tt.entry)
			if err != nil {
				t.Fatalf("ParseServers(%q) 返回错误: %v", tt.entry, err)
			}
			if got[0].Region != tt.wantRegion {
				t.Fatalf("ParseServers(%q).Region = %q, 期望 %q", tt.entry, got[0].Region, tt.wantRegion)
			}
		})
	}
}

func TestParseServersIPv6DuplicatesCollapse(t *testing.T) {
	// 同一地址的方括号与裸写形式必须视为同一个服务器，否则内置清单与
	// --servers 混用时会出现重复条目。
	tests := []struct {
		raw   string
		wantN int
	}{
		{raw: "2606:4700:4700::1111,[2606:4700:4700::1111]", wantN: 1},
		{raw: "udp://[2606:4700:4700::1111],2606:4700:4700::1111", wantN: 1},
		{raw: "2606:4700:4700::1111,tls://[2606:4700:4700::1111]", wantN: 2},
	}
	for _, tt := range tests {
		got, err := ParseServers(tt.raw)
		if err != nil {
			t.Fatalf("ParseServers(%q) 返回错误: %v", tt.raw, err)
		}
		if len(got) != tt.wantN {
			t.Fatalf("ParseServers(%q) 返回 %d 个（%+v）, 期望 %d 个", tt.raw, len(got), got, tt.wantN)
		}
	}
}

func TestParseServersBareIPv6HostExpandsDoHPath(t *testing.T) {
	// 裸 IPv6 主机在 DoH/DoH3 下同样要补全 /dns-query。
	for _, entry := range []string{"https://[2606:4700:4700::1111]", "h3://[2606:4700:4700::1111]"} {
		got, err := ParseServers(entry)
		if err != nil {
			t.Fatalf("ParseServers(%q) 返回错误: %v", entry, err)
		}
		if want := got[0].Address; want != "https://[2606:4700:4700::1111]/dns-query" {
			t.Fatalf("ParseServers(%q).Address = %q, 期望 %q", entry, want,
				"https://[2606:4700:4700::1111]/dns-query")
		}
	}
}

func TestNewRejectsFamilyMismatch(t *testing.T) {
	// 服务器被钉死在某个地址族时，若请求了另一族，必须报错而不是静默地去
	// 测量另一个地址 —— 那会让用户拿到与请求不符的结果。
	opts := Options{Timeout: time.Second, Family: model.IPv6}
	_, err := New(model.Server{Address: "8.8.8.8", Protocol: model.ProtocolUDP}, opts)
	if err == nil {
		t.Fatal("请求 IPv6 但服务器是 IPv4 时应返回错误")
	}

	// 同族与主机名都应被接受。
	if _, err := New(model.Server{Address: "2606:4700:4700::1111", Protocol: model.ProtocolUDP}, opts); err != nil {
		t.Fatalf("IPv6 服务器在 IPv6 模式下被拒绝: %v", err)
	}
	if _, err := New(model.Server{Address: "dns.google", Protocol: model.ProtocolDoT}, opts); err != nil {
		t.Fatalf("主机名服务器在 IPv6 模式下被拒绝: %v", err)
	}
}

func TestPairUDPDoH(t *testing.T) {
	servers := []model.Server{
		{Name: "AliDNS 1", Address: "223.5.5.5", Protocol: model.ProtocolUDP, Region: "CN"},
		{Name: "AliDNS", Address: "https://dns.alidns.com/dns-query", Protocol: model.ProtocolDoH, Region: "CN"},
		{Name: "Google 1", Address: "8.8.8.8", Protocol: model.ProtocolUDP, Region: "CDN"},
		{Name: "Google", Address: "https://dns.google/dns-query", Protocol: model.ProtocolDoH, Region: "CDN"},
		{Name: "只支持 UDP", Address: "4.2.2.1", Protocol: model.ProtocolUDP, Region: "US"},
		// DoT 不参与 UDP+DoH 配对。
		{Name: "DoT 服务", Address: "dns.quad9.net", Protocol: model.ProtocolDoT, Region: "CDN"},
	}

	pairs := PairUDPDoH(servers)

	byKey := map[string]ComboPair{}
	for _, p := range pairs {
		byKey[p.Key] = p
	}
	if len(pairs) != 3 {
		t.Fatalf("配对数 = %d, 期望 3（AliDNS / Google / 只支持 UDP）: %+v", len(pairs), pairs)
	}

	// 两条 UDP 记录（AliDNS 1 / Google 1）必须与其 DoH 对应项配成一对：
	// providerIdentity 会剥掉结尾的序号，使同一服务商的两种传输落到一起。
	// 这与内置清单的一致性由 data 包的测试保证。
	var paired int
	for _, p := range pairs {
		if p.Primary.Protocol == model.ProtocolUDP && p.Secondary.Protocol == model.ProtocolDoH {
			paired++
		}
	}
	if paired != 2 {
		t.Fatalf("成功配对 %d 组, 期望 2 组（AliDNS 与 Google）: %+v", paired, pairs)
	}

	// 只有一种传输的服务商仍要出现，另一侧为零值，而不是被静默丢掉。
	var solo bool
	for _, p := range pairs {
		if p.Primary.Protocol == model.ProtocolUDP && p.Secondary.Address == "" {
			solo = true
		}
	}
	if !solo {
		t.Fatalf("只支持 UDP 的服务商未作为单边配对出现: %+v", pairs)
	}

	// DoT 服务器不应出现在任何配对里。
	for _, p := range pairs {
		if p.Primary.Protocol == model.ProtocolDoT || p.Secondary.Protocol == model.ProtocolDoT {
			t.Fatalf("DoT 服务器出现在了 UDP+DoH 配对中: %+v", p)
		}
	}
}

func TestProviderIdentityGroupsTransportsOfOneProvider(t *testing.T) {
	pairs := [][2]model.Server{
		{
			{Name: "AliDNS 1", Address: "223.5.5.5", Protocol: model.ProtocolUDP, Region: "CN"},
			{Name: "AliDNS", Address: "https://dns.alidns.com/dns-query", Protocol: model.ProtocolDoH, Region: "CN"},
		},
		{
			{Name: "Google 1 (IPv6)", Address: "2001:4860:4860::8888", Protocol: model.ProtocolUDP, Region: "CDN"},
			{Name: "Google", Address: "https://dns.google/dns-query", Protocol: model.ProtocolDoH, Region: "CDN"},
		},
		{
			{Name: "Cloudflare 2", Address: "1.0.0.1", Protocol: model.ProtocolUDP, Region: "CDN"},
			{Name: "Cloudflare", Address: "https://cloudflare-dns.com/dns-query", Protocol: model.ProtocolDoH, Region: "CDN"},
		},
	}
	for _, pair := range pairs {
		a := ProviderIdentity(pair[0])
		b := ProviderIdentity(pair[1])
		if a == "" || b == "" {
			t.Fatalf("身份为空: %q / %q", a, b)
		}
		if a != b {
			t.Fatalf("同一服务商的两种传输身份不同: %q（%s）!= %q（%s）", a, pair[0].Address, b, pair[1].Address)
		}
	}

	// 不同服务商绝不能合并，否则会把无关的服务器对比在一起。
	distinct := []model.Server{
		{Name: "AliDNS", Address: "223.5.5.5", Protocol: model.ProtocolUDP, Region: "CN"},
		{Name: "Google", Address: "8.8.8.8", Protocol: model.ProtocolUDP, Region: "CDN"},
		{Name: "Cloudflare", Address: "1.1.1.1", Protocol: model.ProtocolUDP, Region: "CDN"},
		{Name: "Quad9", Address: "9.9.9.9", Protocol: model.ProtocolUDP, Region: "CDN"},
	}
	seen := map[string]string{}
	for _, s := range distinct {
		id := ProviderIdentity(s)
		if prev, dup := seen[id]; dup {
			t.Fatalf("不同服务商 %s 与 %s 的身份碰撞: %q", prev, s.Name, id)
		}
		seen[id] = s.Name
	}
}

func TestProviderIdentityUsesRegionToSeparateNamesakes(t *testing.T) {
	// 同名但不同地区的服务器不能被当成同一服务商。
	a := model.Server{Name: "Public DNS", Address: "1.1.1.1", Protocol: model.ProtocolUDP, Region: "CDN"}
	b := model.Server{Name: "Public DNS", Address: "223.5.5.5", Protocol: model.ProtocolUDP, Region: "CN"}
	if ProviderIdentity(a) == ProviderIdentity(b) {
		t.Fatalf("不同地区的同名服务器身份相同: %q", ProviderIdentity(a))
	}
}

func TestPairUDPDoHIsEmptyWithoutCombination(t *testing.T) {
	// 只有 DoT 时没有任何 UDP/DoH 组合，结果必须为空而不是产生幽灵配对。
	servers := []model.Server{
		{Name: "a", Address: "dns.google", Protocol: model.ProtocolDoT},
		{Name: "b", Address: "dns.quad9.net", Protocol: model.ProtocolDoT},
	}
	if got := PairUDPDoH(servers); len(got) != 0 {
		t.Fatalf("PairUDPDoH 返回 %+v, 期望空", got)
	}
}

func TestNewFallsBackToSharedTimeout(t *testing.T) {
	// 直接构造 Options（不带超时）时必须回落到与 CLI 相同的默认值，
	// 否则同一次运行里会出现两种超时。
	q, err := New(model.Server{Address: "127.0.0.1", Protocol: model.ProtocolUDP}, Options{})
	if err != nil {
		t.Fatalf("New 返回错误: %v", err)
	}
	defer func() { _ = q.Close() }()

	sq, ok := q.(*streamQuerier)
	if !ok {
		t.Fatalf("UDP 服务器应构造出 streamQuerier, 实际 %T", q)
	}
	if sq.opts.Timeout != config.DefaultTimeout {
		t.Fatalf("回落的超时 = %v, 期望 config.DefaultTimeout = %v", sq.opts.Timeout, config.DefaultTimeout)
	}
}

func TestNewHonoursExplicitTimeout(t *testing.T) {
	q, err := New(model.Server{Address: "127.0.0.1", Protocol: model.ProtocolUDP},
		Options{Timeout: 7 * time.Second})
	if err != nil {
		t.Fatalf("New 返回错误: %v", err)
	}
	defer func() { _ = q.Close() }()

	sq := q.(*streamQuerier)
	if sq.opts.Timeout != 7*time.Second {
		t.Fatalf("显式超时被覆盖为 %v, 期望 7s", sq.opts.Timeout)
	}
}

func TestProbeWouldMatter(t *testing.T) {
	// 探测不是免费的：在 IPv6 出口坏掉的机器上，它要等满超时才能得出
	// 「没有 IPv6」。当探测结果根本不影响筛选时，这笔开销纯属浪费。
	tests := []struct {
		name    string
		servers []model.Server
		want    model.IPVersion
		matters bool
	}{
		{
			name:    "只有 IPv4 字面量：探测可能淘汰它，需要探测",
			servers: []model.Server{{Address: "8.8.8.8"}},
			matters: true,
		},
		{
			name:    "只有 IPv6 字面量：探测可能淘汰它，需要探测",
			servers: []model.Server{{Address: "2606:4700:4700::1111"}},
			matters: true,
		},
		{
			name:    "两类字面量都有",
			servers: []model.Server{{Address: "8.8.8.8"}, {Address: "2606:4700:4700::1111"}},
			matters: true,
		},
		{
			name:    "只有主机名：主机名永不按可达性过滤",
			servers: []model.Server{{Address: "dns.google"}},
			matters: false,
		},
		{
			name:    "空列表",
			servers: nil,
			matters: false,
		},
		{
			name:    "显式 ipv4：可达性不参与判断",
			servers: []model.Server{{Address: "8.8.8.8"}, {Address: "2606:4700:4700::1111"}},
			want:    model.IPv4,
			matters: false,
		},
		{
			name:    "显式 ipv6：可达性不参与判断",
			servers: []model.Server{{Address: "2606:4700:4700::1111"}},
			want:    model.IPv6,
			matters: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := probeWouldMatter(tt.servers, tt.want); got != tt.matters {
				t.Fatalf("probeWouldMatter(%+v, %q) = %v, 期望 %v", tt.servers, tt.want, got, tt.matters)
			}
		})
	}
}

func TestFilterReachableNeedingSkipsProbeWhenItCannotMatter(t *testing.T) {
	// 关键回归：只有主机名（或显式指定地址族）时不得触发探测。用一个会
	// panic 的探测结果来证明这一点——若真的去探测，测试会失败。
	restore := SetCapabilitiesForTest(NetworkCapabilities{IPv4: true, IPv6: true})
	defer restore()

	hostnames := []model.Server{
		{Name: "DoT", Address: "dns.google", Protocol: model.ProtocolDoT},
		{Name: "DoH", Address: "https://dns.google/dns-query", Protocol: model.ProtocolDoH},
	}
	kept, skipped := FilterReachableNeeding(hostnames, model.IPAny)
	if skipped != 0 || len(kept) != len(hostnames) {
		t.Fatalf("只有主机名时被过滤: kept=%d skipped=%d", len(kept), skipped)
	}

	// 显式地址族：仍然按地址族过滤，且不依赖可达性。
	mixed := []model.Server{
		{Name: "v4", Address: "8.8.8.8"},
		{Name: "v6", Address: "2606:4700:4700::1111"},
	}
	kept, skipped = FilterReachableNeeding(mixed, model.IPv4)
	if skipped != 1 || len(kept) != 1 || kept[0].Name != "v4" {
		t.Fatalf("显式 ipv4 过滤结果错误: kept=%+v skipped=%d", kept, skipped)
	}
}

func TestNewFamilyFilterExplicitVersion(t *testing.T) {
	// 显式 --ip-version 是明确指令：只放行该族的字面量，主机名永远放行。
	v4 := NewFamilyFilter(model.IPv4)
	if !v4("8.8.8.8") {
		t.Fatal("ipv4 模式下 IPv4 字面量应放行")
	}
	if v4("2606:4700:4700::1111") {
		t.Fatal("ipv4 模式下 IPv6 字面量应被拒绝")
	}
	if !v4("dns.google") {
		t.Fatal("主机名没有固定地址族，应始终放行")
	}

	v6 := NewFamilyFilter(model.IPv6)
	if v6("8.8.8.8") {
		t.Fatal("ipv6 模式下 IPv4 字面量应被拒绝")
	}
	if !v6("2606:4700:4700::1111") {
		t.Fatal("ipv6 模式下 IPv6 字面量应放行")
	}
	if !v6("dns.google") {
		t.Fatal("主机名应始终放行")
	}
}

func TestNewFamilyFilterUsesProbeVerdict(t *testing.T) {
	// 未显式指定地址族时，由探测结论决定；这条规则必须同时作用于内置
	// 服务器与系统 DNS，否则会出现「跳过了内置 IPv6 却仍在测系统 IPv6」。
	restore := SetCapabilitiesForTest(NetworkCapabilities{IPv4: true, IPv6: false})
	defer restore()

	f := NewFamilyFilter(model.IPAny)
	if !f("8.8.8.8") {
		t.Fatal("IPv4 可用时 IPv4 字面量应放行")
	}
	if f("2606:4700:4700::1111") {
		t.Fatal("IPv6 不可用时 IPv6 字面量应被拒绝")
	}
	if !f("dns.google") {
		t.Fatal("主机名应始终放行（解析时会选可达地址族）")
	}
}

func TestNewFamilyFilterIsPermissiveWhenProbeInconclusive(t *testing.T) {
	// 两个地址族都探不出来（离线、沙箱禁 UDP）时不得过滤任何东西，
	// 否则整份基准会被无声地清空。
	restore := SetCapabilitiesForTest(NetworkCapabilities{})
	defer restore()

	f := NewFamilyFilter(model.IPAny)
	for _, addr := range []string{"8.8.8.8", "2606:4700:4700::1111", "dns.google"} {
		if !f(addr) {
			t.Fatalf("探测无结论时 %q 被过滤了（不得误杀）", addr)
		}
	}
}

func TestSystemDNSLabel(t *testing.T) {
	tests := []struct {
		name  string
		index int
		total int
		want  string
	}{
		{name: "单个系统 DNS", index: 0, total: 1, want: "当前系统 DNS"},
		{name: "总数为 0 时也当作单个", index: 0, total: 0, want: "当前系统 DNS"},
		{name: "多个时第一个", index: 0, total: 2, want: "当前系统 DNS 1"},
		{name: "多个时第二个", index: 1, total: 2, want: "当前系统 DNS 2"},
		{name: "多个时第五个", index: 4, total: 5, want: "当前系统 DNS 5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SystemDNSLabel(tt.index, tt.total); got != tt.want {
				t.Fatalf("SystemDNSLabel(%d, %d) = %q, 期望 %q", tt.index, tt.total, got, tt.want)
			}
		})
	}
}

func TestParseWindowsDNSOutput(t *testing.T) {
	// 站点本地地址 fec0::/10 是 Windows 的遗留值，必须被丢弃。
	out := "8.8.8.8\r\n1.1.1.1 fec0:0:0:ffff::1\r\nfec0:0:0:ffff::2  2606:4700:4700::1111\n"
	got := parseWindowsDNSOutput(out)
	want := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	if len(got) != len(want) {
		t.Fatalf("parseWindowsDNSOutput 返回 %v, 期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseWindowsDNSOutput[%d] = %q, 期望 %q（完整 %v）", i, got[i], want[i], got)
		}
	}
}

func TestErrorString(t *testing.T) {
	if got := errNoServers.Error(); got != "未解析出任何有效的 DNS 服务器" {
		t.Fatalf("errNoServers.Error() = %q", got)
	}
}
