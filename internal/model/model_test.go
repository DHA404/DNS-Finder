package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Protocol
		ok    bool
	}{
		{name: "udp", input: "udp", want: ProtocolUDP, ok: true},
		{name: "UDP", input: "UDP", want: ProtocolUDP, ok: true},
		{name: "dot", input: "dot", want: ProtocolDoT, ok: true},
		{name: "DOT", input: "DOT", want: ProtocolDoT, ok: true},
		{name: "DoT", input: "DoT", want: ProtocolDoT, ok: true},
		{name: "tls 别名", input: "tls", want: ProtocolDoT, ok: true},
		{name: "doh", input: "doh", want: ProtocolDoH, ok: true},
		{name: "DOH", input: "DOH", want: ProtocolDoH, ok: true},
		{name: "DoH", input: "DoH", want: ProtocolDoH, ok: true},
		{name: "doh3", input: "doh3", want: ProtocolDoH3, ok: true},
		{name: "DOH3", input: "DOH3", want: ProtocolDoH3, ok: true},
		{name: "DoH3", input: "DoH3", want: ProtocolDoH3, ok: true},
		{name: "h3 别名", input: "h3", want: ProtocolDoH3, ok: true},
		{name: "未知协议", input: "quic", ok: false},
		{name: "空字符串", input: "", ok: false},
		{name: "大小写混合未收录", input: "uDp", ok: false},
		{name: "带空白的输入不自动裁剪", input: " udp", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseProtocol(tt.input)
			if ok != tt.ok {
				t.Fatalf("ParseProtocol(%q) ok = %v, 期望 %v", tt.input, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("ParseProtocol(%q) = %q, 期望 %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestUnsupportedProtocolExplainsDoH3 checks the build-tag capability guard.
//
// The behaviour is inverted between the two builds, so the assertion is
// deliberately written in terms of the same doh3Disabled constant the guard
// uses: in a default build every protocol is testable, and in a nodoh3 build
// DoH3 must be refused with an actionable message rather than silently failing
// every server.
func TestUnsupportedProtocolExplainsDoH3(t *testing.T) {
	for _, p := range []Protocol{ProtocolUDP, ProtocolDoT, ProtocolDoH} {
		if reason := UnsupportedProtocol(p); reason != "" {
			t.Errorf("UnsupportedProtocol(%q) = %q, 期望空（该协议在任何构建下都可用）", p, reason)
		}
	}

	reason := UnsupportedProtocol(ProtocolDoH3)
	if doh3Disabled {
		if reason == "" {
			t.Fatal("nodoh3 构建下 DoH3 必须被报告为不可用，否则每个 DoH3 服务器都会静默失败")
		}
		// The message has to tell the user what to do instead.
		for _, want := range []string{"nodoh3", "--protocols"} {
			if !strings.Contains(reason, want) {
				t.Errorf("提示信息缺少 %q: %q", want, reason)
			}
		}
	} else if reason != "" {
		t.Errorf("默认构建下 DoH3 应可用, 实际 %q", reason)
	}
}

// TestUnsupportedProtocolsFindsAnyOffender covers the list form, which is what
// the configuration validator calls.
func TestUnsupportedProtocolsFindsAnyOffender(t *testing.T) {
	if reason := UnsupportedProtocols([]Protocol{ProtocolUDP, ProtocolDoH}); reason != "" {
		t.Errorf("全部可用时返回了 %q", reason)
	}
	list := []Protocol{ProtocolUDP, ProtocolDoH3, ProtocolDoH}
	if reason := UnsupportedProtocols(list); doh3Disabled && reason == "" {
		t.Error("列表中含不可用的 DoH3，却未报告")
	}
	if reason := UnsupportedProtocols(nil); reason != "" {
		t.Errorf("空列表返回了 %q", reason)
	}
}

func TestProtocolLabel(t *testing.T) {
	tests := []struct {
		name  string
		input Protocol
		want  string
	}{
		{name: "UDP", input: ProtocolUDP, want: "UDP"},
		{name: "DoT", input: ProtocolDoT, want: "DoT"},
		{name: "DoH", input: ProtocolDoH, want: "DoH"},
		{name: "DoH3", input: ProtocolDoH3, want: "DoH3"},
		{name: "未知协议回落为原始值", input: Protocol("quic"), want: "quic"},
		{name: "空协议回落为空字符串", input: Protocol(""), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.Label(); got != tt.want {
				t.Fatalf("Protocol(%q).Label() = %q, 期望 %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAllProtocolsCanonicalOrder(t *testing.T) {
	want := []Protocol{ProtocolUDP, ProtocolDoT, ProtocolDoH, ProtocolDoH3}
	if len(AllProtocols) != len(want) {
		t.Fatalf("AllProtocols = %v, 期望 %v", AllProtocols, want)
	}
	for i := range want {
		if AllProtocols[i] != want[i] {
			t.Fatalf("AllProtocols[%d] = %q, 期望 %q（完整 %v）", i, AllProtocols[i], want[i], AllProtocols)
		}
	}
}

func TestServerKey(t *testing.T) {
	tests := []struct {
		name   string
		server Server
		want   string
	}{
		{
			name:   "UDP 服务器",
			server: Server{Name: "AliDNS", Address: "223.5.5.5", Protocol: ProtocolUDP},
			want:   "udp|223.5.5.5",
		},
		{
			name:   "DoH 服务器使用完整 URL",
			server: Server{Address: "https://dns.google/dns-query", Protocol: ProtocolDoH},
			want:   "doh|https://dns.google/dns-query",
		},
		{
			name:   "名称不参与 Key",
			server: Server{Name: "某名称", Address: "1.1.1.1", Protocol: ProtocolDoT},
			want:   "dot|1.1.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.server.Key(); got != tt.want {
				t.Fatalf("Server%+v.Key() = %q, 期望 %q", tt.server, got, tt.want)
			}
		})
	}
}

func TestServerKeyDistinguishesProtocol(t *testing.T) {
	// 同一地址的不同协议必须视为不同的服务器，否则内置列表会误判重复。
	udp := Server{Address: "1.1.1.1", Protocol: ProtocolUDP}
	dot := Server{Address: "1.1.1.1", Protocol: ProtocolDoT}
	if udp.Key() == dot.Key() {
		t.Fatalf("UDP 与 DoT 的 Key 相同: %q", udp.Key())
	}
}

func TestSummaryKey(t *testing.T) {
	tests := []struct {
		name    string
		summary Summary
		want    string
	}{
		{
			name:    "国内 UDP",
			summary: Summary{DNS: "8.8.8.8", Protocol: ProtocolUDP, Group: GroupCN},
			want:    "8.8.8.8|udp|cn",
		},
		{
			name:    "国外 DoH",
			summary: Summary{DNS: "https://dns.google/dns-query", Protocol: ProtocolDoH, Group: GroupIntl},
			want:    "https://dns.google/dns-query|doh|intl",
		},
		{
			name:    "导入分组",
			summary: Summary{DNS: "1.1.1.1", Protocol: ProtocolDoH3, Group: GroupImported},
			want:    "1.1.1.1|doh3|imported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.summary.Key(); got != tt.want {
				t.Fatalf("Summary%+v.Key() = %q, 期望 %q", tt.summary, got, tt.want)
			}
		})
	}
}

func TestSummaryKeyDistinguishesGroup(t *testing.T) {
	cn := Summary{DNS: "8.8.8.8", Protocol: ProtocolUDP, Group: GroupCN}
	intl := Summary{DNS: "8.8.8.8", Protocol: ProtocolUDP, Group: GroupIntl}
	if cn.Key() == intl.Key() {
		t.Fatalf("国内与国外分组聚合到了同一个桶: %q", cn.Key())
	}
}

// TestHostOfAcceptsEveryEndpointShape checks the single host-extraction
// implementation: every shape the tool accepts, including the ones that are easy
// to truncate wrongly.
func TestHostOfAcceptsEveryEndpointShape(t *testing.T) {
	tests := []struct {
		endpoint string
		want     string
		why      string
	}{
		{"223.5.5.5", "223.5.5.5", "裸 IPv4"},
		{"223.5.5.5:53", "223.5.5.5", "带端口"},
		{"2400:3200::1", "2400:3200::1", "裸 IPv6 必须保留最后一组"},
		{"2402:4e00::", "2402:4e00::", "以 :: 结尾的 IPv6 不得被当成端口截断"},
		{"[2606:4700:4700::1111]", "2606:4700:4700::1111", "带方括号的 IPv6"},
		{"[2606:4700:4700::1111]:443", "2606:4700:4700::1111", "方括号 IPv6 加端口"},
		{"https://dns.google/dns-query", "dns.google", "DoH URL"},
		{"https://doh.sb", "doh.sb", "无路径的 DoH URL"},
		{"https://dns.google:443/dns-query", "dns.google", "DoH URL 带默认端口"},
		{"udp://1.1.1.1", "1.1.1.1", "带 scheme 的明文端点"},
		{"tls://dot.pub", "dot.pub", "DoT 端点"},
		{"doh.sb", "doh.sb", "裸主机名"},
		{"", "", "空值"},
	}
	for _, tt := range tests {
		if got := HostOf(tt.endpoint); got != tt.want {
			t.Errorf("HostOf(%q) = %q, 期望 %q（%s）", tt.endpoint, got, tt.want, tt.why)
		}
	}
}

// TestServerDisplayIPPrefersResolvedAddress covers the display rule: the
// resolved literal wins, and a hostname endpoint falls back to its host so a row
// always has an identity.
func TestServerDisplayIPPrefersResolvedAddress(t *testing.T) {
	tests := []struct {
		name   string
		server Server
		want   string
	}{
		{
			name:   "字面地址端点",
			server: Server{Address: "223.5.5.5"},
			want:   "223.5.5.5",
		},
		{
			name:   "已解析的主机名端点使用解析结果",
			server: Server{Address: "https://dns.google/dns-query", IP: "8.8.8.8"},
			want:   "8.8.8.8",
		},
		{
			name:   "未解析的主机名端点回落到主机名",
			server: Server{Address: "https://dns.google/dns-query"},
			want:   "dns.google",
		},
		{
			name:   "IPv6 字面量",
			server: Server{Address: "[2606:4700:4700::1111]"},
			want:   "2606:4700:4700::1111",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.server.DisplayIP(); got != tt.want {
				t.Errorf("DisplayIP() = %q, 期望 %q", got, tt.want)
			}
		})
	}
}

// TestSummaryDisplayIPMirrorsServer keeps the two identity paths in step.
func TestSummaryDisplayIPMirrorsServer(t *testing.T) {
	s := Summary{DNS: "https://dns.quad9.net/dns-query"}
	if got := s.DisplayIP(); got != "dns.quad9.net" {
		t.Errorf("Summary.DisplayIP() = %q, 期望 dns.quad9.net", got)
	}
	s.IP = "9.9.9.9"
	if got := s.DisplayIP(); got != "9.9.9.9" {
		t.Errorf("Summary.DisplayIP() 未优先使用已解析地址: %q", got)
	}
}

// TestGroupShortLabel pins the compact wording used in narrow table cells.
func TestGroupShortLabel(t *testing.T) {
	tests := map[string]string{
		GroupCN:       "国内",
		GroupIntl:     "国外",
		GroupMixed:    "混合",
		GroupCustom:   "自定义",
		GroupImported: "导入",
	}
	for group, want := range tests {
		if got := GroupShortLabel(group); got != want {
			t.Errorf("GroupShortLabel(%q) = %q, 期望 %q", group, got, want)
		}
	}
}

func TestGroupLabel(t *testing.T) {
	tests := []struct {
		name  string
		group string
		want  string
	}{
		{name: "国内", group: GroupCN, want: "国内域名"},
		{name: "国外", group: GroupIntl, want: "国外域名"},
		{name: "混合", group: GroupMixed, want: "国内外混合"},
		{name: "自定义", group: GroupCustom, want: "自定义域名"},
		{name: "导入", group: GroupImported, want: "导入数据"},
		{name: "未知分组回落为原始键", group: "other", want: "other"},
		{name: "空分组回落为空字符串", group: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GroupLabel(tt.group); got != tt.want {
				t.Fatalf("GroupLabel(%q) = %q, 期望 %q", tt.group, got, tt.want)
			}
		})
	}
}

func TestGroupKeysAreDistinct(t *testing.T) {
	groups := []string{GroupCN, GroupIntl, GroupMixed, GroupCustom, GroupImported}
	seen := map[string]bool{}
	for _, g := range groups {
		if seen[g] {
			t.Fatalf("分组常量出现重复值: %q", g)
		}
		seen[g] = true
	}
}

func TestSummaryJSONRoundTrip(t *testing.T) {
	// Summary 是导出文件的序列化契约，字段名不能被意外改动。
	in := Summary{
		DNS: "8.8.8.8", Name: "Google", Protocol: ProtocolUDP, Group: GroupCN,
		Total: 10, Success: 9, SuccessRate: 0.9,
		AvgMS: 15.2, P95MS: 28.1, StdDevMS: 4.3,
		IsSystem: true, IsPrivate: true,
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("json.Marshal(Summary) 返回错误: %v", err)
	}
	var out Summary
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("json.Unmarshal(Summary) 返回错误: %v", err)
	}
	if out != in {
		t.Fatalf("Summary 往返后 = %+v, 期望 %+v（JSON: %s）", out, in, data)
	}

	for _, key := range []string{`"dns"`, `"protocol"`, `"group"`, `"success_rate"`, `"avg_ms"`, `"p95_ms"`, `"stddev_ms"`} {
		if !strings.Contains(string(data), key) {
			t.Fatalf("Summary 的 JSON 缺少字段 %s: %s", key, data)
		}
	}
}

func TestFileJSONShape(t *testing.T) {
	// 导出文件的三个顶层块必须保持 meta / raw / summary 的命名。
	f := File{
		Meta:    Meta{Version: "1.0", DomainGroups: []string{GroupCN}, Protocols: []string{"udp"}},
		Raw:     []RawRecord{{DNS: "8.8.8.8", Protocol: ProtocolUDP, Domain: "example.com", Group: GroupCN}},
		Summary: []Summary{{DNS: "8.8.8.8", Protocol: ProtocolUDP, Group: GroupCN, Total: 1, Success: 1}},
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal(File) 返回错误: %v", err)
	}
	for _, key := range []string{`"meta"`, `"raw"`, `"summary"`} {
		if !strings.Contains(string(data), key) {
			t.Fatalf("File 的 JSON 缺少顶层字段 %s: %s", key, data)
		}
	}
	var back File
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("json.Unmarshal(File) 返回错误: %v", err)
	}
	if len(back.Raw) != 1 || len(back.Summary) != 1 {
		t.Fatalf("File 往返后 raw=%d summary=%d, 期望各 1 条", len(back.Raw), len(back.Summary))
	}
}
