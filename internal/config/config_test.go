package config

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"dns-opti/internal/model"
)

// validOptions 返回一份可以通过 Validate 的基线配置，便于逐个分支地制造错误。
func validOptions() Options {
	return Options{
		Domains:   "cn",
		Protocols: []model.Protocol{model.ProtocolUDP},
		Timeout:   time.Second,
		Attempts:  1,
		Formula:   string(FormulaComprehensive),
	}
}

func TestParseProtocols(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []model.Protocol
	}{
		{
			name:  "空字符串返回全部协议",
			input: "",
			want:  []model.Protocol{model.ProtocolUDP, model.ProtocolDoT, model.ProtocolDoH, model.ProtocolDoH3},
		},
		{
			name:  "只有空白也返回全部协议",
			input: "   ",
			want:  []model.Protocol{model.ProtocolUDP, model.ProtocolDoT, model.ProtocolDoH, model.ProtocolDoH3},
		},
		{
			name:  "标准名称",
			input: "udp,dot,doh,doh3",
			want:  []model.Protocol{model.ProtocolUDP, model.ProtocolDoT, model.ProtocolDoH, model.ProtocolDoH3},
		},
		{
			name:  "别名 tls 与 h3",
			input: "tls,h3",
			want:  []model.Protocol{model.ProtocolDoT, model.ProtocolDoH3},
		},
		{
			name:  "保留输入顺序",
			input: "doh3,udp",
			want:  []model.Protocol{model.ProtocolDoH3, model.ProtocolUDP},
		},
		{
			name:  "去重且保留首次出现的位置",
			input: "udp,doh,udp,doh",
			want:  []model.Protocol{model.ProtocolUDP, model.ProtocolDoH},
		},
		{
			name:  "忽略空条目",
			input: "udp,,  ,doh",
			want:  []model.Protocol{model.ProtocolUDP, model.ProtocolDoH},
		},
		{
			name:  "去除首尾空白",
			input: "  udp , doh ",
			want:  []model.Protocol{model.ProtocolUDP, model.ProtocolDoH},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProtocols(tt.input)
			if err != nil {
				t.Fatalf("ParseProtocols(%q) 返回意外错误: %v", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseProtocols(%q) = %v, 期望 %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("ParseProtocols(%q)[%d] = %q, 期望 %q（完整结果 %v）", tt.input, i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

func TestParseProtocolsErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "未知协议", input: "quic"},
		{name: "部分未知", input: "udp,weird"},
		{name: "只有分隔符视为空列表", input: ","},
		{name: "混合大小写未收录", input: "uDp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProtocols(tt.input)
			if err == nil {
				t.Fatalf("ParseProtocols(%q) = %v, 期望错误", tt.input, got)
			}
			if got != nil {
				t.Fatalf("ParseProtocols(%q) 出错时仍返回了 %v, 期望 nil", tt.input, got)
			}
		})
	}
}

func TestParseProtocolsEmptyReturnsCopy(t *testing.T) {
	got, err := ParseProtocols("")
	if err != nil {
		t.Fatalf("ParseProtocols(\"\") 返回意外错误: %v", err)
	}
	// 修改返回值不得污染 model.AllProtocols。
	got[0] = model.ProtocolDoH3
	if model.AllProtocols[0] != model.ProtocolUDP {
		t.Fatalf("ParseProtocols 返回的切片是 model.AllProtocols 的别名，修改后原值为 %q", model.AllProtocols[0])
	}
}

func TestParseServerCategories(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []ServerCategory
		wantErr bool
	}{
		{name: "空字符串表示不过滤", input: "", want: nil},
		{name: "只有空白表示不过滤", input: "  ", want: nil},
		{name: "all 表示不过滤", input: "all", want: nil},
		{name: "cn 与 intl", input: "cn,intl", want: []ServerCategory{"cn", "intl"}},
		{name: "大写会被归一化", input: "CN,Intl", want: []ServerCategory{"cn", "intl"}},
		{name: "all 与 cn 混用只保留 cn", input: "all,cn", want: []ServerCategory{"cn"}},
		{name: "忽略空条目", input: "cn,,intl", want: []ServerCategory{"cn", "intl"}},
		{name: "未知分类报错", input: "global", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseServerCategories(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseServerCategories(%q) = %v, 期望错误", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseServerCategories(%q) 返回意外错误: %v", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseServerCategories(%q) = %v, 期望 %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("ParseServerCategories(%q)[%d] = %q, 期望 %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseProtocolSelection(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantProtos []model.Protocol
		wantCombo  string
		wantErr    bool
	}{
		{
			name:       "空表示全部协议且不是组合",
			input:      "",
			wantProtos: model.AllProtocols,
			wantCombo:  "",
		},
		{
			name:       "普通协议列表",
			input:      "udp,doh",
			wantProtos: []model.Protocol{model.ProtocolUDP, model.ProtocolDoH},
			wantCombo:  "",
		},
		{
			name:       "组合模式展开为 UDP 与 DoH",
			input:      "udp+doh",
			wantProtos: []model.Protocol{model.ProtocolUDP, model.ProtocolDoH},
			wantCombo:  model.ComboUDPDoH,
		},
		{
			name:       "组合模式带空白",
			input:      "  udp+doh  ",
			wantProtos: []model.Protocol{model.ProtocolUDP, model.ProtocolDoH},
			wantCombo:  model.ComboUDPDoH,
		},
		{
			name:    "未知组合模式报错而不是当成普通列表",
			input:   "udp+dot",
			wantErr: true,
		},
		{
			name:    "顺序颠倒的组合也报错",
			input:   "doh+udp",
			wantErr: true,
		},
		{
			name:    "未知协议报错",
			input:   "quic",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protos, combo, err := ParseProtocolSelection(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseProtocolSelection(%q) = (%v, %q), 期望错误", tt.input, protos, combo)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseProtocolSelection(%q) 返回意外错误: %v", tt.input, err)
			}
			if combo != tt.wantCombo {
				t.Fatalf("ParseProtocolSelection(%q) combo = %q, 期望 %q", tt.input, combo, tt.wantCombo)
			}
			if len(protos) != len(tt.wantProtos) {
				t.Fatalf("ParseProtocolSelection(%q) = %v, 期望 %v", tt.input, protos, tt.wantProtos)
			}
			for i := range protos {
				if protos[i] != tt.wantProtos[i] {
					t.Fatalf("ParseProtocolSelection(%q)[%d] = %q, 期望 %q",
						tt.input, i, protos[i], tt.wantProtos[i])
				}
			}
		})
	}
}

func TestParseProtocolSelectionEmptyReturnsCopy(t *testing.T) {
	// 空输入返回全部协议，但必须是副本，不能是 model.AllProtocols 的别名。
	got, _, err := ParseProtocolSelection("")
	if err != nil {
		t.Fatalf("ParseProtocolSelection(\"\") 返回意外错误: %v", err)
	}
	got[0] = model.ProtocolDoH3
	if model.AllProtocols[0] != model.ProtocolUDP {
		t.Fatalf("ParseProtocolSelection 返回了 model.AllProtocols 的别名，修改后原值为 %q", model.AllProtocols[0])
	}
}

func TestParseRegions(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{name: "空表示不过滤", input: "", want: nil},
		{name: "只有空白表示不过滤", input: "   ", want: nil},
		{name: "all 表示不过滤", input: "all", want: nil},
		{name: "单个国家", input: "cn", want: []string{"CN"}},
		{name: "多个国家", input: "cn,hk,tw", want: []string{"CN", "HK", "TW"}},
		{name: "大写归一化", input: "CN,HK", want: []string{"CN", "HK"}},
		{name: "混合大小写与空白", input: " cn , Hk ", want: []string{"CN", "HK"}},
		{name: "去重并保留首次出现", input: "cn,CN,hk", want: []string{"CN", "HK"}},
		{name: "特殊码 CDN", input: "cdn", want: []string{"CDN"}},
		{name: "特殊码 PRIVATE", input: "private", want: []string{"PRIVATE"}},
		{name: "特殊码 UNKNOWN", input: "unknown", want: []string{"UNKNOWN"}},
		{name: "混合国家与特殊码", input: "cn,cdn", want: []string{"CN", "CDN"}},
		{name: "忽略空条目", input: "cn,,hk", want: []string{"CN", "HK"}},
		{name: "字母数与位置不符报错", input: "china", wantErr: true},
		{name: "单字母报错", input: "c", wantErr: true},
		{name: "含数字报错", input: "c1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRegions(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRegions(%q) = %v, 期望错误", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRegions(%q) 返回意外错误: %v", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseRegions(%q) = %v, 期望 %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("ParseRegions(%q)[%d] = %q, 期望 %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseIPVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    model.IPVersion
		wantErr bool
	}{
		{name: "ipv4", input: "ipv4", want: model.IPv4},
		{name: "ipv6", input: "ipv6", want: model.IPv6},
		{name: "both", input: "both", want: model.IPAny},
		{name: "any", input: "any", want: model.IPAny},
		{name: "auto", input: "auto", want: model.IPAny},
		{name: "空表示不限制", input: "", want: model.IPAny},
		{name: "v4 别名", input: "v4", want: model.IPv4},
		{name: "v6 别名", input: "v6", want: model.IPv6},
		{name: "4 别名", input: "4", want: model.IPv4},
		{name: "6 别名", input: "6", want: model.IPv6},
		{name: "大写", input: "IPv6", want: model.IPv6},
		{name: "带空白", input: "  ipv4  ", want: model.IPv4},
		{name: "未知值报错", input: "ipv5", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseIPVersion(%q) = %q, 期望错误", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIPVersion(%q) 返回意外错误: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ParseIPVersion(%q) = %q, 期望 %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestOptionsComboHelpers(t *testing.T) {
	plain := Options{Protocols: []model.Protocol{model.ProtocolUDP}}
	if plain.IsCombo() {
		t.Fatal("普通协议配置不应被判定为组合模式")
	}
	if plain.ComboLabel() != "" {
		t.Fatalf("普通协议配置的 ComboLabel = %q, 期望空", plain.ComboLabel())
	}
	if plain.IsUDPDoHCombo() {
		t.Fatal("普通协议配置不应被判定为 UDP+DoH 组合")
	}

	combo := Options{Protocols: []model.Protocol{model.ProtocolUDP, model.ProtocolDoH}, Combo: model.ComboUDPDoH}
	if !combo.IsCombo() {
		t.Fatal("组合配置应被判定为组合模式")
	}
	if !combo.IsUDPDoHCombo() {
		t.Fatal("组合配置应被判定为 UDP+DoH 组合")
	}
	if combo.ComboLabel() != model.ComboUDPDoHLabel {
		t.Fatalf("ComboLabel = %q, 期望 %q", combo.ComboLabel(), model.ComboUDPDoHLabel)
	}
}

func TestValidateRejectsBadIPVersion(t *testing.T) {
	o := Options{
		Domains:      "cn",
		Protocols:    []model.Protocol{model.ProtocolUDP},
		Timeout:      DefaultTimeout,
		Attempts:     1,
		WarmupDomain: DefaultWarmupDomain,
		Formula:      DefaultFormula,
		IPVersion:    model.IPVersion("ipv9"),
	}
	if err := o.Validate(); err == nil {
		t.Fatal("非法的地址族应被 Validate 拒绝")
	}
}

func TestParseFormula(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Formula
		wantErr bool
	}{
		{name: "speed", input: "speed", want: FormulaSpeed},
		{name: "speed 别名 fast", input: "fast", want: FormulaSpeed},
		{name: "speed 别名 latency", input: "latency", want: FormulaSpeed},
		{name: "stable", input: "stable", want: FormulaStable},
		{name: "stable 别名 stability", input: "stability", want: FormulaStable},
		{name: "comprehensive", input: "comprehensive", want: FormulaComprehensive},
		{name: "jitter", input: "jitter", want: FormulaJitter},
		{name: "jitter 别名 anti-jitter", input: "anti-jitter", want: FormulaJitter},
		{name: "空字符串回落到默认公式", input: "", want: FormulaComprehensive},
		{name: "只有空白回落到默认公式", input: "   ", want: FormulaComprehensive},
		{name: "大小写不敏感", input: "  SPEED ", want: FormulaSpeed},
		{name: "未知公式报错", input: "turbo", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFormula(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseFormula(%q) = %q, 期望错误", tt.input, got)
				}
				if got != "" {
					t.Fatalf("ParseFormula(%q) 出错时返回 %q, 期望空字符串", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFormula(%q) 返回意外错误: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ParseFormula(%q) = %q, 期望 %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Options)
		wantErr string // 期望错误信息包含的关键字，空表示期望成功
	}{
		{
			name:   "基线配置合法",
			mutate: func(*Options) {},
		},
		{
			name:    "超时为 0",
			mutate:  func(o *Options) { o.Timeout = 0 },
			wantErr: "超时时间",
		},
		{
			name:    "超时为负数",
			mutate:  func(o *Options) { o.Timeout = -time.Second },
			wantErr: "超时时间",
		},
		{
			name:    "尝试次数为 0",
			mutate:  func(o *Options) { o.Attempts = 0 },
			wantErr: "尝试次数",
		},
		{
			name:    "尝试次数为负数",
			mutate:  func(o *Options) { o.Attempts = -3 },
			wantErr: "尝试次数",
		},
		{
			name:    "并发数为负数",
			mutate:  func(o *Options) { o.Concurrency = -1 },
			wantErr: "并发数",
		},
		{
			name:    "并发数为 0 表示自动，合法",
			mutate:  func(o *Options) { o.Concurrency = 0 },
			wantErr: "",
		},
		{
			name:    "协议列表为空",
			mutate:  func(o *Options) { o.Protocols = nil },
			wantErr: "协议",
		},
		{
			name:    "未知公式",
			mutate:  func(o *Options) { o.Formula = "made-up" },
			wantErr: "评分公式",
		},
		{
			name:    "公式为空使用默认值，合法",
			mutate:  func(o *Options) { o.Formula = "" },
			wantErr: "",
		},
		{
			name:    "域名模式非法",
			mutate:  func(o *Options) { o.Domains = "," },
			wantErr: "域名列表为空",
		},
		{
			name:    "域名模式合法 all",
			mutate:  func(o *Options) { o.Domains = "all" },
			wantErr: "",
		},
		{
			name:    "自定义域名列表合法",
			mutate:  func(o *Options) { o.Domains = "example.com,example.org" },
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := validOptions()
			tt.mutate(&o)
			err := o.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() 返回意外错误: %v（配置 %+v）", err, o)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, 期望包含 %q 的错误（配置 %+v）", tt.wantErr, o)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() 错误 = %q, 期望包含 %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestOptionsEffectiveConcurrency(t *testing.T) {
	tests := []struct {
		name        string
		concurrency int
		want        int
		wantAuto    bool
	}{
		{name: "0 回落到自动值", concurrency: 0, wantAuto: true},
		{name: "负数同样回落到自动值", concurrency: -4, wantAuto: true},
		{name: "正数原样返回", concurrency: 7, want: 7},
		{name: "1 原样返回", concurrency: 1, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := Options{Concurrency: tt.concurrency}
			got := o.EffectiveConcurrency()
			if tt.wantAuto {
				if want := AutoConcurrency(); got != want {
					t.Fatalf("EffectiveConcurrency()（Concurrency=%d）= %d, 期望 AutoConcurrency() = %d",
						tt.concurrency, got, want)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("EffectiveConcurrency()（Concurrency=%d）= %d, 期望 %d", tt.concurrency, got, tt.want)
			}
			if got < 1 {
				t.Fatalf("EffectiveConcurrency() = %d, 必须至少为 1", got)
			}
		})
	}
}

func TestAutoConcurrencyIsThreePerCPUThread(t *testing.T) {
	// 默认并发数是 CPU 线程数的固定倍数（默认 3 倍），且永远至少为 1。
	if DefaultConcurrencyMultiplier < 1 {
		t.Fatalf("DefaultConcurrencyMultiplier = %d, 必须至少为 1", DefaultConcurrencyMultiplier)
	}
	want := runtime.NumCPU() * DefaultConcurrencyMultiplier
	if want < 1 {
		want = 1
	}
	if got := AutoConcurrency(); got != want {
		t.Fatalf("AutoConcurrency() = %d, 期望 CPU 线程数 %d × %d = %d",
			got, runtime.NumCPU(), DefaultConcurrencyMultiplier, want)
	}
	if got := AutoConcurrency(); got < 1 {
		t.Fatalf("AutoConcurrency() = %d, 必须至少为 1", got)
	}
}

func TestDefaultTimeoutIsTwoSeconds(t *testing.T) {
	// 默认超时是 2s：公共 DNS 的正常应答在几百毫秒内，5s 会让不可达的服务器
	// 拖长整轮测试。
	if DefaultTimeout != 2*time.Second {
		t.Fatalf("DefaultTimeout = %v, 期望 2s", DefaultTimeout)
	}
}

func TestOptionsShouldOpenWeb(t *testing.T) {
	tests := []struct {
		name  string
		web   bool
		noWeb bool
		want  bool
	}{
		{name: "都没设置", web: false, noWeb: false, want: false},
		{name: "仅 --web", web: true, noWeb: false, want: true},
		{name: "仅 --no-web", web: false, noWeb: true, want: false},
		{name: "同时设置时 --no-web 优先", web: true, noWeb: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := Options{Web: tt.web, NoWeb: tt.noWeb}
			if got := o.ShouldOpenWeb(); got != tt.want {
				t.Fatalf("ShouldOpenWeb()（Web=%v NoWeb=%v）= %v, 期望 %v", tt.web, tt.noWeb, got, tt.want)
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	if DefaultAttempts < 1 {
		t.Fatalf("DefaultAttempts = %d, 必须至少为 1", DefaultAttempts)
	}
	if DefaultTimeout <= 0 {
		t.Fatalf("DefaultTimeout = %v, 必须大于 0", DefaultTimeout)
	}
	if DefaultWarmupDomain == "" {
		t.Fatal("DefaultWarmupDomain 不能为空")
	}
	// 默认公式必须是可解析的，且就是综合体验。
	f, err := ParseFormula(DefaultFormula)
	if err != nil {
		t.Fatalf("ParseFormula(DefaultFormula=%q) 返回错误: %v", DefaultFormula, err)
	}
	if f != FormulaComprehensive {
		t.Fatalf("DefaultFormula = %q 解析为 %q, 期望 %q", DefaultFormula, f, FormulaComprehensive)
	}
}
