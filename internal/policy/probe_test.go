package policy

import "testing"

func TestProbesAreWellFormed(t *testing.T) {
	if len(Probes) == 0 {
		t.Fatal("Probes 为空，检测无从进行")
	}
	seen := map[string]bool{}
	for i, p := range Probes {
		if p.Domain == "" {
			t.Errorf("Probes[%d] 缺少域名", i)
		}
		if seen[p.Domain] {
			t.Errorf("域名 %q 重复", p.Domain)
		}
		seen[p.Domain] = true
		if p.Source == "" {
			t.Errorf("域名 %q 未记录来源，无法复核", p.Domain)
		}
		if p.Category.Label() == string(p.Category) {
			t.Errorf("域名 %q 的分类 %q 没有中文名称", p.Domain, p.Category)
		}
	}
	// The requested vendor self-tests must stay in the set: they are the
	// documented probes the feature was specified around.
	for _, want := range []string{
		"malware.testcategory.com",
		"phishing.testcategory.com",
		"advertising.filterdns.net",
	} {
		if !seen[want] {
			t.Errorf("请求指定的测试域 %q 不在检测集合中", want)
		}
	}
}

func TestIsSinkhole(t *testing.T) {
	tests := []struct {
		addr string
		want bool
		why  string
	}{
		{"0.0.0.0", true, "Cloudflare 文档所述的拦截占位地址"},
		{"127.0.0.1", true, "部分厂商用环回地址作占位"},
		{"::", true, "IPv6 未指定地址"},
		{"::1", true, "IPv6 环回"},
		{"104.18.4.35", false, "真实地址"},
		{"220.181.174.38", false, "真实地址"},
		{"", false, "空值不是占位地址"},
		{"not-an-ip", false, "无法解析的值不算占位"},
	}
	for _, tt := range tests {
		if got := IsSinkhole(tt.addr); got != tt.want {
			t.Errorf("IsSinkhole(%q) = %v, 期望 %v（%s）", tt.addr, got, tt.want, tt.why)
		}
	}
}

// TestClassifyAnswer is the heart of the detection: telling a deliberate
// refusal apart from a failure to answer. Getting this backwards would label
// every unreachable resolver as a filtering one.
func TestClassifyAnswer(t *testing.T) {
	tests := []struct {
		name  string
		rcode int
		addrs []string
		want  AnswerState
		why   string
	}{
		{"正常应答", 0, []string{"104.18.4.35"}, AnswerNormal, "真实地址"},
		{"sinkhole 0.0.0.0", 0, []string{"0.0.0.0"}, AnswerBlocked, "Cloudflare 拦截即返回 0.0.0.0"},
		{"sinkhole 127.0.0.1", 0, []string{"127.0.0.1"}, AnswerBlocked, "环回占位"},
		{"NOERROR 空应答", 0, nil, AnswerBlocked, "空答案段是部分厂商的拦截实现"},
		{"NXDOMAIN", 3, nil, AnswerBlocked, "明确的拒绝"},
		{"SERVFAIL", 2, nil, AnswerUnusable, "服务器故障不等于在过滤"},
		{"REFUSED", 5, nil, AnswerUnusable, "拒绝服务不等于在过滤"},
		{"混合：一个真实地址", 0, []string{"0.0.0.0", "1.2.3.4"}, AnswerBlocked, "出现占位即视为拦截"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyAnswer(tt.rcode, tt.addrs); got != tt.want {
				t.Errorf("ClassifyAnswer(%d, %v) = %v, 期望 %v（%s）",
					tt.rcode, tt.addrs, got, tt.want, tt.why)
			}
		})
	}
}

// TestVerdictFromAnyHitWins pins the requested rule: one blocked probe is
// enough.
func TestVerdictFromAnyHitWins(t *testing.T) {
	tests := []struct {
		name   string
		states []AnswerState
		want   Verdict
		why    string
	}{
		{"全部正常", []AnswerState{AnswerNormal, AnswerNormal, AnswerNormal}, VerdictNative, ""},
		{
			"只有一个被拦截",
			[]AnswerState{AnswerNormal, AnswerBlocked, AnswerNormal},
			VerdictSecurity, "任一命中即判为安全",
		},
		{
			"拦截在最后一位",
			[]AnswerState{AnswerNormal, AnswerNormal, AnswerBlocked},
			VerdictSecurity, "位置无关",
		},
		{
			"全部无应答",
			[]AnswerState{AnswerUnusable, AnswerUnusable, AnswerUnusable},
			VerdictUnknown, "无应答不是「不过滤」的证据",
		},
		{
			"部分无应答但有一个正常",
			[]AnswerState{AnswerUnusable, AnswerNormal, AnswerUnusable},
			VerdictNative, "有正常应答即可判定，无应答的部分不影响结论",
		},
		{
			"无应答优先于正常还是拦截",
			[]AnswerState{AnswerUnusable, AnswerBlocked, AnswerUnusable},
			VerdictSecurity, "拦截仍然优先",
		},
		{"空列表", nil, VerdictUnknown, "什么都没探测到"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerdictFrom(tt.states); got != tt.want {
				t.Errorf("VerdictFrom(%v) = %q, 期望 %q（%s）", tt.states, got, tt.want, tt.why)
			}
		})
	}
}

// TestVerdictUnknownIsNeverNative guards the failure mode that matters most: an
// unreachable resolver must not acquire a "no filtering" verdict.
func TestVerdictUnknownIsNeverNative(t *testing.T) {
	v := VerdictFrom([]AnswerState{AnswerUnusable, AnswerUnusable})
	if v == VerdictNative {
		t.Fatal("无任何可用应答时被判为「原生」——这会把不可达误报成不过滤")
	}
	if v.Kind() != Unknown {
		t.Errorf("Kind() = %q, 期望 %q", v.Kind(), Unknown)
	}
	if Label(v.Kind()) != "未确认" {
		t.Errorf("Label = %q, 期望 未确认", Label(v.Kind()))
	}
}

func TestVerdictKindAndLabel(t *testing.T) {
	tests := []struct {
		v    Verdict
		kind Kind
	}{
		{VerdictSecurity, Security},
		{VerdictNative, Native},
		{VerdictUnknown, Unknown},
	}
	for _, tt := range tests {
		if got := tt.v.Kind(); got != tt.kind {
			t.Errorf("%q.Kind() = %q, 期望 %q", tt.v, got, tt.kind)
		}
		if got := tt.v.Label(); got != Label(tt.kind) {
			t.Errorf("%q.Label() = %q, 期望 %q", tt.v, got, Label(tt.kind))
		}
	}
}

func TestAnswerStateString(t *testing.T) {
	tests := map[AnswerState]string{
		AnswerNormal:   "正常",
		AnswerBlocked:  "拦截",
		AnswerUnusable: "无应答",
	}
	for state, want := range tests {
		if got := state.String(); got != want {
			t.Errorf("AnswerState(%d).String() = %q, 期望 %q", state, got, want)
		}
	}
}

// TestDetectionAgrees covers the comparison the report leans on. An unknown
// observation must never count as agreement, because it establishes nothing.
func TestDetectionAgrees(t *testing.T) {
	tests := []struct {
		name    string
		det     Detection
		agree   bool
		comment string
	}{
		{"安全对上安全", Detection{Curated: Security, Observed: VerdictSecurity}, true, ""},
		{"原生对上原生", Detection{Curated: Native, Observed: VerdictNative}, true, ""},
		{
			"实测安全但表内原生",
			Detection{Curated: Native, Observed: VerdictSecurity},
			false, "需人工复核",
		},
		{
			"实测原生但表内安全",
			Detection{Curated: Security, Observed: VerdictNative},
			false, "需人工复核",
		},
		{
			"未确认不算一致",
			Detection{Curated: Security, Observed: VerdictUnknown},
			false, "什么都没证明，不能算作与文档一致",
		},
		{
			"表内未确认时无一致性可言",
			Detection{Curated: Unknown, Observed: VerdictNative},
			false, "没有可对照的主张",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.det.Agrees(); got != tt.agree {
				t.Errorf("Agrees() = %v, 期望 %v（%s）", got, tt.agree, tt.comment)
			}
		})
	}
}

func TestDetectionKindFollowsObservation(t *testing.T) {
	d := Detection{Curated: Native, Observed: VerdictSecurity}
	if d.Kind() != Security {
		t.Errorf("Kind() = %q, 期望实测结果 %q 而非表内值", d.Kind(), Security)
	}
}

func TestCategoryLabel(t *testing.T) {
	if got := CategoryMalware.Label(); got != "恶意软件 / 钓鱼" {
		t.Errorf("CategoryMalware.Label() = %q", got)
	}
	if got := CategoryAdvertising.Label(); got != "广告 / 跟踪" {
		t.Errorf("CategoryAdvertising.Label() = %q", got)
	}
}
