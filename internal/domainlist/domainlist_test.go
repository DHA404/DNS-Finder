package domainlist

import (
	"strings"
	"testing"

	"dns-opti/data"
	"dns-opti/internal/model"
)

// groupOf 返回列表中第一次出现的分组，列表为空时返回 ""。
func groupOf(domains []model.Domain) string {
	if len(domains) == 0 {
		return ""
	}
	return domains[0].Group
}

// groupsIn 返回列表中出现的所有分组（按首次出现顺序，去重）。
func groupsIn(domains []model.Domain) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range domains {
		if seen[d.Group] {
			continue
		}
		seen[d.Group] = true
		out = append(out, d.Group)
	}
	return out
}

func TestSelectBuiltInModes(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		wantNames []string
		wantGroup string
	}{
		{name: "cn", mode: ModeCN, wantNames: data.CNDomains(), wantGroup: model.GroupCN},
		{name: "intl", mode: ModeIntl, wantNames: data.IntlDomains(), wantGroup: model.GroupIntl},
		{name: "大小写不敏感 CN", mode: "CN", wantNames: data.CNDomains(), wantGroup: model.GroupCN},
		{name: "带空白 intl", mode: "  intl  ", wantNames: data.IntlDomains(), wantGroup: model.GroupIntl},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(tt.mode)
			if err != nil {
				t.Fatalf("Select(%q) 返回意外错误: %v", tt.mode, err)
			}
			if len(got) != len(tt.wantNames) {
				t.Fatalf("Select(%q) 返回 %d 个域名, 期望 %d 个", tt.mode, len(got), len(tt.wantNames))
			}
			for i, d := range got {
				if d.Name != tt.wantNames[i] {
					t.Fatalf("Select(%q)[%d].Name = %q, 期望 %q", tt.mode, i, d.Name, tt.wantNames[i])
				}
				if d.Group != tt.wantGroup {
					t.Fatalf("Select(%q)[%d] 域名 %q 的分组 = %q, 期望 %q", tt.mode, i, d.Name, d.Group, tt.wantGroup)
				}
			}
			// 内建模式绝不允许出现第二种分组，国内外必须严格分开。
			for _, g := range groupsIn(got) {
				if g != tt.wantGroup {
					t.Fatalf("Select(%q) 混入了分组 %q（期望只有 %q）", tt.mode, g, tt.wantGroup)
				}
			}
		})
	}
}

func TestSelectAllSplitsGroupsWithoutMixing(t *testing.T) {
	got, err := Select(ModeAll)
	if err != nil {
		t.Fatalf("Select(%q) 返回意外错误: %v", ModeAll, err)
	}
	wantCount := len(data.CNDomains()) + len(data.IntlDomains())
	if len(got) != wantCount {
		t.Fatalf("Select(\"all\") 返回 %d 个域名, 期望 %d 个（国内 %d + 国外 %d）",
			len(got), wantCount, len(data.CNDomains()), len(data.IntlDomains()))
	}

	// 国内域名必须整体在前，国外域名紧随其后，两个分组不交错。
	cnCount := 0
	intlCount := 0
	for i, d := range got {
		switch d.Group {
		case model.GroupCN:
			if intlCount > 0 {
				t.Fatalf("Select(\"all\")[%d] 国内域名 %q 出现在国外域名之后，分组被混用", i, d.Name)
			}
			cnCount++
		case model.GroupIntl:
			intlCount++
		default:
			t.Fatalf("Select(\"all\")[%d] 域名 %q 的分组 = %q, 期望 cn 或 intl", i, d.Name, d.Group)
		}
	}
	if cnCount != len(data.CNDomains()) {
		t.Fatalf("Select(\"all\") 国内域名 %d 个, 期望 %d 个", cnCount, len(data.CNDomains()))
	}
	if intlCount != len(data.IntlDomains()) {
		t.Fatalf("Select(\"all\") 国外域名 %d 个, 期望 %d 个", intlCount, len(data.IntlDomains()))
	}

	// "all" 不得产生第三种分组。
	if groups := groupsIn(got); len(groups) != 2 || groups[0] != model.GroupCN || groups[1] != model.GroupIntl {
		t.Fatalf("Select(\"all\") 分组 = %v, 期望 [cn intl]", groups)
	}
}

// TestSelectMixedPoolsBothListsIntoOneGroup is the core contract of the mixed
// mode: everything lands in exactly one group, and both source lists are
// represented in full.
func TestSelectMixedPoolsBothListsIntoOneGroup(t *testing.T) {
	got, err := Select(ModeMixed)
	if err != nil {
		t.Fatalf("Select(%q) 返回意外错误: %v", ModeMixed, err)
	}

	cn, intl := data.CNDomains(), data.IntlDomains()
	// Both lists may share a domain, so the pooled size is bounded rather than
	// exactly equal to the sum.
	if len(got) > len(cn)+len(intl) {
		t.Fatalf("混合模式返回 %d 个域名, 多于两个列表之和 %d", len(got), len(cn)+len(intl))
	}
	if groups := groupsIn(got); len(groups) != 1 || groups[0] != model.GroupMixed {
		t.Fatalf("Select(%q) 分组 = %v, 期望只有 [%s]", ModeMixed, groups, model.GroupMixed)
	}
	for i, d := range got {
		if d.Group != model.GroupMixed {
			t.Fatalf("混合模式[%d] 域名 %q 的分组 = %q, 期望 %q", i, d.Name, d.Group, model.GroupMixed)
		}
	}

	// Every domestic and international domain must be present, so pooling
	// cannot silently drop a list.
	present := map[string]bool{}
	for _, d := range got {
		present[d.Name] = true
	}
	for _, name := range cn {
		if !present[name] {
			t.Errorf("混合模式缺少国内域名 %q", name)
		}
	}
	for _, name := range intl {
		if !present[name] {
			t.Errorf("混合模式缺少国外域名 %q", name)
		}
	}
}

// TestSelectMixedDeduplicatesAcrossLists guards the weighting bug: a domain
// present in both files must be measured once, not twice, or the pooled latency
// would be skewed towards it.
func TestSelectMixedDeduplicatesAcrossLists(t *testing.T) {
	got, err := Select(ModeMixed)
	if err != nil {
		t.Fatalf("Select(%q) 失败: %v", ModeMixed, err)
	}
	seen := map[string]int{}
	for _, d := range got {
		seen[d.Name]++
	}
	for name, n := range seen {
		if n != 1 {
			t.Errorf("域名 %q 在混合模式里出现了 %d 次", name, n)
		}
	}
}

// TestMixedIsDistinctFromAll pins the reason both modes exist: "all" keeps the
// groups apart, "mixed" pools them, and neither may behave like the other.
func TestMixedIsDistinctFromAll(t *testing.T) {
	all, err := Select(ModeAll)
	if err != nil {
		t.Fatalf("Select(%q) 失败: %v", ModeAll, err)
	}
	mixed, err := Select(ModeMixed)
	if err != nil {
		t.Fatalf("Select(%q) 失败: %v", ModeMixed, err)
	}

	allGroups := groupsIn(all)
	if len(allGroups) != 2 || allGroups[0] != model.GroupCN || allGroups[1] != model.GroupIntl {
		t.Fatalf("Select(%q) 分组 = %v, 期望 [cn intl]", ModeAll, allGroups)
	}
	if groups := groupsIn(mixed); len(groups) != 1 || groups[0] != model.GroupMixed {
		t.Fatalf("Select(%q) 分组 = %v, 期望 [%s]", ModeMixed, groups, model.GroupMixed)
	}
	// The same domains are covered either way; only the grouping differs.
	if len(all) != len(mixed) {
		t.Errorf("all 有 %d 个域名, mixed 有 %d 个, 两者应覆盖同一批域名", len(all), len(mixed))
	}
}

// TestSelectMixedIsCaseInsensitive matches the other built-in keywords.
func TestSelectMixedIsCaseInsensitive(t *testing.T) {
	lower, err := Select(ModeMixed)
	if err != nil {
		t.Fatalf("Select(%q) 失败: %v", ModeMixed, err)
	}
	upper, err := Select(strings.ToUpper(ModeMixed))
	if err != nil {
		t.Fatalf("Select(%q) 失败: %v", strings.ToUpper(ModeMixed), err)
	}
	if len(lower) != len(upper) {
		t.Errorf("大小写结果不一致: %d vs %d", len(lower), len(upper))
	}
}

func TestSelectEmptyDefaultsToAll(t *testing.T) {
	empty, err := Select("")
	if err != nil {
		t.Fatalf("Select(\"\") 返回意外错误: %v", err)
	}
	all, err := Select(ModeAll)
	if err != nil {
		t.Fatalf("Select(%q) 返回意外错误: %v", ModeAll, err)
	}
	if len(empty) != len(all) {
		t.Fatalf("Select(\"\") 返回 %d 个域名, 期望与 all 相同（%d 个）", len(empty), len(all))
	}
	if groups := groupsIn(empty); len(groups) != 2 {
		t.Fatalf("Select(\"\") 分组 = %v, 期望 [cn intl]", groups)
	}
}

func TestSelectCustomList(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want []string
	}{
		{name: "单个域名", mode: "example.com", want: []string{"example.com"}},
		{name: "多个域名", mode: "example.com,example.org", want: []string{"example.com", "example.org"}},
		{name: "去重且保留首次顺序", mode: "a.com,b.com,a.com", want: []string{"a.com", "b.com"}},
		{name: "忽略空条目", mode: "a.com,,  ,b.com", want: []string{"a.com", "b.com"}},
		{name: "去除首尾空白", mode: " a.com , b.com ", want: []string{"a.com", "b.com"}},
		{name: "非法模式关键字被当作域名", mode: "cnn", want: []string{"cnn"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(tt.mode)
			if err != nil {
				t.Fatalf("Select(%q) 返回意外错误: %v", tt.mode, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Select(%q) 返回 %d 个域名, 期望 %d 个（%v）", tt.mode, len(got), len(tt.want), tt.want)
			}
			for i, d := range got {
				if d.Name != tt.want[i] {
					t.Fatalf("Select(%q)[%d].Name = %q, 期望 %q", tt.mode, i, d.Name, tt.want[i])
				}
				if d.Group != model.GroupCustom {
					t.Fatalf("Select(%q)[%d] 域名 %q 的分组 = %q, 期望 %q（自定义列表绝不能混入内建分组）",
						tt.mode, i, d.Name, d.Group, model.GroupCustom)
				}
			}
		})
	}
}

func TestSelectEmptyCustomErrors(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{name: "只有逗号", mode: ","},
		{name: "只有空白条目", mode: " , , "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(tt.mode)
			if err == nil {
				t.Fatalf("Select(%q) = %v, 期望错误", tt.mode, got)
			}
			if got != nil {
				t.Fatalf("Select(%q) 出错时返回了 %v, 期望 nil", tt.mode, got)
			}
			if !strings.Contains(err.Error(), "域名列表为空") {
				t.Fatalf("Select(%q) 错误 = %q, 期望包含 %q", tt.mode, err.Error(), "域名列表为空")
			}
		})
	}
}

func TestSelectCustomIsCaseSensitiveKeywordOnly(t *testing.T) {
	// 模式关键字大小写不敏感，但自定义域名本身必须原样保留。
	upper, err := Select("ALL")
	if err != nil {
		t.Fatalf("Select(\"ALL\") 返回意外错误: %v", err)
	}
	if groups := groupsIn(upper); len(groups) != 2 {
		t.Fatalf("Select(\"ALL\") 分组 = %v, 期望 [cn intl]", groups)
	}

	custom, err := Select("Example.COM")
	if err != nil {
		t.Fatalf("Select(\"Example.COM\") 返回意外错误: %v", err)
	}
	if len(custom) != 1 || custom[0].Name != "Example.COM" {
		t.Fatalf("Select(\"Example.COM\") = %v, 期望保留原样的大小写", custom)
	}
}

func TestSelectNoDuplicates(t *testing.T) {
	for _, mode := range []string{ModeCN, ModeIntl, ModeAll, "", "a.com,a.com,b.com"} {
		t.Run("mode="+mode, func(t *testing.T) {
			got, err := Select(mode)
			if err != nil {
				t.Fatalf("Select(%q) 返回意外错误: %v", mode, err)
			}
			seen := map[string]bool{}
			for _, d := range got {
				key := d.Group + "|" + d.Name
				if seen[key] {
					t.Fatalf("Select(%q) 出现重复域名 %q（分组 %q）", mode, d.Name, d.Group)
				}
				seen[key] = true
			}
		})
	}
}

func TestGroupsFirstSeenOrder(t *testing.T) {
	tests := []struct {
		name    string
		domains []model.Domain
		want    []string
	}{
		{
			name:    "空列表",
			domains: nil,
			want:    nil,
		},
		{
			name: "按首次出现顺序",
			domains: []model.Domain{
				{Name: "b.com", Group: model.GroupIntl},
				{Name: "c.com", Group: model.GroupCustom},
				{Name: "a.com", Group: model.GroupCN},
				{Name: "d.com", Group: model.GroupIntl},
			},
			want: []string{model.GroupIntl, model.GroupCustom, model.GroupCN},
		},
		{
			name: "单一分组",
			domains: []model.Domain{
				{Name: "a.com", Group: model.GroupCN},
				{Name: "b.com", Group: model.GroupCN},
			},
			want: []string{model.GroupCN},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Groups(tt.domains)
			if len(got) != len(tt.want) {
				t.Fatalf("Groups(%v) = %v, 期望 %v", tt.domains, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("Groups(%v)[%d] = %q, 期望 %q（完整 %v）", tt.domains, i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

func TestGroupsMatchesSelectOrder(t *testing.T) {
	// Select 结果交给 Groups 时必须是规范的 cn, intl 顺序。
	for _, mode := range []string{ModeCN, ModeIntl, ModeAll} {
		domains, err := Select(mode)
		if err != nil {
			t.Fatalf("Select(%q) 返回意外错误: %v", mode, err)
		}
		got := Groups(domains)
		if len(got) == 0 {
			t.Fatalf("Groups(Select(%q)) 为空", mode)
		}
		if groupOf(domains) != got[0] {
			t.Fatalf("Groups(Select(%q))[0] = %q, 与首个域名的分组 %q 不一致", mode, got[0], groupOf(domains))
		}
	}
}
