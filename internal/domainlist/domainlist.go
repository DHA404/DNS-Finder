// Package domainlist selects the test domains for a run from the built-in,
// embedded domain lists.
//
// Domestic and international domains are kept apart by default: they are
// reported as separate groups with separate scores, because a resolver can be
// excellent for one and poor for the other, and a single pooled score would
// hide exactly that difference. The CLI's --domains flag chooses which groups
// take part (see PLAN 八).
//
// Merging them is possible but must be asked for. ModeMixed pools both lists
// into one group and is opt-in; it is never what an unqualified run does, so a
// user who did not ask for pooling cannot be shown a blended number by
// accident.
package domainlist

import (
	"fmt"
	"strings"

	"dns-opti/data"
	"dns-opti/internal/model"
)

// Selection modes accepted by --domains.
const (
	ModeCN   = "cn"   // 仅国内域名
	ModeIntl = "intl" // 仅国外域名
	ModeAll  = "all"  // 国内 + 国外域名（分组分别统计）
	// ModeMixed measures the 国内 and 国外 domains as ONE pooled group called
	// "mixed".
	//
	// It is a separate mode from ModeAll rather than a change to it, because
	// the two answer different questions. ModeAll keeps the groups apart and is
	// therefore the mode that can tell a user "fast for 国内, slow for 国外" —
	// pooling would destroy exactly that information. ModeMixed instead
	// describes a resolver's behaviour across a realistic mixed workload, which
	// is what someone picking a single daily-driver resolver cares about. Both
	// are useful, so both exist and neither silently replaces the other.
	ModeMixed = "mixed"
)

// Select returns the domains to test for the given mode. A mode that is not
// one of the built-in keywords is treated as an explicit comma-separated
// domain list; such domains inherit the mode keyword as their group so that
// custom lists stay separate from the built-in ones.
func Select(mode string) ([]model.Domain, error) {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = ModeAll
	}

	switch strings.ToLower(mode) {
	case ModeCN:
		return group(data.CNDomains(), model.GroupCN), nil
	case ModeIntl:
		return group(data.IntlDomains(), model.GroupIntl), nil
	case ModeAll:
		domains := group(data.CNDomains(), model.GroupCN)
		return append(domains, group(data.IntlDomains(), model.GroupIntl)...), nil
	case ModeMixed:
		return mixed(), nil
	default:
		return custom(mode)
	}
}

// mixed pools both built-in lists into a single group.
//
// Both lists are de-duplicated against each other before being tagged, so a
// domain that appears in both files is measured once under the pooled group
// rather than twice. Without that, the pool would silently weight a shared
// domain double and skew every latency figure towards it.
func mixed() []model.Domain {
	seen := make(map[string]struct{})
	var out []model.Domain
	for _, names := range [][]string{data.CNDomains(), data.IntlDomains()} {
		for _, raw := range names {
			name := strings.TrimSpace(raw)
			if name == "" {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, model.Domain{Name: name, Group: model.GroupMixed})
		}
	}
	return out
}

// group attaches a group key to a raw name list, deduplicating while keeping
// the original order.
func group(names []string, g string) []model.Domain {
	seen := make(map[string]struct{}, len(names))
	out := make([]model.Domain, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, model.Domain{Name: name, Group: g})
	}
	return out
}

// custom parses an explicit comma-separated domain list. Each entry becomes a
// domain in the "custom" group.
func custom(raw string) ([]model.Domain, error) {
	seen := make(map[string]struct{})
	var out []model.Domain
	for item := range strings.SplitSeq(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, dup := seen[item]; dup {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, model.Domain{Name: item, Group: model.GroupCustom})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("域名列表为空: %q", raw)
	}
	return out, nil
}

// Groups returns the distinct group keys of a domain list, in first-seen order.
func Groups(domains []model.Domain) []string {
	seen := make(map[string]struct{}, len(domains))
	var out []string
	for _, d := range domains {
		if _, ok := seen[d.Group]; ok {
			continue
		}
		seen[d.Group] = struct{}{}
		out = append(out, d.Group)
	}
	return out
}
