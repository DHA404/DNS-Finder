package policy

import (
	"net/netip"
	"strings"
)

// Probe is one category test domain, together with what a blocking answer for
// it looks like.
//
// The domains are published *by the vendors themselves* as self-tests, which is
// the only reason probing works at all: they are real names that resolve
// normally on a resolver that does not filter, so an abnormal answer is
// evidence. A domain that is merely on somebody's blocklist would not do — a
// truly dead name and a filtered name are indistinguishable.
type Probe struct {
	// Domain is the name to query.
	Domain string
	// Category is the kind of content the domain stands for.
	Category Category
	// Source records who publishes the domain as a test, so a future reader can
	// re-verify it rather than trusting this table.
	Source string
}

// Category is the content class a probe domain represents.
type Category string

// The content classes the probes cover.
const (
	// CategoryMalware is the malware/phishing family: what a 安全 resolver
	// exists to block.
	CategoryMalware Category = "malware"
	// CategoryAdvertising is the advertising/tracking family.
	CategoryAdvertising Category = "advertising"
)

// Label returns the Chinese name of a category.
func (c Category) Label() string {
	switch c {
	case CategoryMalware:
		return "恶意软件 / 钓鱼"
	case CategoryAdvertising:
		return "广告 / 跟踪"
	}
	return string(c)
}

// Probes are the category test domains the type detection queries.
//
// Order matters only for reporting; classification treats any hit as a hit.
//
// The list has two halves, and the distinction is not cosmetic — it was measured.
//
// The vendor self-test domains (the first three) are what the feature was
// specified around, and they are the *documented* way to check a resolver. In
// practice they do not discriminate: on a host whose upstream resolver answers
// them, every resolver — filtering and unfiltered alike — returns the real
// address, so a sweep with only these detects nothing. They are kept because
// they are the requested, documented probes and they are authoritative when
// they do fire.
//
// The advertising domains after them are on the widely-used public blocklists
// that filtering resolvers actually ship. They were verified to discriminate: a
// filtering resolver answers them with a sinkhole while a plain resolver returns
// real addresses. Without them the detection cannot see the very behaviour it
// exists to find.
var Probes = []Probe{
	// --- vendor self-test domains ---
	{
		Domain:   "malware.testcategory.com",
		Category: CategoryMalware,
		Source:   "Cloudflare 1.1.1.1 for Families 官方自检域名",
	},
	{
		// NOTE: Cloudflare's own documentation lists only `malware.` and
		// `nudity.` as official self-tests; `phishing.` is *not* documented.
		// It is kept because it is requested and does resolve under the same
		// testcategory.com zone, but its verdict is treated exactly like any
		// other probe rather than as a documented reference.
		Domain:   "phishing.testcategory.com",
		Category: CategoryMalware,
		Source:   "testcategory.com 同区未文档化域名（Cloudflare 官方仅公布 malware. 与 nudity.）",
	},
	{
		Domain:   "advertising.filterdns.net",
		Category: CategoryAdvertising,
		Source:   "DNSFilter 官方广告分类测试域名",
	},

	// --- 实际可区分的广告域名（实测：拦截型返回 sinkhole，原生返回真实地址）---
	{
		Domain:   "googleads.g.doubleclick.net",
		Category: CategoryAdvertising,
		Source:   "实测可区分：AdGuard / CleanBrowsing 返回 0.0.0.0，原生返回真实地址",
	},
	{
		Domain:   "pagead2.googlesyndication.com",
		Category: CategoryAdvertising,
		Source:   "实测可区分：AdGuard / CleanBrowsing 返回 0.0.0.0，原生返回真实地址",
	},
	{
		Domain:   "ad.doubleclick.net",
		Category: CategoryAdvertising,
		Source:   "实测可区分：AdGuard / CleanBrowsing 返回 0.0.0.0，原生返回真实地址",
	},
}

// Verdict is the outcome of probing one resolver.
type Verdict string

// The verdicts.
const (
	// VerdictSecurity means at least one probe was answered abnormally, so the
	// resolver filters.
	VerdictSecurity Verdict = "security"
	// VerdictNative means every probe that produced a usable answer was
	// answered normally, so no filtering was observed.
	VerdictNative Verdict = "native"
	// VerdictUnknown means no probe produced a usable answer at all, so the
	// resolver says nothing about its policy. It must never be reported as
	// Native: failing to reach a resolver is not evidence that it is unfiltered.
	VerdictUnknown Verdict = "unknown"
)

// Kind maps a verdict onto the policy kind it establishes.
func (v Verdict) Kind() Kind {
	switch v {
	case VerdictSecurity:
		return Security
	case VerdictNative:
		return Native
	}
	return Unknown
}

// Label returns the Chinese name of a verdict.
func (v Verdict) Label() string { return Label(v.Kind()) }

// Answer is how one resolver answered one probe, as classified by AnswerState.
type AnswerState int

// The states an answer can be in.
const (
	// AnswerNormal is a real address: the resolver did not block the name.
	AnswerNormal AnswerState = iota
	// AnswerBlocked is a deliberate refusal: NXDOMAIN, no records, or a
	// sinkhole address.
	AnswerBlocked
	// AnswerUnusable is a failure to obtain any answer — a timeout, a refused
	// connection, a server failure. It is *not* evidence of blocking.
	AnswerUnusable
)

// String renders an answer state for reports.
func (s AnswerState) String() string {
	switch s {
	case AnswerNormal:
		return "正常"
	case AnswerBlocked:
		return "拦截"
	}
	return "无应答"
}

// SinkholeV4 are the IPv4 addresses a filtering resolver returns in place of the
// real answer. Cloudflare documents 0.0.0.0 for its malware blocking; 127.0.0.1
// and the unspecified address are the same idea used by other vendors' block
// pages.
var SinkholeV4 = []string{"0.0.0.0", "127.0.0.1"}

// IsSinkhole reports whether an address is a blocking placeholder rather than a
// real answer.
//
// Callers must pass addresses that came from a *successful* answer; the whole
// point is to separate a deliberate placeholder from a failure to answer, so
// treating "no answer" as a sinkhole would invert the verdict.
func IsSinkhole(address string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() {
		// 0.0.0.0, ::, 127.0.0.1, ::1
		return true
	}
	for _, s := range SinkholeV4 {
		if addr.String() == s {
			return true
		}
	}
	return false
}

// ClassifyAnswer turns one observed answer into an answer state.
//
// rcode is the DNS response code as a number (0 = NOERROR, 3 = NXDOMAIN); addrs
// are the A/AAAA addresses in the answer section, empty when there are none.
//
// The classification is deliberately conservative: only a definitive refusal
// counts as blocking. A response code the caller could not interpret (SERVFAIL,
// REFUSED) is reported as unusable rather than as blocking, because a resolver
// that is failing is not the same as a resolver that is filtering, and confusing
// the two would label a broken resolver as a secure one.
func ClassifyAnswer(rcode int, addrs []string) AnswerState {
	switch rcode {
	case 0: // NOERROR
		if len(addrs) == 0 {
			// NOERROR with an empty answer section: the name exists but has no
			// record of the requested type. For a known-good probe domain that
			// is a deliberate empty answer, which is how several resolvers
			// implement blocking.
			return AnswerBlocked
		}
		for _, a := range addrs {
			if IsSinkhole(a) {
				return AnswerBlocked
			}
		}
		return AnswerNormal
	case 3: // NXDOMAIN
		return AnswerBlocked
	default:
		return AnswerUnusable
	}
}

// VerdictFrom folds the per-probe answer states of one resolver into a verdict.
//
// The rule is "any hit wins": a single blocked probe is enough to call the
// resolver 安全, because blocking *any* of these categories is filtering. Only
// when every probe that produced an answer produced a normal one is the resolver
// called 原生, and only when no probe produced any answer at all is it 未确认.
func VerdictFrom(states []AnswerState) Verdict {
	sawUsable := false
	for _, s := range states {
		switch s {
		case AnswerBlocked:
			return VerdictSecurity
		case AnswerNormal:
			sawUsable = true
		}
	}
	if !sawUsable {
		return VerdictUnknown
	}
	return VerdictNative
}

// Detection is the full record of probing one resolver, kept so the interactive
// screen can show *why* a verdict was reached rather than only the verdict.
type Detection struct {
	// Server is the endpoint that was probed.
	Server string
	// Name is the resolver's display name, when known.
	Name string
	// Curated is the policy the built-in table asserted before probing, so a
	// disagreement between documentation and observation is visible.
	Curated Kind
	// Observed is what the probes concluded.
	Observed Verdict
	// Answers holds the per-probe classification, aligned with Probes.
	Answers []AnswerState
	// Note carries a failure reason when nothing could be probed.
	Note string
}

// ProgressFunc receives one completed detection. It is called from the probing
// goroutine, so an implementation must not block: a slow consumer would stall
// the detection rather than merely lag behind it.
type ProgressFunc func(done, total int, det Detection)

// Agrees reports whether the observation matches the curated table. An unknown
// observation never agrees with a documented policy, because it establishes
// nothing.
func (d Detection) Agrees() bool {
	return d.Observed != VerdictUnknown && d.Observed.Kind() == CanonicalKind(d.Curated)
}

// Kind returns the policy a detection establishes.
func (d Detection) Kind() Kind { return d.Observed.Kind() }
