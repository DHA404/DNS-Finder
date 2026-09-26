// Package engine wires the configuration, the server/domain lists, the
// scheduler and the recorder into a single run.
//
// It owns the lifecycle of a test run: build the task list, stream raw records
// into the recorder, and export the result document. The CLI and the web UI
// both drive the tool through this package, so the two entry points can never
// drift apart.
package engine

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"dns-opti/data"
	"dns-opti/internal/config"
	"dns-opti/internal/dnsclient"
	"dns-opti/internal/domainlist"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/scheduler"
	"dns-opti/internal/store"
)

// Plan is the resolved workload of a configuration: what a run would actually
// test. It is produced by BuildTasks and used to size progress displays and to
// describe the job before it starts.
type Plan struct {
	// Servers, Domains and Total count the resolved workload.
	Servers  int
	Domains  int
	Attempts int
	Total    int
	// ByProto and ByGroup break the counts down for display.
	ByProto map[model.Protocol]int
	ByGroup map[string]int
	// Warnings are the non-fatal remarks collected while resolving.
	Warnings []string
}

// Describe resolves a configuration into a Plan.
func Describe(cfg config.Options) (*Plan, error) {
	servers, domains, warns, err := BuildTasks(cfg)
	if err != nil {
		return nil, err
	}
	plan := &Plan{
		Servers:  len(servers),
		Domains:  len(domains),
		Attempts: cfg.Attempts,
		Total:    len(servers) * len(domains) * cfg.Attempts,
		ByProto:  make(map[model.Protocol]int),
		ByGroup:  make(map[string]int),
		Warnings: warns,
	}
	for _, s := range servers {
		plan.ByProto[s.Protocol]++
	}
	for _, d := range domains {
		plan.ByGroup[d.Group]++
	}
	return plan, nil
}

// DefaultOutputName is the result file name used when none was configured.
func DefaultOutputName() string { return store.DefaultOutputName("") }

// Result is the outcome of a completed run.
type Result struct {
	// Meta is the metadata block written to the result file.
	Meta model.Meta
	// Summaries are the aggregated rows.
	Summaries []model.Summary
	// Histogram is the latency distribution, derived from the recorded raw
	// data. It is only used by the local viewer; it is not part of the
	// exported file (see PLAN 4.3 for the persisted shape).
	Histogram store.Histogram
	// Comparisons holds the per-provider UDP-vs-DoH comparison when the run was
	// configured in a combined mode. It is empty otherwise.
	Comparisons []TransportComparison
	// Path is the file the result was exported to ("" when not exported).
	Path string
	// Failed counts the queries that did not succeed.
	Failed int
	// Total counts every recorded query.
	Total int
	// Duration is the wall-clock time the run took.
	Duration time.Duration
	// Warned is the list of non-fatal remarks (skipped servers, undetectable
	// system DNS, ...) worth showing to the user.
	Warned []string
}

// ProgressFunc receives every completed query.
type ProgressFunc func(scheduler.ProgressEvent)

// RunOptions is the fully resolved input of a run.
type RunOptions struct {
	Config config.Options
	// Progress may be nil.
	Progress ProgressFunc
}

// BuildTasks resolves the options into the servers and domains to test along
// with the remarks produced while doing so. It is shared by the scheduler and
// by callers that only need to preview the workload (e.g. --dry-run).
func BuildTasks(opts config.Options) (servers []model.Server, domains []model.Domain, warns []string, err error) {
	servers, domains, probe, warns, err := buildTasks(opts)
	_ = probe
	return servers, domains, warns, err
}

// BuildTasksWithProbe is BuildTasks plus the reachability verdict that was
// applied, so the caller can record it in the result file.
func BuildTasksWithProbe(opts config.Options) (servers []model.Server, domains []model.Domain, probe *model.NetworkProbe, warns []string, err error) {
	return buildTasks(opts)
}

// buildTasks is the shared implementation of the two exported entry points.
func buildTasks(opts config.Options) (servers []model.Server, domains []model.Domain, probe *model.NetworkProbe, warns []string, err error) {
	domains, err = domainlist.Select(opts.Domains)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(domains) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("域名列表为空")
	}

	var skippedByFamily int

	if opts.Servers != "" {
		servers, err = dnsclient.ParseServers(opts.Servers)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		// An explicit list is still filtered by an explicit --ip-version, so
		// the user's request is honoured consistently; it is *not* filtered by
		// reachability, because --servers is the escape hatch for testing
		// endpoints the automatic probe cannot judge.
		if opts.IPVersion.IsLiteral() {
			servers, skippedByFamily = dnsclient.FilterReachable(servers, opts.IPVersion)
		}
	} else {
		var categories []data.Category
		for _, c := range opts.ServerCategories {
			categories = append(categories, data.Category(c))
		}
		servers = data.Servers(opts.Protocols, categories, opts.Regions, opts.Policies)

		// Report a region or policy filter that matched nothing before the
		// reachability filter gets a chance to hide the reason. A policy filter
		// is the one most likely to empty the list legitimately (most resolvers
		// are 原生), so saying which filter did it matters.
		if len(servers) == 0 {
			if len(opts.Regions) > 0 {
				return nil, nil, nil, nil, fmt.Errorf("没有符合地区筛选（%s）的 DNS 服务器",
					strings.Join(opts.Regions, ", "))
			}
			if len(opts.Policies) > 0 {
				return nil, nil, nil, nil, fmt.Errorf("没有符合过滤策略筛选（%s）的 DNS 服务器",
					policyLabels(opts.Policies))
			}
		}

		servers, skippedByFamily = dnsclient.FilterReachable(servers, opts.IPVersion)
	}

	// The verdict is recorded even when nothing was skipped, so a file always
	// states which families were actually usable on the machine that produced
	// it. Recording it only on a skip would make "no IPv6 servers" ambiguous.
	probe = describeProbe(opts.IPVersion, skippedByFamily)
	if skippedByFamily > 0 {
		warns = append(warns, probe.Label)
	}

	if len(servers) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("没有可测试的 DNS 服务器（请检查 --protocols / --regions / --servers 参数）")
	}

	servers = dnsclient.MarkSpecial(servers)

	if opts.IsCombo() {
		servers = markCombo(servers, opts.Combo)
	}

	if opts.SystemDNS {
		sys := dnsclient.DetectSystemDNS()
		if len(sys) == 0 {
			warns = append(warns, "未能读取系统 DNS 配置，已跳过系统 DNS 对比")
		}
		existing := make(map[string]struct{}, len(servers))
		for _, s := range servers {
			existing[s.Key()] = struct{}{}
		}
		// The same family rules the built-in list is subject to apply here.
		// Testing an IPv6 system resolver on a host whose IPv6 path is dead
		// would spend the whole query budget to produce a guaranteed 0% row,
		// and would contradict the verdict the run already reported.
		familyAllowed := dnsclient.NewFamilyFilter(opts.IPVersion)
		var droppedSystem int
		for i, ip := range sys {
			if !familyAllowed(ip) {
				droppedSystem++
				continue
			}
			s := model.Server{
				Name:      dnsclient.SystemDNSLabel(i, len(sys)),
				Address:   ip,
				Protocol:  model.ProtocolUDP,
				IsSystem:  true,
				IsPrivate: dnsclient.IsPrivate(ip),
			}
			if _, dup := existing[s.Key()]; dup {
				continue
			}
			existing[s.Key()] = struct{}{}
			servers = append(servers, s)
		}
		if droppedSystem > 0 {
			probe.Skipped += droppedSystem
			warns = append(warns, fmt.Sprintf(
				"已跳过 %d 个地址族不可用的系统 DNS（与内置服务器同一判定）", droppedSystem))
		}
		// The appended system resolvers need their derived fields too, so that
		// every row carries a region and a family by the time it is recorded.
		servers = dnsclient.MarkSpecial(servers)

		// The machine's own resolvers are deliberately *not* subject to the
		// region filter: they are the baseline the recommendation is measured
		// against, so dropping them would remove the very comparison the tool
		// exists to make. Say so, because otherwise a filtered run appears to
		// contain out-of-scope servers for no reason.
		if len(opts.Regions) > 0 {
			if added := countSystem(servers); added > 0 {
				warns = append(warns, fmt.Sprintf(
					"地区筛选只作用于内置服务器；为便于对比，仍纳入了 %d 个系统 DNS（不受 --regions 影响）", added))
			}
		}
	}

	return servers, domains, probe, warns, nil
}

// countSystem counts the system resolvers in a server list.
func countSystem(servers []model.Server) int {
	n := 0
	for _, s := range servers {
		if s.IsSystem {
			n++
		}
	}
	return n
}

// policyLabels renders a policy filter for an error message.
func policyLabels(kinds []policy.Kind) string {
	names := make([]string, 0, len(kinds))
	for _, k := range kinds {
		names = append(names, policy.Label(k))
	}
	return strings.Join(names, ", ")
}

// describeProbe turns the address-family decision into the recorded verdict
// plus its human-readable summary.
//
// It is a single source for both, so the sentence printed before the run, the
// sentence kept in the exported file and the numbers a reader can check can
// never disagree with each other.
func describeProbe(want model.IPVersion, skipped int) *model.NetworkProbe {
	cap := dnsclient.DetectCapabilities()
	probe := &model.NetworkProbe{IPv4: cap.IPv4, IPv6: cap.IPv6, Skipped: skipped}

	// An explicit request is an instruction, not a probe result; the verdict is
	// recorded but the wording says what actually decided the filtering.
	if want.IsLiteral() {
		probe.Forced = true
		probe.Label = fmt.Sprintf("已按 --ip-version=%s 跳过 %d 个地址族不符的服务器", want, skipped)
		return probe
	}

	switch {
	case !cap.IPv6 && cap.IPv4:
		probe.Label = fmt.Sprintf(
			"本机 IPv6 实测无响应（已发真实查询确认），已跳过 %d 个 IPv6 服务器；如需强制测试请加 --ip-version=ipv6", skipped)
	case !cap.IPv4 && cap.IPv6:
		probe.Label = fmt.Sprintf(
			"本机 IPv4 实测无响应（已发真实查询确认），已跳过 %d 个 IPv4 服务器；如需强制测试请加 --ip-version=ipv4", skipped)
	case !cap.IPv4 && !cap.IPv6:
		probe.Label = fmt.Sprintf(
			"本机 IPv4 与 IPv6 均实测无响应，未按可达性过滤任何服务器（跳过 %d 个的判定仅基于地址族）", skipped)
	default:
		probe.Label = fmt.Sprintf("已跳过 %d 个本机无法访问的服务器", skipped)
	}
	return probe
}

// markCombo stamps every server with the combination it belongs to, so the
// report can pair a provider's two transports. Servers of protocols the combo
// does not cover are left untouched and therefore never paired.
func markCombo(servers []model.Server, combo string) []model.Server {
	if combo != model.ComboUDPDoH {
		return servers
	}
	out := make([]model.Server, len(servers))
	for i, s := range servers {
		if s.Protocol == model.ProtocolUDP || s.Protocol == model.ProtocolDoH {
			s.Combo = dnsclient.ProviderIdentity(s)
		}
		out[i] = s
	}
	return out
}

// Run executes the benchmark described by opts and exports the result file.
// It is a blocking call; ctx cancels the run.
func Run(ctx context.Context, opts RunOptions) (*Result, error) {
	cfg := opts.Config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	started := time.Now()
	servers, domains, probe, warns, err := buildTasks(cfg)
	if err != nil {
		return nil, err
	}

	recorder, err := store.NewRecorder()
	if err != nil {
		return nil, err
	}
	defer recorder.Cleanup()
	defer recorder.Close()

	sched := scheduler.New(scheduler.Options{
		Servers:     servers,
		Domains:     domains,
		Attempts:    cfg.Attempts,
		Concurrency: cfg.EffectiveConcurrency(),
		Query: dnsclient.Options{
			Timeout:      cfg.Timeout,
			WarmupDomain: cfg.WarmupDomain,
			Family:       cfg.IPVersion,
		},
	}, recorder.Record, opts.Progress)

	// Collect the address family each transport actually settled on. A hostname
	// endpoint only reveals it after resolution, so it cannot be known before
	// the run; without this an IPv6 run would look identical to a dual-stack
	// one in the report and in the viewer's family filter.
	var resolvedMu sync.Mutex
	resolved := make(map[string]model.Server, len(servers))
	sched.OnResolved(func(s model.Server) {
		resolvedMu.Lock()
		resolved[s.Key()] = s
		resolvedMu.Unlock()
	})

	if err := sched.Run(ctx); err != nil {
		return nil, err
	}
	if err := recorder.Close(); err != nil {
		return nil, err
	}
	// Fold the resolved families and literal addresses back in, keeping the
	// original slice order so the metadata block stays stable.
	for i, s := range servers {
		if r, ok := resolved[s.Key()]; ok {
			if r.Family.IsLiteral() {
				servers[i].Family = r.Family
			}
			if r.IP != "" {
				servers[i].IP = r.IP
			}
		}
	}
	recorder.SetServerFlags(servers)

	summaries := recorder.Summaries()
	histogram := recorder.LatencyHistogram()
	meta := buildMeta(cfg, servers, domains, sched.Total(), warns, probe)

	path, err := recorder.Export(meta, store.ExportOptions{Path: cfg.Output, Indent: true})
	if err != nil {
		return nil, err
	}

	failed := 0
	for _, s := range summaries {
		failed += s.Total - s.Success
	}

	return &Result{
		Meta:        meta,
		Summaries:   summaries,
		Histogram:   histogram,
		Comparisons: CompareTransports(summaries),
		Path:        path,
		Failed:      failed,
		Total:       recorder.Count(),
		Duration:    time.Since(started),
		Warned:      warns,
	}, nil
}

// buildMeta assembles the metadata block of the result document.
func buildMeta(cfg config.Options, servers []model.Server, domains []model.Domain, total int, warns []string, probe *model.NetworkProbe) model.Meta {
	protocols := make([]string, 0, len(cfg.Protocols))
	for _, p := range cfg.Protocols {
		protocols = append(protocols, string(p))
	}

	groups := domainlist.Groups(domains)

	policies := make([]string, 0, len(cfg.Policies))
	for _, p := range cfg.Policies {
		policies = append(policies, string(p))
	}

	system := make([]string, 0, 2)
	for _, s := range servers {
		if s.IsSystem {
			system = append(system, s.Address)
		}
	}

	note := ""
	if len(warns) > 0 {
		note = warns[0]
	}

	return model.Meta{
		Version:      "1.0",
		Timestamp:    time.Now().UTC(),
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		Concurrency:  cfg.EffectiveConcurrency(),
		WarmupDomain: cfg.WarmupDomain,
		DomainGroups: groups,
		Protocols:    protocols,
		Combo:        cfg.Combo,
		Regions:      cfg.Regions,
		Policies:     policies,
		Domains:      cfg.Domains,
		IPVersion:    string(cfg.IPVersion),
		Network:      probe,
		DNSServers:   servers,
		SystemDNS:    system,
		Note:         note,
	}
}

// --- run statistics ---

// Outcome aggregates the recorded results of a run into the figures the CLI
// report shows. It is derived from the recorded data, so it can never drift
// from the exported file.
type Outcome struct {
	// Successes and Total count every recorded query.
	Successes, Total int
	// AvgMS is the mean latency over all successful queries.
	AvgMS float64
	// FailedServers lists the servers (protocol included) that never answered.
	FailedServers []string
}

// Summarize folds the recorded outcomes of a run into an Outcome.
func Summarize(summaries []model.Summary) Outcome {
	var out Outcome
	var weighted float64
	for _, s := range summaries {
		out.Total += s.Total
		out.Successes += s.Success
		weighted += s.AvgMS * float64(s.Success)
		if s.Success == 0 {
			out.FailedServers = append(out.FailedServers, fmt.Sprintf("%s (%s)", s.DNS, s.Protocol.Label()))
		}
	}
	if out.Successes > 0 {
		out.AvgMS = weighted / float64(out.Successes)
	}
	sort.Strings(out.FailedServers)
	return out
}
