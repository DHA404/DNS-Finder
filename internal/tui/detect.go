package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dns-opti/data"
	"dns-opti/internal/dnsclient"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
)

// --- messages ---

// detectStartedMsg carries the detection's total, so the progress line can be
// sized before the first result arrives.
type detectStartedMsg struct{ total int }

// detectProgressMsg reports one completed resolver.
type detectProgressMsg struct {
	done, total int
	det         policy.Detection
}

// detectDoneMsg reports that the detection finished, carrying the authoritative
// full result set.
//
// The results travel in this message rather than only through the progress
// stream because the stream is lossy by design (a full buffer drops events so
// the probes are never back-pressured). The verdicts themselves must not be
// lossy, so they are handed over exactly once, here.
type detectDoneMsg struct{ results []policy.Detection }

// waitForDetect waits for the next event on the detection channel.
//
// Progress and completion share one channel so that every pending receive is
// satisfied exactly once. Two channels would leave the loser of a select
// blocking forever, leaking a goroutine per detection, because the channel is
// deliberately never closed — closing it would race with a straggling progress
// send from a run that was cancelled.
func waitForDetect(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// --- commands ---

// startDetect launches the resolver-type detection.
//
// The servers probed are the *built-in inventory*, unfiltered by the user's
// current protocol/region/policy selection. That is deliberate: the detection
// exists to verify the hardcoded table, so restricting it to whatever slice the
// user happened to configure would leave the rest unverified — precisely the
// entries a maintainer needs checked. It is also why the entry sits on the main
// menu rather than inside the test flow.
func (m *Model) startDetect() (screen, tea.Cmd) {
	if m.deps.DetectTypes == nil {
		m.statusMsg = "内部错误：未注入 DetectTypes"
		m.statusErr = true
		return screenError, nil
	}
	if m.detect.running {
		m.statusMsg = "检测已在进行中"
		m.statusErr = false
		return screenDetect, nil
	}

	servers := detectTargets()
	if len(servers) == 0 {
		m.statusMsg = "内置服务器清单为空，无可检测目标"
		m.statusErr = true
		return screenError, nil
	}

	m.detect = detectState{running: true, total: len(servers), results: nil}
	m.detectLines = nil
	m.detectY = 0
	m.statusMsg = ""
	m.statusErr = false

	deps := m.deps
	timeout := m.adv.timeout
	if timeout < 3*time.Second {
		// A probe timeout that is too tight turns a slow resolver into an
		// "unusable answer", which the detection reports as 未确认. The user's
		// benchmark timeout is tuned for measuring latency, not for waiting out
		// a filtered answer, so the floor keeps the verdict meaningful.
		timeout = 3 * time.Second
	}

	return screenDetect, tea.Batch(
		func() tea.Msg {
			ctx, cancel := context.WithCancel(context.Background())
			m.detect.cancel = cancel
			defer cancel()

			// Progress is streamed over a buffered channel and dropped when the
			// buffer is full, exactly as the benchmark's progress is: the
			// verdicts come from the returned slice, and a slow UI must not
			// back-pressure the probes.
			results := deps.DetectTypes(ctx, servers, timeout, func(done, total int, det policy.Detection) {
				select {
				case m.detectEvents <- detectProgressMsg{done: done, total: total, det: det}:
				default:
				}
			})
			// The completion message is sent *blocking*, and it is the only
			// blocking send: it must not be dropped, and a pending receive is
			// guaranteed to be waiting for it.
			m.detectEvents <- detectDoneMsg{results: results}
			return nil
		},
		waitForDetect(m.detectEvents),
	)
}

// detectTargets returns the built-in servers the detection probes.
//
// Only UDP and DoT/DoH endpoints on literal addresses are probed, because the
// detection needs an answer the tool can attribute to one resolver. Every
// protocol is *not* probed: a provider publishes one filtering policy, so
// re-probing its four transports would multiply the runtime to re-learn the
// same fact. The plain UDP address is preferred for that reason.
func detectTargets() []model.Server {
	all := data.Servers([]model.Protocol{model.ProtocolUDP}, nil, nil, nil)
	kept, _ := dnsclient.FilterReachable(all, model.IPAny)
	return dnsclient.MarkSpecial(kept)
}

// cancelDetect stops a detection in flight.
func (m *Model) cancelDetect() {
	if m.detect.cancel != nil {
		m.detect.cancel()
		m.detect.cancel = nil
	}
}

// --- rendering ---

// summarizeDetect counts the verdicts of a detection run.
func summarizeDetect(results []policy.Detection) dnsclient.Summary {
	return dnsclient.Summarize(results)
}

// detectReport renders the detection's findings.
//
// The report is organised around the question a maintainer actually has — "does
// the hardcoded table still match reality?" — so it leads with the
// disagreements and prints the per-probe evidence beside each verdict. A bare
// list of verdicts would be unusable, because the whole point of the detection
// is that its conclusion can be wrong when the network interferes.
func detectReport(results []policy.Detection) []string {
	var b strings.Builder
	summary := summarizeDetect(results)

	fmt.Fprintln(&b, "DNS 类型检测（按分类测试域的实际应答判断）")
	fmt.Fprintln(&b, strings.Repeat("─", 78))
	fmt.Fprintf(&b, " 检测目标 %d 个   安全 %d   原生 %d   未确认 %d\n",
		len(results), summary.Security, summary.Native, summary.Unknown)
	// Agreement is only counted where the table made a claim to check.
	documented := summary.Agree + summary.Disagree
	if documented > 0 {
		fmt.Fprintf(&b, " 与内置表一致 %d / %d", summary.Agree, documented)
		if summary.Disagree > 0 {
			fmt.Fprintf(&b, "   不一致 %d（见下方 ⚠ 行）", summary.Disagree)
		}
		fmt.Fprintln(&b)
	}
	fmt.Fprintf(&b, " 探测域名: %d 个（%s）\n", len(policy.Probes), probeList())
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, " 判定口径: 任一测试域被拦截即判为「安全」；全部正常应答判为「原生」；")
	fmt.Fprintln(&b, "           全部测试域均无可用应答判为「未确认」——无应答不等于不过滤。")
	fmt.Fprintln(&b, " 注意: 部分解析器对拦截的应答是超时（并非 sinkhole），此时本检测无法")
	fmt.Fprintln(&b, "       将其与「不可达」区分，只能给出「未确认」。")

	disagree := dnsclient.Disagreements(results)
	if len(disagree) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "⚠ 与内置表不一致（需人工复核）")
		for _, d := range disagree {
			fmt.Fprintf(&b, "   %-18s 表内=%s  实测=%s   应答: %s\n",
				d.Server, policy.Label(d.Curated), d.Observed.Label(), answersText(d))
		}
	}

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "全部结果（按实测类型分组）")
	for _, group := range []policy.Verdict{policy.VerdictSecurity, policy.VerdictNative, policy.VerdictUnknown} {
		rows := filterVerdict(results, group)
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n [%s] %d 个\n", group.Label(), len(rows))
		for _, d := range rows {
			mark := "  "
			if d.Curated != policy.Unknown && d.Observed != policy.VerdictUnknown && !d.Agrees() {
				mark = "⚠ "
			}
			note := ""
			if d.Curated != policy.Unknown {
				note = "（表内 " + policy.Label(d.Curated) + "）"
			}
			fmt.Fprintf(&b, " %s%-18s %s %s\n", mark, d.Server, answersText(d), note)
		}
	}

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "提示：检测结果仅代表本机网络路径下观测到的行为；换网络可能不同。")
	fmt.Fprintln(&b, "      新增内置 DNS 时应运行本项，并把结论写回 internal/policy 的端点表。")
	return strings.Split(b.String(), "\n")
}

// probeList renders the probe domains for the report header, grouped by
// category so the two families and their roles stay legible.
func probeList() string {
	byCategory := map[policy.Category][]string{}
	for _, p := range policy.Probes {
		byCategory[p.Category] = append(byCategory[p.Category], p.Domain)
	}
	var parts []string
	for _, c := range []policy.Category{policy.CategoryMalware, policy.CategoryAdvertising} {
		if domains := byCategory[c]; len(domains) > 0 {
			parts = append(parts, fmt.Sprintf("%s: %s", c.Label(), strings.Join(domains, " ")))
		}
	}
	return strings.Join(parts, "；")
}

// answersText renders the per-probe verdicts compactly.
func answersText(d policy.Detection) string {
	cells := make([]string, 0, len(d.Answers))
	for _, a := range d.Answers {
		cells = append(cells, a.String())
	}
	return "[" + strings.Join(cells, " / ") + "]"
}

// filterVerdict returns the detections with a given verdict, keeping order.
func filterVerdict(results []policy.Detection, v policy.Verdict) []policy.Detection {
	var out []policy.Detection
	for _, d := range results {
		if d.Observed == v {
			out = append(out, d)
		}
	}
	return out
}

// DetectReportForTest exposes the report renderer to the tests without widening
// the package's real surface.
func detectReportForTest(results []policy.Detection) []string { return detectReport(results) }

// disagreementsForTest exposes the disagreement filter to the tests.
func disagreementsForTest(results []policy.Detection) []policy.Detection {
	return dnsclient.Disagreements(results)
}

// sortDetections orders detections by server address, for a stable listing.
func sortDetections(results []policy.Detection) {
	sort.SliceStable(results, func(i, j int) bool { return results[i].Server < results[j].Server })
}
