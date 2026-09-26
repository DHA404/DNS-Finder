package web

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"dns-opti/internal/dnsclient"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/region"
	"dns-opti/internal/store"
)

// Payload is the dataset the web UI renders. It is either the result of the
// run that just finished or a history file the user imported.
type Payload struct {
	Meta model.Meta `json:"meta"`
	// Summary are the aggregated rows used for ranking.
	Summary []model.Summary `json:"summary"`
	// Source is "run" for the current session's result, "import" for a file
	// the user loaded and "empty" when the page has no data at all.
	Source string `json:"source"`
	// Label describes where the data came from, for the header.
	Label string `json:"label"`
	// ResultPath is the file the payload was read from or written to, when
	// known. It is informational only.
	ResultPath string `json:"result_path,omitempty"`
	// Histogram is the latency distribution of a fresh run. It is nil for
	// imported files, whose formats carry no per-query latencies — the viewer
	// then simply omits the distribution chart.
	Histogram *store.Histogram `json:"histogram,omitempty"`
	// Regions lists the region codes present in Summary, in presentation
	// order, so the viewer's region filter can be built without the page
	// having to re-derive them.
	Regions []RegionFacet `json:"regions,omitempty"`
	// RegionGroups are the quick-filter groups (中国 / 亚太 / 欧洲 / …).
	RegionGroups []region.Group `json:"region_groups,omitempty"`
	// Families lists the address families present in Summary.
	Families []FamilyFacet `json:"families,omitempty"`
	// Policies lists the filtering behaviours present in Summary, so the
	// viewer's 安全 / 原生 distinction is built server-side and can
	// never disagree with the CLI's wording.
	Policies []PolicyFacet `json:"policies,omitempty"`
	// Comparisons holds the per-provider UDP-vs-DoH comparison of a combined
	// run, so the viewer can show both transports side by side.
	Comparisons []engine.TransportComparison `json:"comparisons,omitempty"`
}

// RegionFacet is one region code present in a payload, with how many rows it
// covers. The label is resolved server-side so the page shows the same wording
// as the CLI.
type RegionFacet struct {
	Code  string `json:"code"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// FamilyFacet is one address family present in a payload.
type FamilyFacet struct {
	Value model.IPVersion `json:"value"`
	Label string          `json:"label"`
	Count int             `json:"count"`
}

// PolicyFacet is one filtering behaviour present in a payload.
type PolicyFacet struct {
	Value       policy.Kind `json:"value"`
	Label       string      `json:"label"`
	Description string      `json:"description"`
	Count       int         `json:"count"`
}

// Finalize fills in everything derived from Summary: the region and family
// facets, the quick-filter groups and the UDP-vs-DoH comparison.
//
// It is called on every payload a caller hands to the viewer — a fresh run, an
// import, or a reload — so the page never has to derive a facet itself and can
// never disagree with the CLI about a region name or a pairing.
func (p *Payload) Finalize() *Payload {
	if p == nil {
		return p
	}
	p.Regions = buildRegionFacets(p.Summary)
	p.RegionGroups = region.Groups()
	p.Families = buildFamilyFacets(p.Summary)
	p.Policies = buildPolicyFacets(p.Summary)
	if len(p.Comparisons) == 0 {
		p.Comparisons = engine.CompareTransports(p.Summary)
	}
	return p
}

// buildPolicyFacets counts the rows per filtering behaviour, in the canonical
// policy order with 未确认 last.
func buildPolicyFacets(rows []model.Summary) []PolicyFacet {
	counts := map[policy.Kind]int{}
	for _, s := range rows {
		kind := policy.CanonicalKind(s.Policy)
		if kind == "" {
			kind = policy.Unknown
		}
		counts[kind]++
	}
	if len(counts) == 0 {
		return nil
	}

	kinds := policy.Order(counts)
	out := make([]PolicyFacet, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, PolicyFacet{
			Value:       kind,
			Label:       policy.Label(kind),
			Description: policy.Description(kind),
			Count:       counts[kind],
		})
	}
	return out
}

// buildRegionFacets counts the rows per region code, in presentation order.
func buildRegionFacets(rows []model.Summary) []RegionFacet {
	counts := map[string]int{}
	for _, s := range rows {
		code := region.Canonical(s.Region)
		if code == "" {
			code = region.Unknown
		}
		counts[code]++
	}
	if len(counts) == 0 {
		return nil
	}

	out := make([]RegionFacet, 0, len(counts))
	for _, code := range region.Order(counts) {
		out = append(out, RegionFacet{
			Code:  code,
			Label: region.Label(code),
			Count: counts[code],
		})
	}
	return out
}

// buildFamilyFacets counts the rows per address family, in a fixed order so the
// filter does not reshuffle as data changes.
func buildFamilyFacets(rows []model.Summary) []FamilyFacet {
	counts := map[model.IPVersion]int{}
	for _, s := range rows {
		family := s.Family
		if !family.IsLiteral() {
			// A hostname endpoint whose family was never resolved still has to
			// land somewhere, so it is reported as dual-stack rather than
			// silently dropped from the facet.
			family = model.IPAny
		}
		counts[family]++
	}
	if len(counts) == 0 {
		return nil
	}

	out := make([]FamilyFacet, 0, len(counts))
	for _, family := range []model.IPVersion{model.IPv4, model.IPv6, model.IPAny} {
		if n := counts[family]; n > 0 {
			out = append(out, FamilyFacet{Value: family, Label: family.Label(), Count: n})
		}
	}
	return out
}

// ImportedFormat names the external result dialects the importer understands.
type ImportedFormat string

// Recognised dialects.
const (
	FormatNative  ImportedFormat = "dns-opti"
	FormatDnspy   ImportedFormat = "xxnuo/dns-benchmark"
	FormatDnspick ImportedFormat = "palemoky/dnspick"
)

// Import parses a result file of any supported dialect into a Payload.
//
// The tool's own document (meta / raw / summary) is preferred because it keeps
// every derived statistic. Documents from xxnuo/dns-benchmark and
// palemoky/dnspick are mapped onto the same summary rows so they can be ranked
// with the same four formulas; their rows are placed in a dedicated group
// because the original domestic / international split is not part of those
// formats (see PLAN 七).
func Import(data []byte) (*Payload, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("文件内容为空")
	}

	// 1. Native format: the "summary" key is the marker.
	var native struct {
		Meta    *model.Meta       `json:"meta"`
		Summary []model.Summary   `json:"summary"`
		Raw     []model.RawRecord `json:"raw"`
	}
	if err := json.Unmarshal(data, &native); err == nil && len(native.Summary) > 0 {
		meta := model.Meta{Version: "1.0", Timestamp: time.Now().UTC()}
		if native.Meta != nil {
			meta = *native.Meta
		}
		payload := &Payload{
			Meta:    meta,
			Summary: normalizeSummaries(native.Summary),
			Source:  "import",
			Label:   string(FormatNative),
		}
		// The exported file keeps every per-query latency, so the latency
		// distribution can be recovered exactly for the viewer.
		if len(native.Raw) > 0 {
			hist := store.HistogramFromRecords(native.Raw)
			payload.Histogram = &hist
		}
		return payload.Finalize(), nil
	}

	// 2. A native document whose summary is missing can still be rebuilt from
	//    the raw records.
	if len(native.Raw) > 0 {
		payload := &Payload{
			Meta:   model.Meta{Version: "1.0", Timestamp: time.Now().UTC()},
			Source: "import",
			Label:  string(FormatNative) + " (由原始记录重建)",
		}
		if native.Meta != nil {
			payload.Meta = *native.Meta
		}
		payload.Summary = summarizeRaw(native.Raw)
		hist := store.HistogramFromRecords(native.Raw)
		payload.Histogram = &hist
		return payload.Finalize(), nil
	}

	// 3. xxnuo/dns-benchmark: a map of server -> dnspyre statistics.
	if payload, err := importDnspy(data); err == nil {
		return payload, nil
	}

	// 4. palemoky/dnspick: an object with a "results" array.
	if payload, err := importDnspick(data); err == nil {
		return payload, nil
	}

	return nil, fmt.Errorf("无法识别的 JSON 结果格式：既不是本工具的导出文件，也不符合 xxnuo/dns-benchmark 或 palemoky/dnspick 的字段结构")
}

// normalizeSummaries fills in the derived statistics of rows that arrive
// without them, and guarantees the derived fields are internally consistent.
//
// Region, address family, IP and filtering policy are all derived when the file
// does not carry them — which is the case for every foreign dialect, and for
// files written by an older build of this tool. Derivation keeps the region and
// policy filters usable on imported data instead of collapsing every row into
// UNKNOWN.
func normalizeSummaries(rows []model.Summary) []model.Summary {
	out := make([]model.Summary, 0, len(rows))
	for _, s := range rows {
		if s.Total <= 0 {
			s.Total = s.Success
		}
		if s.Total > 0 && (s.SuccessRate <= 0 || s.SuccessRate > 1) {
			s.SuccessRate = float64(s.Success) / float64(s.Total)
		}
		if s.Group == "" {
			s.Group = model.GroupImported
		}
		if s.Protocol == "" {
			s.Protocol = model.ProtocolUDP
		}
		if s.DNS == "" && s.Name != "" {
			s.DNS = s.Name
		}
		if s.Region == "" {
			s.Region = region.Of(s.DNS, s.IsPrivate)
		} else {
			// Canonical rather than Normalize: a foreign file may label an
			// anycast resolver by vendor name ("CLOUDFLARE"), which has to be
			// folded onto this tool's CDN code before it reaches the viewer.
			s.Region = region.Canonical(s.Region)
		}
		if s.Family == "" {
			s.Family = dnsclient.FamilyOf(s.DNS)
		}
		if s.IP == "" {
			// The display identity. An imported row's DNS field is whatever the
			// foreign file called the server, so the host is extracted from it;
			// a row that is a bare hostname keeps that hostname, because there
			// is no resolution result to use and inventing an address would be
			// worse than showing the name the file actually contained.
			s.IP = model.HostOf(s.DNS)
		}
		if s.Policy == "" {
			s.Policy = policy.OfServer(s.DNS, s.Name)
		}
		out = append(out, s)
	}
	return out
}

// summarizeRaw rebuilds the aggregates from raw records, used when a document
// has raw data but no summary.
func summarizeRaw(records []model.RawRecord) []model.Summary {
	type bucket struct {
		summary model.Summary
		lats    []float64
	}
	buckets := map[string]*bucket{}
	var order []string

	for _, r := range records {
		key := r.DNS + "|" + string(r.Protocol) + "|" + r.Group
		b, ok := buckets[key]
		if !ok {
			b = &bucket{summary: model.Summary{
				DNS: r.DNS, Name: r.Name, Protocol: r.Protocol, Group: r.Group,
			}}
			buckets[key] = b
			order = append(order, key)
		}
		b.summary.Total++
		if r.Success {
			b.summary.Success++
			b.lats = append(b.lats, r.LatencyMS)
		}
	}

	out := make([]model.Summary, 0, len(order))
	for _, key := range order {
		b := buckets[key]
		s := b.summary
		if s.Total > 0 {
			s.SuccessRate = float64(s.Success) / float64(s.Total)
		}
		if len(b.lats) > 0 {
			s.AvgMS = avg(b.lats)
			s.StdDevMS = stddev(b.lats, s.AvgMS)
			s.P95MS = p95(b.lats)
		}
		out = append(out, s)
	}
	// Rebuilding from raw records loses the region and family (those live on
	// the server list, not on a record), so they are derived here through the
	// same normalisation an imported file goes through.
	return normalizeSummaries(out)
}

// importDnspy maps an xxnuo/dns-benchmark document onto summary rows.
//
// The document is a map keyed by the server address; each value carries
// dnspyre's request counts and latency statistics. Because that format has no
// notion of domain groups, every row lands in the "imported" group.
func importDnspy(data []byte) (*Payload, error) {
	type latencyStats struct {
		MeanMs float64 `json:"meanMs"`
		StdMs  float64 `json:"stdMs"`
		P95Ms  float64 `json:"p95Ms"`
		P90Ms  float64 `json:"p90Ms"`
		P50Ms  float64 `json:"p50Ms"`
	}
	type dnspyResult struct {
		TotalRequests         int64        `json:"totalRequests"`
		TotalSuccessResponses int64        `json:"totalSuccessResponses"`
		TotalErrorResponses   int64        `json:"totalErrorResponses"`
		TotalIOErrors         int64        `json:"totalIOErrors"`
		LatencyStats          latencyStats `json:"latencyStats"`
		QueriesPerSecond      float64      `json:"queriesPerSecond"`
		IPAddress             string       `json:"ip"`
		Geocode               string       `json:"geocode"`
	}

	var doc map[string]dnspyResult
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc) == 0 {
		return nil, fmt.Errorf("文档为空")
	}
	// Guard against a native-looking document with unrelated fields: at least
	// one entry must actually carry dnspyre statistics.
	plausible := 0

	var rows []model.Summary
	for server, r := range doc {
		if r.TotalRequests <= 0 {
			continue
		}
		plausible++
		protocol := model.ProtocolUDP
		address := server
		switch {
		case strings.HasPrefix(server, "https://"), strings.Contains(server, "://"):
			protocol = model.ProtocolDoH
			address = server
		default:
			address = server
		}

		total := int(r.TotalRequests)
		success := int(r.TotalSuccessResponses)
		s := model.Summary{
			DNS:      address,
			Name:     address,
			Protocol: protocol,
			Group:    model.GroupImported,
			Total:    total,
			Success:  success,
			AvgMS:    r.LatencyStats.MeanMs,
			StdDevMS: r.LatencyStats.StdMs,
			P95MS:    r.LatencyStats.P95Ms,
			// This dialect carries its own GeoIP verdict, which is the very
			// dimension the viewer filters on; honour it instead of deriving
			// a second opinion. The value is a country code ("US") or a
			// vendor name ("CLOUDFLARE"), and Canonical maps both onto this
			// tool's vocabulary.
			Region: region.Canonical(r.Geocode),
		}
		if s.P95MS <= 0 {
			s.P95MS = r.LatencyStats.P90Ms
		}
		if total > 0 {
			s.SuccessRate = float64(success) / float64(total)
		}
		rows = append(rows, s)
	}
	if plausible == 0 {
		return nil, fmt.Errorf("不是 xxnuo/dns-benchmark 格式")
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].DNS < rows[j].DNS })

	// The rows are built by hand here rather than through normalizeSummaries,
	// so they still need the derived fields (address family, and a region for
	// any entry whose geocode was empty) filled in.
	return (&Payload{
		Meta: model.Meta{
			Version:   "1.0",
			Timestamp: time.Now().UTC(),
			Note:      "导入自 xxnuo/dns-benchmark 结果文件；该格式不含国内外域名分组，全部归入“导入数据”。",
		},
		Summary: normalizeSummaries(rows),
		Source:  "import",
		Label:   string(FormatDnspy),
	}).Finalize(), nil
}

// importDnspick maps a palemoky/dnspick --json document onto summary rows.
func importDnspick(data []byte) (*Payload, error) {
	type dnspickResult struct {
		Rank         int     `json:"rank"`
		Name         string  `json:"name"`
		Address      string  `json:"address"`
		Protocol     string  `json:"protocol"`
		IsSystem     bool    `json:"is_system"`
		AvgLatencyMs float64 `json:"avg_latency_ms"`
		SuccessRate  float64 `json:"success_rate"`
		Successes    int     `json:"successes"`
		Total        int     `json:"total"`
		Score        float64 `json:"score"`
	}
	var doc struct {
		Schema  int             `json:"schema"`
		Results []dnspickResult `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Results) == 0 {
		return nil, fmt.Errorf("文档不含 results 数组")
	}

	var rows []model.Summary
	for _, r := range doc.Results {
		protocol, ok := model.ParseProtocol(r.Protocol)
		if !ok {
			protocol = model.ProtocolUDP
		}
		s := model.Summary{
			DNS:         firstNonEmpty(r.Address, r.Name),
			Name:        firstNonEmpty(r.Name, r.Address),
			Protocol:    protocol,
			Group:       model.GroupImported,
			Total:       r.Total,
			Success:     r.Successes,
			SuccessRate: r.SuccessRate,
			AvgMS:       r.AvgLatencyMs,
			IsSystem:    r.IsSystem,
		}
		if s.Total <= 0 {
			s.Total = r.Successes
		}
		if s.SuccessRate <= 0 && s.Total > 0 {
			s.SuccessRate = float64(s.Success) / float64(s.Total)
		}
		rows = append(rows, s)
	}

	// Like the dnspy branch, these rows are assembled by hand, so they go
	// through the same normalisation to gain their address family and a
	// derived region.
	return (&Payload{
		Meta: model.Meta{
			Version:   "1.0",
			Timestamp: time.Now().UTC(),
			Note:      "导入自 palemoky/dnspick 结果文件；该格式不含国内外域名分组，全部归入“导入数据”。",
		},
		Summary: normalizeSummaries(rows),
		Source:  "import",
		Label:   string(FormatDnspick),
	}).Finalize(), nil
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// --- statistics helpers (kept local so the importer has no dependency on the
// store's streaming internals) ---

func avg(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stddev(values []float64, m float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		d := v - m
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(values)))
}

func p95(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	idx := int(float64(len(sorted))*0.95+0.999999) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
