package web

import (
	"strings"
	"testing"

	"dns-opti/internal/model"
	"dns-opti/internal/policy"
)

// nativeDoc 是一份最小但结构完整的内置格式文档。
const nativeDoc = `{
  "meta": {
    "version": "1.0",
    "timestamp": "2026-09-25T12:00:00Z",
    "platform": "windows/amd64",
    "concurrency": 8,
    "warmup_domain": "example.com",
    "domain_groups": ["cn"],
    "protocols": ["udp"],
    "dns_servers": [{"name": "AliDNS 1", "address": "223.5.5.5", "protocol": "udp"}],
    "system_dns": ["192.168.1.1"]
  },
  "raw": [
    {"dns": "223.5.5.5", "protocol": "udp", "domain": "baidu.com", "group": "cn", "attempt": 1, "success": true, "latency_ms": 10, "ts": 1},
    {"dns": "223.5.5.5", "protocol": "udp", "domain": "baidu.com", "group": "cn", "attempt": 2, "success": true, "latency_ms": 20, "ts": 2},
    {"dns": "223.5.5.5", "protocol": "udp", "domain": "qq.com", "group": "cn", "attempt": 1, "success": false, "latency_ms": 0, "ts": 3},
    {"dns": "1.1.1.1", "protocol": "doh", "domain": "baidu.com", "group": "intl", "attempt": 1, "success": true, "latency_ms": 30, "ts": 4}
  ],
  "summary": [
    {"dns": "223.5.5.5", "name": "AliDNS 1", "protocol": "udp", "group": "cn", "total": 3, "success": 2, "success_rate": 0.6666666666666666, "avg_ms": 15, "p95_ms": 20, "stddev_ms": 5}
  ]
}`

// rawOnlyDoc 只有 raw，没有 summary；导入时必须重建汇总。
const rawOnlyDoc = `{
  "meta": {"version": "1.0", "timestamp": "2026-09-25T12:00:00Z", "warmup_domain": "example.com"},
  "raw": [
    {"dns": "223.5.5.5", "protocol": "udp", "domain": "baidu.com", "group": "cn", "attempt": 1, "success": true, "latency_ms": 10, "ts": 1},
    {"dns": "223.5.5.5", "protocol": "udp", "domain": "baidu.com", "group": "cn", "attempt": 2, "success": true, "latency_ms": 20, "ts": 2},
    {"dns": "223.5.5.5", "protocol": "udp", "domain": "baidu.com", "group": "cn", "attempt": 3, "success": false, "latency_ms": 0, "ts": 3},
    {"dns": "8.8.8.8", "protocol": "dot", "domain": "baidu.com", "group": "intl", "attempt": 1, "success": true, "latency_ms": 40, "ts": 4}
  ]
}`

// dnspyExcerpt 摘自 .example/dns-benchmark/dnspy/web/public/dnspy_result_2024-11-07-17-32-13.json，
// 仅保留两条真实条目（原文件约 500KB，不整体嵌入）。
const dnspyExcerpt = `{
  "1.0.0.1": {
    "totalRequests": 218,
    "totalSuccessResponses": 197,
    "totalNegativeResponses": 5,
    "totalErrorResponses": 4,
    "totalIOErrors": 12,
    "latencyStats": {"minMs": 20, "meanMs": 421, "stdMs": 505, "maxMs": 4294, "p99Ms": 1879, "p95Ms": 1140, "p90Ms": 1140, "p75Ms": 738, "p50Ms": 251},
    "ip": "1.0.0.1",
    "geocode": "CLOUDFLARE",
    "queriesPerSecond": 21.8
  },
  "223.5.5.5": {
    "totalRequests": 302,
    "totalSuccessResponses": 300,
    "totalNegativeResponses": 0,
    "totalErrorResponses": 2,
    "totalIOErrors": 0,
    "latencyStats": {"minMs": 3, "meanMs": 18, "stdMs": 6, "maxMs": 120, "p99Ms": 60, "p95Ms": 34, "p90Ms": 30, "p75Ms": 25, "p50Ms": 16},
    "ip": "223.5.5.5",
    "geocode": "ALIBABA",
    "queriesPerSecond": 109.4
  }
}`

// dnspickDoc 是 palemoky/dnspick 的 --json 输出结构。
const dnspickDoc = `{
  "schema": 1,
  "generated_at": "2026-09-25T12:00:00Z",
  "results": [
    {"rank": 1, "name": "AliDNS", "address": "223.5.5.5", "protocol": "udp", "avg_latency_ms": 12.5, "success_rate": 1, "successes": 40, "total": 40, "score": 80},
    {"rank": 2, "name": "Google", "address": "8.8.8.8", "protocol": "doh", "is_system": true, "avg_latency_ms": 30, "success_rate": 0.9, "successes": 36, "total": 40, "score": 30},
    {"rank": 3, "name": "DoT 服务器", "address": "dns.google", "protocol": "dot", "avg_latency_ms": 25, "success_rate": 0.8, "successes": 32, "total": 40, "score": 25}
  ]
}`

// tagsOf 汇总导入结果中出现的分组（去重）。
func tagsOf(rows []model.Summary) map[string]int {
	out := map[string]int{}
	for _, s := range rows {
		out[s.Group]++
	}
	return out
}

// assertAllImported 断言所有行的分组都是 model.GroupImported。
func assertAllImported(t *testing.T, rows []model.Summary) {
	t.Helper()
	if len(rows) == 0 {
		t.Fatal("导入结果为空")
	}
	for i, s := range rows {
		if s.Group != model.GroupImported {
			t.Fatalf("rows[%d]（dns=%q）的分组 = %q, 期望 %q", i, s.DNS, s.Group, model.GroupImported)
		}
	}
}

// findRow 按 DNS 查找汇总行。
func findRow(rows []model.Summary, dns string) (model.Summary, bool) {
	for _, s := range rows {
		if s.DNS == dns {
			return s, true
		}
	}
	return model.Summary{}, false
}

func TestImportNativeDocument(t *testing.T) {
	payload, err := Import([]byte(nativeDoc))
	if err != nil {
		t.Fatalf("Import(内置格式) 返回错误: %v", err)
	}
	if payload.Source != "import" {
		t.Fatalf("Source = %q, 期望 %q", payload.Source, "import")
	}
	if payload.Label != string(FormatNative) {
		t.Fatalf("Label = %q, 期望 %q", payload.Label, FormatNative)
	}
	if len(payload.Summary) != 1 {
		t.Fatalf("导入 %d 行汇总, 期望 1 行: %+v", len(payload.Summary), payload.Summary)
	}

	s := payload.Summary[0]
	if s.DNS != "223.5.5.5" || s.Protocol != model.ProtocolUDP || s.Group != model.GroupCN {
		t.Fatalf("汇总行的标识字段 = %q/%q/%q, 期望 223.5.5.5/udp/cn", s.DNS, s.Protocol, s.Group)
	}
	if s.Total != 3 || s.Success != 2 {
		t.Fatalf("汇总行 Total=%d Success=%d, 期望 3/2", s.Total, s.Success)
	}
	// 内置格式必须保留原有分组，不能改写成“导入数据”。
	if s.Group == model.GroupImported {
		t.Fatal("内置格式的 cn 分组被改写成 imported")
	}
	// meta 必须原样保留。
	if payload.Meta.Platform != "windows/amd64" {
		t.Fatalf("meta.platform = %q, 期望 windows/amd64", payload.Meta.Platform)
	}
	if payload.Meta.Concurrency != 8 {
		t.Fatalf("meta.concurrency = %d, 期望 8", payload.Meta.Concurrency)
	}
	if len(payload.Meta.DNSServers) != 1 || payload.Meta.DNSServers[0].Address != "223.5.5.5" {
		t.Fatalf("meta.dns_servers = %+v, 期望包含 223.5.5.5", payload.Meta.DNSServers)
	}
}

func TestImportNativeRebuildsSummaryFromRaw(t *testing.T) {
	payload, err := Import([]byte(rawOnlyDoc))
	if err != nil {
		t.Fatalf("Import(仅 raw 的内置格式) 返回错误: %v", err)
	}
	if !strings.Contains(payload.Label, "(由原始记录重建)") {
		t.Fatalf("Label = %q, 期望注明是由原始记录重建", payload.Label)
	}
	if len(payload.Summary) != 2 {
		t.Fatalf("重建出 %d 行汇总, 期望 2 行（223.5.5.5/udp/cn 与 8.8.8.8/dot/intl）: %+v",
			len(payload.Summary), payload.Summary)
	}

	// 223.5.5.5：3 次查询、2 次成功，延迟 10 与 20。
	row, ok := findRow(payload.Summary, "223.5.5.5")
	if !ok {
		t.Fatalf("重建结果中缺少 223.5.5.5: %+v", payload.Summary)
	}
	if row.Total != 3 || row.Success != 2 {
		t.Fatalf("重建行 Total=%d Success=%d, 期望 3/2", row.Total, row.Success)
	}
	if row.SuccessRate != 2.0/3.0 {
		t.Fatalf("重建行 SuccessRate = %v, 期望 %v", row.SuccessRate, 2.0/3.0)
	}
	if row.AvgMS != 15 {
		t.Fatalf("重建行 AvgMS = %v, 期望 15", row.AvgMS)
	}
	if row.P95MS != 20 {
		t.Fatalf("重建行 P95MS = %v, 期望 20", row.P95MS)
	}
	// 只有两次成功记录，总体标准差 = 5。
	if row.StdDevMS != 5 {
		t.Fatalf("重建行 StdDevMS = %v, 期望 5", row.StdDevMS)
	}
	if row.Group != model.GroupCN {
		t.Fatalf("重建行的分组 = %q, 期望沿用原始记录的 %q", row.Group, model.GroupCN)
	}

	// 国外行必须保留自己的分组。
	intlRow, ok := findRow(payload.Summary, "8.8.8.8")
	if !ok {
		t.Fatalf("重建结果中缺少 8.8.8.8: %+v", payload.Summary)
	}
	if intlRow.Group != model.GroupIntl || intlRow.Protocol != model.ProtocolDoT {
		t.Fatalf("8.8.8.8 的分组/协议 = %q/%q, 期望 intl/dot", intlRow.Group, intlRow.Protocol)
	}
	if intlRow.Total != 1 || intlRow.Success != 1 || intlRow.AvgMS != 40 {
		t.Fatalf("8.8.8.8 的统计 = total %d success %d avg %v, 期望 1/1/40", intlRow.Total, intlRow.Success, intlRow.AvgMS)
	}
}

func TestImportDnspyDocument(t *testing.T) {
	payload, err := Import([]byte(dnspyExcerpt))
	if err != nil {
		t.Fatalf("Import(xxnuo/dns-benchmark) 返回错误: %v", err)
	}
	if payload.Label != string(FormatDnspy) {
		t.Fatalf("Label = %q, 期望 %q", payload.Label, FormatDnspy)
	}
	if payload.Source != "import" {
		t.Fatalf("Source = %q, 期望 import", payload.Source)
	}
	if len(payload.Summary) != 2 {
		t.Fatalf("导入 %d 行, 期望 2 行: %+v", len(payload.Summary), payload.Summary)
	}
	assertAllImported(t, payload.Summary)

	// 该格式不含域名分组信息，必须全部归入“导入数据”，且 meta 要有说明。
	if payload.Meta.Note == "" {
		t.Fatal("导入 xxnuo 格式时 meta.note 应有说明")
	}

	// 按 DNS 排序。
	if payload.Summary[0].DNS != "1.0.0.1" || payload.Summary[1].DNS != "223.5.5.5" {
		t.Fatalf("导入行的顺序 = %q, %q, 期望按地址升序 1.0.0.1, 223.5.5.5",
			payload.Summary[0].DNS, payload.Summary[1].DNS)
	}

	row, ok := findRow(payload.Summary, "1.0.0.1")
	if !ok {
		t.Fatalf("缺少 1.0.0.1 行: %+v", payload.Summary)
	}
	if row.Total != 218 || row.Success != 197 {
		t.Fatalf("1.0.0.1 的 Total=%d Success=%d, 期望 218/197", row.Total, row.Success)
	}
	if row.AvgMS != 421 {
		t.Fatalf("1.0.0.1 的 AvgMS = %v, 期望 421（meanMs）", row.AvgMS)
	}
	if row.P95MS != 1140 {
		t.Fatalf("1.0.0.1 的 P95MS = %v, 期望 1140（p95Ms）", row.P95MS)
	}
	if row.StdDevMS != 505 {
		t.Fatalf("1.0.0.1 的 StdDevMS = %v, 期望 505（stdMs）", row.StdDevMS)
	}
	wantRate := 197.0 / 218.0
	if row.SuccessRate != wantRate {
		t.Fatalf("1.0.0.1 的 SuccessRate = %v, 期望 %v", row.SuccessRate, wantRate)
	}
	// 裸地址就是 UDP。
	if row.Protocol != model.ProtocolUDP {
		t.Fatalf("1.0.0.1 的协议 = %q, 期望 %q", row.Protocol, model.ProtocolUDP)
	}

	ali, ok := findRow(payload.Summary, "223.5.5.5")
	if !ok {
		t.Fatalf("缺少 223.5.5.5 行: %+v", payload.Summary)
	}
	if ali.Total != 302 || ali.Success != 300 || ali.AvgMS != 18 || ali.P95MS != 34 {
		t.Fatalf("223.5.5.5 的统计 = %+v, 期望 total 302 success 300 avg 18 p95 34", ali)
	}
}

func TestImportDnspyInfersProtocolFromURLKey(t *testing.T) {
	// xxnuo 的结果也可能以 https URL 作为键，此时协议应推断为 DoH。
	doc := `{
	  "https://dns.google/dns-query": {
	    "totalRequests": 100,
	    "totalSuccessResponses": 95,
	    "latencyStats": {"meanMs": 30, "stdMs": 5, "p95Ms": 50}
	  },
	  "dns.google": {
	    "totalRequests": 50,
	    "totalSuccessResponses": 50,
	    "latencyStats": {"meanMs": 25, "stdMs": 4, "p95Ms": 40}
	  }
	}`
	payload, err := Import([]byte(doc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Summary) != 2 {
		t.Fatalf("导入 %d 行, 期望 2 行: %+v", len(payload.Summary), payload.Summary)
	}
	assertAllImported(t, payload.Summary)

	httpsRow, ok := findRow(payload.Summary, "https://dns.google/dns-query")
	if !ok {
		t.Fatalf("缺少 https 键的行: %+v", payload.Summary)
	}
	if httpsRow.Protocol != model.ProtocolDoH {
		t.Fatalf("https 键的协议 = %q, 期望 %q", httpsRow.Protocol, model.ProtocolDoH)
	}
	plainRow, ok := findRow(payload.Summary, "dns.google")
	if !ok {
		t.Fatalf("缺少裸主机行的行: %+v", payload.Summary)
	}
	if plainRow.Protocol != model.ProtocolUDP {
		t.Fatalf("裸主机键的协议 = %q, 期望 %q", plainRow.Protocol, model.ProtocolUDP)
	}
}

func TestImportDnspyFallsBackToP90WhenP95Missing(t *testing.T) {
	// 该格式部分条目可能只有 p90Ms；p95 缺失时应回落到 p90。
	doc := `{
	  "1.1.1.1": {
	    "totalRequests": 10,
	    "totalSuccessResponses": 10,
	    "latencyStats": {"meanMs": 20, "stdMs": 3, "p90Ms": 45}
	  }
	}`
	payload, err := Import([]byte(doc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Summary) != 1 {
		t.Fatalf("导入 %d 行, 期望 1 行", len(payload.Summary))
	}
	if payload.Summary[0].P95MS != 45 {
		t.Fatalf("P95MS = %v, 期望回落到 p90 的 45", payload.Summary[0].P95MS)
	}
}

func TestImportDnspySkipsEntriesWithoutRequests(t *testing.T) {
	doc := `{
	  "1.1.1.1": {"totalRequests": 0, "totalSuccessResponses": 0},
	  "8.8.8.8": {"totalRequests": 12, "totalSuccessResponses": 12, "latencyStats": {"meanMs": 15, "stdMs": 2, "p95Ms": 30}}
	}`
	payload, err := Import([]byte(doc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Summary) != 1 {
		t.Fatalf("导入 %d 行, 期望 1 行（totalRequests 为 0 的条目应被跳过）: %+v", len(payload.Summary), payload.Summary)
	}
	if payload.Summary[0].DNS != "8.8.8.8" {
		t.Fatalf("保留了 %q, 期望 8.8.8.8", payload.Summary[0].DNS)
	}
}

func TestImportDnspickDocument(t *testing.T) {
	payload, err := Import([]byte(dnspickDoc))
	if err != nil {
		t.Fatalf("Import(palemoky/dnspick) 返回错误: %v", err)
	}
	if payload.Label != string(FormatDnspick) {
		t.Fatalf("Label = %q, 期望 %q", payload.Label, FormatDnspick)
	}
	if payload.Source != "import" {
		t.Fatalf("Source = %q, 期望 import", payload.Source)
	}
	if len(payload.Summary) != 3 {
		t.Fatalf("导入 %d 行, 期望 3 行: %+v", len(payload.Summary), payload.Summary)
	}
	assertAllImported(t, payload.Summary)
	if payload.Meta.Note == "" {
		t.Fatal("导入 dnspick 格式时 meta.note 应有说明")
	}

	// 协议必须按字段推断，而不是统一回落为 UDP。
	ali, ok := findRow(payload.Summary, "223.5.5.5")
	if !ok {
		t.Fatalf("缺少 223.5.5.5: %+v", payload.Summary)
	}
	if ali.Protocol != model.ProtocolUDP {
		t.Fatalf("223.5.5.5 的协议 = %q, 期望 %q", ali.Protocol, model.ProtocolUDP)
	}
	if ali.Total != 40 || ali.Success != 40 || ali.AvgMS != 12.5 {
		t.Fatalf("223.5.5.5 的统计 = %+v, 期望 total 40 success 40 avg 12.5", ali)
	}
	if ali.Name != "AliDNS" {
		t.Fatalf("223.5.5.5 的 Name = %q, 期望 AliDNS", ali.Name)
	}

	google, ok := findRow(payload.Summary, "8.8.8.8")
	if !ok {
		t.Fatalf("缺少 8.8.8.8: %+v", payload.Summary)
	}
	if google.Protocol != model.ProtocolDoH {
		t.Fatalf("8.8.8.8 的协议 = %q, 期望 %q（由 protocol 字段推断）", google.Protocol, model.ProtocolDoH)
	}
	if !google.IsSystem {
		t.Fatalf("8.8.8.8 的 IsSystem = false, 期望沿用 is_system 字段: %+v", google)
	}

	dot, ok := findRow(payload.Summary, "dns.google")
	if !ok {
		t.Fatalf("缺少 dns.google: %+v", payload.Summary)
	}
	if dot.Protocol != model.ProtocolDoT {
		t.Fatalf("dns.google 的协议 = %q, 期望 %q", dot.Protocol, model.ProtocolDoT)
	}
}

func TestImportDnspickInfersSuccessRateAndTotal(t *testing.T) {
	// 缺少 total 时用 successes 填充，缺少 success_rate 时按 successes/total 计算。
	doc := `{"results":[{"name":"A","address":"1.1.1.1","protocol":"udp","successes":3,"avg_latency_ms":10}]}`
	payload, err := Import([]byte(doc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Summary) != 1 {
		t.Fatalf("导入 %d 行, 期望 1 行", len(payload.Summary))
	}
	s := payload.Summary[0]
	if s.Total != 3 || s.Success != 3 {
		t.Fatalf("Total=%d Success=%d, 期望 3/3", s.Total, s.Success)
	}
	if s.SuccessRate != 1 {
		t.Fatalf("SuccessRate = %v, 期望 1", s.SuccessRate)
	}
}

func TestImportDnspickUnknownProtocolFallsBackToUDP(t *testing.T) {
	doc := `{"results":[{"name":"A","address":"1.1.1.1","protocol":"quic","successes":1,"total":1}]}`
	payload, err := Import([]byte(doc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Summary) != 1 {
		t.Fatalf("导入 %d 行, 期望 1 行", len(payload.Summary))
	}
	if payload.Summary[0].Protocol != model.ProtocolUDP {
		t.Fatalf("未知协议的回落值 = %q, 期望 %q", payload.Summary[0].Protocol, model.ProtocolUDP)
	}
}

func TestImportDnspickNameFillsMissingAddress(t *testing.T) {
	// address 为空时用 name 兜底，避免出现 DNS 为空的行。
	doc := `{"results":[{"name":"only-name.example","protocol":"udp","successes":1,"total":1}]}`
	payload, err := Import([]byte(doc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Summary) != 1 {
		t.Fatalf("导入 %d 行, 期望 1 行", len(payload.Summary))
	}
	if payload.Summary[0].DNS != "only-name.example" {
		t.Fatalf("DNS = %q, 期望由 name 兜底为 only-name.example", payload.Summary[0].DNS)
	}
}

func TestImportGarbageErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "纯文本", data: "这不是 JSON"},
		{name: "被截断的 JSON", data: `{"meta": {`},
		{name: "JSON 数字", data: "42"},
		{name: "JSON 字符串", data: `"hello"`},
		{name: "空对象", data: `{}`},
		{name: "空数组", data: `[]`},
		{name: "字段无关的对象", data: `{"foo": "bar", "baz": [1,2,3]}`},
		{name: "results 为空数组", data: `{"results": []}`},
		{name: "所有条目都缺统计", data: `{"1.1.1.1": {"ip": "1.1.1.1"}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := Import([]byte(tt.data))
			if err == nil {
				t.Fatalf("Import(%q) = %+v, 期望错误", tt.data, payload)
			}
			if payload != nil {
				t.Fatalf("Import(%q) 出错时返回了 %+v, 期望 nil", tt.data, payload)
			}
		})
	}
}

func TestImportEmptyErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "nil", data: nil},
		{name: "空字节", data: []byte{}},
		{name: "只有空白", data: []byte("   \n\t  ")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := Import(tt.data)
			if err == nil {
				t.Fatalf("Import(%q) = %+v, 期望错误", tt.data, payload)
			}
			if payload != nil {
				t.Fatalf("Import(%q) 出错时返回了 %+v, 期望 nil", tt.data, payload)
			}
			if !strings.Contains(err.Error(), "空") {
				t.Fatalf("Import(%q) 错误 = %q, 期望提到内容为空", tt.data, err.Error())
			}
		})
	}
}

func TestImportNativeSummaryWinsOverDnspy(t *testing.T) {
	// 同时含 summary 与类 dnspy 字段时，必须优先按内置格式解析。
	doc := `{
	  "meta": {"version": "1.0", "timestamp": "2026-09-25T12:00:00Z"},
	  "summary": [{"dns": "223.5.5.5", "protocol": "udp", "group": "cn", "total": 1, "success": 1, "success_rate": 1, "avg_ms": 5}],
	  "1.0.0.1": {"totalRequests": 10, "totalSuccessResponses": 10}
	}`
	payload, err := Import([]byte(doc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if payload.Label != string(FormatNative) {
		t.Fatalf("Label = %q, 期望 %q", payload.Label, FormatNative)
	}
	if len(payload.Summary) != 1 || payload.Summary[0].DNS != "223.5.5.5" {
		t.Fatalf("按内置格式解析的结果 = %+v, 期望只有 223.5.5.5", payload.Summary)
	}
}

func TestImportDnspyIgnoresNativeLookingDoc(t *testing.T) {
	// 含 raw 的文档即便同时有 dnspy 形状的键，也应走“由原始记录重建”。
	doc := `{
	  "raw": [{"dns": "1.1.1.1", "protocol": "udp", "domain": "a.com", "group": "cn", "success": true, "latency_ms": 5}],
	  "1.0.0.1": {"totalRequests": 10, "totalSuccessResponses": 10, "latencyStats": {"meanMs": 1, "p95Ms": 2}}
	}`
	payload, err := Import([]byte(doc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if !strings.Contains(payload.Label, "(由原始记录重建)") {
		t.Fatalf("Label = %q, 期望注明由原始记录重建", payload.Label)
	}
	if len(payload.Summary) != 1 || payload.Summary[0].DNS != "1.1.1.1" {
		t.Fatalf("重建结果 = %+v, 期望只有 1.1.1.1", payload.Summary)
	}
}

func TestNormalizeSummaries(t *testing.T) {
	tests := []struct {
		name  string
		in    model.Summary
		check func(t *testing.T, got model.Summary)
	}{
		{
			name: "分组缺失时补 imported",
			in:   model.Summary{DNS: "1.1.1.1", Protocol: model.ProtocolUDP, Total: 10, Success: 5},
			check: func(t *testing.T, got model.Summary) {
				if got.Group != model.GroupImported {
					t.Fatalf("Group = %q, 期望 %q", got.Group, model.GroupImported)
				}
			},
		},
		{
			name: "协议缺失时补 udp",
			in:   model.Summary{DNS: "1.1.1.1", Group: model.GroupCN, Total: 10, Success: 5},
			check: func(t *testing.T, got model.Summary) {
				if got.Protocol != model.ProtocolUDP {
					t.Fatalf("Protocol = %q, 期望 %q", got.Protocol, model.ProtocolUDP)
				}
			},
		},
		{
			name: "Total 缺失时用 Success 填充",
			in:   model.Summary{DNS: "1.1.1.1", Group: model.GroupCN, Protocol: model.ProtocolUDP, Success: 4},
			check: func(t *testing.T, got model.Summary) {
				if got.Total != 4 {
					t.Fatalf("Total = %d, 期望 4", got.Total)
				}
				if got.SuccessRate != 1 {
					t.Fatalf("SuccessRate = %v, 期望 1", got.SuccessRate)
				}
			},
		},
		{
			name: "SuccessRate 缺失时计算",
			in:   model.Summary{DNS: "1.1.1.1", Group: model.GroupCN, Protocol: model.ProtocolUDP, Total: 4, Success: 1},
			check: func(t *testing.T, got model.Summary) {
				if got.SuccessRate != 0.25 {
					t.Fatalf("SuccessRate = %v, 期望 0.25", got.SuccessRate)
				}
			},
		},
		{
			name: "非法的 SuccessRate（大于 1）被重算",
			in:   model.Summary{DNS: "1.1.1.1", Group: model.GroupCN, Protocol: model.ProtocolUDP, Total: 4, Success: 2, SuccessRate: 50},
			check: func(t *testing.T, got model.Summary) {
				if got.SuccessRate != 0.5 {
					t.Fatalf("SuccessRate = %v, 期望 0.5", got.SuccessRate)
				}
			},
		},
		{
			name: "DNS 缺失时用 Name 兜底",
			in:   model.Summary{Name: "AliDNS", Group: model.GroupCN, Protocol: model.ProtocolUDP, Total: 1, Success: 1},
			check: func(t *testing.T, got model.Summary) {
				if got.DNS != "AliDNS" {
					t.Fatalf("DNS = %q, 期望 AliDNS", got.DNS)
				}
			},
		},
		{
			name: "合法的行原样保留",
			in: model.Summary{
				DNS: "1.1.1.1", Protocol: model.ProtocolDoH, Group: model.GroupIntl,
				Total: 10, Success: 9, SuccessRate: 0.9, AvgMS: 12, P95MS: 30, StdDevMS: 4,
			},
			check: func(t *testing.T, got model.Summary) {
				if got.Group != model.GroupIntl || got.Protocol != model.ProtocolDoH {
					t.Fatalf("合法行被修改: %+v", got)
				}
				if got.SuccessRate != 0.9 || got.AvgMS != 12 || got.P95MS != 30 || got.StdDevMS != 4 {
					t.Fatalf("合法行的统计被修改: %+v", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSummaries([]model.Summary{tt.in})
			if len(got) != 1 {
				t.Fatalf("normalizeSummaries 返回 %d 行, 期望 1 行", len(got))
			}
			tt.check(t, got[0])
		})
	}
}

func TestNormalizeSummariesKeepsOrderAndCount(t *testing.T) {
	in := []model.Summary{
		{DNS: "a", Total: 1, Success: 1},
		{DNS: "b", Total: 1, Success: 1},
		{DNS: "c", Total: 1, Success: 1},
	}
	got := normalizeSummaries(in)
	if len(got) != 3 {
		t.Fatalf("normalizeSummaries 返回 %d 行, 期望 3 行", len(got))
	}
	for i, want := range []string{"a", "b", "c"} {
		if got[i].DNS != want {
			t.Fatalf("normalizeSummaries[%d].DNS = %q, 期望 %q（必须保持输入顺序）", i, got[i].DNS, want)
		}
	}
}

func TestSummarizeRawMatchesStoreSemantics(t *testing.T) {
	records := []model.RawRecord{
		{DNS: "1.1.1.1", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 10},
		{DNS: "1.1.1.1", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 20},
		{DNS: "1.1.1.1", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: false, LatencyMS: 999},
	}
	got := summarizeRaw(records)
	if len(got) != 1 {
		t.Fatalf("summarizeRaw 返回 %d 行, 期望 1 行", len(got))
	}
	s := got[0]
	if s.Total != 3 || s.Success != 2 {
		t.Fatalf("Total=%d Success=%d, 期望 3/2", s.Total, s.Success)
	}
	if s.AvgMS != 15 {
		t.Fatalf("AvgMS = %v, 期望 15（失败记录的延迟不计入）", s.AvgMS)
	}
	if s.P95MS != 20 {
		t.Fatalf("P95MS = %v, 期望 20", s.P95MS)
	}
	if s.StdDevMS != 5 {
		t.Fatalf("StdDevMS = %v, 期望 5（总体标准差）", s.StdDevMS)
	}
	if s.SuccessRate != 2.0/3.0 {
		t.Fatalf("SuccessRate = %v, 期望 %v", s.SuccessRate, 2.0/3.0)
	}
}

func TestSummarizeRawEmpty(t *testing.T) {
	if got := summarizeRaw(nil); len(got) != 0 {
		t.Fatalf("summarizeRaw(nil) = %+v, 期望空", got)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "取第一个非空", values: []string{"", "  ", "a", "b"}, want: "a"},
		{name: "全为空", values: []string{"", "   "}, want: ""},
		{name: "没有参数", values: nil, want: ""},
		{name: "第一个就是非空", values: []string{"x", "y"}, want: "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstNonEmpty(tt.values...); got != tt.want {
				t.Fatalf("firstNonEmpty(%v) = %q, 期望 %q", tt.values, got, tt.want)
			}
		})
	}
}

func TestP95Helper(t *testing.T) {
	tests := []struct {
		name   string
		values []float64
		want   float64
	}{
		{name: "空切片", values: nil, want: 0},
		{name: "单个值", values: []float64{5}, want: 5},
		{name: "两个值", values: []float64{5, 9}, want: 9},
		{name: "十个值取最大", values: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, want: 10},
		{name: "乱序输入", values: []float64{30, 10, 20}, want: 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p95(tt.values); got != tt.want {
				t.Fatalf("p95(%v) = %v, 期望 %v", tt.values, got, tt.want)
			}
		})
	}
}

func TestAvgAndStddevHelpers(t *testing.T) {
	if got := avg(nil); got != 0 {
		t.Fatalf("avg(nil) = %v, 期望 0", got)
	}
	if got := avg([]float64{1, 2, 3, 4}); got != 2.5 {
		t.Fatalf("avg([1 2 3 4]) = %v, 期望 2.5", got)
	}
	if got := stddev(nil, 0); got != 0 {
		t.Fatalf("stddev(nil) = %v, 期望 0", got)
	}
	// 总体标准差。
	if got := stddev([]float64{2, 4, 4, 4, 5, 5, 7, 9}, 5); got != 2 {
		t.Fatalf("stddev 总体标准差 = %v, 期望 2", got)
	}
}

// TestImportDnspySortedRowsAreStable 确认同一输入重复解析得到完全相同的输出顺序。
func TestImportDnspySortedRowsAreStable(t *testing.T) {
	first, err := Import([]byte(dnspyExcerpt))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := Import([]byte(dnspyExcerpt))
		if err != nil {
			t.Fatalf("第 %d 次 Import 返回错误: %v", i, err)
		}
		if len(again.Summary) != len(first.Summary) {
			t.Fatalf("第 %d 次 Import 行数 = %d, 期望 %d", i, len(again.Summary), len(first.Summary))
		}
		for j := range first.Summary {
			if again.Summary[j].DNS != first.Summary[j].DNS {
				t.Fatalf("第 %d 次 Import 的顺序不稳定: [%d] = %q, 期望 %q",
					i, j, again.Summary[j].DNS, first.Summary[j].DNS)
			}
		}
	}
}

func TestImportPayloadGroupsAreAllImported(t *testing.T) {
	// 汇总所有外部方言：导入的行一律归入 GroupImported。
	for _, tt := range []struct {
		name string
		data string
	}{
		{name: "dnspy", data: dnspyExcerpt},
		{name: "dnspick", data: dnspickDoc},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := Import([]byte(tt.data))
			if err != nil {
				t.Fatalf("Import 返回错误: %v", err)
			}
			assertAllImported(t, payload.Summary)
			if counts := tagsOf(payload.Summary); len(counts) != 1 {
				t.Fatalf("导入结果混入了多个分组: %v", counts)
			}
		})
	}
}

// --- 地区 / 地址族支持 ---

// TestImportDerivesRegionAndFamily verifies that rows arriving without region
// information get one derived, so the viewer's region filter works on every
// supported dialect rather than collapsing into a single UNKNOWN bucket.
func TestImportDerivesRegionAndFamily(t *testing.T) {
	payload, err := Import([]byte(nativeDoc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}

	byDNS := map[string]model.Summary{}
	for _, s := range payload.Summary {
		byDNS[s.DNS] = s
	}

	// nativeDoc 的 summary 只有 AliDNS；raw 里还有 1.1.1.1，因此重建后
	// 两行都应在。原生 summary 优先，所以这里断言 summary 里那一行。
	cn, ok := byDNS["223.5.5.5"]
	if !ok {
		t.Fatalf("导入结果中没有 223.5.5.5: %+v", payload.Summary)
	}
	if cn.Region != "CN" {
		t.Fatalf("223.5.5.5 的地区 = %q, 期望 CN", cn.Region)
	}
	if cn.Family != model.IPv4 {
		t.Fatalf("223.5.5.5 的地址族 = %q, 期望 %q", cn.Family, model.IPv4)
	}
}

// TestImportRebuiltRowsGetRegionAndFamily verifies the rebuild-from-raw path
// also derives region and family, since a raw record carries neither.
func TestImportRebuiltRowsGetRegionAndFamily(t *testing.T) {
	payload, err := Import([]byte(rawOnlyDoc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Summary) == 0 {
		t.Fatal("由 raw 重建后没有汇总行")
	}

	want := map[string]string{"223.5.5.5": "CN", "8.8.8.8": "CDN"}
	for _, s := range payload.Summary {
		region, ok := want[s.DNS]
		if !ok {
			continue
		}
		if s.Region != region {
			t.Fatalf("%s 的地区 = %q, 期望 %q", s.DNS, s.Region, region)
		}
		if s.Family != model.IPv4 {
			t.Fatalf("%s 的地址族 = %q, 期望 %q", s.DNS, s.Family, model.IPv4)
		}
		delete(want, s.DNS)
	}
	if len(want) != 0 {
		t.Fatalf("以下服务器未出现在重建结果中: %v（实际 %+v）", want, payload.Summary)
	}
}

// TestImportBuildsRegionFacets verifies the payload carries the region facets
// the viewer's filter is built from, with counts that add up to the row count.
func TestImportBuildsRegionFacets(t *testing.T) {
	payload, err := Import([]byte(nativeDoc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Regions) == 0 {
		t.Fatal("导入结果没有地区分面，查看器的地区筛选会无法渲染")
	}
	var total int
	seen := map[string]bool{}
	for _, r := range payload.Regions {
		if r.Code == "" {
			t.Fatal("地区分面含空地区码")
		}
		if seen[r.Code] {
			t.Fatalf("地区分面出现重复地区码 %q", r.Code)
		}
		seen[r.Code] = true
		if r.Label == "" {
			t.Fatalf("地区 %q 没有显示名称", r.Code)
		}
		if r.Count <= 0 {
			t.Fatalf("地区 %q 的记录数为 %d", r.Code, r.Count)
		}
		total += r.Count
	}
	if total != len(payload.Summary) {
		t.Fatalf("地区分面记录数合计 %d，与汇总行数 %d 不符", total, len(payload.Summary))
	}
}

// TestImportBuildsRegionGroupsAndFamilies verifies the quick-filter groups and
// the address-family facets are always present.
// TestImportBuildsPolicyFacets verifies the 安全 / 拦截广告 / 原生 distinction
// reaches the viewer, which is what its policy filter is built from.
func TestImportBuildsPolicyFacets(t *testing.T) {
	payload, err := Import([]byte(nativeDoc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Policies) == 0 {
		t.Fatal("导入结果没有过滤策略分面")
	}

	seen := map[policy.Kind]bool{}
	total := 0
	for _, f := range payload.Policies {
		if f.Label == "" {
			t.Errorf("策略 %q 没有显示名称", f.Value)
		}
		if f.Description == "" {
			t.Errorf("策略 %q 没有说明文字", f.Value)
		}
		if f.Count <= 0 {
			t.Errorf("策略 %q 的记录数为 %d", f.Value, f.Count)
		}
		if seen[f.Value] {
			t.Errorf("策略 %q 在分面里出现了两次", f.Value)
		}
		seen[f.Value] = true
		total += f.Count
	}
	// Every row must be accounted for exactly once, or a chip would undercount.
	if total != len(payload.Summary) {
		t.Errorf("策略分面合计 %d 条, 但共有 %d 行", total, len(payload.Summary))
	}
	// 未确认 must always sort last, so a real policy leads the filter.
	if len(payload.Policies) > 1 && payload.Policies[len(payload.Policies)-1].Value == policy.Native {
		t.Errorf("策略顺序异常: %v", payload.Policies)
	}
}

// TestImportPolicyOrderPutsUnknownLast pins the ordering rule directly.
func TestImportPolicyOrderPutsUnknownLast(t *testing.T) {
	rows := []model.Summary{
		{DNS: "203.0.113.7", Name: "无来源", Group: model.GroupCN, Total: 1, Success: 1},
		{DNS: "94.140.14.14", Name: "AdGuard", Group: model.GroupCN, Total: 1, Success: 1},
		{DNS: "9.9.9.9", Name: "Quad9", Group: model.GroupCN, Total: 1, Success: 1},
		{DNS: "223.5.5.5", Name: "AliDNS", Group: model.GroupCN, Total: 1, Success: 1},
	}
	facets := buildPolicyFacets(normalizeSummaries(rows))
	if len(facets) != 3 {
		t.Fatalf("分面数 = %d, 期望 3（原生/安全/未确认）", len(facets))
	}
	want := []policy.Kind{policy.Native, policy.Security, policy.Unknown}
	for i, kind := range want {
		if facets[i].Value != kind {
			t.Errorf("分面[%d] = %q, 期望 %q（完整 %v）", i, facets[i].Value, kind, facets)
		}
	}
}

// TestNormalizeSummariesDerivesIPAndPolicy checks the derived display identity
// on imported rows, which the viewer shows instead of a vendor name.
func TestNormalizeSummariesDerivesIPAndPolicy(t *testing.T) {
	tests := []struct {
		name       string
		row        model.Summary
		wantIP     string
		wantPolicy policy.Kind
	}{
		{
			name:       "裸 IPv4",
			row:        model.Summary{DNS: "223.5.5.5"},
			wantIP:     "223.5.5.5",
			wantPolicy: policy.Native,
		},
		{
			name:       "DoH URL 取出主机",
			row:        model.Summary{DNS: "https://dns.adguard-dns.com/dns-query"},
			wantIP:     "dns.adguard-dns.com",
			wantPolicy: policy.Security,
		},
		{
			name:       "IPv6 字面量保留全部字段",
			row:        model.Summary{DNS: "2606:4700:4700::1111"},
			wantIP:     "2606:4700:4700::1111",
			wantPolicy: policy.Native,
		},
		{
			name:       "带端口的端点去掉端口",
			row:        model.Summary{DNS: "9.9.9.9:53"},
			wantIP:     "9.9.9.9",
			wantPolicy: policy.Security,
		},
		{
			name:       "未收录端点策略未确认",
			row:        model.Summary{DNS: "203.0.113.7"},
			wantIP:     "203.0.113.7",
			wantPolicy: policy.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSummaries([]model.Summary{tt.row})
			if len(got) != 1 {
				t.Fatalf("normalizeSummaries 返回 %d 行", len(got))
			}
			if got[0].IP != tt.wantIP {
				t.Errorf("IP = %q, 期望 %q", got[0].IP, tt.wantIP)
			}
			if got[0].Policy != tt.wantPolicy {
				t.Errorf("Policy = %q, 期望 %q", got[0].Policy, tt.wantPolicy)
			}
			if got[0].DisplayIP() != tt.wantIP {
				t.Errorf("DisplayIP() = %q, 期望 %q", got[0].DisplayIP(), tt.wantIP)
			}
		})
	}
}

// TestFinalizeBuildsPoliciesForEmptyPayload ensures the filter still renders
// before any data is loaded.
func TestFinalizeBuildsPoliciesForEmptyPayload(t *testing.T) {
	p := (&Payload{Source: "empty"}).Finalize()
	if p == nil {
		t.Fatal("Finalize 返回 nil")
	}
	if len(p.Policies) != 0 {
		t.Errorf("空数据集不应有策略分面, 实际 %v", p.Policies)
	}
}

// TestImportBuildsRegionGroupsAndFamilies verifies the region groups and the
// address family facet.
func TestImportBuildsRegionGroupsAndFamilies(t *testing.T) {
	payload, err := Import([]byte(nativeDoc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.RegionGroups) == 0 {
		t.Fatal("导入结果没有地区快捷分组")
	}
	for _, g := range payload.RegionGroups {
		if g.ID == "" || g.Label == "" || len(g.Codes) == 0 {
			t.Fatalf("地区分组不完整: %+v", g)
		}
	}

	if len(payload.Families) == 0 {
		t.Fatal("导入结果没有地址族分面")
	}
	for _, f := range payload.Families {
		if f.Label == "" {
			t.Fatalf("地址族 %q 没有显示名称", f.Value)
		}
		if f.Count <= 0 {
			t.Fatalf("地址族 %q 的记录数为 %d", f.Value, f.Count)
		}
	}
}

// TestImportHonoursForeignGeocode verifies the reference dialect's own GeoIP
// verdict is used, including its vendor names.
func TestImportHonoursForeignGeocode(t *testing.T) {
	payload, err := Import([]byte(dnspyExcerpt))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}

	byDNS := map[string]model.Summary{}
	for _, s := range payload.Summary {
		byDNS[s.DNS] = s
	}

	// "CLOUDFLARE" 必须折叠成 CDN，而不是变成一个无法标注的伪国家。
	if got := byDNS["1.0.0.1"].Region; got != "CDN" {
		t.Fatalf("1.0.0.1 的地区 = %q，期望 CDN（geocode CLOUDFLARE 应折叠）", got)
	}
	// "ALIBABA" 必须折叠成 CN。
	if got := byDNS["223.5.5.5"].Region; got != "CN" {
		t.Fatalf("223.5.5.5 的地区 = %q，期望 CN（geocode ALIBABA 应折叠）", got)
	}
	// 地址族由地址推导。
	if got := byDNS["1.0.0.1"].Family; got != model.IPv4 {
		t.Fatalf("1.0.0.1 的地址族 = %q，期望 %q", got, model.IPv4)
	}
}

// TestImportVendorGeocodesDoNotLeakIntoFacets verifies no facet is labelled
// with a raw vendor name: those must all have been folded onto a region code.
func TestImportVendorGeocodesDoNotLeakIntoFacets(t *testing.T) {
	payload, err := Import([]byte(dnspyExcerpt))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	for _, r := range payload.Regions {
		if r.Code == "CLOUDFLARE" || r.Code == "ALIBABA" {
			t.Fatalf("地区分面泄漏了厂商名: %+v", r)
		}
		if r.Label == "CLOUDFLARE" || r.Label == "ALIBABA" {
			t.Fatalf("地区分面标签泄漏了厂商名: %+v", r)
		}
	}
}

// TestImportBuildsComparisonsFromSummary verifies the UDP-vs-DoH comparison is
// derived for an imported combined run, not only for a fresh one.
func TestImportBuildsComparisonsFromSummary(t *testing.T) {
	const comboDoc = `{
  "meta": {"version": "1.0", "timestamp": "2026-09-25T12:00:00Z", "combo": "udp+doh"},
  "raw": [],
  "summary": [
    {"dns": "223.5.5.5", "name": "AliDNS 1", "protocol": "udp", "group": "cn", "region": "CN",
     "total": 10, "success": 10, "success_rate": 1, "avg_ms": 20, "p95_ms": 25, "stddev_ms": 3, "combo": "alidns|CN"},
    {"dns": "https://dns.alidns.com/dns-query", "name": "AliDNS", "protocol": "doh", "group": "cn", "region": "CN",
     "total": 10, "success": 10, "success_rate": 1, "avg_ms": 32, "p95_ms": 40, "stddev_ms": 5, "combo": "alidns|CN"}
  ]
}`
	payload, err := Import([]byte(comboDoc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Comparisons) != 1 {
		t.Fatalf("导入组合结果后得到 %d 组对比，期望 1 组: %+v", len(payload.Comparisons), payload.Comparisons)
	}
	c := payload.Comparisons[0]
	if !c.Comparable {
		t.Fatalf("两侧都成功时应可对比: %+v", c)
	}
	if c.AvgDeltaMS != 12 {
		t.Fatalf("DoH − UDP = %v，期望 12", c.AvgDeltaMS)
	}
}

// TestFinalizeIsIdempotent verifies calling Finalize twice changes nothing, so
// it is safe to call on every response.
func TestFinalizeIsIdempotent(t *testing.T) {
	payload, err := Import([]byte(nativeDoc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	regions := len(payload.Regions)
	families := len(payload.Families)
	groups := len(payload.RegionGroups)
	comps := len(payload.Comparisons)

	payload.Finalize()

	if len(payload.Regions) != regions {
		t.Fatalf("Finalize 改变了地区分面数量: %d -> %d", regions, len(payload.Regions))
	}
	if len(payload.Families) != families {
		t.Fatalf("Finalize 改变了地址族分面数量: %d -> %d", families, len(payload.Families))
	}
	if len(payload.RegionGroups) != groups {
		t.Fatalf("Finalize 改变了地区分组数量: %d -> %d", groups, len(payload.RegionGroups))
	}
	if len(payload.Comparisons) != comps {
		t.Fatalf("Finalize 改变了对比数量: %d -> %d", comps, len(payload.Comparisons))
	}
}

// TestFinalizeOnNilPayload verifies Finalize tolerates a nil receiver, since a
// server with no dataset can reach it.
func TestFinalizeOnNilPayload(t *testing.T) {
	var p *Payload
	if got := p.Finalize(); got != nil {
		t.Fatalf("(*Payload)(nil).Finalize() = %+v，期望 nil", got)
	}
}

// TestImportNativeDocRetainsRowOrder verifies import does not reorder rows, so
// the viewer's tables stay stable across reloads.
func TestImportNativeDocRetainsRowOrder(t *testing.T) {
	payload, err := Import([]byte(nativeDoc))
	if err != nil {
		t.Fatalf("Import 返回错误: %v", err)
	}
	if len(payload.Summary) < 1 {
		t.Fatalf("期望至少一行汇总，实际 %d 行", len(payload.Summary))
	}
	if payload.Summary[0].DNS != "223.5.5.5" {
		t.Fatalf("首行 = %q，期望 223.5.5.5（保持原始顺序）", payload.Summary[0].DNS)
	}
}

// TestImportEmptyDocumentLeavesNoFacets verifies a dataset with no rows yields
// no facets rather than a bogus UNKNOWN entry.
func TestImportEmptyDocumentLeavesNoFacets(t *testing.T) {
	payload := (&Payload{Source: "empty", Label: "尚无数据"}).Finalize()
	if len(payload.Regions) != 0 {
		t.Fatalf("空数据集的地区分面 = %+v，期望为空", payload.Regions)
	}
	if len(payload.Families) != 0 {
		t.Fatalf("空数据集的地址族分面 = %+v，期望为空", payload.Families)
	}
	// 快捷分组与数据无关，仍应下发，这样筛选栏在载入数据前就能渲染。
	if len(payload.RegionGroups) == 0 {
		t.Fatal("空数据集也应带上地区快捷分组")
	}
}
