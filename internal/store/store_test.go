package store

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dns-opti/internal/model"
)

// approx 比较两个浮点数是否足够接近（相对误差 1e-9）。
func approx(got, want float64) bool {
	if got == want {
		return true
	}
	scale := math.Max(math.Abs(want), 1)
	return math.Abs(got-want) <= 1e-9*scale
}

// newTestRecorder 创建记录器并在用例结束时关闭与清理。
func newTestRecorder(t *testing.T) *Recorder {
	t.Helper()
	r, err := NewRecorder()
	if err != nil {
		t.Fatalf("NewRecorder() 返回错误: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		r.Cleanup()
	})
	return r
}

// feed 按顺序写入记录，任何失败都会终止用例。
func feed(t *testing.T, r *Recorder, records ...model.RawRecord) {
	t.Helper()
	for i, rec := range records {
		if err := r.Record(rec); err != nil {
			t.Fatalf("Record(第 %d 条 %+v) 返回错误: %v", i, rec, err)
		}
	}
}

func TestRecorderSummariesExactStatistics(t *testing.T) {
	r := newTestRecorder(t)

	// 已知输入：8 次成功、2 次失败，成功延迟为 10,20,30,40,50,60,70,80。
	// 期望：Total=10, Success=8, SuccessRate=0.8
	//       Avg = 360/8 = 45
	//       偏差平方和 = 2*(35²+25²+15²+5²) = 2*(1225+625+225+25) = 8400
	//       总体标准差 = sqrt(8400/8) = sqrt(525)
	//       P95 最近秩 = sorted[ceil(0.95*8)-1] = sorted[7] = 80
	lats := []float64{10, 20, 30, 40, 50, 60, 70, 80}
	for _, ms := range lats {
		feed(t, r, model.RawRecord{
			DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Group: model.GroupCN,
			Domain: "example.com", Success: true, LatencyMS: ms,
		})
	}
	feed(t, r,
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Group: model.GroupCN, Domain: "example.com", Success: false},
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Group: model.GroupCN, Domain: "example.com", Success: false, LatencyMS: 9999},
	)

	if got := r.Count(); got != 10 {
		t.Fatalf("Count() = %d, 期望 10（失败记录也计入总数）", got)
	}

	sums := r.Summaries()
	if len(sums) != 1 {
		t.Fatalf("Summaries() 返回 %d 行, 期望 1 行: %+v", len(sums), sums)
	}
	s := sums[0]

	if s.Total != 10 {
		t.Fatalf("Summary.Total = %d, 期望 10", s.Total)
	}
	if s.Success != 8 {
		t.Fatalf("Summary.Success = %d, 期望 8（失败记录不计入成功数）", s.Success)
	}
	if !approx(s.SuccessRate, 0.8) {
		t.Fatalf("Summary.SuccessRate = %v, 期望 0.8", s.SuccessRate)
	}
	if !approx(s.AvgMS, 45) {
		t.Fatalf("Summary.AvgMS = %v, 期望 45（失败记录的延迟不参与统计）", s.AvgMS)
	}
	wantStdDev := math.Sqrt(525.0)
	if !approx(s.StdDevMS, wantStdDev) {
		t.Fatalf("Summary.StdDevMS = %v, 期望 %v（总体标准差）", s.StdDevMS, wantStdDev)
	}
	if !approx(s.P95MS, 80) {
		t.Fatalf("Summary.P95MS = %v, 期望 80（最近秩 P95）", s.P95MS)
	}
	if s.DNS != "8.8.8.8" || s.Protocol != model.ProtocolUDP || s.Group != model.GroupCN {
		t.Fatalf("Summary 的标识字段 = %q/%q/%q, 期望 8.8.8.8/udp/cn", s.DNS, s.Protocol, s.Group)
	}
}

func TestRecorderPercentileNearestRank(t *testing.T) {
	// 最近秩 P95：rank = ceil(0.95*n)，取排序后第 rank 个（1 基）。
	tests := []struct {
		name   string
		values []float64
		want   float64
	}{
		{name: "单个值", values: []float64{7}, want: 7},
		{name: "两个值 P95 取最大", values: []float64{5, 9}, want: 9},
		{name: "10 个值 P95 取第 10 个", values: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, want: 10},
		{name: "20 个值 P95 取第 19 个", values: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}, want: 19},
		{name: "乱序输入不影响结果", values: []float64{40, 10, 30, 20}, want: 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestRecorder(t)
			for _, v := range tt.values {
				feed(t, r, model.RawRecord{
					DNS: "1.1.1.1", Protocol: model.ProtocolUDP, Group: model.GroupCN,
					Success: true, LatencyMS: v,
				})
			}
			sums := r.Summaries()
			if len(sums) != 1 {
				t.Fatalf("Summaries() 返回 %d 行, 期望 1 行", len(sums))
			}
			if !approx(sums[0].P95MS, tt.want) {
				t.Fatalf("输入 %v 的 P95MS = %v, 期望 %v", tt.values, sums[0].P95MS, tt.want)
			}
		})
	}
}

func TestRecorderFailureOnlyBucket(t *testing.T) {
	r := newTestRecorder(t)
	feed(t, r,
		model.RawRecord{DNS: "203.0.113.1", Protocol: model.ProtocolDoT, Group: model.GroupIntl, Success: false},
		model.RawRecord{DNS: "203.0.113.1", Protocol: model.ProtocolDoT, Group: model.GroupIntl, Success: false, LatencyMS: 5000},
		model.RawRecord{DNS: "203.0.113.1", Protocol: model.ProtocolDoT, Group: model.GroupIntl, Success: false},
	)

	sums := r.Summaries()
	if len(sums) != 1 {
		t.Fatalf("Summaries() 返回 %d 行, 期望 1 行", len(sums))
	}
	s := sums[0]
	if s.Total != 3 || s.Success != 0 {
		t.Fatalf("失败桶 Total=%d Success=%d, 期望 3/0（失败记录计入 Total，不计入 Success）", s.Total, s.Success)
	}
	if s.SuccessRate != 0 {
		t.Fatalf("失败桶 SuccessRate = %v, 期望 0", s.SuccessRate)
	}
	// 全部失败时没有任何有效延迟，统计量必须为 0 而不是 Inf/NaN。
	if s.AvgMS != 0 || s.P95MS != 0 || s.StdDevMS != 0 {
		t.Fatalf("失败桶的延迟统计 = avg %v p95 %v stddev %v, 期望全为 0", s.AvgMS, s.P95MS, s.StdDevMS)
	}
}

func TestRecorderSeparatesBucketsAndKeepsOrder(t *testing.T) {
	r := newTestRecorder(t)
	feed(t, r,
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Group: model.GroupIntl, Name: "Google", Success: true, LatencyMS: 10},
		model.RawRecord{DNS: "223.5.5.5", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 20},
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 30},
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolDoH, Group: model.GroupIntl, Success: true, LatencyMS: 40},
	)

	sums := r.Summaries()
	if len(sums) != 4 {
		t.Fatalf("Summaries() 返回 %d 行, 期望 4 行（按 dns+protocol+group 分桶）: %+v", len(sums), sums)
	}
	wantKeys := []string{
		"8.8.8.8|udp|intl",
		"223.5.5.5|udp|cn",
		"8.8.8.8|udp|cn",
		"8.8.8.8|doh|intl",
	}
	for i, want := range wantKeys {
		if got := sums[i].Key(); got != want {
			t.Fatalf("Summaries()[%d].Key() = %q, 期望 %q（首次出现顺序）", i, got, want)
		}
	}
	if sums[0].Name != "Google" {
		t.Fatalf("Summaries()[0].Name = %q, 期望 %q", sums[0].Name, "Google")
	}
	// 同一个 DNS 的不同分组绝不能合并。
	if sums[0].Key() == sums[2].Key() {
		t.Fatal("国内与国外分组被合并到同一个汇总行")
	}
}

func TestRecorderSummariesEmpty(t *testing.T) {
	r := newTestRecorder(t)
	if got := r.Summaries(); len(got) != 0 {
		t.Fatalf("未写入任何记录时 Summaries() = %+v, 期望空", got)
	}
	if got := r.Count(); got != 0 {
		t.Fatalf("Count() = %d, 期望 0", got)
	}
}

func TestRecorderFlushCloseIdempotent(t *testing.T) {
	r, err := NewRecorder()
	if err != nil {
		t.Fatalf("NewRecorder() 返回错误: %v", err)
	}
	defer r.Cleanup()

	feed(t, r, model.RawRecord{DNS: "1.1.1.1", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 1})

	if err := r.Flush(); err != nil {
		t.Fatalf("Flush() 返回错误: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close() 返回错误: %v", err)
	}
	// Close 可重复调用且不应报错（closeOnce 保护）。
	if err := r.Close(); err != nil {
		t.Fatalf("第二次 Close() 返回错误: %v", err)
	}
	// Close 之后 Flush 也应安全。
	if err := r.Flush(); err != nil {
		t.Fatalf("Close 之后的 Flush() 返回错误: %v", err)
	}
}

func TestRecorderCleanupRemovesTempFile(t *testing.T) {
	r, err := NewRecorder()
	if err != nil {
		t.Fatalf("NewRecorder() 返回错误: %v", err)
	}
	path := r.TempPath()
	if path == "" {
		t.Fatal("TempPath() 为空")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("临时文件 %s 在创建后不存在: %v", path, err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close() 返回错误: %v", err)
	}
	r.Cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Cleanup() 之后临时文件 %s 仍存在（stat 错误 = %v）", path, err)
	}
	// 重复 Cleanup 不应 panic。
	r.Cleanup()
}

func TestRecorderSetServerFlags(t *testing.T) {
	r := newTestRecorder(t)
	feed(t, r,
		model.RawRecord{DNS: "192.168.1.1", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 5},
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 15},
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolDoH, Group: model.GroupCN, Name: "已有名称", Success: true, LatencyMS: 25},
	)

	r.SetServerFlags([]model.Server{
		{Name: "路由器", Address: "192.168.1.1", Protocol: model.ProtocolUDP, IsSystem: true, IsPrivate: true},
		{Name: "Google", Address: "8.8.8.8", Protocol: model.ProtocolUDP, IsPrivate: false},
		{Name: "Google DoH", Address: "8.8.8.8", Protocol: model.ProtocolDoH, IsPrivate: false},
	})

	sums := r.Summaries()
	byKey := map[string]model.Summary{}
	for _, s := range sums {
		byKey[s.Key()] = s
	}

	priv := byKey["192.168.1.1|udp|cn"]
	if !priv.IsPrivate || !priv.IsSystem {
		t.Fatalf("内网服务器未标记 IsPrivate/IsSystem: %+v", priv)
	}
	if priv.Name != "路由器" {
		t.Fatalf("内网服务器 Name = %q, 期望 %q", priv.Name, "路由器")
	}

	pub := byKey["8.8.8.8|udp|cn"]
	if pub.IsPrivate {
		t.Fatalf("公网服务器被误标为 IsPrivate: %+v", pub)
	}
	if pub.Name != "Google" {
		t.Fatalf("公网服务器 Name = %q, 期望 %q", pub.Name, "Google")
	}

	// 已有名称的汇总行不应被服务器名称覆盖。
	named := byKey["8.8.8.8|doh|cn"]
	if named.Name != "已有名称" {
		t.Fatalf("已命名汇总行的 Name = %q, 期望保留 %q", named.Name, "已有名称")
	}
}

// TestRecorderRawFileIsJSONLines 确认临时文件确实是 JSON Lines，并且转义不会丢字段。
func TestRecorderRawFileIsJSONLines(t *testing.T) {
	r, err := NewRecorder()
	if err != nil {
		t.Fatalf("NewRecorder() 返回错误: %v", err)
	}
	defer func() {
		_ = r.Close()
		r.Cleanup()
	}()

	feed(t, r,
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Domain: "a.com", Group: model.GroupCN, Attempt: 1, Success: true, LatencyMS: 1.5, TS: 100},
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Domain: "b.com", Group: model.GroupCN, Attempt: 2, Success: false},
	)
	if err := r.Close(); err != nil {
		t.Fatalf("Close() 返回错误: %v", err)
	}

	data, err := os.ReadFile(r.TempPath())
	if err != nil {
		t.Fatalf("读取临时文件失败: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("临时文件有 %d 行, 期望每行一条记录（共 2 行）: %q", len(lines), data)
	}
	var first model.RawRecord
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("第一行不是合法 JSON: %v（%q）", err, lines[0])
	}
	if first.Domain != "a.com" || !first.Success || first.LatencyMS != 1.5 {
		t.Fatalf("第一行反序列化 = %+v, 期望 a.com/true/1.5", first)
	}
}

// exportFixture 写入一组记录并导出，返回导出路径与记录器。
func exportFixture(t *testing.T, indent bool, path string) (string, *Recorder, model.Meta) {
	t.Helper()
	r := newTestRecorder(t)
	feed(t, r,
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Domain: "a.com", Group: model.GroupCN, Attempt: 1, Success: true, LatencyMS: 10, TS: 1},
		model.RawRecord{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Domain: "b.com", Group: model.GroupCN, Attempt: 1, Success: false, TS: 2},
		model.RawRecord{DNS: "1.1.1.1", Protocol: model.ProtocolDoH, Domain: "c.com", Group: model.GroupIntl, Attempt: 1, Success: true, LatencyMS: 30, TS: 3},
	)

	meta := model.Meta{
		Version:      "1.0",
		Timestamp:    time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC),
		Platform:     "windows/amd64",
		Concurrency:  4,
		WarmupDomain: "example.com",
		DomainGroups: []string{model.GroupCN, model.GroupIntl},
		Protocols:    []string{"udp", "doh"},
		DNSServers: []model.Server{
			{Name: "Google", Address: "8.8.8.8", Protocol: model.ProtocolUDP},
			{Name: "Cloudflare", Address: "1.1.1.1", Protocol: model.ProtocolDoH},
		},
		SystemDNS: []string{"192.168.1.1"},
		Note:      "测试备注",
	}

	got, err := r.Export(meta, ExportOptions{Path: path, Indent: indent})
	if err != nil {
		t.Fatalf("Export(indent=%v) 返回错误: %v", indent, err)
	}
	if got != path {
		t.Fatalf("Export 返回路径 %q, 期望请求的 %q", got, path)
	}
	return got, r, meta
}

func TestExportRoundTripsToModelFile(t *testing.T) {
	for _, indent := range []bool{false, true} {
		t.Run(map[bool]string{false: "紧凑", true: "缩进"}[indent], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result.json")
			_, _, meta := exportFixture(t, indent, path)

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("读取导出文件失败: %v", err)
			}

			var file model.File
			if err := json.Unmarshal(data, &file); err != nil {
				t.Fatalf("导出文件无法反序列化为 model.File: %v\n内容: %s", err, data)
			}

			if len(file.Raw) != 3 {
				t.Fatalf("导出文件 raw 有 %d 条, 期望 3 条\n内容: %s", len(file.Raw), data)
			}
			if len(file.Summary) != 2 {
				t.Fatalf("导出文件 summary 有 %d 条, 期望 2 条\n内容: %s", len(file.Summary), data)
			}

			// meta 必须完整保留。
			if file.Meta.Version != meta.Version {
				t.Fatalf("meta.version = %q, 期望 %q", file.Meta.Version, meta.Version)
			}
			if !file.Meta.Timestamp.Equal(meta.Timestamp) {
				t.Fatalf("meta.timestamp = %v, 期望 %v", file.Meta.Timestamp, meta.Timestamp)
			}
			if file.Meta.Concurrency != meta.Concurrency {
				t.Fatalf("meta.concurrency = %d, 期望 %d", file.Meta.Concurrency, meta.Concurrency)
			}
			if len(file.Meta.DNSServers) != 2 {
				t.Fatalf("meta.dns_servers 有 %d 条, 期望 2 条", len(file.Meta.DNSServers))
			}
			if file.Meta.Note != meta.Note {
				t.Fatalf("meta.note = %q, 期望 %q", file.Meta.Note, meta.Note)
			}
			if len(file.Meta.DomainGroups) != 2 || file.Meta.DomainGroups[0] != model.GroupCN {
				t.Fatalf("meta.domain_groups = %v, 期望 [cn intl]", file.Meta.DomainGroups)
			}
			if len(file.Meta.SystemDNS) != 1 || file.Meta.SystemDNS[0] != "192.168.1.1" {
				t.Fatalf("meta.system_dns = %v, 期望 [192.168.1.1]", file.Meta.SystemDNS)
			}

			// raw 的内容必须逐条保留。
			if file.Raw[0].Domain != "a.com" || !file.Raw[0].Success {
				t.Fatalf("raw[0] = %+v, 期望 a.com 成功", file.Raw[0])
			}
			if file.Raw[1].Success {
				t.Fatalf("raw[1] = %+v, 期望失败记录", file.Raw[1])
			}
			if file.Raw[2].Protocol != model.ProtocolDoH {
				t.Fatalf("raw[2].Protocol = %q, 期望 %q", file.Raw[2].Protocol, model.ProtocolDoH)
			}

			// summary 的统计值必须与 Summaries() 一致。
			var udp model.Summary
			for _, s := range file.Summary {
				if s.Protocol == model.ProtocolUDP {
					udp = s
				}
			}
			if udp.Total != 2 || udp.Success != 1 {
				t.Fatalf("UDP 汇总 Total=%d Success=%d, 期望 2/1", udp.Total, udp.Success)
			}
			if !approx(udp.SuccessRate, 0.5) {
				t.Fatalf("UDP 汇总 SuccessRate = %v, 期望 0.5", udp.SuccessRate)
			}
			if !approx(udp.AvgMS, 10) {
				t.Fatalf("UDP 汇总 AvgMS = %v, 期望 10", udp.AvgMS)
			}
		})
	}
}

func TestExportIndentProducesValidJSON(t *testing.T) {
	// 缩进模式下手写拼装的文档最容易出错，这里额外校验结构。
	for _, indent := range []bool{false, true} {
		name := "紧凑"
		if indent {
			name = "缩进"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result.json")
			exportFixture(t, indent, path)

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("读取导出文件失败: %v", err)
			}
			if !json.Valid(data) {
				t.Fatalf("导出文件不是合法 JSON（indent=%v）:\n%s", indent, data)
			}
			// 顶层必须是对象且恰好包含 meta / raw / summary 三个键。
			var top map[string]json.RawMessage
			if err := json.Unmarshal(data, &top); err != nil {
				t.Fatalf("顶层不是 JSON 对象: %v", err)
			}
			for _, key := range []string{"meta", "raw", "summary"} {
				if _, ok := top[key]; !ok {
					t.Fatalf("导出文件缺少顶层键 %q（indent=%v）:\n%s", key, indent, data)
				}
			}
			if len(top) != 3 {
				t.Fatalf("导出文件顶层有 %d 个键（%v）, 期望恰好 3 个", len(top), keysOf(top))
			}
		})
	}
}

func TestExportIndentIsActuallyIndented(t *testing.T) {
	dir := t.TempDir()
	compact := filepath.Join(dir, "compact.json")
	pretty := filepath.Join(dir, "pretty.json")
	exportFixture(t, false, compact)
	exportFixture(t, true, pretty)

	compactData, err := os.ReadFile(compact)
	if err != nil {
		t.Fatalf("读取紧凑文件失败: %v", err)
	}
	prettyData, err := os.ReadFile(pretty)
	if err != nil {
		t.Fatalf("读取缩进文件失败: %v", err)
	}
	if strings.Count(string(compactData), "\n") >= strings.Count(string(prettyData), "\n") {
		t.Fatalf("缩进版本的行数（%d）没有多于紧凑版本（%d）",
			strings.Count(string(prettyData), "\n"), strings.Count(string(compactData), "\n"))
	}
	if !strings.Contains(string(prettyData), "\n  \"meta\":") {
		t.Fatalf("缩进版本未按预期的两空格缩进:\n%s", prettyData)
	}
}

func TestExportEmptyRecorder(t *testing.T) {
	// 没有任何记录时也必须写出合法的空 raw / summary 数组。
	r := newTestRecorder(t)
	path := filepath.Join(t.TempDir(), "empty.json")
	if _, err := r.Export(model.Meta{Version: "1.0"}, ExportOptions{Path: path, Indent: true}); err != nil {
		t.Fatalf("Export 返回错误: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取导出文件失败: %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("空结果的导出文件不是合法 JSON:\n%s", data)
	}
	var file model.File
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("空结果无法反序列化: %v", err)
	}
	if len(file.Raw) != 0 || len(file.Summary) != 0 {
		t.Fatalf("空结果导出后 raw=%d summary=%d, 期望都为 0", len(file.Raw), len(file.Summary))
	}
}

func TestExportCreatesMissingDirectory(t *testing.T) {
	r := newTestRecorder(t)
	feed(t, r, model.RawRecord{DNS: "1.1.1.1", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 1})

	path := filepath.Join(t.TempDir(), "nested", "deeper", "result.json")
	got, err := r.Export(model.Meta{Version: "1.0"}, ExportOptions{Path: path})
	if err != nil {
		t.Fatalf("Export 到不存在的目录时返回错误: %v", err)
	}
	if got != path {
		t.Fatalf("Export 返回 %q, 期望 %q", got, path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("导出文件未创建: %v", err)
	}
}

func TestExportDefaultPathIsJSON(t *testing.T) {
	// Path 为空时在当前目录生成带时间戳的文件名；为避免污染仓库，切到临时目录。
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() 失败: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("os.Chdir(%q) 失败: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	r := newTestRecorder(t)
	feed(t, r, model.RawRecord{DNS: "1.1.1.1", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 1})

	got, err := r.Export(model.Meta{Version: "1.0"}, ExportOptions{})
	if err != nil {
		t.Fatalf("Export 使用默认路径时返回错误: %v", err)
	}
	if !strings.HasSuffix(got, ".json") {
		t.Fatalf("默认导出路径 %q 未以 .json 结尾", got)
	}
	if filepath.Dir(got) != "." {
		t.Fatalf("默认导出路径 %q 不在当前目录", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("默认路径导出文件不存在: %v", err)
	}
}

func TestDefaultOutputName(t *testing.T) {
	tests := []struct {
		name string
		dir  string
	}{
		{name: "无目录", dir: ""},
		{name: "指定目录", dir: "out"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DefaultOutputName(tt.dir)
			if !strings.HasSuffix(got, ".json") {
				t.Fatalf("DefaultOutputName(%q) = %q, 期望以 .json 结尾", tt.dir, got)
			}
			if !strings.Contains(got, "dns-opti_result_") {
				t.Fatalf("DefaultOutputName(%q) = %q, 期望包含前缀 dns-opti_result_", tt.dir, got)
			}
			if tt.dir == "" {
				if strings.ContainsAny(got, `/\`) {
					t.Fatalf("DefaultOutputName(\"\") = %q, 期望不含路径分隔符", got)
				}
				return
			}
			if filepath.Dir(got) != tt.dir {
				t.Fatalf("DefaultOutputName(%q) = %q, 期望目录为 %q", tt.dir, got, tt.dir)
			}
		})
	}
}

func TestDefaultOutputNameIsTimestamped(t *testing.T) {
	a := DefaultOutputName("")
	time.Sleep(1100 * time.Millisecond)
	b := DefaultOutputName("")
	// 时间戳精确到秒，两次调用（间隔 >1s）必须产生不同的名字。
	if a == b {
		t.Fatalf("间隔超过 1 秒的两次 DefaultOutputName 结果相同: %q", a)
	}
}

func TestPercentileHelperEdgeCases(t *testing.T) {
	if got := percentile(nil, 0.95); got != 0 {
		t.Fatalf("percentile(nil, 0.95) = %v, 期望 0", got)
	}
	values := []float64{3, 1, 2}
	got := percentile(values, 0.5)
	if got != 2 {
		t.Fatalf("percentile([3 1 2], 0.5) = %v, 期望 2", got)
	}
	// 不得打乱调用方切片的顺序。
	if values[0] != 3 || values[1] != 1 || values[2] != 2 {
		t.Fatalf("percentile 修改了输入切片: %v", values)
	}
}

func TestStddevHelperIsPopulationStddev(t *testing.T) {
	values := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	m := mean(values)
	if !approx(m, 5) {
		t.Fatalf("mean(%v) = %v, 期望 5", values, m)
	}
	// 总体标准差 = 2；样本标准差约为 2.138。
	if got := stddev(values, m); !approx(got, 2) {
		t.Fatalf("stddev(%v) = %v, 期望 2（总体标准差）", values, got)
	}
	if got := stddev(nil, 0); got != 0 {
		t.Fatalf("stddev(nil) = %v, 期望 0", got)
	}
	if got := mean(nil); got != 0 {
		t.Fatalf("mean(nil) = %v, 期望 0", got)
	}
}

// keysOf 返回 map 的键，用于失败信息。
func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
