package engine

import (
	"math"
	"testing"

	"dns-opti/internal/model"
)

// approxEqual compares two floats with a tolerance, so a weighted average can be
// asserted without depending on the exact order of the additions.
func approxEqual(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

// comboSummary builds one summary row of a combined run.
func comboSummary(combo, dns, name string, proto model.Protocol, group string, success, total int, avg, p95, sd float64) model.Summary {
	rate := 0.0
	if total > 0 {
		rate = float64(success) / float64(total)
	}
	return model.Summary{
		DNS: dns, Name: name, Protocol: proto, Group: group, Combo: combo,
		Total: total, Success: success, SuccessRate: rate,
		AvgMS: avg, P95MS: p95, StdDevMS: sd,
		Region: "CN",
	}
}

func TestCompareTransportsPairsBothSides(t *testing.T) {
	rows := []model.Summary{
		comboSummary("alidns|CN", "223.5.5.5", "AliDNS 1", model.ProtocolUDP, model.GroupCN, 10, 10, 20, 25, 3),
		comboSummary("alidns|CN", "https://dns.alidns.com/dns-query", "AliDNS", model.ProtocolDoH, model.GroupCN, 10, 10, 30, 40, 5),
	}

	got := CompareTransports(rows)
	if len(got) != 1 {
		t.Fatalf("得到 %d 组对比, 期望 1 组: %+v", len(got), got)
	}
	c := got[0]
	if c.UDP == nil || c.DoH == nil {
		t.Fatalf("一组对比应同时具备两侧: %+v", c)
	}
	if !c.Comparable {
		t.Fatalf("两侧都有成功查询时应可对比: %+v", c)
	}
	if !approxEqual(c.AvgDeltaMS, 10, 1e-9) {
		t.Fatalf("AvgDeltaMS = %v, 期望 10（DoH 30 − UDP 20）", c.AvgDeltaMS)
	}
	if !approxEqual(c.P95DeltaMS, 15, 1e-9) {
		t.Fatalf("P95DeltaMS = %v, 期望 15", c.P95DeltaMS)
	}
	if !approxEqual(c.RateDelta, 0, 1e-9) {
		t.Fatalf("RateDelta = %v, 期望 0", c.RateDelta)
	}
	if c.Region != "CN" {
		t.Fatalf("Region = %q, 期望 CN", c.Region)
	}
}

func TestCompareTransportsKeepsOneSidedProviders(t *testing.T) {
	// 只发布一种传输的服务商仍要出现（另一侧为空），而不是被静默丢掉。
	rows := []model.Summary{
		comboSummary("solo|US", "4.2.2.1", "Solo", model.ProtocolUDP, model.GroupCN, 5, 5, 30, 35, 2),
	}
	got := CompareTransports(rows)
	if len(got) != 1 {
		t.Fatalf("得到 %d 组, 期望 1 组: %+v", len(got), got)
	}
	if got[0].UDP == nil {
		t.Fatalf("UDP 侧不应为空: %+v", got[0])
	}
	if got[0].DoH != nil {
		t.Fatalf("DoH 侧应为空: %+v", got[0].DoH)
	}
	if got[0].Comparable {
		t.Fatalf("只有一侧数据时不应标记为可对比: %+v", got[0])
	}
	// 单侧数据不得产生一个看起来像测量值的 delta。
	if got[0].AvgDeltaMS != 0 || got[0].P95DeltaMS != 0 || got[0].RateDelta != 0 {
		t.Fatalf("单侧数据的 delta 应为 0: %+v", got[0])
	}
}

func TestCompareTransportsIgnoresUnpairedProtocols(t *testing.T) {
	// DoT 不参与 UDP+DoH 配对，且没有 Combo 标记的行表示它不属于任何组合。
	rows := []model.Summary{
		comboSummary("alidns|CN", "223.5.5.5", "AliDNS 1", model.ProtocolUDP, model.GroupCN, 1, 1, 20, 20, 0),
		comboSummary("alidns|CN", "dns.alidns.com", "AliDNS", model.ProtocolDoT, model.GroupCN, 1, 1, 15, 15, 0),
		// 没有 Combo 的行（例如普通协议的运行）必须被忽略。
		{DNS: "9.9.9.9", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 1, Success: 1},
	}
	got := CompareTransports(rows)
	if len(got) != 1 {
		t.Fatalf("得到 %d 组, 期望 1 组（DoT 与无标记行都应被忽略）: %+v", len(got), got)
	}
	if got[0].DoH != nil {
		t.Fatalf("DoT 不应被当作 DoH 侧: %+v", got[0].DoH)
	}
}

func TestCompareTransportsWeightsAcrossGroups(t *testing.T) {
	// 同一个服务商同一传输在国内外两个域名组各有一行，聚合后的平均值必须按
	// 成功次数加权，而不是简单取两行的算术平均。
	rows := []model.Summary{
		comboSummary("x|CN", "1.1.1.1", "X", model.ProtocolUDP, model.GroupCN, 90, 90, 10, 12, 1),
		comboSummary("x|CN", "1.1.1.1", "X", model.ProtocolUDP, model.GroupIntl, 10, 10, 110, 120, 5),
	}
	got := CompareTransports(rows)
	if len(got) != 1 {
		t.Fatalf("得到 %d 组, 期望 1 组", len(got))
	}
	side := got[0].UDP
	if side == nil {
		t.Fatal("UDP 侧为空")
	}
	if side.Total != 100 || side.Success != 100 {
		t.Fatalf("总量聚合错误: total=%d success=%d, 期望各 100", side.Total, side.Success)
	}
	// (10*90 + 110*10) / 100 = 20
	if !approxEqual(side.AvgMS, 20, 1e-9) {
		t.Fatalf("加权平均 = %v, 期望 20（简单平均会是 60）", side.AvgMS)
	}
	if len(side.Groups) != 2 {
		t.Fatalf("应保留两个域名组的明细: %+v", side.Groups)
	}
	if g := side.Groups[model.GroupIntl]; !approxEqual(g.AvgMS, 110, 1e-9) {
		t.Fatalf("国外域名组明细 = %+v, 期望 avg 110", g)
	}
}

func TestCompareTransportsMarksAggregatedSides(t *testing.T) {
	// AliDNS 有两个 UDP 端点但只有一个 DoH 端点。聚合侧必须记录它覆盖了哪些
	// 地址，否则一行里悄悄合并了两台服务器会误导用户。
	rows := []model.Summary{
		comboSummary("alidns|CN", "223.5.5.5", "AliDNS 1", model.ProtocolUDP, model.GroupCN, 1, 1, 20, 20, 0),
		comboSummary("alidns|CN", "223.6.6.6", "AliDNS 2", model.ProtocolUDP, model.GroupCN, 1, 1, 30, 30, 0),
		comboSummary("alidns|CN", "https://dns.alidns.com/dns-query", "AliDNS", model.ProtocolDoH, model.GroupCN, 1, 1, 25, 25, 0),
	}
	got := CompareTransports(rows)
	if len(got) != 1 {
		t.Fatalf("得到 %d 组, 期望 1 组", len(got))
	}
	udp := got[0].UDP
	if udp == nil {
		t.Fatal("UDP 侧为空")
	}
	if udp.Endpoints != 2 {
		t.Fatalf("UDP 侧端点数为 %d, 期望 2: %+v", udp.Endpoints, udp.Addresses)
	}
	if len(udp.Addresses) != 2 {
		t.Fatalf("UDP 侧应记录两个地址: %+v", udp.Addresses)
	}
	if udp.DNS() != udp.Addresses[0] {
		t.Fatalf("DNS() = %q, 期望首个地址 %q", udp.DNS(), udp.Addresses[0])
	}
	if label := udp.Label(); label == udp.Addresses[0] {
		t.Fatalf("聚合侧的 Label 应标明端点数量, 实际 %q", label)
	}
	if !approxEqual(udp.AvgMS, 25, 1e-9) {
		t.Fatalf("两个端点的平均值 = %v, 期望 25", udp.AvgMS)
	}

	doh := got[0].DoH
	if doh == nil {
		t.Fatal("DoH 侧为空")
	}
	if doh.Endpoints != 1 {
		t.Fatalf("DoH 侧端点数为 %d, 期望 1", doh.Endpoints)
	}
	if label := doh.Label(); label != doh.Addresses[0] {
		t.Fatalf("单端点侧的 Label 应就是地址, 实际 %q", label)
	}
}

func TestCompareTransportsDeduplicatesRepeatedAddresses(t *testing.T) {
	// 同一地址在不同域名组的行折叠到同一侧时，端点计数不能翻倍。
	rows := []model.Summary{
		comboSummary("x|CN", "1.1.1.1", "X", model.ProtocolUDP, model.GroupCN, 1, 1, 20, 20, 0),
		comboSummary("x|CN", "1.1.1.1", "X", model.ProtocolUDP, model.GroupIntl, 1, 1, 22, 22, 0),
	}
	got := CompareTransports(rows)
	if got[0].UDP.Endpoints != 1 {
		t.Fatalf("端点数为 %d, 期望 1（同一地址跨域名组只算一个）: %+v",
			got[0].UDP.Endpoints, got[0].UDP.Addresses)
	}
}

func TestCompareTransportsRequiresBothSidesToHaveSuccess(t *testing.T) {
	// 一侧全部失败时不能给出 delta：缺失侧的全 0 会被误读成「非常快」。
	rows := []model.Summary{
		comboSummary("x|CN", "1.1.1.1", "X", model.ProtocolUDP, model.GroupCN, 10, 10, 20, 22, 1),
		comboSummary("x|CN", "https://x/dns-query", "X", model.ProtocolDoH, model.GroupCN, 0, 10, 0, 0, 0),
	}
	got := CompareTransports(rows)
	c := got[0]
	if c.Comparable {
		t.Fatalf("DoH 全部失败时不应标记为可对比: %+v", c)
	}
	if c.AvgDeltaMS != 0 || c.P95DeltaMS != 0 || c.RateDelta != 0 {
		t.Fatalf("不可对比时 delta 应为 0: %+v", c)
	}
	if c.DoH.AvgMS != 0 || c.DoH.P95MS != 0 || c.DoH.StdDevMS != 0 {
		t.Fatalf("全失败的一侧延迟字段应为 0（不得伪装成测量值）: %+v", c.DoH)
	}
	if !approxEqual(c.DoH.SuccessRate, 0, 1e-9) {
		t.Fatalf("全失败一侧的成功率 = %v, 期望 0", c.DoH.SuccessRate)
	}
}

func TestCompareTransportsOrdersComparableFirst(t *testing.T) {
	rows := []model.Summary{
		// 只有 UDP 的服务商。
		comboSummary("solo|US", "4.2.2.1", "Solo", model.ProtocolUDP, model.GroupCN, 1, 1, 30, 30, 0),
		// 两侧齐全的服务商。
		comboSummary("both|CN", "1.1.1.1", "Both", model.ProtocolUDP, model.GroupCN, 1, 1, 20, 20, 0),
		comboSummary("both|CN", "https://both/dns-query", "Both", model.ProtocolDoH, model.GroupCN, 1, 1, 25, 25, 0),
	}
	got := CompareTransports(rows)
	if len(got) != 2 {
		t.Fatalf("得到 %d 组, 期望 2 组", len(got))
	}
	if !got[0].Comparable {
		t.Fatalf("可对比的组应排在最前: %+v", got)
	}
	if got[0].Name != "Both" {
		t.Fatalf("首组 = %q, 期望 Both", got[0].Name)
	}
}

func TestCompareTransportsEmptyInput(t *testing.T) {
	if got := CompareTransports(nil); len(got) != 0 {
		t.Fatalf("空输入应返回空结果, 实际 %+v", got)
	}
}

func TestCompareTransportsIsDeterministic(t *testing.T) {
	// 同一份输入重复调用必须给出相同顺序，否则报告会在刷新之间抖动。
	rows := []model.Summary{
		comboSummary("a|CN", "1.1.1.1", "A", model.ProtocolUDP, model.GroupCN, 1, 1, 20, 20, 0),
		comboSummary("b|CN", "2.2.2.2", "B", model.ProtocolUDP, model.GroupCN, 1, 1, 20, 20, 0),
		comboSummary("c|CN", "3.3.3.3", "C", model.ProtocolUDP, model.GroupCN, 1, 1, 20, 20, 0),
	}
	first := CompareTransports(rows)
	for i := 0; i < 8; i++ {
		got := CompareTransports(rows)
		if len(got) != len(first) {
			t.Fatalf("第 %d 次调用长度不同: %d != %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].Combo != first[j].Combo {
				t.Fatalf("第 %d 次调用顺序不同: %v != %v", i, got, first)
			}
		}
	}
}
