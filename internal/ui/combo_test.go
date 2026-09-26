package ui

import (
	"strings"
	"testing"

	"dns-opti/internal/engine"
	"dns-opti/internal/model"
)

// side builds one transport side of a comparison.
func side(proto model.Protocol, endpoints int, success, total int, avg, p95 float64) *engine.TransportSide {
	addresses := make([]string, 0, endpoints)
	for i := 0; i < endpoints; i++ {
		addresses = append(addresses, "addr"+string(rune('a'+i)))
	}
	rate := 0.0
	if total > 0 {
		rate = float64(success) / float64(total)
	}
	return &engine.TransportSide{
		Addresses:   addresses,
		Protocol:    proto,
		Endpoints:   endpoints,
		Total:       total,
		Success:     success,
		SuccessRate: rate,
		AvgMS:       avg,
		P95MS:       p95,
	}
}

// comparison builds one provider comparison with consistent deltas.
func comparison(name string, udp, doh *engine.TransportSide) engine.TransportComparison {
	c := engine.TransportComparison{Combo: name, Name: name, Region: "CN", UDP: udp, DoH: doh}
	if udp != nil && doh != nil {
		c.Comparable = udp.Success > 0 && doh.Success > 0
		if c.Comparable {
			c.AvgDeltaMS = doh.AvgMS - udp.AvgMS
			c.P95DeltaMS = doh.P95MS - udp.P95MS
			c.RateDelta = doh.SuccessRate - udp.SuccessRate
		}
	}
	return c
}

func TestPrintTransportComparisonEmptyIsSilent(t *testing.T) {
	// 普通运行没有对比数据，不得输出任何内容（否则报告里会出现空表）。
	var b strings.Builder
	printTransportComparison(&b, nil)
	if b.String() != "" {
		t.Fatalf("无对比数据时输出了内容: %q", b.String())
	}

	b.Reset()
	printTransportComparison(&b, []engine.TransportComparison{})
	if b.String() != "" {
		t.Fatalf("空对比切片时输出了内容: %q", b.String())
	}
}

func TestPrintTransportComparisonRendersBothSides(t *testing.T) {
	got := renderComparison(t, []engine.TransportComparison{
		comparison("alidns|CN",
			side(model.ProtocolUDP, 1, 10, 10, 20, 25),
			side(model.ProtocolDoH, 1, 10, 10, 32, 40)),
	})

	for _, want := range []string{"UDP 与 DoH 对比", "alidns|CN", "UDP", "DoH", "+12ms", "可对比 1 组"} {
		if !strings.Contains(got, want) {
			t.Errorf("对比报告缺少 %q:\n%s", want, got)
		}
	}
}

func TestPrintTransportComparisonMarksAggregatedSides(t *testing.T) {
	// 一个服务商有 2 个 UDP 端点但只有 1 个 DoH 端点时，必须标注端点数，
	// 否则会把两台服务器并成一行而不自知。
	got := renderComparison(t, []engine.TransportComparison{
		comparison("alidns|CN",
			side(model.ProtocolUDP, 2, 10, 10, 20, 25),
			side(model.ProtocolDoH, 1, 10, 10, 30, 35)),
	})
	if !strings.Contains(got, "2 个端点") {
		t.Errorf("聚合侧未标注端点数:\n%s", got)
	}
}

func TestPrintTransportComparisonOmitsDeltaWhenNotComparable(t *testing.T) {
	// 一侧全部失败时不得给出差值：缺失侧的全 0 会被读成「快了多少」。
	got := renderComparison(t, []engine.TransportComparison{
		comparison("x|CN",
			side(model.ProtocolUDP, 1, 10, 10, 20, 25),
			side(model.ProtocolDoH, 1, 0, 10, 0, 0)),
	})
	if strings.Contains(got, "-20ms") || strings.Contains(got, "+20ms") {
		t.Errorf("不可对比的一行给出了差值:\n%s", got)
	}
	if !strings.Contains(got, "没有任何服务商的两种传输都成功") {
		t.Errorf("全部不可对比时应给出说明:\n%s", got)
	}
}

func TestPrintTransportComparisonSinglePairIsHedged(t *testing.T) {
	// 只有一组可对比数据时不能说「普遍」——一个服务商不构成趋势。
	got := renderComparison(t, []engine.TransportComparison{
		comparison("only|CN",
			side(model.ProtocolUDP, 1, 10, 10, 20, 25),
			side(model.ProtocolDoH, 1, 10, 10, 22, 27)),
	})
	if strings.Contains(got, "普遍") {
		t.Errorf("单组数据却给出了「普遍」的结论:\n%s", got)
	}
	if !strings.Contains(got, "只有一组可对比数据") {
		t.Errorf("单组数据未给出谨慎说明:\n%s", got)
	}
}

func TestPrintTransportComparisonAllSlower(t *testing.T) {
	got := renderComparison(t, []engine.TransportComparison{
		comparison("a|CN", side(model.ProtocolUDP, 1, 10, 10, 20, 25), side(model.ProtocolDoH, 1, 10, 10, 30, 35)),
		comparison("b|CN", side(model.ProtocolUDP, 1, 10, 10, 22, 27), side(model.ProtocolDoH, 1, 10, 10, 33, 38)),
	})
	if !strings.Contains(got, "普遍比 UDP 慢") {
		t.Errorf("全部更慢时未给出对应结论:\n%s", got)
	}
}

func TestPrintTransportComparisonAllFaster(t *testing.T) {
	got := renderComparison(t, []engine.TransportComparison{
		comparison("a|CN", side(model.ProtocolUDP, 1, 10, 10, 30, 35), side(model.ProtocolDoH, 1, 10, 10, 20, 25)),
		comparison("b|CN", side(model.ProtocolUDP, 1, 10, 10, 33, 38), side(model.ProtocolDoH, 1, 10, 10, 22, 27)),
	})
	if !strings.Contains(got, "反而更快") {
		t.Errorf("全部更快时未给出对应结论:\n%s", got)
	}
}

func TestPrintTransportComparisonMixedVerdict(t *testing.T) {
	got := renderComparison(t, []engine.TransportComparison{
		comparison("a|CN", side(model.ProtocolUDP, 1, 10, 10, 20, 25), side(model.ProtocolDoH, 1, 10, 10, 30, 35)),
		comparison("b|CN", side(model.ProtocolUDP, 1, 10, 10, 30, 35), side(model.ProtocolDoH, 1, 10, 10, 20, 25)),
	})
	if !strings.Contains(got, "互有胜负") {
		t.Errorf("互有胜负时未给出对应结论:\n%s", got)
	}
}

func TestPrintTransportComparisonOneSidedRowShowsDashes(t *testing.T) {
	// 只有 UDP 的服务商仍要出现在表里，另一侧显示为「—」。
	got := renderComparison(t, []engine.TransportComparison{
		comparison("solo|CN", side(model.ProtocolUDP, 1, 10, 10, 20, 25), nil),
	})
	if !strings.Contains(got, "solo|CN") {
		t.Errorf("单边服务商未出现在表中:\n%s", got)
	}
	if !strings.Contains(got, "—") {
		t.Errorf("缺失的一侧未显示为破折号:\n%s", got)
	}
}

func TestPrintTransportComparisonRendersRegionLabel(t *testing.T) {
	// 地区应显示中文名而不是裸代码。
	c := comparison("a|CN", side(model.ProtocolUDP, 1, 10, 10, 20, 25), side(model.ProtocolDoH, 1, 10, 10, 30, 35))
	c.Region = "DE"
	got := renderComparison(t, []engine.TransportComparison{c})
	if !strings.Contains(got, "德国") {
		t.Errorf("地区未渲染为中文名:\n%s", got)
	}
}

// renderComparison captures the comparison section as plain text.
func renderComparison(t *testing.T, comparisons []engine.TransportComparison) string {
	t.Helper()
	var b strings.Builder
	printTransportComparison(&b, comparisons)
	return b.String()
}
