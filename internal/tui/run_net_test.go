package tui

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dns-opti/internal/config"
	"dns-opti/internal/engine"
	"dns-opti/internal/model"
	"dns-opti/internal/scheduler"
	"dns-opti/internal/store"
	"dns-opti/internal/ui"
)

// The tests here exercise the adapters that connect the interactive interface
// to the real engine and the real web server. They are opt-in
// (DNS_OPTI_NET_TESTS=1) because they open sockets.

// TestRunEngineWritesResult verifies runEngine exports a result file and
// reports progress — the contract the menu's "开始测试" relies on.
func TestRunEngineWritesResult(t *testing.T) {
	if os.Getenv("DNS_OPTI_NET_TESTS") != "1" {
		t.Skip("设置 DNS_OPTI_NET_TESTS=1 可运行联网集成测试")
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "tui-result.json")
	cfg := config.Options{
		Domains:      "baidu.com",
		Protocols:    []model.Protocol{model.ProtocolUDP},
		Servers:      "223.5.5.5",
		Output:       out,
		Timeout:      4 * time.Second,
		Attempts:     1,
		WarmupDomain: "example.com",
		Formula:      string(config.FormulaComprehensive),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("配置无效: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	events := 0
	res, err := runEngine(ctx, cfg, func(scheduler.ProgressEvent) { events++ })
	if err != nil {
		t.Fatalf("runEngine 返回错误: %v", err)
	}
	if events == 0 {
		t.Error("runEngine 没有报告任何进度事件")
	}
	if res.Total == 0 || len(res.Summaries) == 0 {
		t.Fatalf("结果为空: total=%d summaries=%d", res.Total, len(res.Summaries))
	}
	if res.Path != out {
		t.Errorf("结果路径 = %q, 期望 %q", res.Path, out)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("结果文件未写入: %v", err)
	}

	// The rendered report must mention the query count, so the result screen
	// has something meaningful to show.
	report := ui.ResultView(res, config.FormulaComprehensive)
	if !strings.Contains(report, "查询总数") {
		t.Errorf("报告缺少统计行:\n%s", report)
	}
}

// TestRunEngineDefaultsOutput checks that a configuration without an output
// path still produces a file, which is what the menu relies on so a run is
// never lost.
func TestRunEngineDefaultsOutput(t *testing.T) {
	if os.Getenv("DNS_OPTI_NET_TESTS") != "1" {
		t.Skip("设置 DNS_OPTI_NET_TESTS=1 可运行联网集成测试")
	}

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := config.Options{
		Domains:      "baidu.com",
		Protocols:    []model.Protocol{model.ProtocolUDP},
		Servers:      "223.5.5.5",
		Timeout:      4 * time.Second,
		Attempts:     1,
		WarmupDomain: "example.com",
		Formula:      string(config.FormulaComprehensive),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := runEngine(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("runEngine 返回错误: %v", err)
	}
	if res.Path == "" {
		t.Fatal("未配置输出路径时没有生成默认文件")
	}
	// The interactive interface reports the path back to the user, so it must
	// be absolute and point at the working directory the program was started in.
	if !filepath.IsAbs(res.Path) {
		t.Errorf("默认输出 %q 不是绝对路径", res.Path)
	}
	if got := filepath.Dir(res.Path); got != dir {
		t.Errorf("默认输出目录 = %q, 期望 %q", got, dir)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Errorf("默认输出文件不存在: %v", err)
	}
}

// TestStartWebServesAndStops verifies the menu's "打开 Web 页面" action binds a
// loopback port, serves the payload over HTTP and shuts down again.
func TestStartWebServesAndStops(t *testing.T) {
	if os.Getenv("DNS_OPTI_NET_TESTS") != "1" {
		t.Skip("设置 DNS_OPTI_NET_TESTS=1 可运行联网集成测试")
	}

	hist := store.HistogramFromRecords([]model.RawRecord{
		{DNS: "223.5.5.5", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 12},
		{DNS: "223.5.5.5", Protocol: model.ProtocolUDP, Group: model.GroupCN, Success: true, LatencyMS: 30},
	})

	res := &engine.Result{
		Meta: model.Meta{Version: "1.0", Concurrency: 4, WarmupDomain: "example.com"},
		Summaries: []model.Summary{{
			DNS: "223.5.5.5", Name: "AliDNS", Protocol: model.ProtocolUDP,
			Group: model.GroupCN, Total: 2, Success: 2, SuccessRate: 1,
			AvgMS: 21, P95MS: 30, StdDevMS: 9,
		}},
		Histogram: hist,
		Path:      "result.json",
	}

	// The menu opens a browser on start; suppress that in the test.
	t.Setenv("BROWSER", "true")

	url, stop, err := startWeb(res)
	if err != nil {
		t.Fatalf("startWeb 返回错误: %v", err)
	}
	defer stop()

	// The viewer must only ever bind the loopback interface.
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("startWeb 返回的地址 = %q, 期望绑定 127.0.0.1", url)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	// The data endpoint must serve the payload we handed over.
	resp, err := client.Get(url + "/api/result")
	if err != nil {
		t.Fatalf("请求 %s/api/result 失败: %v", url, err)
	}
	body, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/result 状态码 = %d", resp.StatusCode)
	}
	if !strings.Contains(body, "223.5.5.5") {
		t.Errorf("/api/result 未包含服务器数据:\n%s", body)
	}
	// The histogram must travel with the payload so the distribution chart can
	// be drawn.
	if !strings.Contains(body, "histogram") {
		t.Errorf("/api/result 未包含延迟分布数据:\n%s", body)
	}
	// A non-loopback Host must be rejected.
	req, _ := http.NewRequest(http.MethodGet, url+"/api/result", nil)
	req.Host = "evil.example.com"
	bad, err := client.Do(req)
	if err == nil {
		// The transport normally rewrites Host; when it does not, the server
		// must still refuse.
		if bad.StatusCode != http.StatusForbidden {
			t.Errorf("非本机 Host 的请求状态码 = %d, 期望 403", bad.StatusCode)
		}
		bad.Body.Close()
	}

	// After stopping, the port must be closed.
	stop()
	if _, err := client.Get(url + "/api/result"); err == nil {
		t.Error("stop() 之后服务仍在响应")
	}
}

// readAllClose reads a response body and closes it.
func readAllClose(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			b.Write(buf[:n])
		}
		if err != nil {
			if err.Error() == "EOF" {
				return b.String(), nil
			}
			return b.String(), nil
		}
	}
}
