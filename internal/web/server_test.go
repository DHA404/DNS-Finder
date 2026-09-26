package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dns-opti/internal/config"
	"dns-opti/internal/model"
	"dns-opti/internal/scorer"
)

// loopbackHost 是 loopbackOnly 中间件接受的 Host，测试请求必须显式设置。
const loopbackHost = "127.0.0.1"

// newTestServer 构建一个测试用的 Server 及其路由。
func newTestServer(t *testing.T, payload *Payload) (*Server, http.Handler) {
	t.Helper()
	s := New(Options{Payload: payload, ResultPath: "result.json"})
	h, err := s.routes()
	if err != nil {
		t.Fatalf("routes() 返回错误: %v", err)
	}
	return s, h
}

// do 发起一次请求并返回响应记录器；target 为相对路径。
func do(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doWithHost(t, h, method, target, body, loopbackHost)
}

// doWithHost 允许指定 Host，用于验证 loopbackOnly 的拒绝分支。
func doWithHost(t *testing.T, h http.Handler, method, target, body, host string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// decodeJSON 把响应体解析到 v。
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP 状态码 = %d, 期望 200；响应体: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("响应体不是合法 JSON: %v；内容: %s", err, rec.Body.String())
	}
}

// samplePayload 构造一份覆盖国内 / 国外两组、多种协议的测试数据。
func samplePayload() *Payload {
	return &Payload{
		Meta: model.Meta{
			Version:      "1.0",
			Timestamp:    time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC),
			Platform:     "windows/amd64",
			Concurrency:  4,
			WarmupDomain: "example.com",
			DomainGroups: []string{model.GroupCN, model.GroupIntl},
			Protocols:    []string{"udp", "doh"},
		},
		Summary: []model.Summary{
			{DNS: "223.5.5.5", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 12, P95MS: 20, StdDevMS: 3},
			{DNS: "119.29.29.29", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 9, SuccessRate: 0.9, AvgMS: 18, P95MS: 40, StdDevMS: 6},
			{DNS: "https://doh.pub/dns-query", Protocol: model.ProtocolDoH, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 25, P95MS: 30, StdDevMS: 2},
			{DNS: "8.8.8.8", Protocol: model.ProtocolUDP, Group: model.GroupIntl, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 15, P95MS: 35, StdDevMS: 8},
		},
		Source: "run",
		Label:  "本次测试结果",
	}
}

func TestHandleFormulasReturnsFour(t *testing.T) {
	_, h := newTestServer(t, nil)
	rec := do(t, h, http.MethodGet, "/api/formulas", "")

	var doc formulaDoc
	decodeJSON(t, rec, &doc)

	if len(doc.Formulas) != 4 {
		t.Fatalf("/api/formulas 返回 %d 个公式, 期望 4 个: %+v", len(doc.Formulas), doc.Formulas)
	}
	if doc.Active != config.FormulaComprehensive {
		t.Fatalf("active = %q, 期望默认公式 %q", doc.Active, config.FormulaComprehensive)
	}

	wantIDs := []config.Formula{
		config.FormulaSpeed, config.FormulaStable, config.FormulaComprehensive, config.FormulaJitter,
	}
	for i, want := range wantIDs {
		if doc.Formulas[i].ID != want {
			t.Fatalf("formulas[%d].ID = %q, 期望 %q", i, doc.Formulas[i].ID, want)
		}
		if doc.Formulas[i].Expr == "" || doc.Formulas[i].Name == "" {
			t.Fatalf("formulas[%d] 缺少展示信息: %+v", i, doc.Formulas[i])
		}
	}
}

func TestHandleFormulasMatchesScorerCatalogue(t *testing.T) {
	_, h := newTestServer(t, nil)
	rec := do(t, h, http.MethodGet, "/api/formulas", "")

	var doc formulaDoc
	decodeJSON(t, rec, &doc)
	if len(doc.Formulas) != len(scorer.Formulas) {
		t.Fatalf("返回 %d 个公式, 与 scorer.Formulas 的 %d 个不一致", len(doc.Formulas), len(scorer.Formulas))
	}
}

func TestHandleResultWithPayload(t *testing.T) {
	payload := samplePayload()
	s, h := newTestServer(t, payload)
	s.opts.ResultPath = "out/result.json"

	rec := do(t, h, http.MethodGet, "/api/result", "")
	var got Payload
	decodeJSON(t, rec, &got)

	if len(got.Summary) != len(payload.Summary) {
		t.Fatalf("返回 %d 行, 期望 %d 行", len(got.Summary), len(payload.Summary))
	}
	if got.Source != "run" {
		t.Fatalf("source = %q, 期望 run", got.Source)
	}
	if got.Label != "本次测试结果" {
		t.Fatalf("label = %q, 期望 本次测试结果", got.Label)
	}
	if got.ResultPath != "out/result.json" {
		t.Fatalf("result_path = %q, 期望 out/result.json", got.ResultPath)
	}
	if got.Meta.Platform != "windows/amd64" {
		t.Fatalf("meta.platform = %q, 期望 windows/amd64", got.Meta.Platform)
	}
}

func TestHandleResultWithoutPayload(t *testing.T) {
	_, h := newTestServer(t, nil)
	rec := do(t, h, http.MethodGet, "/api/result", "")

	var got Payload
	decodeJSON(t, rec, &got)

	if got.Source != "empty" {
		t.Fatalf("无数据时 source = %q, 期望 empty", got.Source)
	}
	if got.Label != "尚无数据" {
		t.Fatalf("无数据时 label = %q, 期望 尚无数据", got.Label)
	}
	if len(got.Summary) != 0 {
		t.Fatalf("无数据时返回了 %d 行汇总, 期望 0 行", len(got.Summary))
	}
}

func TestHandleImportValidNativeDocument(t *testing.T) {
	s, h := newTestServer(t, nil)
	rec := do(t, h, http.MethodPost, "/api/import?name=my-result.json", nativeDoc)

	var got Payload
	decodeJSON(t, rec, &got)
	if len(got.Summary) != 1 {
		t.Fatalf("导入后返回 %d 行, 期望 1 行: %+v", len(got.Summary), got.Summary)
	}
	if got.Source != "import" {
		t.Fatalf("source = %q, 期望 import", got.Source)
	}
	if got.ResultPath != "my-result.json" {
		t.Fatalf("result_path = %q, 期望 my-result.json", got.ResultPath)
	}
	// 导入成功后服务器必须持有这份数据，随后 /api/result 应返回它。
	if s.opts.Payload == nil {
		t.Fatal("导入后服务器未保存 Payload")
	}
	if s.opts.Payload.Summary[0].DNS != "223.5.5.5" {
		t.Fatalf("服务器保存的行 = %+v, 期望 223.5.5.5", s.opts.Payload.Summary[0])
	}

	rec = do(t, h, http.MethodGet, "/api/result", "")
	var after Payload
	decodeJSON(t, rec, &after)
	if len(after.Summary) != 1 {
		t.Fatalf("/api/result 之后返回 %d 行, 期望 1 行", len(after.Summary))
	}
}

func TestHandleImportGarbageReturns400(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "纯文本", body: "这不是 JSON"},
		{name: "被截断的 JSON", body: `{"meta": {`},
		{name: "空对象", body: `{}`},
		{name: "空请求体", body: ""},
		{name: "只有空白", body: "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, h := newTestServer(t, nil)
			rec := do(t, h, http.MethodPost, "/api/import", tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("状态码 = %d, 期望 400；响应体: %s", rec.Code, rec.Body.String())
			}
			var errBody map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
				t.Fatalf("400 响应不是合法 JSON: %v；内容: %s", err, rec.Body.String())
			}
			if errBody["error"] == "" {
				t.Fatalf("400 响应缺少 error 字段: %s", rec.Body.String())
			}
			// 失败的导入不得覆盖已有数据。
			if s.opts.Payload != nil {
				t.Fatalf("导入失败后服务器仍保存了 Payload: %+v", s.opts.Payload)
			}
		})
	}
}

func TestHandleExportSetsAttachmentAndValidJSON(t *testing.T) {
	payload := samplePayload()
	_, h := newTestServer(t, payload)

	rec := do(t, h, http.MethodGet, "/api/export", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200；响应体: %s", rec.Code, rec.Body.String())
	}

	disposition := rec.Header().Get("Content-Disposition")
	if !strings.HasPrefix(disposition, "attachment;") {
		t.Fatalf("Content-Disposition = %q, 期望以 attachment; 开头", disposition)
	}
	if !strings.Contains(disposition, "filename=") || !strings.Contains(disposition, ".json") {
		t.Fatalf("Content-Disposition = %q, 期望包含 .json 文件名", disposition)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, 期望 application/json", ct)
	}

	var file model.File
	if err := json.Unmarshal(rec.Body.Bytes(), &file); err != nil {
		t.Fatalf("导出内容不是合法 JSON: %v\n%s", err, rec.Body.String())
	}
	if len(file.Summary) != len(payload.Summary) {
		t.Fatalf("导出 summary 有 %d 条, 期望 %d 条", len(file.Summary), len(payload.Summary))
	}
	if file.Meta.Version != "1.0" {
		t.Fatalf("导出 meta.version = %q, 期望 1.0", file.Meta.Version)
	}
	// raw 必须是空数组而不是 null，便于前端直接遍历。
	if !strings.Contains(rec.Body.String(), `"raw": []`) {
		t.Fatalf("导出的 raw 不是空数组:\n%s", rec.Body.String())
	}
	// 导出内容必须能被 Import 重新读回。
	again, err := Import(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("导出的文档无法被 Import 读回: %v", err)
	}
	if len(again.Summary) != len(payload.Summary) {
		t.Fatalf("重新导入后 %d 行, 期望 %d 行", len(again.Summary), len(payload.Summary))
	}
}

func TestHandleExportFilenameFromTimestamp(t *testing.T) {
	payload := samplePayload()
	_, h := newTestServer(t, payload)
	rec := do(t, h, http.MethodGet, "/api/export", "")

	// meta.timestamp 为 2026-09-25T12:00:00Z，本地时区下文件名应含该时刻的格式化结果。
	want := payload.Meta.Timestamp.Local().Format("2006-01-02-15-04-05")
	disposition := rec.Header().Get("Content-Disposition")
	if !strings.Contains(disposition, want) {
		t.Fatalf("Content-Disposition = %q, 期望包含时间戳 %q", disposition, want)
	}
}

func TestHandleExportWithoutPayloadReturns404(t *testing.T) {
	_, h := newTestServer(t, nil)
	rec := do(t, h, http.MethodGet, "/api/export", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("无数据时导出状态码 = %d, 期望 404；响应体: %s", rec.Code, rec.Body.String())
	}
	var errBody map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("404 响应不是合法 JSON: %v", err)
	}
	if errBody["error"] == "" {
		t.Fatalf("404 响应缺少 error 字段: %s", rec.Body.String())
	}
}

func TestHandleRankWithFormulaAndSummary(t *testing.T) {
	_, h := newTestServer(t, nil)

	body := `{"formula":"comprehensive","summary":` + summaryJSON(t, samplePayload().Summary) + `}`
	rec := do(t, h, http.MethodPost, "/api/rank", body)

	var resp rankResponse
	decodeJSON(t, rec, &resp)

	if resp.Formula != config.FormulaComprehensive {
		t.Fatalf("formula = %q, 期望 %q", resp.Formula, config.FormulaComprehensive)
	}
	if resp.Notice == "" {
		t.Fatal("响应缺少 notice 提示")
	}
	if !strings.Contains(resp.Notice, "排名可能变化") {
		t.Fatalf("notice = %q, 期望提示同一 DNS 在不同公式下排名可能变化", resp.Notice)
	}
	if len(resp.Groups) != 2 {
		t.Fatalf("返回 %d 个分组, 期望 2 个（cn 与 intl）: %+v", len(resp.Groups), resp.Groups)
	}

	// 分组顺序必须规范：cn 在前，intl 在后。
	if resp.Groups[0].Group != model.GroupCN || resp.Groups[1].Group != model.GroupIntl {
		t.Fatalf("分组顺序 = %q, %q, 期望 cn, intl", resp.Groups[0].Group, resp.Groups[1].Group)
	}
	if resp.Groups[0].Label != "国内域名" || resp.Groups[1].Label != "国外域名" {
		t.Fatalf("分组标签 = %q, %q, 期望 国内域名, 国外域名", resp.Groups[0].Label, resp.Groups[1].Label)
	}
	if len(resp.Groups[0].Rows) != 3 {
		t.Fatalf("国内分组有 %d 行, 期望 3 行", len(resp.Groups[0].Rows))
	}
	if len(resp.Groups[1].Rows) != 1 {
		t.Fatalf("国外分组有 %d 行, 期望 1 行", len(resp.Groups[1].Rows))
	}

	// 名次必须是 1 起、连续，且按分数降序。
	for gi, g := range resp.Groups {
		for i, r := range g.Rows {
			if r.Rank != i+1 {
				t.Fatalf("groups[%d].rows[%d].Rank = %d, 期望 %d", gi, i, r.Rank, i+1)
			}
			if r.Group != g.Group {
				t.Fatalf("groups[%d].rows[%d].Group = %q, 期望 %q（分组不得混用）", gi, i, r.Group, g.Group)
			}
			if i > 0 && g.Rows[i-1].Score < r.Score {
				t.Fatalf("groups[%d] 未按分数降序: rows[%d].Score=%v, rows[%d].Score=%v",
					gi, i-1, g.Rows[i-1].Score, i, r.Score)
			}
		}
	}

	// 综合体验下国内最优是 223.5.5.5（1000/(6+10)=62.5）而不是 doh.pub（1000/(12.5+15)≈36.36）。
	if got := resp.Groups[0].Rows[0].DNS; got != "223.5.5.5" {
		t.Fatalf("国内分组第一名 = %q, 期望 223.5.5.5", got)
	}
}

func TestHandleRankFallsBackToStoredPayload(t *testing.T) {
	_, h := newTestServer(t, samplePayload())

	// 请求体不带 summary 时，服务器应使用自己持有的数据。
	rec := do(t, h, http.MethodPost, "/api/rank", `{"formula":"speed"}`)
	var resp rankResponse
	decodeJSON(t, rec, &resp)

	if resp.Formula != config.FormulaSpeed {
		t.Fatalf("formula = %q, 期望 %q", resp.Formula, config.FormulaSpeed)
	}
	if len(resp.Groups) != 2 {
		t.Fatalf("返回 %d 个分组, 期望 2 个", len(resp.Groups))
	}
}

func TestHandleRankProtocolFilter(t *testing.T) {
	_, h := newTestServer(t, nil)
	body := `{"formula":"speed","protocol":"udp","summary":` + summaryJSON(t, samplePayload().Summary) + `}`

	rec := do(t, h, http.MethodPost, "/api/rank", body)
	var resp rankResponse
	decodeJSON(t, rec, &resp)

	for gi, g := range resp.Groups {
		for i, r := range g.Rows {
			if r.Protocol != model.ProtocolUDP {
				t.Fatalf("groups[%d].rows[%d].Protocol = %q, 期望 udp（协议过滤未生效）", gi, i, r.Protocol)
			}
		}
	}
	// 国内只剩两条 UDP，国外剩一条。
	if len(resp.Groups) != 2 || len(resp.Groups[0].Rows) != 2 || len(resp.Groups[1].Rows) != 1 {
		t.Fatalf("UDP 过滤后的分组行数不符: %+v", resp.Groups)
	}
}

func TestHandleRankUnknownProtocolIsIgnored(t *testing.T) {
	// 未知协议名不构成错误，只是不施加协议过滤。
	_, h := newTestServer(t, nil)
	body := `{"formula":"speed","protocol":"quic","summary":` + summaryJSON(t, samplePayload().Summary) + `}`

	rec := do(t, h, http.MethodPost, "/api/rank", body)
	var resp rankResponse
	decodeJSON(t, rec, &resp)

	total := 0
	for _, g := range resp.Groups {
		total += len(g.Rows)
	}
	if total != 4 {
		t.Fatalf("未知协议过滤后共 %d 行, 期望 4 行（不做过滤）", total)
	}
}

func TestHandleRankUnknownFormulaReturns400(t *testing.T) {
	_, h := newTestServer(t, nil)
	rec := do(t, h, http.MethodPost, "/api/rank", `{"formula":"turbo","summary":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d, 期望 400；响应体: %s", rec.Code, rec.Body.String())
	}
	var errBody map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("400 响应不是合法 JSON: %v", err)
	}
	if errBody["error"] == "" {
		t.Fatalf("400 响应缺少 error 字段: %s", rec.Body.String())
	}
}

func TestHandleRankInvalidBodyReturns400(t *testing.T) {
	_, h := newTestServer(t, nil)
	rec := do(t, h, http.MethodPost, "/api/rank", `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d, 期望 400；响应体: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRankEmptySummaryYieldsNoGroups(t *testing.T) {
	_, h := newTestServer(t, nil)
	rec := do(t, h, http.MethodPost, "/api/rank", `{"formula":"speed","summary":[]}`)

	var resp rankResponse
	decodeJSON(t, rec, &resp)
	if len(resp.Groups) != 0 {
		t.Fatalf("空数据返回 %d 个分组, 期望 0 个: %+v", len(resp.Groups), resp.Groups)
	}
	// 空数据时 groups 必须是“空的”而不是被省略；前端 app.js 对 null 与 []
	// 一视同仁，因此这里只要求解码后为空切片。
	if !strings.Contains(rec.Body.String(), `"groups"`) {
		t.Fatalf("空数据的响应缺少 groups 字段: %s", rec.Body.String())
	}
}

func TestHandleRankFormulaChangesOrder(t *testing.T) {
	// 同一份数据在极速优先与综合体验下应给出不同排序：这正是该功能的卖点。
	rows := []model.Summary{
		{DNS: "fast.example", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 10, P95MS: 80, StdDevMS: 40},
		{DNS: "steady.example", Protocol: model.ProtocolUDP, Group: model.GroupCN, Total: 10, Success: 10, SuccessRate: 1, AvgMS: 20, P95MS: 22, StdDevMS: 2},
	}
	summary := summaryJSON(t, rows)
	_, h := newTestServer(t, nil)

	rec := do(t, h, http.MethodPost, "/api/rank", `{"formula":"speed","summary":`+summary+`}`)
	var speed rankResponse
	decodeJSON(t, rec, &speed)

	rec = do(t, h, http.MethodPost, "/api/rank", `{"formula":"comprehensive","summary":`+summary+`}`)
	var comprehensive rankResponse
	decodeJSON(t, rec, &comprehensive)

	if len(speed.Groups) != 1 || len(comprehensive.Groups) != 1 {
		t.Fatalf("分组数异常: speed=%d comprehensive=%d", len(speed.Groups), len(comprehensive.Groups))
	}
	if speed.Groups[0].Rows[0].DNS != "fast.example" {
		t.Fatalf("极速优先第一名 = %q, 期望 fast.example", speed.Groups[0].Rows[0].DNS)
	}
	if comprehensive.Groups[0].Rows[0].DNS != "steady.example" {
		t.Fatalf("综合体验第一名 = %q, 期望 steady.example", comprehensive.Groups[0].Rows[0].DNS)
	}
}

func TestHandlersRejectWrongMethod(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        string
		wantAllowed string
	}{
		{name: "result 只接受 GET", method: http.MethodPost, path: "/api/result", wantAllowed: http.MethodGet},
		{name: "formulas 只接受 GET", method: http.MethodPost, path: "/api/formulas", wantAllowed: http.MethodGet},
		{name: "import 只接受 POST", method: http.MethodGet, path: "/api/import", wantAllowed: http.MethodPost},
		{name: "export 只接受 GET", method: http.MethodPost, path: "/api/export", wantAllowed: http.MethodGet},
		{name: "rank 只接受 POST", method: http.MethodGet, path: "/api/rank", wantAllowed: http.MethodPost},
		{name: "DELETE 同样被拒绝", method: http.MethodDelete, path: "/api/formulas", wantAllowed: http.MethodGet},
		{name: "PUT 同样被拒绝", method: http.MethodPut, path: "/api/rank", wantAllowed: http.MethodPost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, h := newTestServer(t, samplePayload())
			rec := do(t, h, tt.method, tt.path, "")

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s 状态码 = %d, 期望 405；响应体: %s", tt.method, tt.path, rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Allow"); got != tt.wantAllowed {
				t.Fatalf("%s %s 的 Allow 头 = %q, 期望 %q", tt.method, tt.path, got, tt.wantAllowed)
			}
			var errBody map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
				t.Fatalf("405 响应不是合法 JSON: %v", err)
			}
			if errBody["error"] == "" {
				t.Fatalf("405 响应缺少 error 字段: %s", rec.Body.String())
			}
		})
	}
}

func TestLoopbackOnlyAcceptsLoopbackHosts(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{name: "127.0.0.1", host: "127.0.0.1"},
		{name: "127.0.0.1 带端口", host: "127.0.0.1:43120"},
		{name: "localhost", host: "localhost"},
		{name: "localhost 带端口", host: "localhost:8080"},
		{name: "IPv6 回环", host: "::1"},
		{name: "方括号 IPv6 回环", host: "[::1]"},
		{name: "方括号 IPv6 回环带端口", host: "[::1]:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, h := newTestServer(t, nil)
			rec := doWithHost(t, h, http.MethodGet, "/api/formulas", "", tt.host)
			if rec.Code != http.StatusOK {
				t.Fatalf("Host=%q 时状态码 = %d, 期望 200；响应体: %s", tt.host, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestLoopbackOnlyRejectsNonLoopbackHost(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{name: "外部域名", host: "evil.example.com"},
		{name: "外部域名带端口", host: "evil.example.com:80"},
		{name: "局域网地址", host: "192.168.1.10"},
		{name: "IPv6 非回环", host: "[2606:4700:4700::1111]:80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, h := newTestServer(t, samplePayload())
			rec := doWithHost(t, h, http.MethodGet, "/api/formulas", "", tt.host)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("Host=%q 时状态码 = %d, 期望 403；响应体: %s", tt.host, rec.Code, rec.Body.String())
			}
			var errBody map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
				t.Fatalf("403 响应不是合法 JSON: %v", err)
			}
			if !strings.Contains(errBody["error"], "本机") {
				t.Fatalf("403 的错误信息 = %q, 期望说明仅允许本机访问", errBody["error"])
			}
		})
	}
}

func TestLoopbackOnlyAppliesToAllRoutes(t *testing.T) {
	// 静态资源与 API 都必须经过同一层校验。
	for _, path := range []string{"/", "/index.html", "/api/result", "/api/formulas"} {
		t.Run(path, func(t *testing.T) {
			_, h := newTestServer(t, samplePayload())
			rec := doWithHost(t, h, http.MethodGet, path, "", "evil.example.com")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s 在非回环 Host 下状态码 = %d, 期望 403", path, rec.Code)
			}
		})
	}
}

func TestStaticAssetsAreServedWithNoCache(t *testing.T) {
	_, h := newTestServer(t, nil)

	// http.FileServer 会把 /index.html 规范化为 /，因此用根路径取首页。
	rec := do(t, h, http.MethodGet, "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/ 状态码 = %d, 期望 200；响应体: %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("静态资源的 Cache-Control = %q, 期望 no-store", cc)
	}
	if !strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("/ 未返回 HTML 内容: %.200s", rec.Body.String())
	}

	// /index.html 是 301 到 / 的规范重定向，仍必须带上 no-store。
	rec = do(t, h, http.MethodGet, "/index.html", "")
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("/index.html 状态码 = %d, 期望 301（FileServer 的规范重定向）", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "./" && loc != "/" {
		t.Fatalf("/index.html 的 Location = %q, 期望 ./ 或 /", loc)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("重定向响应的 Cache-Control = %q, 期望 no-store", cc)
	}
}

func TestJSONResponsesDisableHTMLEscape(t *testing.T) {
	// writeJSON 关闭了 HTML 转义，中文提示必须原样出现在响应里。
	_, h := newTestServer(t, nil)
	rec := do(t, h, http.MethodGet, "/api/result", "")
	if !strings.Contains(rec.Body.String(), "尚无数据") {
		t.Fatalf("响应中未出现未转义的中文提示: %s", rec.Body.String())
	}
}

func TestMethodNotAllowedHelper(t *testing.T) {
	rec := httptest.NewRecorder()
	methodNotAllowed(rec, http.MethodGet)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("状态码 = %d, 期望 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow = %q, 期望 %q", got, http.MethodGet)
	}
}

func TestWriteErrHelper(t *testing.T) {
	rec := httptest.NewRecorder()
	writeErr(rec, http.StatusBadRequest, "出错了")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d, 期望 400", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if body["error"] != "出错了" {
		t.Fatalf("error = %q, 期望 出错了", body["error"])
	}
}

// summaryJSON 把汇总行序列化为 JSON 字面量，供 /api/rank 请求体使用。
func summaryJSON(t *testing.T, rows []model.Summary) string {
	t.Helper()
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("序列化 summary 失败: %v", err)
	}
	return string(data)
}
