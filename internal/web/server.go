// Package web serves the local result viewer.
//
// The server binds to the loopback interface only and is meant to be opened
// from the machine that ran the test. It serves the embedded static assets,
// the result data and the scoring metadata; it offers nothing that would be
// meaningful to expose on a public interface (see PLAN 七).
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"dns-opti/internal/config"
	"dns-opti/internal/model"
	"dns-opti/internal/scorer"
)

//go:embed static
var staticFS embed.FS

// Options configures the local web server.
type Options struct {
	// Port is the loopback port; 0 selects a free one.
	Port int
	// Payload is the data to show. It may be empty, in which case the page
	// starts with the import panel.
	Payload *Payload
	// ResultPath is the file the payload came from, shown in the header.
	ResultPath string
	// OpenBrowser opens the default browser once the server is listening.
	OpenBrowser bool
	// Out receives the incidental status lines (the bound URL, the shutdown
	// notice). It defaults to stderr so that a scripted run with --json still
	// gets a clean JSON document on stdout.
	Out io.Writer
}

// out returns the writer for incidental status lines.
func (o Options) out() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return os.Stderr
}

// Server is the local result viewer.
type Server struct {
	opts Options
	http *http.Server
	addr string
}

// New creates the viewer.
func New(opts Options) *Server {
	return &Server{opts: opts}
}

// URL returns the address the viewer is reachable at. It is only valid after
// Listen has returned.
func (s *Server) URL() string { return "http://" + s.addr }

// Close shuts the server down. It is used by the interactive interface, which
// starts the viewer in the background rather than blocking on Serve.
func (s *Server) Close() {
	if s.http == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

// Listen binds the loopback listener and starts serving in the background. It
// returns once the socket is bound, so URL is immediately usable.
func (s *Server) Listen() (string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.opts.Port))
	if err != nil {
		return "", fmt.Errorf("无法监听本地端口: %w", err)
	}
	s.addr = ln.Addr().String()

	mux, err := s.routes()
	if err != nil {
		_ = ln.Close()
		return "", err
	}
	s.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		// Serve returns ErrServerClosed on a normal shutdown.
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(s.opts.out(), "本地预览服务已停止: %v\n", err)
		}
	}()

	if s.opts.OpenBrowser {
		go func() {
			// Give the listener a moment before the browser connects.
			time.Sleep(150 * time.Millisecond)
			_ = OpenBrowser(s.URL())
		}()
	}
	return s.URL(), nil
}

// Serve starts the server and blocks until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	url, err := s.Listen()
	if err != nil {
		return err
	}
	fmt.Fprintf(s.opts.out(), "本地预览已启动: %s\n", url)

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.http.Shutdown(shutdownCtx)
}

// routes builds the HTTP handler.
func (s *Server) routes() (http.Handler, error) {
	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("加载内置静态资源失败: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", noCache(http.FileServer(http.FS(static))))
	mux.HandleFunc("/api/result", s.handleResult)
	mux.HandleFunc("/api/formulas", s.handleFormulas)
	mux.HandleFunc("/api/import", s.handleImport)
	mux.HandleFunc("/api/export", s.handleExport)
	mux.HandleFunc("/api/rank", s.handleRank)
	return loopbackOnly(mux), nil
}

// handleResult returns the active dataset.
func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	out := Payload{Source: "empty", Label: "尚无数据"}
	if s.opts.Payload != nil {
		// Copy rather than mutate the shared payload: ResultPath belongs to the
		// response, and writing it into the stored dataset would race with a
		// concurrent request (and would leak the path into an export).
		out = *s.opts.Payload
	}
	out.ResultPath = s.opts.ResultPath
	// Finalize is idempotent and cheap, so the empty dataset gets its region
	// groups too — the filter then renders even before any data is loaded.
	writeJSON(w, http.StatusOK, out.Finalize())
}

// formulaDoc is the formula catalogue sent to the browser.
type formulaDoc struct {
	Active   config.Formula       `json:"active"`
	Formulas []scorer.FormulaInfo `json:"formulas"`
}

// handleFormulas returns the four scoring formulas and their descriptions, so
// the UI never hard-codes the ranking rules.
func (s *Server) handleFormulas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, formulaDoc{
		Active:   config.FormulaComprehensive,
		Formulas: scorer.Formulas,
	})
}

// handleImport accepts a result file of any supported dialect.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	// Bound the upload so a stray huge file cannot exhaust memory.
	r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
	data, err := readAll(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取上传内容失败: "+err.Error())
		return
	}
	payload, err := Import(data)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	payload.ResultPath = strings.TrimSpace(r.URL.Query().Get("name"))
	s.opts.Payload = payload
	writeJSON(w, http.StatusOK, payload)
}

// handleExport writes the active dataset back out as a native result document.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	payload := s.opts.Payload
	if payload == nil {
		writeErr(w, http.StatusNotFound, "尚无数据可导出")
		return
	}

	doc := model.File{Meta: payload.Meta, Raw: []model.RawRecord{}, Summary: payload.Summary}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "序列化失败: "+err.Error())
		return
	}

	name := "dns-opti_result.json"
	if payload.Meta.Timestamp.IsZero() {
		name = fmt.Sprintf("dns-opti_result_%s.json", time.Now().Format("2006-01-02-15-04-05"))
	} else {
		name = fmt.Sprintf("dns-opti_result_%s.json", payload.Meta.Timestamp.Local().Format("2006-01-02-15-04-05"))
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// rankResponse is the ranking produced for one formula and filter.
type rankResponse struct {
	Formula config.Formula `json:"formula"`
	Notice  string         `json:"notice"`
	Groups  []groupRanking `json:"groups"`
}

// groupRanking is the ranking of one domain group.
type groupRanking struct {
	Group string          `json:"group"`
	Label string          `json:"label"`
	Rows  []scorer.Ranked `json:"rows"`
}

// handleRank recomputes the ranking for a formula. The browser sends the
// dataset it currently holds, so imported data is ranked server-side with the
// exact same code path as a fresh run.
func (s *Server) handleRank(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req struct {
		Formula  config.Formula  `json:"formula"`
		Summary  []model.Summary `json:"summary"`
		Protocol string          `json:"protocol"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	formula, err := config.ParseFormula(string(req.Formula))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	rows := req.Summary
	if len(rows) == 0 && s.opts.Payload != nil {
		rows = s.opts.Payload.Summary
	}

	filter := scorer.Filter{}
	if p, ok := model.ParseProtocol(req.Protocol); ok {
		filter.Protocol = p
	}

	resp := rankResponse{
		Formula: formula,
		Notice:  "同一 DNS 在不同公式下排名可能变化，请结合使用场景选择公式。",
	}
	for _, group := range scorer.GroupKeys(rows) {
		f := filter
		f.Group = group
		ranked := scorer.Rank(rows, formula, f)
		if len(ranked) == 0 {
			continue
		}
		resp.Groups = append(resp.Groups, groupRanking{
			Group: group,
			Label: model.GroupLabel(group),
			Rows:  ranked,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// readAll reads the request body; the byte limit is installed by MaxBytesReader
// before this is called.
func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeErr writes an error as JSON.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// methodNotAllowed answers with 405 and the allowed method.
func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeErr(w, http.StatusMethodNotAllowed, "只支持 "+allowed+" 请求")
}

// noCache disables caching for the static assets, so a rebuilt page is always
// picked up when the tool is re-run.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// loopbackOnly rejects requests that did not originate from the loopback
// interface. The listener already binds 127.0.0.1; this is a second line of
// defence against a misconfigured proxy or a DNS-rebinding attempt.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch host {
		case "127.0.0.1", "localhost", "::1", "[::1]":
		default:
			writeErr(w, http.StatusForbidden, "该服务仅允许本机访问")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// OpenBrowser opens url in the system's default browser. Failures are not
// fatal: the URL is printed so the user can open it manually.
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
