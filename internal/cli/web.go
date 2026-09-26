package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"dns-opti/internal/engine"
	"dns-opti/internal/web"
)

// runWeb executes the "web" command.
func runWeb(cmd *cobra.Command, o webOptions) error {
	out := cmd.OutOrStdout()

	// Incidental status goes to stderr; the URL is printed there too, and the
	// command's own narrative goes to stdout.
	opts := web.Options{Port: o.port, OpenBrowser: !o.noOpen, Out: cmd.ErrOrStderr()}
	label := "尚未载入数据（可在页面上导入结果 JSON）"

	if strings.TrimSpace(o.result) != "" {
		data, err := os.ReadFile(o.result)
		if err != nil {
			return fmt.Errorf("读取结果文件失败: %w", err)
		}
		payload, err := web.Import(data)
		if err != nil {
			return fmt.Errorf("解析结果文件失败: %w", err)
		}
		opts.Payload = payload
		opts.ResultPath = o.result
		label = payload.Label
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(out, "加载数据: %s\n", label)
	if opts.Payload != nil {
		fmt.Fprintf(out, "记录数: %d\n", len(opts.Payload.Summary))
	}
	return serveWeb(ctx, opts)
}

// serveWeb starts the local viewer and blocks until the context is cancelled.
func serveWeb(ctx context.Context, opts web.Options) error {
	srv := web.New(opts)
	if err := srv.Serve(ctx); err != nil {
		return err
	}
	fmt.Fprintln(opts.Out, "\n本地预览已关闭。")
	return nil
}

// payloadFromResult converts a finished run into the viewer's payload.
func payloadFromResult(res *engine.Result) *web.Payload {
	hist := res.Histogram
	return (&web.Payload{
		Meta:        res.Meta,
		Summary:     res.Summaries,
		Source:      "run",
		Label:       "本次测试结果",
		Histogram:   &hist,
		Comparisons: res.Comparisons,
	}).Finalize()
}
