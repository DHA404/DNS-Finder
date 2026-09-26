package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dns-opti/internal/model"
)

// ExportOptions controls how a result document is written.
type ExportOptions struct {
	// Path is the destination file. Empty selects a timestamped name in the
	// current directory.
	Path string
	// Indent pretty-prints the document. Raw records are indented too, but
	// they are streamed through rather than buffered.
	Indent bool
}

// Export writes meta, raw and summary to a single JSON file. The raw records
// are streamed straight out of the temporary JSON Lines file, so exporting
// never materialises the whole run in memory.
func (r *Recorder) Export(meta model.Meta, opts ExportOptions) (string, error) {
	if err := r.Flush(); err != nil {
		return "", err
	}

	path := opts.Path
	if strings.TrimSpace(path) == "" {
		path = DefaultOutputName("")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("创建输出目录失败: %w", err)
		}
	}

	out, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer out.Close()

	w := bufio.NewWriterSize(out, 128*1024)
	if err := writeDocument(w, r, meta, opts.Indent); err != nil {
		return "", err
	}
	if err := w.Flush(); err != nil {
		return "", fmt.Errorf("写入输出文件失败: %w", err)
	}
	if err := out.Sync(); err != nil {
		return "", fmt.Errorf("同步输出文件失败: %w", err)
	}
	return path, nil
}

// writeDocument renders the result document as
//
//	{ "meta": {...}, "raw": [ ... ], "summary": [ ... ] }
//
// with the raw array streamed straight out of the JSON Lines file.
func writeDocument(w io.Writer, r *Recorder, meta model.Meta, indent bool) error {
	// Top-level keys sit one level inside the outer braces.
	keyPrefix := ""
	childLevel := 0
	if indent {
		keyPrefix = "  "
		childLevel = 1
	}

	metaJSON, err := marshal(meta, indent, childLevel)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "{%s%s\"meta\": %s,", nl(indent), keyPrefix, metaJSON); err != nil {
		return err
	}

	summary := r.Summaries()
	summaryJSON, err := marshal(summary, indent, childLevel)
	if err != nil {
		return err
	}

	// raw
	if _, err := fmt.Fprintf(w, "%s%s\"raw\": [", nl(indent), keyPrefix); err != nil {
		return err
	}
	if err := streamRaw(w, r.tempPath, indent); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s%s],", nl(indent), keyPrefix); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "%s%s\"summary\": %s%s}%s", nl(indent), keyPrefix, summaryJSON, nl(indent), nl(indent)); err != nil {
		return err
	}
	return nil
}

// streamRaw copies the JSON Lines records into a JSON array, one record per
// line, without ever holding more than one line in memory.
func streamRaw(w io.Writer, path string, indent bool) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("读取原始记录失败: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	first := true
	prefix := ""
	if indent {
		prefix = "    "
	}
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		first = false
		if _, err := fmt.Fprintf(w, "%s%s%s", nl(indent), prefix, line); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取原始记录失败: %w", err)
	}
	return nil
}

// marshal encodes v, optionally with two-space indentation. level is how many
// indentation levels the value's first line is already nested at, so that the
// closing brace lines up with the key that introduced it.
func marshal(v any, indent bool, level int) (string, error) {
	var (
		data []byte
		err  error
	)
	if indent {
		data, err = json.MarshalIndent(v, strings.Repeat("  ", level), "  ")
	} else {
		data, err = json.Marshal(v)
	}
	if err != nil {
		return "", fmt.Errorf("序列化失败: %w", err)
	}
	return string(data), nil
}

// nl returns a newline when pretty-printing is enabled.
func nl(indent bool) string {
	if indent {
		return "\n"
	}
	return ""
}

// timeStamp formats the current time for default file names.
func timeStamp() string { return time.Now().Format("2006-01-02-15-04-05") }
