// Package settings persists the interactive UI's configuration next to the
// executable and reads it back on startup.
//
// The file deliberately lives in the same directory as the binary instead of in
// a per-user configuration directory (os.UserConfigDir, %APPDATA%, ~/.config):
// this tool is a single binary that people download, double-click and carry
// around in a folder or on a USB stick. A per-user directory would put the
// configuration somewhere else than the thing it configures — surprising for a
// portable tool, hard to find when it has to be inspected, edited or deleted,
// and it would not travel with the binary onto the next machine.
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// FileName is the fixed name of the settings file created next to the binary.
const FileName = "dns-opti.settings.json"

// settingsPerm is the mode a freshly created settings file gets. It is fixed
// rather than configurable because the file only holds UI preferences; note
// that on Windows the mode bits are a synthetic view of the read-only
// attribute, so this value is what Save passes to os.Chmod, not something
// os.Stat will necessarily echo back on that platform.
const settingsPerm os.FileMode = 0o644

// tempPattern is the name pattern of the temporary file an atomic save writes
// before renaming it onto the destination. The leading dot keeps it from being
// mistaken for a user file if a crash lands between the write and the rename.
const tempPattern = ".dns-opti-settings-*.tmp"

// writeProbePattern is the name pattern of the throwaway file used to find out
// whether a directory accepts new files.
const writeProbePattern = ".dns-opti-writecheck-*"

// executablePath resolves the path of the running binary.
//
// This is a package-level variable for one reason only: tests must be able to
// point Dir at a temporary directory, because a test that resolves the real
// executable directory would overwrite the settings file of whoever runs the
// test suite. Production code never reassigns it.
var executablePath = os.Executable

// Settings is the persisted configuration. It mirrors the subset of
// config.Options that the interactive menu edits.
//
// The protocol and region lists are plain strings rather than model.Protocol
// values so that the file stays readable and hand-editable without this
// package depending on the rest of the program.
type Settings struct {
	// Domains is a group keyword (cn|intl|all) or an explicit domain list.
	Domains string `json:"domains,omitempty"`
	// Protocols is the tested transports, in priority order.
	Protocols []string `json:"protocols,omitempty"`
	// Combo is the combined-mode selector (such as "udp+doh"), empty when the
	// selection is an ordinary protocol list.
	Combo string `json:"combo,omitempty"`
	// Regions restricts the built-in server list to ISO 3166-1 alpha-2 codes
	// (or CDN / PRIVATE / UNKNOWN). Empty means no filter.
	Regions []string `json:"regions,omitempty"`
	// Policies restricts the built-in server list by filtering behaviour
	// (native / security / adblock). Empty means no filter.
	Policies []string `json:"policies,omitempty"`
	// IPVersion restricts testing to one address family.
	IPVersion string `json:"ip_version,omitempty"`
	// ServerClass restricts the server list to 国内 / 国外 entries.
	ServerClass string `json:"server_class,omitempty"`
	// TimeoutMS bounds a single query, in milliseconds.
	TimeoutMS int `json:"timeout_ms,omitempty"`
	// Attempts is how many times each domain is queried on each server.
	Attempts int `json:"attempts,omitempty"`
	// Concurrency is how many servers are tested at the same time; 0 means
	// "resolve automatically".
	Concurrency int `json:"concurrency,omitempty"`
	// SystemDNS adds the machine's own resolvers to the comparison.
	//
	// It is a pointer so that "the user never touched this" is distinguishable
	// from "the user turned it off": a plain bool would make the zero value
	// false and both states would persist identically, which would silently
	// override a default of true. The same reasoning applies to OpenBrowser.
	// A non-nil pointer to false is written out as false, while a nil pointer
	// is omitted from the file entirely.
	SystemDNS *bool `json:"system_dns,omitempty"`
	// Formula selects the ranking formula used by the report.
	Formula string `json:"formula,omitempty"`
	// WarmupDomain is queried once per server before measurement starts.
	WarmupDomain string `json:"warmup_domain,omitempty"`
	// OpenBrowser controls whether the web UI opens a browser. Pointer for the
	// same unset-versus-false reason as SystemDNS.
	OpenBrowser *bool `json:"open_browser,omitempty"`
}

// Dir returns the directory the settings file lives in: the directory of the
// running executable when that can be determined and written to, otherwise the
// working directory, and finally "." so that callers always get a usable path.
func Dir() string {
	if dir := executableDir(); dir != "" && isWritableDir(dir) {
		return dir
	}
	if wd, err := os.Getwd(); err == nil && wd != "" {
		return wd
	}
	return "."
}

// Path returns the full path of the settings file.
func Path() string { return filepath.Join(Dir(), FileName) }

// Load reads the settings file next to the executable.
//
// A missing file is the normal first run rather than a failure: it returns a
// zero Settings with ok=false and a nil error, so the caller can quietly keep
// its built-in defaults. A file that exists but cannot be parsed returns a
// non-nil error alongside the same zero value, so the caller can warn that the
// saved preferences were ignored without having to abort the run.
//
// Load never creates or repairs the file — reading is strictly read-only, and
// writing is Save's job — so an empty first run leaves no trace behind.
func Load() (Settings, bool, error) { return LoadFrom(Path()) }

// LoadFrom reads the settings file at an explicit path, for tests and for
// callers that need a specific location.
func LoadFrom(path string) (Settings, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Settings{}, false, nil
		}
		return Settings{}, false, fmt.Errorf("读取设置文件 %s 失败: %w", path, err)
	}

	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{}, false, fmt.Errorf("解析设置文件 %s 失败: %w", path, err)
	}
	return s, true, nil
}

// Save writes the settings atomically to the file next to the executable.
func Save(s Settings) error { return SaveTo(Path(), s) }

// SaveTo writes the settings atomically to an explicit path.
//
// "Atomically" means the destination is replaced by a rename of a completely
// written temporary file that lives in the *same* directory as the destination:
// a rename inside one directory is atomic, so a crash or a power loss leaves
// either the previous file or the new one, never a truncated half-written
// settings file. A temporary file in the OS temp directory would not do, since
// that directory is usually on another volume, where the rename degrades into a
// copy plus a delete and the file is briefly incomplete.
//
// The containing directory must already exist and is never created, so an
// explicit path with a typo is reported instead of silently materialising a
// directory tree next to the binary.
func SaveTo(path string, s Settings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化设置失败: %w", err)
	}
	// MarshalIndent produces no trailing newline; adding one keeps the file a
	// well-formed text file that editors and diff tools round-trip cleanly.
	data = append(data, '\n')

	// An existing file keeps its mode: if the user tightened it, silently
	// loosening it back to settingsPerm would be a surprise.
	perm := settingsPerm
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}

	f, err := os.CreateTemp(filepath.Dir(path), tempPattern)
	if err != nil {
		return fmt.Errorf("创建设置临时文件失败: %w", err)
	}
	tmp := f.Name()
	// Every failure path below must leave the directory exactly as it was, so
	// the cleanup lives here rather than in each branch. After a successful
	// rename the temporary name no longer exists and this removal is a no-op.
	defer os.Remove(tmp)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("写入设置临时文件失败: %w", err)
	}
	// Flush to the disk before the rename: without it a crash could leave the
	// new name pointing at a file whose contents never made it out of the page
	// cache.
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("同步设置临时文件失败: %w", err)
	}
	// The file must be closed before the rename, because Windows refuses to
	// rename a file that is still open.
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭设置临时文件失败: %w", err)
	}
	// Set the mode before the rename so the destination is never visible with
	// the wrong permissions, not even for an instant.
	if err := os.Chmod(tmp, perm); err != nil {
		return fmt.Errorf("修改设置文件权限失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换设置文件失败: %w", err)
	}
	return nil
}

// executableDir resolves the directory holding the running binary, or "" when
// that cannot be determined at all.
func executableDir() string {
	exe, err := executablePath()
	if err != nil || exe == "" {
		return ""
	}
	// A binary is often reached through a symlink: a shim in /usr/local/bin, or
	// a link inside a portable folder. Resolving it keeps the settings file
	// next to the real binary, so the link and its target share one
	// configuration instead of each growing its own. A path that cannot be
	// resolved — a broken link, a platform without symlink support — is used as
	// it is rather than thrown away.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	return filepath.Dir(exe)
}

// isWritableDir reports whether dir exists and accepts a new file.
//
// Trying it is the only portable answer the standard library offers: the
// permission bits cannot be trusted for this, because on Windows they are a
// synthetic view of the read-only attribute rather than the ACL that actually
// decides (an install directory under Program Files reports itself writable),
// and on Unix they say nothing about read-only mounts. The probe file is
// created and removed immediately, and its name is dotted so that even a crash
// between the two leaves something clearly not a user file.
func isWritableDir(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}

	probe, err := os.CreateTemp(dir, writeProbePattern)
	if err != nil {
		return false
	}
	name := probe.Name()
	// Close before removing: Windows will not delete a file that is still open.
	_ = probe.Close()
	_ = os.Remove(name)
	return true
}
