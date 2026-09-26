package settings

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// boolPtr 返回布尔值的指针，用来在表驱动用例里构造 Settings 的指针字段。
func boolPtr(v bool) *bool { return &v }

// stubExecutable 把 executablePath 换成固定路径，并在用例结束时恢复。
//
// 每个调用 Dir/Path/Load/Save 的用例都必须先调用它：否则这些函数会解析出
// 真实可执行文件所在目录，测试就会覆盖运行测试那个人的真实设置文件。
func stubExecutable(t *testing.T, path string, err error) {
	t.Helper()
	original := executablePath
	executablePath = func() (string, error) { return path, err }
	t.Cleanup(func() { executablePath = original })
}

// useTempExeDir 把可执行文件"放"到临时目录里，返回该临时目录（已解析符号链接）。
//
// 这里必须创建一个**真实存在的文件**，而不是只把 executablePath 指向一个假路径：
// Dir() 会对可执行文件调用 filepath.EvalSymlinks，只有路径真实存在时解析才会成功。
// 用一个不存在的路径做桩，Dir() 会走"解析失败则退回原路径"的分支，于是返回未解析
// 的目录，而用例却拿解析后的目录去比对——本机临时目录里没有符号链接时两者恰好相同，
// 一到 CI 就暴露：macOS 的 /var 是指向 /private/var 的符号链接，Windows 的
// 8.3 短名（RUNNER~1）也会被解析成真实用户名。
//
// 返回值同样取解析后的路径，这样所有调用方都能与 Dir()/Path() 的真实产物直接比较。
func useTempExeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "dns-opti.exe")
	// 内容无关紧要：这里只需要它在文件系统上真实存在。
	if err := os.WriteFile(exe, []byte("stub"), 0o644); err != nil {
		t.Fatalf("创建占位可执行文件失败: %v", err)
	}
	stubExecutable(t, exe, nil)

	// 与 Dir() 保持一致地解析符号链接，使比较基准就是生产代码会返回的目录。
	if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != "" {
		return resolved
	}
	return dir
}

// fullSettings 返回一份所有字段都非零的设置，用来做往返测试。
func fullSettings() Settings {
	return Settings{
		Domains:      "cn",
		Protocols:    []string{"udp", "doh"},
		Combo:        "udp+doh",
		Regions:      []string{"CN", "HK"},
		IPVersion:    "ipv4",
		ServerClass:  "cn",
		TimeoutMS:    2500,
		Attempts:     5,
		Concurrency:  16,
		SystemDNS:    boolPtr(true),
		Formula:      "stable",
		WarmupDomain: "example.com",
		OpenBrowser:  boolPtr(false),
	}
}

// diffSettings 比较两份设置，相同时返回空字符串，否则返回第一处差异的中文描述。
func diffSettings(got, want Settings) string {
	switch {
	case got.Domains != want.Domains:
		return "Domains"
	case got.Combo != want.Combo:
		return "Combo"
	case got.IPVersion != want.IPVersion:
		return "IPVersion"
	case got.ServerClass != want.ServerClass:
		return "ServerClass"
	case got.TimeoutMS != want.TimeoutMS:
		return "TimeoutMS"
	case got.Attempts != want.Attempts:
		return "Attempts"
	case got.Concurrency != want.Concurrency:
		return "Concurrency"
	case got.Formula != want.Formula:
		return "Formula"
	case got.WarmupDomain != want.WarmupDomain:
		return "WarmupDomain"
	}
	if d := diffStrings("Protocols", got.Protocols, want.Protocols); d != "" {
		return d
	}
	if d := diffStrings("Regions", got.Regions, want.Regions); d != "" {
		return d
	}
	if d := diffBools("SystemDNS", got.SystemDNS, want.SystemDNS); d != "" {
		return d
	}
	return diffBools("OpenBrowser", got.OpenBrowser, want.OpenBrowser)
}

// diffStrings 比较两个字符串切片。
func diffStrings(field string, got, want []string) string {
	if (got == nil) != (want == nil) {
		return field + " 的 nil 状态"
	}
	if len(got) != len(want) {
		return field + " 的长度"
	}
	for i := range got {
		if got[i] != want[i] {
			return field
		}
	}
	return ""
}

// diffBools 比较两个指针布尔值，nil 与 false 必须区分开。
func diffBools(field string, got, want *bool) string {
	if (got == nil) != (want == nil) {
		return field + " 的 nil 状态"
	}
	if got != nil && *got != *want {
		return field
	}
	return ""
}

// isZeroSettings 报告 s 是否为零值。
//
// Settings 含有切片与指针字段，因此不能用 == 直接比较，只能逐字段判断。
func isZeroSettings(s Settings) bool { return diffSettings(s, Settings{}) == "" }

// stubExeName 是 useTempExeDir 放进临时目录的占位可执行文件名。
//
// 它必须是一个真实存在的文件（见 useTempExeDir 的说明），因此它也是这些目录里
// 唯一一个"与设置无关、但理应存在"的条目。"没有残留文件"的断言要按名字精确地
// 忽略它，而不是放宽成"只要没有 .tmp 就行"——后者会让真正的残留物漏过去。
const stubExeName = "dns-opti.exe"

// onlyFiles 返回目录里与设置相关的所有条目名，用来断言没有残留的临时文件。
//
// 占位可执行文件被排除在外：它是测试夹具的一部分，不是 Save 留下的东西。
func onlyFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录 %s 失败: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name() == stubExeName {
			continue
		}
		names = append(names, e.Name())
	}
	return names
}

// assertCleanDir 断言目录里只剩期望的条目，没有残留的临时文件。
//
// 比较的是忽略占位可执行文件后的名单，因此 want 只需列出设置相关文件。
func assertCleanDir(t *testing.T, dir string, want ...string) {
	t.Helper()
	got := onlyFiles(t, dir)
	if len(got) != len(want) {
		t.Fatalf("目录 %s 的内容 = %v, 期望 %v（不应留下临时文件）", dir, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("目录 %s 的内容 = %v, 期望 %v", dir, got, want)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Settings
	}{
		{name: "所有字段都非零", in: fullSettings()},
		{
			name: "指针布尔为 false 时不被当作未设置",
			in:   Settings{Domains: "all", SystemDNS: boolPtr(false), OpenBrowser: boolPtr(false)},
		},
		{
			name: "零值设置可以正常往返",
			in:   Settings{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := useTempExeDir(t)

			if err := Save(tt.in); err != nil {
				t.Fatalf("Save() 失败: %v", err)
			}
			got, ok, err := Load()
			if err != nil {
				t.Fatalf("Load() 失败: %v", err)
			}
			if !ok {
				t.Fatal("Load() 返回 ok=false, 期望 true（刚保存过的文件应当存在）")
			}
			if d := diffSettings(got, tt.in); d != "" {
				t.Fatalf("往返后 %s 不一致: got=%+v want=%+v", d, got, tt.in)
			}

			// 保存必须写在可执行文件所在目录，而不是当前工作目录。
			assertCleanDir(t, dir, FileName)
		})
	}
}

func TestPointerBoolsDistinguishUnsetFromFalse(t *testing.T) {
	dir := useTempExeDir(t)

	// 只有显式设置为 false 的指针才会写进文件；nil 表示"用户没碰过"，
	// 必须整个键都省略，否则读回来就成了"用户明确关掉了"。
	if err := Save(Settings{Domains: "cn", SystemDNS: boolPtr(false)}); err != nil {
		t.Fatalf("Save() 失败: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("读取设置文件失败: %v", err)
	}
	if !bytes.Contains(data, []byte(`"system_dns": false`)) {
		t.Fatalf("文件内容 = %s, 期望含有 \"system_dns\": false", data)
	}
	if bytes.Contains(data, []byte("open_browser")) {
		t.Fatalf("文件内容 = %s, nil 指针的 open_browser 不应被写入", data)
	}

	got, ok, err := Load()
	if err != nil {
		t.Fatalf("Load() 失败: %v", err)
	}
	if !ok {
		t.Fatal("Load() 返回 ok=false, 期望 true")
	}
	if got.SystemDNS == nil {
		t.Fatal("SystemDNS 读回来是 nil, 期望指向 false（未设置与 false 必须可区分）")
	}
	if *got.SystemDNS {
		t.Fatal("SystemDNS 读回来是 true, 期望 false")
	}
	if got.OpenBrowser != nil {
		t.Fatalf("OpenBrowser 读回来是 %v, 期望 nil", *got.OpenBrowser)
	}

	// 没有任何指针字段时，两个键都必须缺席。
	if err := Save(Settings{Domains: "cn"}); err != nil {
		t.Fatalf("Save() 失败: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("读取设置文件失败: %v", err)
	}
	if bytes.Contains(data, []byte("system_dns")) || bytes.Contains(data, []byte("open_browser")) {
		t.Fatalf("文件内容 = %s, nil 指针字段不应出现", data)
	}
}

func TestLoadMissingFile(t *testing.T) {
	dir := useTempExeDir(t)

	// 首次运行时文件不存在是正常情况，不是错误。
	if err := os.Remove(filepath.Join(dir, FileName)); err != nil && !os.IsNotExist(err) {
		t.Fatalf("清理设置文件失败: %v", err)
	}

	got, ok, err := Load()
	if err != nil {
		t.Fatalf("Load() 文件不存在时返回错误: %v", err)
	}
	if ok {
		t.Fatal("Load() 文件不存在时返回 ok=true, 期望 false")
	}
	if !isZeroSettings(got) {
		t.Fatalf("Load() 文件不存在时返回 %+v, 期望零值", got)
	}
	// 读取绝不能顺手把文件创建出来。
	if _, statErr := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(statErr) {
		t.Fatal("Load() 不应创建设置文件（读取必须是无副作用的）")
	}
	assertCleanDir(t, dir)
}

func TestLoadCorruptFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "被截断的 JSON", content: `{"domains": "cn", "protocol`},
		{name: "不是 JSON", content: "这不是 JSON\n"},
		{name: "空文件", content: ""},
		{name: "类型不匹配", content: `{"attempts": "three"}`},
		{name: "只有半个括号", content: "{"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("写入损坏的设置文件失败: %v", err)
			}

			got, ok, err := LoadFrom(path)
			if err == nil {
				t.Fatalf("LoadFrom() 解析损坏文件返回 nil 错误, 期望报错（内容 %q）", tt.content)
			}
			if ok {
				t.Fatalf("LoadFrom() 解析失败时返回 ok=true, 期望 false（内容 %q）", tt.content)
			}
			if !isZeroSettings(got) {
				t.Fatalf("LoadFrom() 解析失败时返回 %+v, 期望零值", got)
			}
		})
	}
}

func TestLoadFromAndSaveToExplicitPath(t *testing.T) {
	// 显式路径与可执行文件目录无关，这里甚至不需要注入 seam。
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-name.json")

	want := fullSettings()
	if err := SaveTo(path, want); err != nil {
		t.Fatalf("SaveTo() 失败: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("SaveTo() 未在 %s 创建文件: %v", path, err)
	}

	got, ok, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() 失败: %v", err)
	}
	if !ok {
		t.Fatal("LoadFrom() 返回 ok=false, 期望 true")
	}
	if d := diffSettings(got, want); d != "" {
		t.Fatalf("显式路径往返后 %s 不一致: got=%+v want=%+v", d, got, want)
	}
	assertCleanDir(t, dir, filepath.Base(path))
}

func TestLoadFromMissingExplicitPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.json")

	got, ok, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() 文件不存在时返回错误: %v", err)
	}
	if ok {
		t.Fatal("LoadFrom() 文件不存在时返回 ok=true, 期望 false")
	}
	if !isZeroSettings(got) {
		t.Fatalf("LoadFrom() 文件不存在时返回 %+v, 期望零值", got)
	}
}

func TestSaveFileFormat(t *testing.T) {
	dir := useTempExeDir(t)

	in := Settings{Domains: "cn", SystemDNS: boolPtr(false), OpenBrowser: boolPtr(true)}
	if err := Save(in); err != nil {
		t.Fatalf("Save() 失败: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("读取设置文件失败: %v", err)
	}

	// 2 空格缩进 + 结尾换行，逐字节比对。
	want := "{\n  \"domains\": \"cn\",\n  \"system_dns\": false,\n  \"open_browser\": true\n}\n"
	if string(data) != want {
		t.Fatalf("文件内容 = %q, 期望 %q", data, want)
	}

	// 结尾必须有换行符，且只有一个。
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Fatalf("文件内容 = %q, 期望以换行符结尾", data)
	}
	if bytes.HasSuffix(data, []byte("\n\n")) {
		t.Fatalf("文件内容 = %q, 结尾不应有多余空行", data)
	}

	// 除首行与右花括号外，每行都必须恰好以两个空格开头。
	for i, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "{" || line == "}" {
			continue
		}
		if !strings.HasPrefix(line, "  ") {
			t.Fatalf("第 %d 行 = %q, 期望以两个空格缩进", i+1, line)
		}
		if strings.HasPrefix(line, "   ") {
			t.Fatalf("第 %d 行 = %q, 缩进多于两个空格（要求 2 空格缩进）", i+1, line)
		}
	}
}

func TestSaveIsAtomicAndLeavesNoTempFile(t *testing.T) {
	dir := useTempExeDir(t)

	for i, s := range []Settings{
		{Domains: "cn", Attempts: 1},
		{Domains: "intl", Attempts: 2},
		{Domains: "all", Attempts: 3},
	} {
		if err := Save(s); err != nil {
			t.Fatalf("第 %d 次 Save() 失败: %v", i+1, err)
		}
		assertCleanDir(t, dir, FileName)
	}

	// 覆盖写已存在的文件同样不能留下临时文件。
	if err := Save(fullSettings()); err != nil {
		t.Fatalf("覆盖写 Save() 失败: %v", err)
	}
	assertCleanDir(t, dir, FileName)
}

func TestSaveFailureLeavesNoTempFile(t *testing.T) {
	t.Run("目标目录不存在", func(t *testing.T) {
		base := t.TempDir()
		path := filepath.Join(base, "missing", FileName)

		err := SaveTo(path, fullSettings())
		if err == nil {
			t.Fatal("SaveTo() 目标目录不存在时返回 nil, 期望报错")
		}
		// 报错必须来自"在目标目录里创建临时文件"这一步，而不是后面的重命名。
		// 这正说明临时文件就建在目标目录里：如果实现用的是系统临时目录，
		// 临时文件会创建成功，错误只会出现在 Rename 阶段。
		if !strings.Contains(err.Error(), "临时文件") {
			t.Fatalf("SaveTo() 错误 = %q, 期望是创建临时文件失败（说明临时文件建在目标目录）", err)
		}
		// 未创建目录，也不应留下任何东西。
		if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
			t.Fatal("SaveTo() 不应自行创建目录")
		}
		assertCleanDir(t, base)
	})

	t.Run("重命名失败", func(t *testing.T) {
		// 把目标路径做成一个目录，Rename 必然失败：这样临时文件已经写完，
		// 正好检验失败路径会不会把它清理掉。
		dir := t.TempDir()
		path := filepath.Join(dir, FileName)
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("创建同名目录失败: %v", err)
		}

		if err := SaveTo(path, fullSettings()); err == nil {
			t.Fatal("SaveTo() 目标是目录时返回 nil, 期望报错")
		}
		assertCleanDir(t, dir, FileName)
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			t.Fatalf("期望 %s 仍是一个目录, stat=%v err=%v", path, info, err)
		}
	})
}

func TestSaveWritesTempFileInDestinationDirectory(t *testing.T) {
	// 临时文件必须和目标是同一个目录，否则跨卷 Rename 就不再是原子操作。
	// "目标目录不存在"那个用例已经从报错来源证明了这一点；这里再从反面确认：
	// 把工作目录换成一个干净的临时目录，保存之后它必须仍然是空的。
	dir := useTempExeDir(t)
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() 失败: %v", err)
	}

	if err := Save(fullSettings()); err != nil {
		t.Fatalf("Save() 失败: %v", err)
	}

	// 设置文件必须落在可执行文件目录，而不是工作目录。
	assertCleanDir(t, dir, FileName)
	assertCleanDir(t, cwd)
}

func TestSavePreservesExistingFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows 的权限位只是只读属性的映射视图，Chmod 0o600 之后 Stat 仍报
		// 0o666 一类的值，这个断言在该平台上没有意义。
		t.Skip("Windows 的权限位不可靠，跳过模式保留测试")
	}

	dir := useTempExeDir(t)
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("预置设置文件失败: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("设置初始权限失败: %v", err)
	}

	if err := Save(fullSettings()); err != nil {
		t.Fatalf("Save() 失败: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() 失败: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("覆盖写之后权限 = %o, 期望保留 %o", got, 0o600)
	}
}

func TestSaveCreatesFileWithSettingsPerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的权限位不可靠，跳过新建文件权限测试")
	}

	dir := useTempExeDir(t)
	if err := Save(Settings{Domains: "cn"}); err != nil {
		t.Fatalf("Save() 失败: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("Stat() 失败: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("新建文件权限 = %o, 期望 %o", got, settingsPerm)
	}
}

func TestDirAndPath(t *testing.T) {
	// useTempExeDir 返回的已经是解析符号链接后的目录，也就是 Dir() 应当给出的值。
	real := useTempExeDir(t)

	got := Dir()
	if got == "" {
		t.Fatal("Dir() 返回空字符串")
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("Dir() = %q, 期望绝对路径", got)
	}
	if got != real {
		t.Fatalf("Dir() = %q, 期望 %q", got, real)
	}

	// Path() 必须与 Dir() 自洽：不能自己再去解析一次而得到不同的目录。
	path := Path()
	if path != filepath.Join(got, FileName) {
		t.Fatalf("Path() = %q, 期望 %q", path, filepath.Join(got, FileName))
	}
	if filepath.Dir(path) != got {
		t.Fatalf("Path() 的目录 = %q, 与 Dir() = %q 不一致", filepath.Dir(path), got)
	}
	if filepath.Base(path) != FileName {
		t.Fatalf("Path() = %q, 期望以 %q 结尾", path, FileName)
	}
	if !strings.HasSuffix(path, string(os.PathSeparator)+FileName) {
		t.Fatalf("Path() = %q, 期望以分隔符加 %q 结尾", path, FileName)
	}
}

func TestDirFallsBackToWorkingDirectory(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() 失败: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{name: "可执行文件路径取不到", path: "", wantErr: os.ErrNotExist},
		{name: "可执行文件路径为空", path: "", wantErr: nil},
		{name: "可执行文件所在目录不存在", path: filepath.Join(t.TempDir(), "missing", "dns-opti.exe"), wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubExecutable(t, tt.path, tt.wantErr)
			if got := Dir(); got != wd {
				t.Fatalf("Dir() = %q, 期望回落到工作目录 %q", got, wd)
			}
			if got := Path(); got != filepath.Join(wd, FileName) {
				t.Fatalf("Path() = %q, 期望 %q", got, filepath.Join(wd, FileName))
			}
		})
	}
}

func TestDirResolvesSymlinkedExecutable(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	target := filepath.Join(realDir, "dns-opti.exe")
	if err := os.WriteFile(target, []byte("stub"), 0o644); err != nil {
		t.Fatalf("创建占位可执行文件失败: %v", err)
	}

	link := filepath.Join(base, "link.exe")
	if err := os.Symlink(target, link); err != nil {
		// 部分环境（非管理员且未开启开发者模式的 Windows）不允许创建符号链接。
		t.Skipf("无法创建符号链接，跳过: %v", err)
	}

	stubExecutable(t, link, nil)
	want, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		want = realDir
	}
	if got := Dir(); got != want {
		t.Fatalf("Dir() = %q, 期望解析符号链接后得到 %q（设置文件应与真实二进制放在一起）", got, want)
	}

	// 符号链接解析失败（悬空链接）时必须退回原始路径，而不是丢掉结果。
	dangling := filepath.Join(base, "dangling.exe")
	if err := os.Symlink(filepath.Join(base, "gone.exe"), dangling); err != nil {
		t.Skipf("无法创建符号链接，跳过: %v", err)
	}
	stubExecutable(t, dangling, nil)
	if got := Dir(); got == "" {
		t.Fatal("Dir() 对悬空符号链接返回空字符串，期望退回原始路径")
	}
}

func TestDirDoesNotUseUnwritableExecutableDirectory(t *testing.T) {
	// 可执行文件所在目录可能不存在（解压前/被删除/只读挂载）。此时 Dir 必须
	// 回落到工作目录，而不是返回一个不可写的路径——但真实目录不一定是可写的，
	// 所以这个用例会接受两种结果之一：不存在的目录一定不能被选中。
	stubExecutable(t, filepath.Join(t.TempDir(), "missing", "dns-opti.exe"), nil)
	got := Dir()
	if strings.Contains(got, "missing") {
		t.Fatalf("Dir() = %q, 期望不要选中不存在的目录", got)
	}
}

func TestFileNameConstant(t *testing.T) {
	// 文件名是对外契约（用户可能手工编辑/删除它），固定住以便集成时不要随手改。
	if FileName != "dns-opti.settings.json" {
		t.Fatalf("FileName = %q, 期望 %q", FileName, "dns-opti.settings.json")
	}
	if filepath.Base(FileName) != FileName {
		t.Fatalf("FileName = %q, 必须是纯文件名而不是路径", FileName)
	}
}
