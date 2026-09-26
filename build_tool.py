#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns-opti 构建工具（交互式终端界面，纯 Go 项目）

项目结构（本仓库配置）：
    go.mod              module dns-opti
    cmd/dns-opti        入口（./cmd/dns-opti）
    internal/cli        版本注入点 dns-opti/internal/cli.Version
    internal/web/static 内嵌静态资源（go:embed，源码，禁止清理）
    dist/               构建产物输出目录（.gitignore 已忽略）
    .goreleaser.yml     发布打包配置（本工具与其 ldflags / 产物命名保持一致）

功能：
- 构建生产版：go build -trimpath -ldflags "-s -w -X dns-opti/internal/cli.Version=..."（CGO_ENABLED=0）
- 构建开发版：go build 保留符号与调试信息（不加 -s -w）
- 清理构建缓存：dist/ 中的二进制与压缩包、__pycache__/、根目录游离二进制
- 安装依赖：go mod download + go mod tidy（本项目无 npm 前端，前端项自动跳过）
- 运行冒烟测试：scripts/smoke.{sh,ps1} 不存在时回退到 go test ./...

使用方法：
    python build_tool.py              # 启动交互式界面
    python build_tool.py --cli        # 命令行模式
    python build_tool.py build --platform win --arch amd64 --type production
    python build_tool.py build --platform win --arch amd64 --tags nodoh3
    python build_tool.py clean --all
    python build_tool.py install --target backend
    python build_tool.py smoke
"""

import argparse
import io  # 用于 _run_command 的 TextIOWrapper，Windows pipe 稳定逐行解码
import json
import locale
import os
import shutil
import string
import subprocess
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.align import Align
from rich.box import ROUNDED


# ----------------------------------------------------------------------
# 标准流编码加固
# 中文 Windows 控制台默认 GBK（cp936），rich 打印 ✓/✗ 等符号时会抛
# UnicodeEncodeError 导致工具中途崩溃，这里统一切到 UTF-8 容错模式。
# ----------------------------------------------------------------------
def _configure_stdio_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf is None:
            continue
        try:
            reconf(encoding="utf-8", errors="replace")
        except Exception:
            pass


_configure_stdio_encoding()


# ----------------------------------------------------------------------
# 辅助：检测系统语言
# ----------------------------------------------------------------------
def get_system_language() -> str:
    """检测系统语言（zh / en）"""
    if sys.platform == "win32":
        try:
            import ctypes
            windll = ctypes.windll.kernel32
            user_lang_id = windll.GetUserDefaultUILanguage()
            zh_lang_ids = {0x804, 0x404, 0x1004, 0x1404, 0xC04}
            if user_lang_id in zh_lang_ids:
                return "zh"
        except Exception:
            pass

    try:
        lang = locale.getlocale()[0] or ""
        if "zh" in lang.lower():
            return "zh"
        return "en"
    except Exception:
        return "en"


class I18n:
    """国际化支持"""

    STRINGS = {
        "zh": {
            # 顶部 / 通用
            "title": "dns-opti 构建工具",
            "version": "版本",
            "main_menu": "主菜单",
            # 主菜单 1-7（6=使用镜像构建7
            "build_production": "构建生产版",
            "build_development": "构建开发版",
            "clean_cache": "清理构建缓存",
            "install_deps": "安装依赖",
            "run_smoke": "运行冒烟测试",
            "build_with_mirror": "使用镜像构建（国内推荐）",
            "exit": "退出",
            # 平台选择
            "select_platform": "选择目标平台",
            "windows": "Windows",
            "macos": "macOS",
            "linux": "Linux",
            "all_platforms": "所有平台",
            # 架构选择（与 Wails 对齐：win=amd64/arm64，mac=arm64/x64/universal，linux=amd64/arm64）
            "select_arch": "选择架构",
            "x64": "x64 (64位)",
            "x86": "x86 (32位)",
            "arm64": "ARM64",
            "universal": "Universal (macOS 通用包)",
            # 构建过程
            "building": "正在构建",
            "compiling": "正在编译项目代码",
            "packaging": "正在打包",
            "success": "构建成功",
            "failed": "构建失败",
            "output_dir": "输出目录",
            "output_size": "输出大小",
            # 清理菜单
            "clean_menu": "清理菜单",
            "clean_all": "清理所有缓存",
            "clean_out": "清理 out/ 目录（已废弃，仅兼容旧菜单）",
            "clean_dist": "清理 dist/ 中的构建产物",
            "clean_vite": "清理 .vite/ 目录（已废弃，Vite 缓存已合并入 dist）",
            "clean_npm": "清理 frontend/node_modules/.cache/",
            "clean_bin": "清理 build/bin/ 目录（Wails 产物）",
            "clean_wailsjs": "清理 wailsjs/ 目录（Wails 自动生成，可选）",
            "clean_pycache": "清理 __pycache__/ 目录",
            # W6: 根目录游离二进制清理（go build 错产物）
            "clean_root_exe": "清理根目录游离二进制（dns-opti / dns-opti.exe）",
            "back": "返回",
            "cleaning": "正在清理",
            "cleaned": "已清理",
            "clean_complete": "清理完成",
            "space_freed": "共释放空间",
            "confirm_clean": "确认清理",
            "confirm_clean_msg": "此操作将删除构建文件，是否继续？",
            # 环境检测
            "checking_env": "正在检查环境",
            "node_not_found": "未找到 Node.js，请确保已安装",
            "go_not_found": "未找到 Go，请安装 Go 1.23+ 并加入 PATH",
            "wails_not_found": "未找到 wails CLI，请先安装",
            "installing_deps": "正在安装依赖",
            "deps_installed": "依赖已安装",
            # 错误 / 警告
            "error": "错误",
            "warning": "警告",
            "press_enter": "按回车键继续",
            "project_dir": "项目目录",
            "not_exist": "目录不存在，跳过",
            "delete_failed": "删除失败",
            "unknown_target": "未知的清理目标",
            "build_type": "构建类型",
            "platform": "目标平台",
            "architecture": "目标架构",
            "step": "步骤",
            "of": "/",
            "command_failed": "命令执行失败，退出码",
            "command_success": "命令执行成功",
            "cmd_error": "执行命令时发生错误",
            "unsupported_combo": "不支持的平台/架构组合",
            "no_node_modules": "frontend/node_modules 目录不存在，正在安装依赖",
            # 影响说明
            "impact_clean_all": "清理 dist/ 构建产物、__pycache__/ 与根目录游离二进制，下次构建将重新编译",
            "impact_clean_out": "清理编译输出（已废弃，本项目无 out/ 目录）",
            "impact_clean_dist": "仅删除 dist/ 下的 dns-opti 二进制与发布压缩包（保留 demo JSON、截图等非产物文件）",
            "impact_clean_vite": "清理 Vite 缓存（已废弃，本项目无 .vite/ 目录）",
            "impact_clean_npm": "清理 npm 模块缓存，不影响已安装的依赖",
            "impact_clean_bin": "清理 Wails 打包产物（可执行文件、安装包），下次构建会重新生成",
            "impact_clean_wailsjs": "清理 Wails 自动生成的 JS 绑定（下次 wails dev/build 会自动重建）",
            "impact_clean_pycache": "清理 Python 编译缓存，不影响源代码",
            # W6: 根目录游离二进制清理的影响说明
            "impact_clean_root_exe": "清理在仓库根目录直接 go build 产生的 dns-opti / dns-opti.exe（.gitignore 已忽略，但会与 dist/ 正式产物混淆）",
            # W6: build 前置健康检查文案
            "root_exe_warning": "检测到根目录有游离二进制（非 dist/ 正式产物）",
            "root_exe_warning_hint": "正式产物应位于 dist/。请用 `python build_tool.py clean --root-exe` 或 `clean --all` 移除根目录的 dns-opti / dns-opti.exe",
            # 修复 Bug L: 当 Node.js/npm 在 PATH 中查不到时，给出可执行的排查提示
            "node_install_hint": "请确认 Node.js 已正确安装（https://nodejs.org/）并将其安装目录加入系统 PATH，然后重新打开终端或重启 IDE。",
            "node_found_at": "已在 PATH 外的位置找到 {cmd}：{path}。请将该目录加入 PATH 后重试。",
            "node_searched_paths": "已检查的常见安装路径：",
            # Wails 错误提示（W1 / W5）
            "wails_install_hint": "请通过 Go 安装 Wails CLI：\n  go install github.com/wailsapp/wails/v2/cmd/wails@latest\n并将 GOPATH/bin 加入 PATH。",
            "go_install_hint": "请安装 Go 1.23+（https://go.dev/dl/）并将其 bin 目录加入系统 PATH。",
            # 安装依赖功能相关
            "install_deps_fresh": "首次安装依赖（npm install）",
            "install_deps_update": "更新依赖（npm install）",
            "install_deps_reinstall": "彻底重装依赖（删除 frontend/node_modules 后 npm install）",
            "select_install_mode": "选择安装模式",
            "deps_already_installed": "依赖已安装，无需重复安装",
            "reinstall_confirm_msg": "即将删除 frontend/node_modules 与 frontend/package-lock.json 后重新安装，是否继续？",
            "deps_reinstalled": "依赖已重装完成",
            "no_node_modules_skip_reinstall": "frontend/node_modules 不存在，无需重装，将执行首次安装",
            "install_deps_force_done": "强制重装完成",
            "install_deps_target": "本项目无 npm 前端依赖（静态资源内嵌于 internal/web/static），Go 依赖请用 go mod 管理",
            "no_frontend": "本项目无前端依赖目录，跳过",
            # 多包管理器检测（auto-detect from lockfile）
            "pkg_manager_detected": "已自动检测到包管理器",
            "pkg_manager_unknown": "未识别前端包管理器，将使用 npm 兜底",
            "pkg_manager_npm": "npm",
            "pkg_manager_yarn": "yarn",
            "pkg_manager_pnpm": "pnpm",
            # Go 后端依赖（W4 + 新增）
            "install_deps_go": "安装 Go 后端依赖",
            "install_deps_go_desc": "执行 go mod download + go mod tidy",
            "install_deps_go_already": "Go 依赖已就绪（go.sum 存在）",
            "install_deps_go_done": "Go 后端依赖已就绪",
            "install_deps_go_reinstalled": "Go 后端依赖已重新生成（go.sum 已刷新）",
            "go_mod_not_found": "未找到 go.mod（已检查项目根目录），请确认 Go 模块目录结构",
            "go_sum_lock": "go.sum（依赖锁文件）",
            "go_deps_target": "Go 后端依赖（go.mod 所在目录）；本项目无 npm 前端依赖",
            "select_deps_target": "选择依赖目标",
            "deps_target_frontend": "前端依赖（本项目不存在，自动跳过）",
            "deps_target_backend": "Go 依赖 (go.mod/go.sum)",
            "deps_target_all": "全部（前端自动跳过 + 后端 Go）",
            # 多包管理器检测（auto-detect from lockfile）
            "pkg_manager_detected": "已自动检测到包管理器",
            "pkg_manager_unknown": "未识别前端包管理器，将使用 npm 兜底",
            "pkg_manager_npm": "npm",
            "pkg_manager_yarn": "yarn",
            "pkg_manager_pnpm": "pnpm",
            # Go 后端依赖（W4 + 新增）
            "install_deps_go": "安装 Go 后端依赖",
            "install_deps_go_desc": "执行 go mod download + go mod tidy",
            "install_deps_go_already": "Go 依赖已就绪（go.sum 存在）",
            "install_deps_go_done": "Go 后端依赖已就绪",
            "install_deps_go_reinstalled": "Go 后端依赖已重新生成（go.sum 已刷新）",
            "go_mod_not_found": "未找到 go.mod（已检查项目根目录），请确认 Go 模块目录结构",
            "go_sum_lock": "go.sum（依赖锁文件）",
            "go_deps_target": "Go 后端依赖（go.mod 所在目录）；本项目无 npm 前端依赖",
            "select_deps_target": "选择依赖目标",
            "deps_target_frontend": "前端依赖（本项目不存在，自动跳过）",
            "deps_target_backend": "Go 依赖 (go.mod/go.sum)",
            "deps_target_all": "全部（前端自动跳过 + 后端 Go）",
            # 冒烟测试（菜单 5）
            "smoke_running": "正在运行冒烟测试",
            "smoke_success": "冒烟测试通过",
            "smoke_failed": "冒烟测试失败",
            "smoke_binary_missing": "未找到 dist/ 下的构建产物；请先构建一次",
            "smoke_no_launch": "仅运行单元测试，不启动任何二进制",
            "smoke_fallback": "未找到 scripts/smoke 脚本，回退运行 go vet ./... + go test ./...",
            # Wails 平台 / 架构（W3 / W4）
            "arch_32bit_unsupported": "Wails 不再支持 32 位 Windows（win/x86），请改用 amd64 或 arm64",
            "wails_platform_string": "Wails 平台字符串",
            "ldflags_version": "注入版本号（dns-opti/internal/cli.Version）",
            "use_build_script": "使用 scripts/build.sh / scripts/build.ps1 封装（更稳）",
            # 镜像构建（M1）
            "mirror_mode_enabled": "镜像模式已启用",
            "mirror_mode_disabled": "镜像模式未启用",
            "mirror_go_proxy": "Go 代理",
            "mirror_npm_registry": "npm 镜像",
            "mirror_gosumdb_off": "已关闭 GOSUMDB（跳过校验）",
            "mirror_fix_checksum": "自动修复 go.sum 校验失败（checksum mismatch）",
            "mirror_current_status": "当前镜像状态",
            "mirror_on": "开启",
            "mirror_off": "关闭",
        },
        "en": {
            "title": "dns-opti Build Tool",
            "version": "Version",
            "main_menu": "Main Menu",
            "build_production": "Build Production",
            "build_development": "Build Development",
            "clean_cache": "Clean Build Cache",
            "install_deps": "Install Dependencies",
            "run_smoke": "Run Smoke Test",
            "build_with_mirror": "Build with Mirror (Recommended for China)",
            "exit": "Exit",
            "select_platform": "Select Target Platform",
            "windows": "Windows",
            "macos": "macOS",
            "linux": "Linux",
            "all_platforms": "All Platforms",
            "select_arch": "Select Architecture",
            "x64": "x64 (64-bit)",
            "x86": "x86 (32-bit)",
            "arm64": "ARM64",
            "universal": "Universal (macOS fat binary)",
            "building": "Building",
            "compiling": "Compiling project code",
            "packaging": "Packaging",
            "success": "Build successful",
            "failed": "Build failed",
            "output_dir": "Output directory",
            "output_size": "Output size",
            "clean_menu": "Clean Menu",
            "clean_all": "Clean all cache",
            "clean_out": "Clean out/ directory (deprecated, legacy menu only)",
            "clean_dist": "Clean build artifacts in dist/",
            "clean_vite": "Clean .vite/ directory (deprecated, Vite cache merged into dist)",
            "clean_npm": "Clean frontend/node_modules/.cache/",
            "clean_bin": "Clean build/bin/ directory (Wails artifacts)",
            "clean_wailsjs": "Clean wailsjs/ directory (Wails auto-generated, optional)",
            "clean_pycache": "Clean __pycache__/ directory",
            "clean_root_exe": "Clean orphan binaries in repo root (dns-opti / dns-opti.exe)",
            "back": "Back",
            "cleaning": "Cleaning",
            "cleaned": "Cleaned",
            "clean_complete": "Clean complete",
            "space_freed": "Space freed",
            "confirm_clean": "Confirm Clean",
            "confirm_clean_msg": "This will delete build files. Continue?",
            "checking_env": "Checking environment",
            "node_not_found": "Node.js not found. Please ensure it is installed",
            "go_not_found": "Go not found. Please install Go 1.23+ and add it to PATH",
            "wails_not_found": "wails CLI not found. Please install it first",
            "installing_deps": "Installing dependencies",
            "deps_installed": "Dependencies installed",
            "error": "Error",
            "warning": "Warning",
            "press_enter": "Press Enter to continue",
            "project_dir": "Project directory",
            "not_exist": "Directory does not exist, skipping",
            "delete_failed": "Delete failed",
            "unknown_target": "Unknown clean target",
            "build_type": "Build type",
            "platform": "Target platform",
            "architecture": "Target architecture",
            "step": "Step",
            "of": "/",
            "command_failed": "Command failed with exit code",
            "command_success": "Command executed successfully",
            "cmd_error": "Error executing command",
            "unsupported_combo": "Unsupported platform/architecture combination",
            "no_node_modules": "frontend/node_modules does not exist, installing dependencies",
            "impact_clean_all": "Cleans dist/ artifacts, __pycache__/ and orphan root binaries; next build recompiles everything",
            "impact_clean_out": "Cleans compiled output (deprecated, no out/ in this project)",
            "impact_clean_dist": "Removes only dns-opti binaries and release archives in dist/ (keeps demo JSON, screenshots and other non-artifact files)",
            "impact_clean_vite": "Cleans Vite cache (deprecated, no .vite/ in this project)",
            "impact_clean_npm": "Cleans npm module cache, does not affect installed dependencies",
            "impact_clean_bin": "Cleans Wails artifacts (binaries/installers), next build regenerates them",
            "impact_clean_wailsjs": "Cleans Wails auto-generated JS bindings (regenerated on next wails dev/build)",
            "impact_clean_pycache": "Cleans Python compiled cache, does not affect source code",
            # W6: impact + warning strings
            "impact_clean_root_exe": "Cleans dns-opti / dns-opti.exe produced by running `go build` in the repo root (gitignored, but easy to confuse with real artifacts in dist/)",
            "root_exe_warning": "Detected orphan binaries in repo root (not real artifacts from dist/)",
            "root_exe_warning_hint": "Real artifacts live in dist/. Run `python build_tool.py clean --root-exe` or `clean --all` to remove dns-opti / dns-opti.exe from the repo root",
            # Bug L fix
            "node_install_hint": "Please make sure Node.js is installed (https://nodejs.org/) and its installation directory is added to the system PATH, then reopen the terminal or restart the IDE.",
            "node_found_at": "Found {cmd} outside PATH at: {path}. Please add this directory to PATH and retry.",
            "node_searched_paths": "Checked the following common installation paths:",
            # Wails hints (W1 / W5)
            "wails_install_hint": "Please install the Wails CLI via Go:\n  go install github.com/wailsapp/wails/v2/cmd/wails@latest\nand add GOPATH/bin to your PATH.",
            "go_install_hint": "Please install Go 1.23+ (https://go.dev/dl/) and add its bin directory to the system PATH.",
            "install_deps_fresh": "Install dependencies (first time, npm install)",
            "install_deps_update": "Update dependencies (npm install)",
            "install_deps_reinstall": "Reinstall dependencies (delete frontend/node_modules, then npm install)",
            "select_install_mode": "Select install mode",
            "deps_already_installed": "Dependencies are already installed, no need to install again",
            "reinstall_confirm_msg": "This will delete frontend/node_modules and frontend/package-lock.json, then reinstall. Continue?",
            "deps_reinstalled": "Dependencies reinstalled",
            "no_node_modules_skip_reinstall": "frontend/node_modules does not exist, will perform first-time install",
            "install_deps_force_done": "Force reinstall completed",
            "install_deps_target": "No npm frontend deps in this project (static assets are embedded from internal/web/static); Go deps are managed by `go mod`",
            "no_frontend": "No frontend dependency directory in this project, skipping",
            # Multi-package-manager detection (auto-detect from lockfile)
            "pkg_manager_detected": "Auto-detected package manager",
            "pkg_manager_unknown": "Unrecognized frontend package manager, falling back to npm",
            "pkg_manager_npm": "npm",
            "pkg_manager_yarn": "yarn",
            "pkg_manager_pnpm": "pnpm",
            # Go backend dependencies (W4 + new)
            "install_deps_go": "Install Go backend dependencies",
            "install_deps_go_desc": "Run go mod download + go mod tidy",
            "install_deps_go_already": "Go dependencies already ready (go.sum exists)",
            "install_deps_go_done": "Go backend dependencies ready",
            "install_deps_go_reinstalled": "Go backend dependencies regenerated (go.sum refreshed)",
            "go_mod_not_found": "go.mod not found (checked project root), please verify Go module directory structure",
            "go_sum_lock": "go.sum (dependency lock file)",
            "go_deps_target": "Go backend deps (go.mod dir); this project has no npm frontend deps",
            "select_deps_target": "Select dependency target",
            "deps_target_frontend": "Frontend deps (absent in this project, skipped automatically)",
            "deps_target_backend": "Go deps (go.mod/go.sum)",
            "deps_target_all": "All (frontend skipped + backend Go)",
            # Smoke test (menu 5)
            "smoke_running": "Running smoke test",
            "smoke_success": "Smoke test passed",
            "smoke_failed": "Smoke test failed",
            "smoke_binary_missing": "No binary found under dist/; please run a build first",
            "smoke_no_launch": "Run unit tests only; do not launch any binary",
            "smoke_fallback": "scripts/smoke not found, falling back to go vet ./... + go test ./...",
            # Wails platform / arch (W3 / W4)
            "arch_32bit_unsupported": "Wails no longer supports 32-bit Windows (win/x86). Please use amd64 or arm64.",
            "wails_platform_string": "Wails platform string",
            "ldflags_version": "Inject version (dns-opti/internal/cli.Version)",
            "use_build_script": "Use scripts/build.sh / scripts/build.ps1 wrapper (more reliable)",
            # Mirror build (M1)
            "mirror_mode_enabled": "Mirror mode enabled",
            "mirror_mode_disabled": "Mirror mode disabled",
            "mirror_go_proxy": "Go proxy",
            "mirror_npm_registry": "npm registry",
            "mirror_gosumdb_off": "GOSUMDB disabled (skip checksum verification)",
            "mirror_fix_checksum": "Auto-fix go.sum checksum mismatch",
            "mirror_current_status": "Current mirror status",
            "mirror_on": "On",
            "mirror_off": "Off",
        },
    }

    def __init__(self):
        self.lang = get_system_language()

    def set_language(self, lang: str):
        self.lang = lang

    def get(self, key: str) -> str:
        return self.STRINGS.get(self.lang, self.STRINGS["en"]).get(key, key)


class BuildTool:
    """dns-opti 构建工具主类（默认 Go 模块模式；保留 Wails 模式仅为兼容历史布局）

    本仓库配置（dns-opti）：
      - go.mod（module dns-opti）位于仓库根 → gomod 模式
      - 入口包 ./cmd/dns-opti，版本注入点 dns-opti/internal/cli.Version
      - 产物输出到 dist/（命名 dns-opti[-GOOS-GOARCH][.exe]，与 .goreleaser.yml 一致）
      - 无 npm 前端（internal/web/static 为 go:embed 静态资源，禁止清理）
      - CGO_ENABLED=0，支持 -tags nodoh3 构建标签

    自动检测项目类型：
      - wails.json 存在 → Wails 模式（本仓库无此文件，永不触发）
      - go.mod 存在 → Go 模块模式（本仓库实际使用的模式）
    """

    # ------------------------------------------------------------------
    # W3: Wails 平台字符串映射（替代旧 npm script 名，仅 Wails 模式使用）
    # ------------------------------------------------------------------
    #   win/x64    -> windows/amd64
    #   win/arm64  -> windows/arm64
    #   win/x86    -> 不支持（Wails 自 2.x 起不再支持 32 位 Windows）
    #   mac/x64    -> darwin/amd64
    #   mac/arm64  -> darwin/arm64
    #   mac/universal -> darwin/universal
    #   linux/x64  -> linux/amd64
    #   linux/arm64 -> linux/arm64
    # ------------------------------------------------------------------
    PLATFORM_ARCH_MAP = {
        "win": {
            "x64": "windows/amd64",
            "arm64": "windows/arm64",
        },
        "mac": {
            "arm64": "darwin/arm64",
            "x64": "darwin/amd64",
            "universal": "darwin/universal",
        },
        "linux": {
            "x64": "linux/amd64",
            "arm64": "linux/arm64",
        },
    }

    # ------------------------------------------------------------------
    # W5: 新 Wails 栈的清理目标
    #   - dist:  前端构建产物（Vite 输出，Wails go:embed 源）
    #   - bin:   Wails 打包的可执行文件 / 安装包（NSIS/dmg/AppImage/deb/zip/...）
    #   - npm:   npm 内部缓存（node_modules/.cache）
    #   - wailsjs: Wails 自动生成的 JS 绑定（可清理，下次 dev/build 自动重建）
    #   - pycache: Python 字节码缓存
    # ------------------------------------------------------------------
    CLEAN_TARGETS = {
        "dist": "frontend/dist",
        "bin": "build/bin",
        "npm": "frontend/node_modules/.cache",
        "wailsjs": "wailsjs",
        "pycache": "__pycache__",
    }

    # 根目录"游离二进制"清理目标（与 .gitignore 第 3-4 行对齐）：
    # - 在仓库根目录直接 `go build`（不带 -o dist/...）会产出 dns-opti / dns-opti.exe，
    #   它们被 .gitignore 忽略，但容易与 dist/ 下的正式产物混淆。
    # - 纳入 `clean --all` 的兜底清理，走文件删除（Path.unlink）而非 rmtree。
    CLEAN_FILE_TARGETS = {
        "root_exe": ["dns-opti.exe", "dns-opti"],
    }

    # 旧键名仍保留，标记为"已废弃"——旧 CLI 选项 `--out/--vite` 不会报错但提示无意义
    LEGACY_CLEAN_TARGETS = {
        "out": "out",
        "vite": ".vite",
    }

    # ------------------------------------------------------------------
    # dns-opti（Go 模块模式）的构建与清理配置
    #   - 产物目录 dist/（.goreleaser.yml 的输出目录，.gitignore 已忽略）
    #   - dist/ 里除产物外还有 demo JSON / 截图等本地文件，因此 dist 走"按文件名
    #     匹配"清理（GOMOD_DIST_PATTERNS），绝不整目录 rmtree
    #   - internal/web/static 是 go:embed 源码，任何模式下都不可清理
    # ------------------------------------------------------------------
    BINARY_NAME = "dns-opti"
    MAIN_PKG = "./cmd/dns-opti"
    DIST_DIR = "dist"
    GOMOD_DIST_PATTERNS = ("dns-opti*", "checksums.txt")

    GOMOD_CLEAN_TARGETS = {
        "dist": "dist",
        "pycache": "__pycache__",
    }

    # Go 模块模式下根目录游离二进制
    GOMOD_CLEAN_FILE_TARGETS = {
        "root_exe": ["dns-opti.exe", "dns-opti"],
    }

    # 版本号只在本模式使用（与 .goreleaser.yml 的 ldflags 对齐）
    APP_VERSION_VAR = "dns-opti/internal/cli.Version"
    # Wails 模式遗留变量（本仓库不使用）
    APP_OWNER = "dns-opti"
    APP_REPO = "dns-finder"

    def __init__(self, project_root: Optional[str] = None, i18n: Optional[I18n] = None):
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.console = Console()
        self.i18n = i18n or I18n()
        self.use_mirror = False  # M1: 镜像构建开关

        # 自动检测项目模式
        self.project_mode = self._detect_project_mode()
        self.module_dir = self.project_root  # Go 模块所在目录
        if self.project_mode == "gomod":
            # 优先仓库根 go.mod（本项目布局），其次兼容历史子目录布局
            if (self.project_root / "go.mod").exists():
                self.module_dir = self.project_root
            elif (self.project_root / "Maxpro2API" / "go.mod").exists():
                self.module_dir = self.project_root / "Maxpro2API"

        self.build_tags: Optional[str] = None  # 如 "nodoh3"（见 .goreleaser.yml 备用构建）
        self._app_version = self._read_app_version()
        self.wails_project_dir = self._detect_wails_project_dir()
        self._verify_project()

    def _detect_project_mode(self) -> str:
        """自动检测项目模式

        - 找到 wails.json → "wails"（Wails 桌面应用）
        - 找到 go.mod → "gomod"（纯 Go 模块）
        - 都找不到 → "unknown"
        """
        # 优先检测 wails.json（任何布局）
        for rel in ("", "backend", "Maxpro2API", "maxpro2api"):
            candidate = (self.project_root / rel) if rel else self.project_root
            if (candidate / "wails.json").exists():
                return "wails"
        # 其次检测 go.mod（项目根或 Maxpro2API/ 下）
        if (self.project_root / "Maxpro2API" / "go.mod").exists():
            return "gomod"
        if (self.project_root / "go.mod").exists():
            return "gomod"
        return "unknown"

    def _detect_wails_project_dir(self) -> Path:
        """探测 wails.json 所在的实际目录

        - 旧布局：仓库根直接放 wails.json
        - 新布局：仓库根/backend/wails.json
        - 布局：仓库根/Maxpro2API/wails.json（或 maxpro2api/wails.json，兼容旧名）
        - 都找不到时回退到 project_root
        """
        for rel in ("", "backend", "Maxpro2API", "maxpro2api"):
            candidate = (self.project_root / rel) if rel else self.project_root
            if (candidate / "wails.json").exists():
                return candidate
        return self.project_root

    # ------------------------------------------------------------------
    # 项目根校验
    # ------------------------------------------------------------------
    def _verify_project(self) -> None:
        """校验当前目录是有效的项目根

        自动检测项目类型，不再致命退出：
        - Wails 项目：需要 wails.json（本仓库无此文件）
        - Go 模块项目（dns-opti）：仓库根需要 go.mod
        - 未知模式：仅打印警告，不阻塞
        """
        if self.project_mode == "wails":
            candidates = [
                self.project_root / "wails.json",
                self.project_root / "backend" / "wails.json",
                self.project_root / "Maxpro2API" / "wails.json",
                self.project_root / "maxpro2api" / "wails.json",
            ]
            if not any(p.exists() for p in candidates):
                self.console.print(
                    Panel(
                        f"[red]{self.i18n.get('error')}[/red]: "
                        f"{self.i18n.get('project_dir')} {self.project_root}\n"
                        f"[dim]未找到 wails.json（已检查 wails.json、backend/wails.json、Maxpro2API/wails.json 与 maxpro2api/wails.json）[/dim]",
                        title=self.i18n.get("title"),
                    )
                )
                sys.exit(1)
        elif self.project_mode == "gomod":
            # Go 模块模式不需要 wails.json，只需确保 go.mod 存在
            go_mod_path = self.module_dir / "go.mod"
            if not go_mod_path.exists():
                self.console.print(
                    Panel(
                        f"[red]{self.i18n.get('error')}[/red]: "
                        f"{self.i18n.get('project_dir')} {self.project_root}\n"
                        f"[dim]未找到 go.mod（已检查 {self.module_dir}/go.mod）[/dim]",
                        title=self.i18n.get("title"),
                    )
                )
                sys.exit(1)
        else:
            self.console.print(
                Panel(
                    f"[yellow]{self.i18n.get('warning')}[/yellow]: "
                    f"{self.i18n.get('project_dir')} {self.project_root}\n"
                    f"[dim]未检测到 wails.json 或 go.mod，部分功能可能不可用[/dim]",
                    title=self.i18n.get("title"),
                )
            )

    def _read_app_version(self) -> str:
        """读取项目版本号

        - Wails 模式：从 wails.json 读取 productVersion
        - Go 模块模式：module_dir/VERSION → git describe --tags --always → 'dev'
          （本仓库无 VERSION 文件且非 git 仓库时会落在 'dev'，与
            internal/cli.Version 的默认值一致）
        """
        if self.project_mode == "wails":
            for rel in ("wails.json", "backend/wails.json", "Maxpro2API/wails.json", "maxpro2api/wails.json"):
                wails_json = self.project_root / rel
                if wails_json.exists():
                    try:
                        data = json.loads(wails_json.read_text(encoding="utf-8"))
                        return str(data.get("info", {}).get("productVersion", "dev"))
                    except Exception:
                        return "dev"
            return "dev"
        # Go 模块模式：优先 VERSION 文件
        version_file = self.module_dir / "VERSION"
        if version_file.exists():
            try:
                text = version_file.read_text(encoding="utf-8").strip()
                if text:
                    return text
            except Exception:
                pass
        # 其次 git describe（与 .goreleaser.yml 的 {{ .Version }} 取值方式一致）
        git = self._resolve_executable("git")
        if git is not None:
            try:
                proc = subprocess.run(
                    [git, "describe", "--tags", "--always"],
                    cwd=str(self.module_dir),
                    capture_output=True,
                    timeout=10,
                    shell=False,
                )
                if proc.returncode == 0:
                    text = proc.stdout.decode("utf-8", errors="replace").strip()
                    if text:
                        return text
            except Exception:
                pass
        return "dev"

    # ------------------------------------------------------------------
    # TUI 头部 / 菜单
    # ------------------------------------------------------------------
    def show_header(self):
        """显示工具头部信息"""
        header = Text()
        header.append(self.i18n.get("title"), style="bold cyan")
        header.append(f" | {self.i18n.get('version')} {self._app_version}", style="dim")
        if self.project_mode == "gomod":
            header.append(" | Go 模块模式", style="green")

        self.console.print(Panel(Align.center(header), box=ROUNDED, border_style="cyan"))
        self.console.print()

    def show_main_menu(self) -> str:
        """显示主菜单（1-7）

        菜单顺序：
          1 = 构建生产版
          2 = 构建开发版
          3 = 清理构建缓存
          4 = 安装依赖
          5 = 运行冒烟测试
          6 = 使用镜像构建（国内推荐）
          7 = 退出
        """
        self.show_header()

        # M1: 镜像状态提示
        mirror_status = self.i18n.get("mirror_on") if self.use_mirror else self.i18n.get("mirror_off")
        self.console.print(f"[dim]{self.i18n.get('mirror_current_status')}[/dim]: [bold {'green' if self.use_mirror else 'yellow'}]{mirror_status}[/bold {'green' if self.use_mirror else 'yellow'}]")

        table = Table(show_header=False, box=ROUNDED, border_style="blue", padding=(0, 2))
        table.add_column("Option", style="cyan", justify="right")
        table.add_column("Description", style="white")

        table.add_row("1", self.i18n.get("build_production"))
        table.add_row("2", self.i18n.get("build_development"))
        table.add_row("3", self.i18n.get("clean_cache"))
        table.add_row("4", self.i18n.get("install_deps"))
        table.add_row("5", self.i18n.get("run_smoke"))
        # M1: 新增镜像构建菜单
        table.add_row("6", self.i18n.get("build_with_mirror"))
        table.add_row("7", self.i18n.get("exit"))

        self.console.print(
            Panel(
                table,
                title=f"[bold yellow]{self.i18n.get('main_menu')}[/bold yellow]",
                border_style="yellow",
            )
        )

        choice = Prompt.ask(
            f"\n[bold cyan]{self.i18n.get('main_menu')}[/bold cyan] [cyan][1-7][/cyan]",
            choices=["1", "2", "3", "4", "5", "6", "7"],
            default="1",
        )

        return choice

    # ------------------------------------------------------------------
    # 平台 / 架构选择（W3：mac 新增 universal）
    # ------------------------------------------------------------------
    def select_platform(self) -> str:
        """选择平台（1=Windows 2=macOS 3=Linux 4=全部）"""
        table = Table(show_header=False, box=ROUNDED, border_style="blue", padding=(0, 2))
        table.add_column("Option", style="cyan", justify="right")
        table.add_column("Platform", style="white")

        table.add_row("1", self.i18n.get("windows"))
        table.add_row("2", self.i18n.get("macos"))
        table.add_row("3", self.i18n.get("linux"))
        table.add_row("4", self.i18n.get("all_platforms"))

        self.console.print(
            Panel(
                table,
                title=f"[bold yellow]{self.i18n.get('select_platform')}[/bold yellow]",
                border_style="yellow",
            )
        )

        choice = Prompt.ask(
            f"[bold cyan]{self.i18n.get('select_platform')}[/bold cyan] [cyan][1-4][/cyan]",
            choices=["1", "2", "3", "4"],
            default="1",
        )

        platform_map = {"1": "win", "2": "mac", "3": "linux", "4": "all"}
        return platform_map[choice]

    def select_arch(self, platform: str) -> str:
        """选择架构

        W3: 与 Wails 对齐
        - win:    amd64 / arm64（x86 已废弃）
        - mac:    arm64 / amd64 / universal
        - linux:  amd64 / arm64
        - all:    直接返回 amd64（与 all 组合时架构不再细分）
        """
        if platform == "all":
            return "amd64"

        table = Table(show_header=False, box=ROUNDED, border_style="blue", padding=(0, 2))
        table.add_column("Option", style="cyan", justify="right")
        table.add_column("Architecture", style="white")

        if platform == "win":
            # W3: 移除 x86 入口（Wails 不再支持 32 位 Windows）
            table.add_row("1", self.i18n.get("x64"))
            table.add_row("2", self.i18n.get("arm64"))
        elif platform == "mac":
            table.add_row("1", self.i18n.get("arm64"))
            table.add_row("2", self.i18n.get("x64"))
            # W3: mac 新增 universal 选项
            table.add_row("3", self.i18n.get("universal"))
        else:
            table.add_row("1", self.i18n.get("x64"))
            table.add_row("2", self.i18n.get("arm64"))

        if platform == "mac":
            choices = ["1", "2", "3"]
            default = "1"
        else:
            choices = ["1", "2"]
            default = "1"

        self.console.print(
            Panel(
                table,
                title=f"[bold yellow]{self.i18n.get('select_arch')}[/bold yellow]",
                border_style="yellow",
            )
        )

        choice = Prompt.ask(
            f"[bold cyan]{self.i18n.get('select_arch')}[/bold cyan] [cyan][1-{len(choices)}][/cyan]",
            choices=choices,
            default=default,
        )

        # 平台 → 选项 → 架构 token（与 PLATFORM_ARCH_MAP 的键对齐）
        if platform == "win":
            return "x64" if choice == "1" else "arm64"
        if platform == "mac":
            return {"1": "arm64", "2": "x64", "3": "universal"}[choice]
        return "x64" if choice == "1" else "arm64"

    # ------------------------------------------------------------------
    # 环境检测：Node / Go / Wails
    # ------------------------------------------------------------------
    def _check_node_available(self) -> bool:
        """检测 Node.js 与 npm 是否可用

        修复 Bug L: Windows 上 subprocess + shell=False + list 形式不展开 PATHEXT
        因此 `["npm", "--version"]` 在只有 npm.cmd / 没有 npm.exe 的环境下会直接
        FileNotFoundError；同时错误地先让 npm 把 node 的检查短路掉。
        解决思路：先用 shutil.which() 解析出真正的可执行文件路径（.exe / .cmd 都行），
        再把完整路径交给 subprocess，避免依赖 CreateProcess 自身的 PATHEXT 展开。
        """
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            progress.add_task(self.i18n.get("checking_env"), total=None)
            for cmd in ["node", "npm"]:
                executable = self._resolve_executable(cmd)
                if executable is None:
                    self.console.print(
                        f"[red]{self.i18n.get('error')}[/red]: "
                        f"{self.i18n.get('node_not_found')}: '{cmd}'"
                    )
                    self._print_node_install_hint(cmd)
                    return False
                try:
                    subprocess.run(
                        [executable, "--version"],
                        check=True,
                        capture_output=True,
                        timeout=10,
                        shell=False,  # 修复 Bug B: Windows + 中文路径下避免 cmd /c 重新解码
                    )
                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
                    self.console.print(
                        f"[red]{self.i18n.get('error')}[/red]: "
                        f"{self.i18n.get('node_not_found')}: '{cmd}' ({e})"
                    )
                    self._print_node_install_hint(cmd)
                    return False
        return True

    def _check_go_available(self) -> bool:
        """W1: 检测 Go 是否可用（wails build 强依赖 Go 1.23+）"""
        executable = self._resolve_executable("go")
        if executable is None:
            self.console.print(
                f"[red]{self.i18n.get('error')}[/red]: "
                f"{self.i18n.get('go_not_found')}"
            )
            self.console.print(
                f"[yellow]{self.i18n.get('go_install_hint')}[/yellow]"
            )
            return False
        try:
            subprocess.run(
                [executable, "version"],
                check=True,
                capture_output=True,
                timeout=10,
                shell=False,
            )
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            self.console.print(
                f"[red]{self.i18n.get('error')}[/red]: "
                f"{self.i18n.get('go_not_found')} ({e})"
            )
            self.console.print(
                f"[yellow]{self.i18n.get('go_install_hint')}[/yellow]"
            )
            return False
        return True

    def _check_wails_available(self) -> bool:
        """W1: 检测 wails CLI 是否可用
        优先级：直调 `wails` → 解析为完整路径；若没有则打印安装提示。
        """
        executable = self._resolve_executable("wails")
        if executable is None:
            self.console.print(
                f"[red]{self.i18n.get('error')}[/red]: "
                f"{self.i18n.get('wails_not_found')}"
            )
            self.console.print(
                f"[yellow]{self.i18n.get('wails_install_hint')}[/yellow]"
            )
            return False
        try:
            subprocess.run(
                [executable, "version"],
                check=True,
                capture_output=True,
                timeout=10,
                shell=False,
            )
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            self.console.print(
                f"[red]{self.i18n.get('error')}[/red]: "
                f"{self.i18n.get('wails_not_found')} ({e})"
            )
            self.console.print(
                f"[yellow]{self.i18n.get('wails_install_hint')}[/yellow]"
            )
            return False
        return True

    def _check_root_exe_artifacts(self) -> None:
        """检测根目录是否有非 dist/ 的游离二进制（build 前健康检查）

        背景：直接在仓库根执行 `go build`（不带 -o dist/...）会产出
        dns-opti / dns-opti.exe。它们被 .gitignore 忽略，但会与 dist/ 下的
        正式产物混淆，也可能让人误跑旧二进制。

        本方法不阻塞 build，仅做黄字警告并提示用 `clean --root-exe` / `clean --all` 移除。
        """
        file_targets = (
            self.GOMOD_CLEAN_FILE_TARGETS
            if self.project_mode != "wails"
            else self.CLEAN_FILE_TARGETS
        )
        offenders: list[Path] = []
        for file_name in file_targets.get("root_exe", []):
            p = self.project_root / file_name
            if p.exists() and p.is_file():
                offenders.append(p)
        if not offenders:
            return
        # 拼接成一行可读的列表
        names = ", ".join(f"[cyan]{p.name}[/cyan]" for p in offenders)
        self.console.print(
            f"[yellow]⚠ {self.i18n.get('root_exe_warning')}[/yellow]: {names}"
        )
        self.console.print(
            f"  [dim]{self.i18n.get('root_exe_warning_hint')}[/dim]"
        )

    def _resolve_executable(self, cmd: str) -> Optional[str]:
        """解析可执行文件路径，兼容 Windows 上 .cmd/.bat 脚本后缀

        shutil.which() 在 Windows 上会通过 PATHEXT 找到 .exe / .cmd / .bat，
        这里再手动追加候选后缀作为兜底，覆盖 PATHEXT 被改坏等极端情况。
        """
        path = shutil.which(cmd)
        if path:
            return path
        if sys.platform == "win32":
            for ext in (".cmd", ".bat", ".exe", ".ps1"):
                path = shutil.which(cmd + ext)
                if path:
                    return path
        return None

    def _print_node_install_hint(self, cmd: str) -> None:
        """当 Node.js/npm 检测失败时，输出排查提示并尝试在常见安装路径中回退查找"""
        self.console.print(
            f"[yellow]{self.i18n.get('warning')}[/yellow]: "
            f"{self.i18n.get('node_install_hint')}"
        )

        # Windows 常见安装路径（多盘符、多 Program Files 变体）
        candidate_dirs: list[str] = []
        if sys.platform == "win32":
            for prefix in (r"C:\Program Files", r"C:\Program Files (x86)", r"D:\Program Files", r"D:\Program Files (x86)"):
                candidate_dirs.append(os.path.join(prefix, "nodejs"))
            # 用户级安装（nvm-windows、官方 msi 用户级安装）
            candidate_dirs.append(os.path.expandvars(r"%LOCALAPPDATA%\Programs\nodejs"))
            candidate_dirs.append(os.path.expandvars(r"%APPDATA%\nvm"))
            # 一些用户装在 J:/K:/ 等非系统盘，逐个盘符扫一下 nodejs 目录
            for letter in string.ascii_uppercase:
                if letter in {"A", "B"}:  # 跳过软驱/光驱字母
                    continue
                candidate_dirs.append(fr"{letter}:\Program Files\nodejs")
                candidate_dirs.append(fr"{letter}:\Program Files (x86)\nodejs")

        # 命中就提示用户加到 PATH
        for path in candidate_dirs:
            for ext in (".exe", ".cmd", ".bat"):
                candidate = os.path.join(path, cmd + ext)
                if os.path.exists(candidate):
                    self.console.print(
                        f"[green]✓[/green] "
                        f"{self.i18n.get('node_found_at').format(cmd=cmd, path=candidate)}"
                    )
                    return

        # 没命中常见路径，把扫过的路径列出来方便用户对照
        if candidate_dirs:
            self.console.print(f"[dim]{self.i18n.get('node_searched_paths')}[/dim]")
            for path in candidate_dirs:
                self.console.print(f"  [dim]- {path}[/dim]")

    # ------------------------------------------------------------------
    # W4: 前端依赖检查（node_modules 在 frontend/ 下）
    # ------------------------------------------------------------------
    def _check_dependencies(self) -> bool:
        """检查前端依赖是否存在；缺失则触发首次安装

        自动按项目模式选择前端目录：
        - Wails 模式：frontend/
        - Go 模块模式：webui/
        """
        if self.project_mode == "gomod":
            webui_dir = self.module_dir / "webui"
            if not webui_dir.exists():
                self.console.print(
                    f"[dim]{self.i18n.get('no_frontend')} "
                    f"(internal/web/static 为 go:embed 静态资源，无需构建)[/dim]"
                )
                return True
            node_modules = webui_dir / "node_modules"
            if not node_modules.exists():
                self.console.print(
                    f"[yellow]{self.i18n.get('warning')}[/yellow]: "
                    f"{self.i18n.get('no_node_modules')} (webui/)"
                )
                return self._run_command("npm", ["install"], cwd=str(webui_dir))
            return True

        # Wails 模式：frontend/
        # 路径探测：兼容从仓库根、backend/、Maxpro2API/、maxpro2api/ 四种启动方式
        frontend_dir = self.project_root / "frontend"
        if not frontend_dir.exists():
            if (self.project_root / "backend" / "frontend").exists():
                frontend_dir = self.project_root / "backend" / "frontend"
            elif (self.project_root / "Maxpro2API" / "frontend").exists():
                frontend_dir = self.project_root / "Maxpro2API" / "frontend"
            elif (self.project_root / "maxpro2api" / "frontend").exists():
                frontend_dir = self.project_root / "maxpro2api" / "frontend"
        node_modules = frontend_dir / "node_modules"
        if not frontend_dir.exists():
            self.console.print(
                f"[red]{self.i18n.get('error')}[/red]: "
                f"{self.i18n.get('not_exist')}: {frontend_dir}"
            )
            return False
        if not node_modules.exists():
            self.console.print(
                f"[yellow]{self.i18n.get('warning')}[/yellow]: "
                f"{self.i18n.get('no_node_modules')}"
            )
            return self._run_command("npm", ["install"], cwd=str(frontend_dir))
        return True

    # ------------------------------------------------------------------
    # 子进程环境变量
    # ------------------------------------------------------------------
    def _get_subprocess_env(self) -> dict[str, str]:
        """为子进程注入常用镜像 / 代理环境变量

        旧栈注入 ELECTRON_MIRROR 解决 GitHub Releases 国内不可达（ETIMEDOUT 20.205.243.166:443）。
        新栈改为：
          - GO 镜像：goproxy.cn（解决 go mod 国内拉取慢）
          - NPM 镜像：npmmirror.com（保留旧逻辑，覆盖 npm 拉取）
          - 透传用户已有的 WAILS_* / HTTP_PROXY

        M1: 镜像构建模式增强
          - 当 use_mirror=True 时，强制覆盖为国内镜像（即使用户已设置其他值）
          - 关闭 GOSUMDB（跳过 checksum 校验，解决 go.sum 不一致问题）
          - 修复 checksum mismatch 错误
        """
        env = os.environ.copy()

        if self.use_mirror:
            # M1: 镜像模式 - 强制使用国内镜像
            env["GOPROXY"] = "https://goproxy.cn,direct"
            env["NPM_CONFIG_REGISTRY"] = "https://registry.npmmirror.com"
            env["GOSUMDB"] = "off"  # M1: 关闭 checksum 校验
            self.console.print(f"[dim]M1[/dim]: {self.i18n.get('mirror_mode_enabled')}")
            self.console.print(f"  - {self.i18n.get('mirror_go_proxy')}: https://goproxy.cn")
            self.console.print(f"  - {self.i18n.get('mirror_npm_registry')}: https://registry.npmmirror.com")
            self.console.print(f"  - {self.i18n.get('mirror_gosumdb_off')}")
        else:
            # 默认模式 - 使用 setdefault，不覆盖用户已设置的值
            env.setdefault("GOPROXY", "https://goproxy.cn,direct")
            env.setdefault("GOPRIVATE", "")
            env.setdefault(
                "NPM_CONFIG_REGISTRY",
                "https://registry.npmmirror.com",
            )

        return env

    # ------------------------------------------------------------------
    # 通用子进程执行（带流式输出 + 解码 + 异常清理）
    # ------------------------------------------------------------------
    def _run_command(self, cmd: str, args: list[str], cwd: Optional[str] = None, extra_env: Optional[dict[str, str]] = None) -> bool:
        """执行一条外部命令并实时打印输出

        修复 Bug M: Windows 上 subprocess + shell=False + list 形式不展开 PATHEXT，
        因此 `["npm", ...]` 在只有 npm.cmd 时会 FileNotFoundError。
        复用 _resolve_executable 解析出真实可执行路径（.exe / .cmd / .bat）后再交给 Popen。

        extra_env：额外环境变量（合并到基础环境之上），用于 GOOS/GOARCH 等跨平台编译变量。
        """
        executable = self._resolve_executable(cmd)
        if executable is None:
            # 允许直接传入已存在的可执行文件路径（如 dist/dns-opti.exe）
            candidate = Path(cmd)
            if not candidate.is_absolute():
                candidate = self.module_dir / cmd
            if candidate.exists():
                executable = str(candidate)
        if executable is None:
            self.console.print(
                f"[red]✗[/red] {self.i18n.get('cmd_error')}: "
                f"{self.i18n.get('node_not_found')}: '{cmd}'"
            )
            self._print_node_install_hint(cmd)
            return False
        command = [executable] + args
        self.console.print(f"\n[dim]{self.i18n.get('project_dir')}[/dim]: [cyan]{' '.join(command)}[/cyan]")
        self.console.print("-" * 60)

        process_env = self._get_subprocess_env()
        if extra_env:
            process_env.update(extra_env)

        process: Optional[subprocess.Popen] = None
        try:
            # 修复 Bug B: shell=False 让 list 形式由系统 exec，避免 cmd /c 在 Windows 中文路径下重新按 GBK 解码
            # 修复 Bug C: try/finally 确保异常路径 kill 僵尸进程
            # 修复 Bug F: 用 io.TextIOWrapper 显式 line_buffering，Windows pipe 不支持 bufsize=1
            # 修复 Bug N: 通过 env= 注入镜像（新版替换为 GOPROXY + NPM_CONFIG_REGISTRY）
            process = subprocess.Popen(
                command,
                cwd=cwd or str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                env=process_env,
            )

            if process.stdout:
                # TextIOWrapper 提供可靠的逐行解码，line_buffering=True 在 Windows 上也工作
                with io.TextIOWrapper(
                    process.stdout,
                    encoding="utf-8",
                    errors="replace",
                    line_buffering=True,
                ) as stdout:
                    for line in stdout:
                        self.console.print(line.rstrip())

            process.wait()
            self.console.print("-" * 60)

            if process.returncode == 0:
                self.console.print(f"[green]✓[/green] {self.i18n.get('command_success')}")
                return True
            else:
                self.console.print(f"[red]✗[/red] {self.i18n.get('command_failed')}: {process.returncode}")
                return False

        except Exception as e:
            # 修复 Bug C: 异常路径主动 kill 子进程，避免 npm 卡住时留下僵尸进程
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except Exception:
                    pass
            self.console.print(f"[red]✗[/red] {self.i18n.get('cmd_error')}: {e}")
            return False

    # ------------------------------------------------------------------
    # 目录大小 / 格式化
    # ------------------------------------------------------------------
    def _get_directory_size(self, path: Path) -> int:
        """递归计算目录占用字节数（容错：跳过无权限的文件）"""
        total_size = 0
        if not path.exists():
            return 0
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                file_path = Path(dirpath) / filename
                try:
                    total_size += file_path.stat().st_size
                except (OSError, PermissionError):
                    pass
        return total_size

    def _format_size(self, size_bytes: int) -> str:
        """把字节数格式化为 B / KB / MB / GB / TB"""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

    # ------------------------------------------------------------------
    # 构建入口
    # ------------------------------------------------------------------
    GOMOD_PLATFORM_MAP = {
        "win": {"x64": ("windows", "amd64"), "arm64": ("windows", "arm64")},
        "mac": {"x64": ("darwin", "amd64"), "arm64": ("darwin", "arm64"), "universal": ("darwin", "amd64")},
        "linux": {"x64": ("linux", "amd64"), "arm64": ("linux", "arm64")},
    }

    def build(self, build_type: str, platform: str, arch: str, tags: Optional[str] = None) -> bool:
        """统一构建入口：自动按项目模式分派

        tags：Go 构建标签（如 nodoh3，对应 .goreleaser.yml 的备用构建）
        """
        self.build_tags = tags
        self.console.print()
        self.console.print(
            Panel(
                f"[cyan]{self.i18n.get('build_type')}[/cyan]: [bold]{build_type}[/bold]\n"
                f"[cyan]{self.i18n.get('platform')}[/cyan]: [bold]{platform}[/bold]\n"
                f"[cyan]{self.i18n.get('architecture')}[/cyan]: [bold]{arch}[/bold]\n"
                f"[cyan]{self.i18n.get('version')}[/cyan]: [bold]{self._app_version}[/bold]"
                + (f"\n[cyan]-tags[/cyan]: [bold]{tags}[/bold]" if tags else ""),
                title=f"[bold]{self.i18n.get('building')}[/bold]",
                border_style="cyan",
            )
        )

        # Go 模块模式：走 go build
        if self.project_mode == "gomod":
            return self._build_gomod(build_type, platform, arch)

        # Wails 模式：走 wails build
        # 1) Node + Go + Wails 三件套检测
        if not self._check_node_available():
            return False
        if not self._check_go_available():
            return False
        if not self._check_wails_available():
            return False

        # 2) 前端依赖检查
        if not self._check_dependencies():
            return False

        # 2.5) 根目录游离 exe 健康检查（不阻塞 build，仅 warn）
        self._check_root_exe_artifacts()

        # 3) 平台/架构组合校验
        if platform != "all":
            if platform not in self.PLATFORM_ARCH_MAP:
                self.console.print(
                    f"[red]✗[/red] {self.i18n.get('unsupported_combo')}: {platform}/{arch}"
                )
                return False
            if arch not in self.PLATFORM_ARCH_MAP[platform]:
                if platform == "win" and arch == "x86":
                    self.console.print(
                        f"[red]✗[/red] {self.i18n.get('arch_32bit_unsupported')}"
                    )
                else:
                    self.console.print(
                        f"[red]✗[/red] {self.i18n.get('unsupported_combo')}: {platform}/{arch}"
                    )
                return False

        # 4) all → 矩阵构建
        if platform == "all":
            return self._build_all_platforms(build_type)

        return self._build_single_platform(build_type, platform, arch)

    # ------------------------------------------------------------------
    # Go 模块模式：go build
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # 产物命名 / host 探测（与 .goreleaser.yml、dist/ 现有命名保持一致）
    # ------------------------------------------------------------------
    def _host_goos(self) -> str:
        return {"win32": "windows", "cygwin": "windows", "darwin": "darwin"}.get(sys.platform, "linux")

    def _host_goarch(self) -> str:
        try:
            import platform as _plat

            machine = _plat.machine().lower()
        except Exception:
            machine = ""
        return {
            "amd64": "amd64",
            "x86_64": "amd64",
            "x64": "amd64",
            "arm64": "arm64",
            "aarch64": "arm64",
        }.get(machine, "amd64")

    def _gomod_output_name(self, goos: str, goarch: str, force_suffix: bool = False) -> str:
        """dist/ 下的产物文件名

        - 目标为当前 host：dns-opti / dns-opti.exe（日常本地构建）
        - 其余目标：dns-opti-{goos}-{goarch}[.exe]（与现有 dist/ 命名一致）
        """
        name = self.BINARY_NAME
        if force_suffix or (goos, goarch) != (self._host_goos(), self._host_goarch()):
            name = f"{self.BINARY_NAME}-{goos}-{goarch}"
        if goos == "windows":
            name += ".exe"
        return name

    def _gomod_build_args(self, out_path: Path, ldflags: str) -> list[str]:
        """组装 go build 参数（-trimpath [-tags] -ldflags -o <out> ./cmd/dns-opti）"""
        args = ["build", "-trimpath", "-ldflags", ldflags]
        if self.build_tags:
            args.extend(["-tags", self.build_tags])
        args.extend(["-o", str(out_path), self.MAIN_PKG])
        return args

    def _build_gomod(self, build_type: str, platform: str, arch: str) -> bool:
        """Go 模块模式构建：go build（CGO_ENABLED=0，产物输出到 dist/）"""
        # 1) Go 环境检测
        if not self._check_go_available():
            return False

        # 2) 前端构建（本项目无 webui/ 目录，整段自动跳过）
        webui_dir = self.module_dir / "webui"
        if webui_dir.exists():
            if not self._check_node_available():
                return False
            node_modules_dir = webui_dir / "node_modules"
            if not node_modules_dir.exists():
                self.console.print(
                    f"\n[bold]{self.i18n.get('step')} 1/2[/bold]: "
                    f"{self.i18n.get('installing_deps')} (webui/)"
                )
                if not self._run_command("npm", ["install"], cwd=str(webui_dir)):
                    self.console.print(f"[red]✗ {self.i18n.get('failed')}[/red]")
                    return False
            static_admin = self.module_dir / "static" / "admin"
            if not static_admin.exists() or not (static_admin / "index.html").exists():
                self.console.print(
                    f"\n[bold]{self.i18n.get('step')} 1/2[/bold]: "
                    f"{self.i18n.get('compiling')} (webui)"
                )
                if not self._run_command("npm", ["run", "build"], cwd=str(webui_dir)):
                    self.console.print(f"[red]✗ {self.i18n.get('failed')}[/red]")
                    return False
            else:
                self.console.print(
                    f"\n[dim]✔ static/admin 已存在，跳过前端构建[/dim]"
                )

        # 3) 根目录游离二进制健康检查（不阻塞 build，仅 warn）
        self._check_root_exe_artifacts()

        # 4) 架构别名归一：CLI 传 amd64、TUI 传 x64，两种写法都要能用
        arch_key = {"amd64": "x64", "x86_64": "x64", "64": "x64"}.get(arch, arch)

        # 5) 产物目录 dist/（.goreleaser.yml 同款输出目录）
        ldflags = self._build_gomod_ldflags(build_type)
        output_dir = self.module_dir / self.DIST_DIR
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.console.print(f"[red]✗[/red] {self.i18n.get('cmd_error')}: {e}")
            return False

        def compile_one(goos: str, goarch: str, out_name: str, step_label: str) -> bool:
            out_path = output_dir / out_name
            env = self._get_subprocess_env()
            env["GOOS"] = goos
            env["GOARCH"] = goarch
            env["CGO_ENABLED"] = "0"  # 纯 Go，跨平台交叉编译无需 C 工具链
            self.console.print(
                f"\n[bold]{step_label}[/bold]: "
                f"{self.i18n.get('building')} {goos}/{goarch} → "
                f"{self.DIST_DIR}/{out_name}"
            )
            return self._run_command(
                "go",
                self._gomod_build_args(out_path, ldflags),
                cwd=str(self.module_dir),
                extra_env=env,
            )

        # 6) all → 矩阵构建（与 .goreleaser.yml 的 goos/goarch 矩阵一致）
        if platform == "all":
            targets = [
                ("windows", "amd64"),
                ("windows", "arm64"),
                ("linux", "amd64"),
                ("linux", "arm64"),
                ("darwin", "amd64"),
                ("darwin", "arm64"),
            ]
            for idx, (goos, goarch) in enumerate(targets, 1):
                out_name = self._gomod_output_name(goos, goarch, force_suffix=True)
                if not compile_one(goos, goarch, out_name, f"{self.i18n.get('step')} {idx}/{len(targets)}"):
                    self.console.print(f"[red]✗ {goos}/{goarch} {self.i18n.get('failed')}[/red]")
                    return False
            self.console.print(f"\n[bold green]✓ {self.i18n.get('success')}[/bold green]")
            self.console.print(f"[cyan]{self.i18n.get('output_dir')}[/cyan]: {output_dir}")
            self.console.print(
                f"[cyan]{self.i18n.get('output_size')}[/cyan]: "
                f"{self._format_size(self._get_directory_size(output_dir))}"
            )
            return True

        # 7) 单平台
        if platform not in self.GOMOD_PLATFORM_MAP or arch_key not in self.GOMOD_PLATFORM_MAP[platform]:
            self.console.print(
                f"[red]✗[/red] {self.i18n.get('unsupported_combo')}: {platform}/{arch}"
            )
            return False

        goos, goarch = self.GOMOD_PLATFORM_MAP[platform][arch_key]
        out_name = self._gomod_output_name(goos, goarch)

        if not compile_one(goos, goarch, out_name, f"{self.i18n.get('step')} 1/1"):
            self.console.print(f"[red]✗ {self.i18n.get('failed')}[/red]")
            return False

        out_path = output_dir / out_name
        self.console.print(f"\n[bold green]✓ {self.i18n.get('success')}[/bold green]")
        if out_path.exists():
            self.console.print(
                f"[cyan]{self.i18n.get('output_dir')}[/cyan]: {out_path} "
                f"({self._format_size(out_path.stat().st_size)})"
            )
        return True

    def _build_gomod_ldflags(self, build_type: str = "production") -> str:
        """Go 模块模式的 ldflags

        - production：-s -w 去符号表 + 注入 dns-opti/internal/cli.Version
        - development：保留符号与调试信息，仅注入版本号
        （与 .goreleaser.yml 的 `-s -w -X dns-opti/internal/cli.Version={{ .Version }}` 对齐）
        """
        strip = "-s -w " if build_type != "development" else ""
        return f"{strip}-X {self.APP_VERSION_VAR}={self._app_version}".strip()

    # ------------------------------------------------------------------
    # W2: Wails 单平台构建
    # ------------------------------------------------------------------
    def _build_single_platform(self, build_type: str, platform: str, arch: str) -> bool:
        """单平台构建（Wails 模式）

        W2: 关键改造
        - 删除 `npm run build` 步骤（wails build 内部已自动执行 frontend:install + frontend:build）
        - 改为 wails build -platform <plat> [-nsis for Windows]
        - 注入 ldflags（-X main.appVersion / main.appOwner / main.appRepo）+ -trimpath
        - devtools / debug 走 wails build -devtools -debug
        """
        platform_str = self.PLATFORM_ARCH_MAP[platform][arch]
        self.console.print(
            f"\n[bold]{self.i18n.get('step')} 1{self.i18n.get('of')}2[/bold]: "
            f"{self.i18n.get('compiling')} ({platform_str})"
        )

        cmd_args = self._build_wails_args(platform_str, build_type, platform)

        if not self._run_command("wails", cmd_args, cwd=str(self.wails_project_dir)):
            self.console.print(f"[red]✗ {self.i18n.get('failed')}[/red]")
            return False

        self.console.print(f"\n[bold green]✓ {self.i18n.get('success')}[/bold green]")
        bin_dir = self.wails_project_dir / "build" / "bin"
        if bin_dir.exists():
            self.console.print(f"[cyan]{self.i18n.get('output_dir')}[/cyan]: {bin_dir}")
            self.console.print(
                f"[cyan]{self.i18n.get('output_size')}[/cyan]: "
                f"{self._format_size(self._get_directory_size(bin_dir))}"
            )

        return True

    def _build_wails_args(
        self,
        platform_str: str,
        build_type: str,
        platform_key: str,
    ) -> list[str]:
        """组装 wails build 命令行参数"""
        ldflags = self._build_wails_ldflags()
        args: list[str] = ["build", "-trimpath", "-ldflags", ldflags, "-platform", platform_str]

        if platform_key == "win":
            args.append("-nsis")

        if build_type == "development":
            args.extend(["-devtools", "-debug"])
            if platform_key == "win":
                args.remove("-nsis")

        return args

    def _build_wails_ldflags(self) -> str:
        """Wails 模式 ldflags：注入 appVersion / appOwner / appRepo"""
        return (
            f"-s -w -X main.appVersion={self._app_version} "
            f"-X main.appOwner={self.APP_OWNER} "
            f"-X main.appRepo={self.APP_REPO}"
        )

    # ------------------------------------------------------------------
    # 全部平台
    # ------------------------------------------------------------------
    def _build_all_platforms(self, build_type: str) -> bool:
        """Wails 模式：构建当前 host 平台

        跨平台矩阵构建在 CI 中通过 GitHub Actions 拆分，本工具仅作快速验证。
        """
        self.console.print(
            f"\n[bold]{self.i18n.get('step')} 1{self.i18n.get('of')}2[/bold]: "
            f"{self.i18n.get('compiling')} (all=current host)"
        )

        ldflags = self._build_wails_ldflags()
        args = ["build", "-trimpath", "-ldflags", ldflags, "-platform", "all"]
        if build_type == "development":
            args.extend(["-devtools", "-debug"])

        if not self._run_command("wails", args, cwd=str(self.wails_project_dir)):
            self.console.print(f"[red]✗ {self.i18n.get('failed')}[/red]")
            return False

        self.console.print(f"\n[bold green]✓ {self.i18n.get('success')}[/bold green]")
        bin_dir = self.wails_project_dir / "build" / "bin"
        if bin_dir.exists():
            self.console.print(f"[cyan]{self.i18n.get('output_dir')}[/cyan]: {bin_dir}")
            self.console.print(
                f"[cyan]{self.i18n.get('output_size')}[/cyan]: "
                f"{self._format_size(self._get_directory_size(bin_dir))}"
            )
        return True

    # ------------------------------------------------------------------
    # 清理菜单
    # ------------------------------------------------------------------
    def show_clean_menu(self):
        """显示清理菜单（Wails 1-8 / dns-opti 1-5）"""
        self.console.print()

        is_wails = self.project_mode == "wails"
        table = Table(show_header=True, box=ROUNDED, border_style="blue", padding=(0, 2))
        table.add_column("选项", style="cyan", justify="center", width=6)
        table.add_column("操作", style="white")
        table.add_column("影响", style="yellow")

        if is_wails:
            table.add_row("1", self.i18n.get("clean_all"), self.i18n.get("impact_clean_all"))
            table.add_row("2", self.i18n.get("clean_dist"), self.i18n.get("impact_clean_dist"))
            table.add_row("3", self.i18n.get("clean_bin"), self.i18n.get("impact_clean_bin"))
            table.add_row("4", self.i18n.get("clean_npm"), self.i18n.get("impact_clean_npm"))
            table.add_row("5", self.i18n.get("clean_wailsjs"), self.i18n.get("impact_clean_wailsjs"))
            table.add_row("6", self.i18n.get("clean_pycache"), self.i18n.get("impact_clean_pycache"))
            table.add_row("7", self.i18n.get("clean_root_exe"), self.i18n.get("impact_clean_root_exe"))
            table.add_row("8", self.i18n.get("back"), "")
            max_opt = 8
            back_opt = "8"
        else:
            # Go 模块模式（dns-opti）：dist/ 按产物文件名清理，不整目录删除
            table.add_row("1", self.i18n.get("clean_all"), self.i18n.get("impact_clean_all"))
            table.add_row("2", self.i18n.get("clean_dist"), self.i18n.get("impact_clean_dist"))
            table.add_row("3", self.i18n.get("clean_pycache"), self.i18n.get("impact_clean_pycache"))
            table.add_row("4", self.i18n.get("clean_root_exe"), self.i18n.get("impact_clean_root_exe"))
            table.add_row("5", self.i18n.get("back"), "")
            max_opt = 5
            back_opt = "5"

        self.console.print(
            Panel(
                table,
                title=f"[bold yellow]{self.i18n.get('clean_menu')}[/bold yellow]",
                border_style="yellow",
            )
        )

        choices = [str(i) for i in range(1, max_opt + 1)]
        choice = Prompt.ask(
            f"[bold cyan]{self.i18n.get('clean_menu')}[/bold cyan] [cyan][1-{max_opt}][/cyan]",
            choices=choices,
            default="1",
        )

        if choice == back_opt:
            return

        if is_wails:
            targets_map = {
                "1": "all", "2": "dist", "3": "bin", "4": "npm",
                "5": "wailsjs", "6": "pycache", "7": "root_exe",
            }
        else:
            targets_map = {
                "1": "all", "2": "dist", "3": "pycache", "4": "root_exe",
            }
        target = targets_map[choice]

        if Confirm.ask(
            f"\n[bold yellow]{self.i18n.get('confirm_clean')}[/bold yellow]\n"
            f"{self.i18n.get('confirm_clean_msg')}"
        ):
            self.clean([target])

        Prompt.ask(f"\n[green]✓[/green] {self.i18n.get('press_enter')}")

    def _clean_dist_artifacts(self) -> int:
        """清理 dist/ 下的构建产物（按 GOMOD_DIST_PATTERNS 文件名匹配）

        dist/ 除了 dns-opti 二进制与发布压缩包外，还有 demo JSON、截图等本地
        参考文件，因此绝不整目录 rmtree，只删除匹配产物模式的文件。
        """
        dist_dir: Optional[Path] = None
        for base in (self.module_dir, self.project_root):
            candidate = base / self.DIST_DIR
            if candidate.is_dir():
                dist_dir = candidate
                break
        if dist_dir is None:
            self.console.print(
                f"[dim]○ {self.DIST_DIR}/ - {self.i18n.get('not_exist')}[/dim]"
            )
            return 0

        import fnmatch

        freed = 0
        removed = 0
        for file_path in sorted(p for p in dist_dir.rglob("*") if p.is_file()):
            if not any(
                fnmatch.fnmatch(file_path.name, pattern)
                for pattern in self.GOMOD_DIST_PATTERNS
            ):
                continue
            rel = file_path.relative_to(dist_dir)
            try:
                size = file_path.stat().st_size
                file_path.unlink()
            except Exception as e:
                self.console.print(
                    f"  [red]✗[/red] {self.i18n.get('delete_failed')}: {rel} ({e})"
                )
                continue
            self.console.print(
                f"[yellow]{self.i18n.get('cleaning')}[/yellow] "
                f"{self.DIST_DIR}/{rel} ({self._format_size(size)})"
            )
            self.console.print(f"  [green]✓[/green] {self.i18n.get('cleaned')}")
            freed += size
            removed += 1

        if removed == 0:
            self.console.print(
                f"[dim]○ {self.DIST_DIR}/ - "
                f"无匹配的构建产物（{', '.join(self.GOMOD_DIST_PATTERNS)}）[/dim]"
            )
        return freed

    def clean(self, targets: list[str]) -> bool:
        """执行清理；按项目模式选择对应的清理目标集"""
        # 按模式选择清理目标集
        is_gomod = self.project_mode != "wails"
        if self.project_mode == "wails":
            clean_targets = self.CLEAN_TARGETS
            clean_file_targets = self.CLEAN_FILE_TARGETS
        else:
            clean_targets = self.GOMOD_CLEAN_TARGETS
            clean_file_targets = self.GOMOD_CLEAN_FILE_TARGETS

        # 兼容旧 CLI 别名：gomod 模式下 --bin 等价于清理 dist/ 产物；
        # --npm / --wailsjs 在本项目无对应目录，直接跳过
        if is_gomod:
            mapped: list[str] = []
            for t in targets:
                if t == "bin":
                    mapped.append("dist")
                elif t in {"npm", "wailsjs"}:
                    self.console.print(
                        f"[dim]○ {t} - {self.i18n.get('no_frontend')}[/dim]"
                    )
                else:
                    mapped.append(t)
            targets = mapped

        valid_keys = set(clean_targets.keys()) | set(clean_file_targets.keys())

        if "all" in targets:
            targets_to_clean = list(valid_keys)
        else:
            targets_to_clean = targets

        final_targets: list[str] = []
        for t in targets_to_clean:
            if t in valid_keys:
                final_targets.append(t)
            elif t in self.LEGACY_CLEAN_TARGETS:
                self.console.print(
                    f"[yellow]{self.i18n.get('warning')}[/yellow]: "
                    f"[cyan]{t}[/cyan] → {self.i18n.get('not_exist')} (legacy, no-op)"
                )
            else:
                self.console.print(
                    f"[red]✗[/red] {self.i18n.get('unknown_target')}: {t}"
                )

        self.console.print(
            f"\n[cyan]{self.i18n.get('cleaning')}[/cyan]: "
            f"{', '.join(final_targets) or '(nothing)'}"
        )

        total_cleaned = 0

        # 目录型清理（优先 module_dir，再回退 project_root）
        base_dirs = [self.module_dir, self.project_root]
        for target in final_targets:
            if target not in clean_targets:
                continue
            # dns-opti 的 dist/ 混有 demo JSON / 截图等本地文件，只能按产物文件名清理
            if is_gomod and target == "dist":
                total_cleaned += self._clean_dist_artifacts()
                continue
            dir_name = clean_targets[target]
            dir_path = None
            for base in base_dirs:
                candidate = base / dir_name
                if candidate.exists():
                    dir_path = candidate
                    break

            if dir_path is None:
                self.console.print(f"[dim]○ {dir_name}/ - {self.i18n.get('not_exist')}[/dim]")
                continue

            size = self._get_directory_size(dir_path)
            self.console.print(
                f"[yellow]{self.i18n.get('cleaning')}[/yellow] {dir_name}/ "
                f"({self._format_size(size)})"
            )

            try:
                shutil.rmtree(dir_path)
                self.console.print(f"  [green]✓[/green] {self.i18n.get('cleaned')}")
                total_cleaned += size
            except Exception as e:
                self.console.print(f"  [red]✗[/red] {self.i18n.get('delete_failed')}: {e}")

        # 文件型清理（根目录游离 exe 等）
        for target in final_targets:
            if target not in clean_file_targets:
                continue
            for file_name in clean_file_targets[target]:
                file_path = self.project_root / file_name
                if not file_path.exists():
                    self.console.print(
                        f"[dim]○ {file_name} - {self.i18n.get('not_exist')}[/dim]"
                    )
                    continue
                try:
                    size = file_path.stat().st_size
                    file_path.unlink()
                    self.console.print(
                        f"[yellow]{self.i18n.get('cleaning')}[/yellow] {file_name} "
                        f"({self._format_size(size)})"
                    )
                    self.console.print(f"  [green]✓[/green] {self.i18n.get('cleaned')}")
                    total_cleaned += size
                except Exception as e:
                    self.console.print(
                        f"  [red]✗[/red] {self.i18n.get('delete_failed')}: {e}"
                    )

        self.console.print(f"\n[bold green]✓ {self.i18n.get('clean_complete')}[/bold green]")
        self.console.print(
            f"[bold]{self.i18n.get('space_freed')}[/bold]: "
            f"[cyan]{self._format_size(total_cleaned)}[/cyan]"
        )

        return True

    # ------------------------------------------------------------------
    # 多包管理器自动检测（auto-detect from lockfile）
    # ------------------------------------------------------------------
    def _detect_pkg_manager(self, frontend_dir: Path) -> str:
        """根据 frontend/ 下的 lockfile 自动检测包管理器

        优先级：pnpm > yarn > npm（pnpm 最快，yarn 其次，npm 兜底）
        返回的 cmd 是系统 PATH 中可直接调用的命令名（已通过 _resolve_executable 解析）。
        """
        pnpm_lock = frontend_dir / "pnpm-lock.yaml"
        yarn_lock = frontend_dir / "yarn.lock"
        npm_lock = frontend_dir / "package-lock.json"

        # 1) 优先 pnpm
        if pnpm_lock.exists():
            exe = self._resolve_executable("pnpm")
            if exe is not None:
                self.console.print(
                    f"[dim]{self.i18n.get('pkg_manager_detected')}[/dim]: "
                    f"[cyan]{self.i18n.get('pkg_manager_pnpm')}[/cyan] "
                    f"([dim]pnpm-lock.yaml[/dim])"
                )
                return "pnpm"
        # 2) 其次 yarn
        if yarn_lock.exists():
            exe = self._resolve_executable("yarn")
            if exe is not None:
                self.console.print(
                    f"[dim]{self.i18n.get('pkg_manager_detected')}[/dim]: "
                    f"[cyan]{self.i18n.get('pkg_manager_yarn')}[/cyan] "
                    f"([dim]yarn.lock[/dim])"
                )
                return "yarn"
        # 3) 兜底 npm
        self.console.print(
            f"[dim]{self.i18n.get('pkg_manager_detected')}[/dim]: "
            f"[cyan]{self.i18n.get('pkg_manager_npm')}[/cyan]"
        )
        return "npm"

    def _run_pkg_install(self, frontend_dir: Path) -> bool:
        """根据检测到的包管理器执行 install 命令

        - npm install
        - yarn install --frozen-lockfile
        - pnpm install --frozen-lockfile
        """
        mgr = self._detect_pkg_manager(frontend_dir)
        if mgr == "yarn":
            return self._run_command("yarn", ["install", "--frozen-lockfile"], cwd=str(frontend_dir))
        if mgr == "pnpm":
            return self._run_command("pnpm", ["install", "--frozen-lockfile"], cwd=str(frontend_dir))
        return self._run_command("npm", ["install"], cwd=str(frontend_dir))

    def _get_pkg_manager_lock_files(self, frontend_dir: Path) -> list[Path]:
        """返回对应包管理器的所有 lock 文件路径（用于 force 重装时一并清理）"""
        files: list[Path] = []
        for name in ("pnpm-lock.yaml", "yarn.lock", "package-lock.json"):
            p = frontend_dir / name
            if p.exists():
                files.append(p)
        return files

    # ------------------------------------------------------------------
    # Go 后端依赖安装（新增）
    # ------------------------------------------------------------------
    def install_go_dependencies(self, force: bool = False) -> bool:
        """安装/刷新 Go 后端依赖

        - force=False（默认）：仅当 go.sum 不存在时执行 go mod download + go mod tidy
        - force=True：先删除 go.sum 后再执行，强制刷新锁定文件
        """
        # 1) Go 可用性检测
        if not self._check_go_available():
            return False

        # 路径探测：Go 模块模式直接使用 self.module_dir，Wails 模式走旧有回退逻辑
        if self.project_mode == "gomod":
            backend_dir = self.module_dir
            go_mod = backend_dir / "go.mod"
            go_sum = backend_dir / "go.sum"
        else:
            # Wails 模式：从仓库根或 backend/ 找 go.mod
            go_mod = self.project_root / "go.mod"
            go_sum = self.project_root / "go.sum"
            backend_dir = self.project_root
            if not go_mod.exists():
                alt_backend = self.project_root / "backend"
                alt_mod = alt_backend / "go.mod"
                if alt_backend.exists() and alt_mod.exists():
                    backend_dir = alt_backend
                    go_mod = alt_mod
                    go_sum = alt_backend / "go.sum"

        if not backend_dir.exists() or not go_mod.exists():
            self.console.print(
                f"[red]{self.i18n.get('error')}[/red]: "
                f"{self.i18n.get('go_mod_not_found')}"
            )
            self.console.print(
                f"[dim]{self.i18n.get('project_dir')}[/dim]: [cyan]{backend_dir}[/cyan]"
            )
            return False

        # 2) 非强制 + go.sum 已存在：跳过
        if not force and go_sum.exists():
            self.console.print(
                f"[green]✓[/green] {self.i18n.get('install_deps_go_already')}: "
                f"[cyan]{go_sum}[/cyan]"
            )
            self.console.print(
                f"[dim]{self.i18n.get('go_deps_target')}[/dim]"
            )
            return True

        # 3) 强制重装：删除 go.sum 后重新生成
        if force and go_sum.exists():
            self.console.print(
                f"[yellow]{self.i18n.get('cleaning')}[/yellow] "
                f"[cyan]{go_sum.name}[/cyan] "
                f"({self._format_size(go_sum.stat().st_size)})"
            )
            try:
                go_sum.unlink()
                self.console.print(f"  [green]✓[/green] {self.i18n.get('cleaned')}")
            except Exception as e:
                self.console.print(
                    f"  [red]✗[/red] {self.i18n.get('delete_failed')}: {e}"
                )
                return False

        # 4) 执行 go mod download + go mod tidy
        self.console.print(
            f"\n[bold]{self.i18n.get('install_deps_go')}[/bold]: "
            f"[cyan]{backend_dir}[/cyan]"
        )
        self.console.print(
            f"[dim]{self.i18n.get('go_deps_target')}[/dim]"
        )
        ok1 = self._run_command(
            "go",
            ["mod", "download"],
            cwd=str(backend_dir),
        )
        ok2 = self._run_command(
            "go",
            ["mod", "tidy"],
            cwd=str(backend_dir),
        )
        if ok1 and ok2:
            self.console.print(
                f"[bold green]✓[/bold green] {self.i18n.get('install_deps_go_done')}"
            )
            return True
        return False

    # ------------------------------------------------------------------
    # 统一入口：按 target 安装（frontend / backend / all）
    # ------------------------------------------------------------------
    def install_dependencies_unified(
        self,
        target: str = "all",
        force: bool = False,
    ) -> bool:
        """统一的依赖安装入口（CLI/TUI 共用）

        - target="frontend"：仅前端 npm 依赖
        - target="backend"：仅 Go 后端依赖
        - target="all"：前端 + 后端依次执行
        """
        target_norm = (target or "all").lower()
        if target_norm not in {"frontend", "backend", "all"}:
            self.console.print(
                f"[red]{self.i18n.get('error')}[/red]: "
                f"target must be one of frontend/backend/all, got '{target}'"
            )
            return False

        results: list[bool] = []
        if target_norm in {"frontend", "all"}:
            self.console.print(
                f"\n[bold cyan]━━━ frontend deps ━━━[/bold cyan]"
            )
            results.append(self.install_dependencies(force=force))
        if target_norm in {"backend", "all"}:
            self.console.print(
                f"\n[bold cyan]━━━ backend Go deps ━━━[/bold cyan]"
            )
            results.append(self.install_go_dependencies(force=force))

        return all(results) if results else False

    # ------------------------------------------------------------------
    # 依赖安装（W4: 操作 frontend/node_modules）
    # ------------------------------------------------------------------
    def install_dependencies(self, force: bool = False) -> bool:
        """安装/重装前端 npm 依赖（操作 frontend/node_modules 或 webui/node_modules）

        - force=False（默认）：仅当前端依赖目录不存在才执行 install
        - force=True：先删除依赖目录与全部 lockfile 后再 install

        本项目（dns-opti）无 npm 前端目录，直接跳过并返回成功。
        自动检测包管理器：pnpm-lock.yaml > yarn.lock > package-lock.json > npm 兜底
        """
        # 按项目模式选择前端目录
        if self.project_mode == "gomod":
            frontend_dir = self.module_dir / "webui"
        else:
            # Wails 模式：frontend/
            frontend_dir = self.project_root / "frontend"
            if not frontend_dir.exists():
                if (self.project_root / "backend" / "frontend").exists():
                    frontend_dir = self.project_root / "backend" / "frontend"
                elif (self.project_root / "Maxpro2API" / "frontend").exists():
                    frontend_dir = self.project_root / "Maxpro2API" / "frontend"
                elif (self.project_root / "maxpro2api" / "frontend").exists():
                    frontend_dir = self.project_root / "maxpro2api" / "frontend"
                elif (self.project_root / ".." / "frontend").exists():
                    alt_frontend = (self.project_root / ".." / "frontend").resolve()
                    if alt_frontend.exists():
                        frontend_dir = alt_frontend
        if not frontend_dir.exists():
            if self.project_mode == "gomod":
                self.console.print(
                    f"[dim]{self.i18n.get('no_frontend')} "
                    f"(internal/web/static 为 go:embed 静态资源)[/dim]"
                )
                return True
            self.console.print(
                f"[red]{self.i18n.get('error')}[/red]: "
                f"{self.i18n.get('not_exist')}: {frontend_dir}"
            )
            return False

        # 1) Node.js/npm 可用性检测（仅在确实存在前端目录时才需要）
        if not self._check_node_available():
            return False

        node_modules = frontend_dir / "node_modules"

        # 2) 非强制 + 已安装：直接提示成功，不重复安装
        if not force and node_modules.exists():
            self.console.print(
                f"[green]✓[/green] {self.i18n.get('deps_already_installed')}: "
                f"[cyan]{node_modules}[/cyan]"
            )
            self.console.print(
                f"[dim]{self.i18n.get('project_dir')}[/dim]: "
                f"[cyan]{frontend_dir}[/cyan]"
            )
            self.console.print(
                f"[dim]{self.i18n.get('install_deps_target')}[/dim]"
            )
            return True

        # 3) 强制重装：删除 frontend/node_modules 与所有 lockfile
        if force:
            if not node_modules.exists():
                self.console.print(
                    f"[yellow]{self.i18n.get('warning')}[/yellow]: "
                    f"{self.i18n.get('no_node_modules_skip_reinstall')}"
                )
            else:
                self.console.print(
                    f"[yellow]{self.i18n.get('cleaning')}[/yellow] "
                    f"[cyan]{node_modules.name}/[/cyan] "
                    f"({self._format_size(self._get_directory_size(node_modules))})"
                )
                try:
                    shutil.rmtree(node_modules)
                    self.console.print(f"  [green]✓[/green] {self.i18n.get('cleaned')}")
                except Exception as e:
                    self.console.print(
                        f"  [red]✗[/red] {self.i18n.get('delete_failed')}: {e}"
                    )
                    return False

            for lock in self._get_pkg_manager_lock_files(frontend_dir):
                try:
                    lock.unlink()
                    self.console.print(
                        f"  [green]✓[/green] {self.i18n.get('cleaned')}: "
                        f"[cyan]{lock.name}[/cyan]"
                    )
                except Exception as e:
                    self.console.print(
                        f"  [yellow]{self.i18n.get('warning')}[/yellow]: "
                        f"{self.i18n.get('delete_failed')}: {e}"
                    )

        # 4) 执行包管理器 install（在 frontend/ 下）
        self.console.print(
            f"\n[bold]{self.i18n.get('installing_deps')}[/bold]: "
            f"[cyan]{frontend_dir}[/cyan]"
        )
        self.console.print(
            f"[dim]{self.i18n.get('install_deps_target')}[/dim]"
        )
        return self._run_pkg_install(frontend_dir)

    # ------------------------------------------------------------------
    # TUI 安装依赖子菜单
    # ------------------------------------------------------------------
    def show_install_menu(self) -> None:
        """TUI 模式下的安装依赖子菜单（支持前端 / 后端 / 全部）"""
        # 按项目模式选择前端目录
        if self.project_mode == "gomod":
            frontend_dir = self.module_dir / "webui"
        else:
            frontend_dir = self.project_root / "frontend"
            if not frontend_dir.exists():
                if (self.project_root / "backend" / "frontend").exists():
                    frontend_dir = self.project_root / "backend" / "frontend"
                elif (self.project_root / "Maxpro2API" / "frontend").exists():
                    frontend_dir = self.project_root / "Maxpro2API" / "frontend"

        node_modules = frontend_dir / "node_modules" if frontend_dir.exists() else None

        # Go 模块路径：Go 模块模式直接使用 self.module_dir
        if self.project_mode == "gomod":
            backend_dir = self.module_dir
            go_mod = backend_dir / "go.mod"
            go_sum = backend_dir / "go.sum"
        else:
            backend_dir = self.project_root
            go_mod = self.project_root / "go.mod"
            go_sum = self.project_root / "go.sum"
            if not go_mod.exists():
                alt_be = self.project_root / "backend"
                alt_mod = alt_be / "go.mod"
                if alt_be.exists() and alt_mod.exists():
                    backend_dir = alt_be
                    go_mod = alt_mod
                    go_sum = alt_be / "go.sum"

        # 顶层状态提示
        self.console.print()
        if not frontend_dir.exists():
            fe_state = f"[dim]- {self.i18n.get('no_frontend')}[/dim]"
        elif node_modules is not None and node_modules.exists():
            fe_state = f"[green]✓[/green] {self.i18n.get('deps_already_installed')}"
        else:
            fe_state = f"[yellow]⚠[/yellow] {self.i18n.get('no_node_modules')}"
        be_state = (
            f"[green]✓[/green] {self.i18n.get('install_deps_go_already')}"
            if go_sum is not None and go_sum.exists()
            else (
                f"[red]✗[/red] {self.i18n.get('go_mod_not_found')}"
                if go_mod is None or not go_mod.exists()
                else f"[yellow]⚠[/yellow] {self.i18n.get('go_sum_lock')} {self.i18n.get('not_exist')}"
            )
        )
        self.console.print(
            f"  frontend: {fe_state}\n"
            f"  backend : {be_state}"
        )

        # 前端目录缺失（dns-opti 属正常情况：无 npm 前端，仅提示不阻塞）
        if not frontend_dir.exists():
            if self.project_mode != "gomod":
                self.console.print(
                    f"[red]{self.i18n.get('error')}[/red]: "
                    f"{self.i18n.get('not_exist')}: {frontend_dir}"
                )
                Prompt.ask(f"\n[green]✓[/green] {self.i18n.get('press_enter')}")
                return
            self.console.print(
                f"[dim]{self.i18n.get('no_frontend')} "
                f"(internal/web/static 为 go:embed 静态资源)[/dim]"
            )

        # 后端目录缺失（仅提示，不阻塞）
        if backend_dir.exists() and go_mod is not None and go_mod.exists():
            pass  # ok
        else:
            self.console.print(
                f"[yellow]{self.i18n.get('warning')}[/yellow]: "
                f"{self.i18n.get('go_mod_not_found')}"
            )

        # 选 1 时直接走前端/全部/后端的二级菜单
        self.console.print()
        table = Table(show_header=False, box=ROUNDED, border_style="blue", padding=(0, 2))
        table.add_column("Option", style="cyan", justify="right")
        table.add_column("Description", style="white")

        table.add_row("1", self.i18n.get("deps_target_frontend"))
        table.add_row("2", self.i18n.get("deps_target_backend"))
        table.add_row("3", self.i18n.get("deps_target_all"))
        table.add_row("4", self.i18n.get("back"))

        self.console.print(
            Panel(
                table,
                title=f"[bold yellow]{self.i18n.get('select_deps_target')}[/bold yellow]",
                border_style="yellow",
            )
        )

        target = Prompt.ask(
            f"[bold cyan]{self.i18n.get('select_deps_target')}[/bold cyan] [cyan][1-4][/cyan]",
            choices=["1", "2", "3", "4"],
            default="3",
        )

        if target == "4":
            return

        if target == "1":
            self._tui_install_frontend(force=False)
        elif target == "2":
            self.install_go_dependencies(force=False)
            Prompt.ask(f"\n[green]✓[/green] {self.i18n.get('press_enter')}")
        elif target == "3":
            self.install_dependencies_unified(target="all", force=False)
            Prompt.ask(f"\n[green]✓[/green] {self.i18n.get('press_enter')}")

    # ------------------------------------------------------------------
    # TUI 前端依赖子流程（更新 / 重装）
    # ------------------------------------------------------------------
    def _tui_install_frontend(self, force: bool = False) -> None:
        """前端依赖子流程：自动检测包管理器，更新或重装"""
        if self.project_mode == "gomod":
            frontend_dir = self.module_dir / "webui"
        else:
            frontend_dir = self.project_root / "frontend"
        if not frontend_dir.exists():
            self.console.print(
                f"[dim]{self.i18n.get('no_frontend')}[/dim]"
            )
            Prompt.ask(f"\n[green]✓[/green] {self.i18n.get('press_enter')}")
            return
        node_modules = frontend_dir / "node_modules"

        if not force and node_modules.exists():
            # 已安装 → 给出子菜单
            self.console.print()
            table = Table(show_header=False, box=ROUNDED, border_style="blue", padding=(0, 2))
            table.add_column("Option", style="cyan", justify="right")
            table.add_column("Description", style="white")
            table.add_row("1", self.i18n.get("install_deps_update"))
            table.add_row("2", self.i18n.get("install_deps_reinstall"))
            table.add_row("3", self.i18n.get("back"))

            self.console.print(
                Panel(
                    table,
                    title=f"[bold yellow]{self.i18n.get('select_install_mode')}[/bold yellow]",
                    border_style="yellow",
                )
            )

            choice = Prompt.ask(
                f"[bold cyan]{self.i18n.get('select_install_mode')}[/bold cyan] [cyan][1-3][/cyan]",
                choices=["1", "2", "3"],
                default="1",
            )

            if choice == "1":
                self.console.print(
                    f"\n[bold]{self.i18n.get('installing_deps')}[/bold]: "
                    f"[cyan]{frontend_dir}[/cyan]"
                )
                self._run_pkg_install(frontend_dir)
            elif choice == "2":
                if Confirm.ask(
                    f"\n[bold yellow]{self.i18n.get('confirm_clean')}[/bold yellow]\n"
                    f"{self.i18n.get('reinstall_confirm_msg')}"
                ):
                    self.install_dependencies(force=True)
        else:
            # 首次或强制重装
            if force and node_modules.exists():
                if Confirm.ask(
                    f"\n[bold yellow]{self.i18n.get('confirm_clean')}[/bold yellow]\n"
                    f"{self.i18n.get('reinstall_confirm_msg')}"
                ):
                    self.install_dependencies(force=True)
            else:
                self.install_dependencies(force=False)

        Prompt.ask(f"\n[green]✓[/green] {self.i18n.get('press_enter')}")

    # ------------------------------------------------------------------
    # 冒烟测试（菜单 5 / CLI smoke 子命令）
    # ------------------------------------------------------------------
    def run_smoke(self, no_launch: bool = False, binary: Optional[str] = None) -> bool:
        """运行冒烟测试

        - 优先执行 scripts/smoke.{sh,ps1}（本仓库无 scripts/，会走回退分支）
        - 回退：go test ./... （可选 no_launch 时跳过任何进程启动）
        - binary 显式指定时，额外运行一次 `<binary> --version` 验证产物可执行
        """
        self.console.print()
        self.console.print(
            Panel(
                f"[cyan]{self.i18n.get('smoke_running')}[/cyan]\n"
                f"[dim]no_launch={no_launch} binary={binary or '(auto)'}[/dim]",
                title=f"[bold]{self.i18n.get('run_smoke')}[/bold]",
                border_style="cyan",
            )
        )

        # 优先调脚本；找不到再回退到 go test
        script_args = self._build_smoke_command(no_launch, binary)
        if script_args is None:
            # 回退：编译检查 + 全量单测（本项目测试分布在 internal/**）
            self.console.print(f"[dim]{self.i18n.get('smoke_fallback')}[/dim]")
            ok = self._run_command(
                "go",
                ["vet", "./..."],
                cwd=str(self.module_dir),
            )
            if ok:
                ok = self._run_command(
                    "go",
                    ["test", "-timeout", "120s", "-count=1", "./..."],
                    cwd=str(self.module_dir),
                )
            # 显式指定二进制时，验证它真的能跑起来
            if ok and binary:
                ok = self._run_command(binary, ["--version"], cwd=str(self.module_dir))
        else:
            cmd, args = script_args
            ok = self._run_command(cmd, args, cwd=str(self.project_root))

        if ok:
            self.console.print(f"[bold green]✓ {self.i18n.get('smoke_success')}[/bold green]")
            return True
        self.console.print(f"[bold red]✗ {self.i18n.get('smoke_failed')}[/bold red]")
        return False

    def _build_smoke_command(
        self, no_launch: bool, binary: Optional[str]
    ) -> Optional[tuple[str, list[str]]]:
        """根据 host 平台返回 (cmd, args)；None 表示回退到 go test"""
        if sys.platform == "win32":
            script = self.project_root / "scripts" / "smoke.ps1"
            if not script.exists():
                return None
            args = ["-NoProfile", "-File", str(script)]
            if no_launch:
                args.append("-NoLaunch")
            if binary:
                args.extend(["-Binary", binary])
            return ("powershell", args)
        # macOS / Linux
        script = self.project_root / "scripts" / "smoke.sh"
        if not script.exists():
            return None
        # 用 bash 显式执行，避免用户 shell 差异
        args = [str(script)]
        if no_launch:
            args.append("--no-launch")
        if binary:
            args.append(binary)
        return ("bash", args)


# ----------------------------------------------------------------------
# TUI 入口
# ----------------------------------------------------------------------
def run_tui():
    """运行交互式界面"""
    i18n = I18n()
    build_tool = BuildTool(i18n=i18n)

    while True:
        choice = build_tool.show_main_menu()

        if choice == "1":
            platform = build_tool.select_platform()
            arch = build_tool.select_arch(platform)
            build_tool.build("production", platform, arch)
            Prompt.ask(f"\n[green]✓[/green] {i18n.get('press_enter')}")

        elif choice == "2":
            platform = build_tool.select_platform()
            arch = build_tool.select_arch(platform)
            build_tool.build("development", platform, arch)
            Prompt.ask(f"\n[green]✓[/green] {i18n.get('press_enter')}")

        elif choice == "3":
            build_tool.show_clean_menu()

        elif choice == "4":
            # 安装依赖子菜单（首次安装 / 更新 / 彻底重装）
            build_tool.show_install_menu()

        elif choice == "5":
            # 新增：运行冒烟测试
            no_launch = Confirm.ask(
                f"[bold cyan]{i18n.get('smoke_no_launch')}[/bold cyan]?",
                default=False,
            )
            build_tool.run_smoke(no_launch=no_launch)
            Prompt.ask(f"\n[green]✓[/green] {i18n.get('press_enter')}")

        elif choice == "6":
            # M1: 切换镜像模式
            build_tool.use_mirror = not build_tool.use_mirror
            status = i18n.get("mirror_on") if build_tool.use_mirror else i18n.get("mirror_off")
            build_tool.console.print(f"[bold green]✓[/bold green] {i18n.get('mirror_current_status')}: [bold]{status}[/bold]")
            Prompt.ask(f"\n[green]✓[/green] {i18n.get('press_enter')}")

        elif choice == "7":
            build_tool.console.print("[bold cyan]Bye![/bold cyan]")
            break


# ----------------------------------------------------------------------
# CLI 参数解析
# ----------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="dns-opti Build Tool (Go module: ./cmd/dns-opti, artifacts in dist/)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--cli", action="store_true", help="Command line mode (non-interactive)")
    parser.add_argument("--lang", choices=["zh", "en"], help="Language (default: auto-detect)")

    subparsers = parser.add_subparsers(dest="command")

    # build 子命令
    build_parser = subparsers.add_parser("build", help="Build project (go build, output to dist/)")
    build_parser.add_argument(
        "--type",
        choices=["production", "development"],
        default="production",
        help="Build type (default: production; development keeps symbols, no -s -w)",
    )
    build_parser.add_argument(
        "--platform",
        choices=["win", "mac", "linux", "all"],
        default="win",
        help="Target platform (default: win)",
    )
    build_parser.add_argument(
        "--arch",
        choices=["amd64", "arm64", "x64", "universal"],
        default="amd64",
        help="Target architecture (default: amd64)",
    )
    # 构建标签（.goreleaser.yml 的备用构建 dns-opti-nodoh3）
    build_parser.add_argument(
        "--tags",
        help="Go build tags, e.g. nodoh3 (drop QUIC/DoH3 deps, see .goreleaser.yml)",
    )
    # 是否用 scripts/build.sh / build.ps1 封装
    build_parser.add_argument(
        "--use-script",
        action="store_true",
        help="Delegate to scripts/build.{sh,ps1} instead of calling go directly (no-op if scripts are absent)",
    )
    # M1: 镜像构建开关
    build_parser.add_argument(
        "--mirror",
        action="store_true",
        help="Enable mirror mode (GOPROXY=goproxy.cn, GOSUMDB=off, NPM_CONFIG_REGISTRY=npmmirror.com)",
    )

    # clean 子命令
    clean_parser = subparsers.add_parser("clean", help="Clean build artifacts / caches")
    clean_parser.add_argument("--all", action="store_true", help="Clean all targets")
    clean_parser.add_argument("--dist", action="store_true", help="Clean dns-opti artifacts in dist/ (keeps demo JSON / screenshots)")
    clean_parser.add_argument("--bin", action="store_true", help="Alias of --dist in Go module mode; build/bin/ in Wails mode")
    clean_parser.add_argument("--npm", action="store_true", help="No-op in this project (no npm frontend)")
    clean_parser.add_argument("--wailsjs", action="store_true", help="Clean wailsjs/ (Wails only, no-op in Go module mode)")
    clean_parser.add_argument("--pycache", action="store_true", help="Clean __pycache__/")
    # W6: 清理根目录的游离二进制
    clean_parser.add_argument(
        "--root-exe",
        action="store_true",
        help="Clean root-level orphan binaries (dns-opti / dns-opti.exe from accidental `go build`)",
    )
    # 兼容旧 CLI 选项（提示已废弃但仍能解析）
    clean_parser.add_argument("--out", action="store_true", help="(deprecated) Clean out/")
    clean_parser.add_argument("--vite", action="store_true", help="(deprecated) Clean .vite/")

    # install 子命令
    install_parser = subparsers.add_parser("install", help="Install npm / go dependencies")
    install_parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Delete dependency cache (node_modules + lockfile / go.sum) before installing",
    )
    install_parser.add_argument(
        "--target",
        choices=["frontend", "backend", "all"],
        default="all",
        help="Dependency target (default: all). frontend=npm, backend=go mod",
    )
    install_parser.add_argument(
        "--manager",
        choices=["auto", "npm", "yarn", "pnpm"],
        default="auto",
        help="Frontend package manager (default: auto-detect from lockfile)",
    )

    # smoke 子命令（新增）
    smoke_parser = subparsers.add_parser("smoke", help="Run scripts/smoke.{sh,ps1}")
    smoke_parser.add_argument(
        "--no-launch",
        action="store_true",
        help="Only run E2E unit tests; do not launch desktop process",
    )
    smoke_parser.add_argument(
        "--binary",
        help="Explicit path to the binary under test (e.g. dist/dns-opti.exe)",
    )

    return parser.parse_args()


# ----------------------------------------------------------------------
# CLI → 业务调用映射
# ----------------------------------------------------------------------
def _normalize_arch(arch: str) -> str:
    """CLI 接受 x64 作为 amd64 的别名（兼容旧命令）"""
    return "amd64" if arch == "x64" else arch


def main() -> int:
    args = parse_args()

    # 修复 Bug K: TTY 不可用且无 --cli / 子命令时直接退出
    is_tty = sys.stdin.isatty() and sys.stdout.isatty()
    if not is_tty and not (args.cli or args.command):
        print(
            "ERROR: TTY not available. Use `python build_tool.py --cli build` or "
            "`python build_tool.py clean --all` for non-interactive use.",
            file=sys.stderr,
        )
        return 2

    i18n = I18n()
    if args.lang:
        i18n.set_language(args.lang)

    if args.cli or args.command:
        build_tool = BuildTool(i18n=i18n)

        # M1: 检查是否启用镜像模式
        if hasattr(args, "mirror") and args.mirror:
            build_tool.use_mirror = True

        if args.command == "build":
            arch = _normalize_arch(getattr(args, "arch", "amd64"))
            success = build_tool.build(
                build_type=args.type,
                platform=args.platform,
                arch=arch,
                tags=getattr(args, "tags", None),
            )
            return 0 if success else 1

        elif args.command == "clean":
            targets: list[str] = []
            if getattr(args, "all", False):
                targets.append("all")
            if getattr(args, "dist", False):
                targets.append("dist")
            if getattr(args, "bin", False):
                targets.append("bin")
            if getattr(args, "npm", False):
                targets.append("npm")
            if getattr(args, "wailsjs", False):
                targets.append("wailsjs")
            if getattr(args, "pycache", False):
                targets.append("pycache")
            if getattr(args, "root_exe", False):
                targets.append("root_exe")
            # 兼容旧 CLI 选项
            if getattr(args, "out", False):
                targets.append("out")
            if getattr(args, "vite", False):
                targets.append("vite")

            if not targets:
                build_tool.console.print(
                    f"[red]{i18n.get('error')}[/red]: "
                    f"--all, --dist, --bin, --npm, --wailsjs, --pycache, --root-exe"
                )
                return 1

            success = build_tool.clean(targets)
            return 0 if success else 1

        elif args.command == "install":
            # 显式指定 manager 时，覆盖默认的 lockfile 自动检测
            manager = getattr(args, "manager", "auto")
            if manager != "auto":
                # 临时把 _detect_pkg_manager 行为锁定为指定 manager
                _orig_detect = build_tool._detect_pkg_manager
                def _forced_detect(frontend_dir, mgr=manager):
                    name_key = {
                        "npm": "pkg_manager_npm",
                        "yarn": "pkg_manager_yarn",
                        "pnpm": "pkg_manager_pnpm",
                    }[mgr]
                    build_tool.console.print(
                        f"[dim]{build_tool.i18n.get('pkg_manager_detected')}[/dim]: "
                        f"[cyan]{build_tool.i18n.get(name_key)}[/cyan] "
                        f"([dim]--manager={mgr}[/dim])"
                    )
                    return mgr
                build_tool._detect_pkg_manager = _forced_detect  # type: ignore
            try:
                success = build_tool.install_dependencies_unified(
                    target=getattr(args, "target", "all"),
                    force=getattr(args, "force", False),
                )
            finally:
                if manager != "auto":
                    build_tool._detect_pkg_manager = _orig_detect  # type: ignore
            return 0 if success else 1

        elif args.command == "smoke":
            success = build_tool.run_smoke(
                no_launch=getattr(args, "no_launch", False),
                binary=getattr(args, "binary", None),
            )
            return 0 if success else 1

        else:
            run_tui()
    else:
        run_tui()

    return 0


if __name__ == "__main__":
    sys.exit(main())
