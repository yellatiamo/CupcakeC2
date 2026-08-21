package transport

import (
	"encoding/binary"
	"log"
	"net"
	"fmt"
	"io"
	"cupcake-server/pkg/globals"
	"cupcake-server/internal/service"
	"github.com/hashicorp/yamux"
)

// StartTCPListener starts the raw TCP server with Yamux multiplexing
func StartTCPListener(ln *globals.Listener) {
	addr := fmt.Sprintf("%s:%d", ln.BindIP, ln.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[TCP] Failed to listen on %s: %v", addr, err)
		ln.Status = "Failed"
		return
	}
	ln.TCPServer = listener
	ln.Status = "Running"
	log.Printf("[TCP] Listening on %s (Multiplexing enabled)", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ln.Status == "Stopped" {
				return
			}
			log.Printf("[TCP] Accept error: %v", err)
			continue
		}
		
		// 1. Wrap raw TCP connection in Yamux Server Session
		// ⚡️ CRITICAL FIX: Disable Yamux KeepAlive
		// We rely on our own C2 heartbeat or TCP's native keepalive.
		// Yamux's ping is too aggressive for C2 agents.
		config := yamux.DefaultConfig()
		config.EnableKeepAlive = false
		config.LogOutput = io.Discard // Silence noisy logs

		session, err := yamux.Server(conn, config)
		if err != nil {
			log.Printf("[TCP] Yamux session failed: %v", err)
			conn.Close()
			continue
		}
		log.Printf("[TCP] New Yamux Session established from %s", conn.RemoteAddr())

		// 2. Accept the first stream (Control Stream) for registration/C2
		go func() {
			conn, err := session.Accept()
			if err != nil {
				log.Printf("[TCP Error] Session accept failed: %v", err)
				session.Close()
				return
			}
			
			streamID := uint32(0)
			if s, ok := conn.(*yamux.Stream); ok {
				streamID = s.StreamID()
			}
			log.Printf("[TCP] Accepted new stream (ID: %d) from %s", streamID, conn.RemoteAddr())
			
			// Process C2 logic on the control stream
			// We pass the session along to store it in the client object later
			services.ProcessTCPConnection(conn, conn.RemoteAddr().String(), ln, session)
		}()
	}
}

// Helper to send framed message (Length-Prefixed JSON)
func SendTCPMessage(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)
	
	// Write Header + Body
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	return nil
}

