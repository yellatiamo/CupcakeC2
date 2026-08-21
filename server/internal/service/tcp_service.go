package services

import (
	"cupcake-server/pkg/globals"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/hashicorp/yamux"
)

// yamuxLogOutput is silent by default; set CUPCAKE_YAMUX_DEBUG=1 for session logs.
func yamuxLogOutput() io.Writer {
	if os.Getenv("CUPCAKE_YAMUX_DEBUG") == "1" || os.Getenv("CUPCAKE_YAMUX_DEBUG") == "true" {
		return log.Writer()
	}
	return io.Discard
}

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

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ln.Status == "Stopped" {
				return
			}
			log.Printf("[TCP] Accept error: %v", err)
			continue
		}
		
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 30 * time.Second
	// 🚀 对齐 agent 端 tcp.rs:95 的 16MB 接收窗口 — 原 1MB 会让单 ack 帧(~2.78MB base64)
	// 跨窗口往返,大文件传输尾部延迟显著。16MB 让 Yamux 流控不被 server 端闷盖。
	config.MaxStreamWindowSize = 16 * 1024 * 1024
	config.LogOutput = yamuxLogOutput()

	session, err := yamux.Server(conn, config)
		if err != nil {
			log.Printf("[TCP] Yamux session failed: %v", err)
			conn.Close()
			continue
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[TCP] outer panic recovered: %v", r)
				}
			}()
			// 🛡️ FIX: 30s timeout for control stream — prevents goroutine leak
			timer := time.AfterFunc(30*time.Second, func() {
				log.Printf("[TCP] Timeout waiting for control stream, closing session")
				session.Close()
				conn.Close()
			})

			stream, err := session.Accept()
			timer.Stop()

			if err != nil {
				log.Printf("[TCP Error] Session accept failed: %v", err)
				conn.Close()
				return
			}

			ProcessTCPConnection(stream, stream.RemoteAddr().String(), ln, session)
		}()
	}
}

// SendTCPMessage helper (Moved from transport)
func SendTCPMessage(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)
	
	if _, err := conn.Write(header); err != nil { return err }
	if _, err := conn.Write(data); err != nil { return err }
	return nil
}
// ConnectToBindAgent initiates a connection to a forward (bind) agent
func ConnectToBindAgent(targetAddr string, ln *globals.Listener) error {
	log.Printf("[TCP] Attempting to connect to Bind Agent at %s...", targetAddr)
	
	var conn net.Conn
	var err error
	
	// ⚡ RETRY LOGIC: Bind Agent might have jitter/delay or the port isn't open yet.
	// Try 5 times with 2s interval.
	for i := 0; i < 5; i++ {
		conn, err = net.DialTimeout("tcp", targetAddr, 3*time.Second)
		if err == nil {
			break
		}
		log.Printf("[TCP] Connect attempt %d failed: %v. Retrying...", i+1, err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to bind agent after retries: %v", err)
	}

	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 30 * time.Second
	config.MaxStreamWindowSize = 1024 * 1024
	config.LogOutput = yamuxLogOutput()

	// 🛡️ 设计决策：服务端连接后作为 Yamux Server 运行，Agent 作为 Client
	session, err := yamux.Server(conn, config)
	if err != nil {
		conn.Close()
		return fmt.Errorf("yamux initialization failed: %v", err)
	}

	log.Printf("[TCP] Outbound session established to %s", targetAddr)

	go func() {
		// 等待 Agent 打开控制流 (Agent 实现了 Mode::Client)
		stream, err := session.Accept()
		if err != nil {
			log.Printf("[TCP Error] Failed to accept stream from bind agent: %v", err)
			session.Close()
			return
		}
		
		log.Printf("[TCP] Accepted control stream from bind agent at %s", targetAddr)
		ProcessTCPConnection(stream, targetAddr, ln, session)
	}()

	return nil
}
