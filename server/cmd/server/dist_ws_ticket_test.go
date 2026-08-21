package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedDistUsesWSTicketsNotDurableQueryToken asserts the product UI that
// go:embed embeds (web/dist) mints short-lived tickets and never opens
// pty/shell/build-logs WebSockets with durable ?token=.
//
// This drives the real shipped asset tree on disk (//go:embed web/dist/*).
// Rebuild with: powershell -File scripts/build-frontend.ps1
func TestShippedDistUsesWSTicketsNotDurableQueryToken(t *testing.T) {
	// Prefer embed tree; fall back to vite intermediate server/dist if present.
	dist := filepath.Join("web", "dist", "assets", "js")
	if st, err := os.Stat(dist); err != nil || !st.IsDir() {
		dist = filepath.Join("dist", "assets", "js")
	}
	if st, err := os.Stat(dist); err != nil || !st.IsDir() {
		t.Fatalf("shipped dist missing at web/dist (or dist) — run scripts/build-frontend.ps1 before go test: %v", err)
	}

	var (
		sawMint  bool
		sawTicket bool
		badFiles []string
	)

	err := filepath.WalkDir(dist, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".js") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := string(raw)
		if strings.Contains(s, "/api/auth/ws-ticket") {
			sawMint = true
		}
		if strings.Contains(s, "?ticket=") || strings.Contains(s, "ticket=${") || strings.Contains(s, "encodeURIComponent(e)") && strings.Contains(s, "ticket=") {
			// Minified builds use encodeURIComponent(e) after minting into e.
			if strings.Contains(s, "ticket=") {
				sawTicket = true
			}
		}
		if strings.Contains(s, "?ticket=") {
			sawTicket = true
		}

		// Durable session token in query for interactive WS routes.
		if hasDurableWSToken(s) {
			badFiles = append(badFiles, filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawMint {
		t.Fatal("no dist JS references POST /api/auth/ws-ticket — panel cannot mint upgrade tickets")
	}
	if !sawTicket {
		t.Fatal("no dist JS opens WebSocket with ?ticket= — panel still not using upgrade tickets")
	}
	if len(badFiles) > 0 {
		t.Fatalf("dist still opens interactive WS with durable ?token=: %v", badFiles)
	}
}

func hasDurableWSToken(s string) bool {
	// Patterns that open product interactive sockets with long-lived session token.
	needles := []string{
		"/api/pty/",
		"/api/shell/",
		"/api/build/logs/",
	}
	for _, n := range needles {
		idx := 0
		for {
			i := strings.Index(s[idx:], n)
			if i < 0 {
				break
			}
			i += idx
			// Look at a window after the route for token= vs ticket=
			end := i + 160
			if end > len(s) {
				end = len(s)
			}
			win := s[i:end]
			if strings.Contains(win, "token=") && !strings.Contains(win, "ticket=") {
				// token= without ticket= in the same short window → durable auth
				return true
			}
			if strings.Contains(win, "?token=") || strings.Contains(win, "&token=") {
				return true
			}
			idx = i + len(n)
		}
	}
	// Classic pre-hardening construct: encodeURIComponent(session) as token=
	if strings.Contains(s, "token=${encodeURIComponent") &&
		(strings.Contains(s, "/api/pty/") || strings.Contains(s, "/api/shell/") || strings.Contains(s, "build/logs")) {
		return true
	}
	return false
}
