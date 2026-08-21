package main

import (
	"net/http"
	"testing"
	"time"
)

func TestNewAdminHTTPServerTimeouts(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	srv := newAdminHTTPServer("127.0.0.1:0", h)
	if srv.ReadHeaderTimeout != 15*time.Second {
		t.Fatalf("ReadHeaderTimeout: got %v want 15s", srv.ReadHeaderTimeout)
	}
	// Body may stream for a long time (upload → agent chunks); must not hard-cap.
	if srv.ReadTimeout != 0 {
		t.Fatalf("ReadTimeout: got %v want 0 (no whole-request deadline)", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout: got %v want 0", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 180*time.Second {
		t.Fatalf("IdleTimeout: got %v want 180s", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != 1<<20 {
		t.Fatalf("MaxHeaderBytes: got %d want %d", srv.MaxHeaderBytes, 1<<20)
	}
	if srv.Handler == nil {
		t.Fatal("handler must be set")
	}
	if srv.Addr != "127.0.0.1:0" {
		t.Fatalf("Addr: got %q", srv.Addr)
	}
}
