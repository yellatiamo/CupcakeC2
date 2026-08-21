package controllers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"cupcake-server/internal/model"
	"cupcake-server/internal/service"
)

func TestSanitizeAgentForAPITrimsNULSalt(t *testing.T) {
	a := model.Agent{UUID: "u1", EncryptionSalt: "8MGUK4\x00\x00\x00"}
	got := sanitizeAgentForAPI(a)
	if strings.Contains(got.EncryptionSalt, "\x00") {
		t.Fatalf("salt still has NUL: %q", got.EncryptionSalt)
	}
	if got.EncryptionSalt != "8MGUK4" {
		t.Fatalf("salt=%q want 8MGUK4", got.EncryptionSalt)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `\u0000`) {
		t.Fatalf("JSON still has null escapes: %s", raw)
	}
}

func TestWriteAgentFSErrorOfflineIs404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/t", func(c *gin.Context) {
		writeAgentFSError(c, services.ErrAgentOffline)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "agent offline") {
		t.Fatalf("body=%s", w.Body.String())
	}
}

func TestWriteAgentFSErrorLegacyStringOffline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/t", func(c *gin.Context) {
		writeAgentFSError(c, errors.New("agent offline"))
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", w.Code)
	}
}

func TestWriteAgentFSErrorOtherIs500(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/t", func(c *gin.Context) {
		writeAgentFSError(c, errors.New("disk full"))
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", w.Code)
	}
}

func TestStartTunnelEmptyPort400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/tunnel/start", StartTunnel)
	w := httptest.NewRecorder()
	body := `{"uuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","port":"","type":"socks5"}`
	req := httptest.NewRequest(http.MethodPost, "/api/tunnel/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"status":"success"`) {
		t.Fatal("must not succeed with empty port")
	}
}

