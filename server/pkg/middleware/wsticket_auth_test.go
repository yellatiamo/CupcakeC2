package middleware

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"cupcake-server/internal/model"
	"cupcake-server/internal/storage"
	"cupcake-server/pkg/wsticket"
)

// setupAuthSettingsDB provides a minimal DB so AuthMiddleware's GetSetting
// (panel IP allowlist / MCP policy) does not panic when the cache is cold.
func setupAuthSettingsDB(t *testing.T) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "auth_ws.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.GlobalSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	prev := store.DB
	store.DB = db
	InvalidateAuthCache()
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
		store.DB = prev
		InvalidateAuthCache()
	})
}

func TestPurposeFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/api/pty/uuid-1", wsticket.PurposePTY},
		{"/api/shell/uuid-1", wsticket.PurposeShell},
		{"/api/build/logs/task-9", wsticket.PurposeBuildLogs},
		{"/api/clients", ""},
		{"/api/pty", ""}, // no trailing slash segment
		{"/api/auth/ws-ticket", ""},
	}
	for _, tc := range cases {
		got := purposeFromPath(tc.path)
		if got != tc.want {
			t.Errorf("purposeFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestIsWSUpgradePath(t *testing.T) {
	if !isWSUpgradePath("/api/pty/x") || !isWSUpgradePath("/api/shell/x") || !isWSUpgradePath("/api/build/logs/x") {
		t.Fatal("expected WS paths true")
	}
	if isWSUpgradePath("/api/clients") || isWSUpgradePath("/api/auth/ws-ticket") {
		t.Fatal("expected non-WS paths false")
	}
}

// WS upgrade paths must reject durable session-style ?token= without Authorization.
func TestWSPathRejectsQuerySessionToken(t *testing.T) {
	setupAuthSettingsDB(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/api/pty/:uuid", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	r.GET("/api/shell/:uuid", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	r.GET("/api/build/logs/:task_id", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	paths := []string{
		"/api/pty/agent-1?token=fake-session-bearer",
		"/api/shell/agent-1?token=fake-session-bearer",
		"/api/build/logs/task-1?token=fake-session-bearer",
		"/api/pty/agent-1", // no ticket at all
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", p, w.Code)
		}
	}
}

func TestWSPathAcceptsValidTicket(t *testing.T) {
	setupAuthSettingsDB(t)
	gin.SetMode(gin.TestMode)
	wsticket.ResetForTest()
	raw, err := wsticket.Mint(3, "op1", "operator", wsticket.PurposePTY, wsticket.DefaultTTL)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	r := gin.New()
	r.Use(AuthMiddleware())
	var got Principal
	r.GET("/api/pty/:uuid", func(c *gin.Context) {
		p, ok := CurrentPrincipal(c)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		got = p
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/pty/agent-1?ticket="+raw, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got.Kind != "user" || got.Username != "op1" || got.Role != "operator" {
		t.Fatalf("principal = %+v", got)
	}

	// Reuse same ticket → 401
	req2 := httptest.NewRequest(http.MethodGet, "/api/pty/agent-1?ticket="+raw, nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("reuse status = %d, want 401", w2.Code)
	}
}

func TestWSPathRejectsWrongPurposeTicket(t *testing.T) {
	setupAuthSettingsDB(t)
	gin.SetMode(gin.TestMode)
	wsticket.ResetForTest()
	raw, err := wsticket.Mint(1, "op1", "operator", wsticket.PurposeShell, wsticket.DefaultTTL)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/api/pty/:uuid", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/api/pty/agent-1?ticket="+raw, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

