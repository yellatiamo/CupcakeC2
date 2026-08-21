package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"cupcake-server/pkg/metrics"
	"cupcake-server/pkg/middleware"
)

func TestHandleMetricsJSONShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.ResetForTest()
	metrics.IncMCPDeny()
	metrics.IncMCPDeny()
	metrics.IncRBACDeny()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		middleware.SetPrincipalForTest(c, middleware.Principal{Kind: "user", Username: "admin", Role: "admin"})
		c.Next()
	})
	r.GET("/api/metrics", middleware.RequireAdmin(), HandleMetrics)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v body=%s", err, w.Body.String())
	}
	for _, key := range []string{
		"agents_online", "agents_total", "mcp_denies_total",
		"rbac_denies_total", "db_ok", "uptime_sec",
	} {
		if _, ok := body[key]; !ok {
			t.Errorf("missing key %q in %v", key, body)
		}
	}
	if int(body["mcp_denies_total"].(float64)) != 2 {
		t.Errorf("mcp_denies_total = %v, want 2", body["mcp_denies_total"])
	}
	if int(body["rbac_denies_total"].(float64)) != 1 {
		t.Errorf("rbac_denies_total = %v, want 1", body["rbac_denies_total"])
	}
	// DB not initialized in unit test
	if body["db_ok"] != false {
		t.Errorf("db_ok = %v, want false without DB", body["db_ok"])
	}
	if body["uptime_sec"].(float64) < 0 {
		t.Errorf("uptime_sec negative: %v", body["uptime_sec"])
	}
}

func TestHandleMetricsRequiresAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		middleware.SetPrincipalForTest(c, middleware.Principal{Kind: "user", Username: "op", Role: "operator"})
		c.Next()
	})
	r.GET("/api/metrics", middleware.RequireAdmin(), HandleMetrics)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("operator status = %d, want 403", w.Code)
	}
}

func TestHandleGetAuditLogsEmptyWithoutDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/settings/logs/audit", HandleGetAuditLogs)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/settings/logs/audit?limit=10", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var logs []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &logs); err != nil {
		t.Fatalf("json: %v body=%s", err, w.Body.String())
	}
	if logs == nil {
		t.Fatal("expected empty array, got null")
	}
}
