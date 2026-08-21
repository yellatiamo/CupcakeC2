package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"cupcake-server/pkg/middleware"
)

// setupRBACRouter mirrors production admin/operator gating for critical routes.
func setupRBACRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Inject principal from header for tests (X-Test-Role)
	r.Use(func(c *gin.Context) {
		role := c.GetHeader("X-Test-Role")
		if role == "" {
			role = "operator"
		}
		middleware.SetPrincipalForTest(c, middleware.Principal{Kind: "user", Username: "t", Role: role})
		c.Next()
	})
	api := r.Group("/api")
	{
		// Admin routes
		api.POST("/listeners", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.GET("/maintenance/export", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/maintenance/update_templates", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/maintenance/reset", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/plugins/upload", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/plugins/run", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.DELETE("/plugins/:id", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/modules/upload", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/modules/push", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.DELETE("/modules/:id", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.DELETE("/clients/:uuid", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/clients/migrate", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/agents/connect", middleware.RequireAdmin(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})

		// Operator routes
		api.POST("/cmd", middleware.RequireOperator(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/processes/kill", middleware.RequireOperator(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/files/upload", middleware.RequireOperator(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/files/delete", middleware.RequireOperator(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/tunnel/start", middleware.RequireOperator(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.POST("/modules/query", middleware.RequireOperator(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.GET("/shell/:uuid", middleware.RequireOperator(), func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})

		// Viewer-readable (no extra role gate — AuthMiddleware only in prod)
		api.GET("/dashboard", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		api.GET("/clients", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
	}
	return r
}

func doReq(r *gin.Engine, method, path, role string) int {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Test-Role", role)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestOperatorForbiddenOnAdminRoutes(t *testing.T) {
	r := setupRBACRouter()
	paths := []struct {
		method string
		path   string
	}{
		{"POST", "/api/listeners"},
		{"GET", "/api/maintenance/export"},
		{"POST", "/api/maintenance/update_templates"},
		{"POST", "/api/maintenance/reset"},
		{"POST", "/api/plugins/upload"},
		{"POST", "/api/plugins/run"},
		{"DELETE", "/api/plugins/x"},
		{"POST", "/api/modules/upload"},
		{"POST", "/api/modules/push"},
		{"DELETE", "/api/modules/x"},
		{"DELETE", "/api/clients/u1"},
		{"POST", "/api/clients/migrate"},
		{"POST", "/api/agents/connect"},
	}
	for _, p := range paths {
		code := doReq(r, p.method, p.path, "operator")
		if code != http.StatusForbidden {
			t.Fatalf("%s %s: operator want 403 got %d", p.method, p.path, code)
		}
	}
}

func TestViewerDeniedOnOperatorAndAdminRoutes(t *testing.T) {
	r := setupRBACRouter()
	// Viewer denied on /cmd and kill (operator)
	operatorPaths := []struct {
		method string
		path   string
	}{
		{"POST", "/api/cmd"},
		{"POST", "/api/processes/kill"},
		{"POST", "/api/files/upload"},
		{"POST", "/api/files/delete"},
		{"POST", "/api/tunnel/start"},
		{"POST", "/api/modules/query"},
		{"GET", "/api/shell/u1"},
	}
	for _, p := range operatorPaths {
		code := doReq(r, p.method, p.path, "viewer")
		if code != http.StatusForbidden {
			t.Fatalf("%s %s: viewer want 403 got %d", p.method, p.path, code)
		}
	}
	// Viewer denied on plugins / modules admin
	adminPaths := []struct {
		method string
		path   string
	}{
		{"POST", "/api/plugins/run"},
		{"POST", "/api/plugins/upload"},
		{"POST", "/api/modules/upload"},
		{"POST", "/api/modules/push"},
	}
	for _, p := range adminPaths {
		code := doReq(r, p.method, p.path, "viewer")
		if code != http.StatusForbidden {
			t.Fatalf("%s %s: viewer want 403 got %d", p.method, p.path, code)
		}
	}
}

func TestOperatorAllowedOnOperatorRoutes(t *testing.T) {
	r := setupRBACRouter()
	paths := []struct {
		method string
		path   string
	}{
		{"POST", "/api/cmd"},
		{"POST", "/api/processes/kill"},
		{"POST", "/api/files/upload"},
		{"POST", "/api/modules/query"},
	}
	for _, p := range paths {
		code := doReq(r, p.method, p.path, "operator")
		if code != http.StatusOK {
			t.Fatalf("%s %s: operator want 200 got %d", p.method, p.path, code)
		}
	}
}

func TestOperatorDeniedOnModulesUploadPushAndPlugins(t *testing.T) {
	r := setupRBACRouter()
	paths := []struct {
		method string
		path   string
	}{
		{"POST", "/api/modules/upload"},
		{"POST", "/api/modules/push"},
		{"POST", "/api/plugins/run"},
		{"POST", "/api/plugins/upload"},
		{"DELETE", "/api/plugins/x"},
	}
	for _, p := range paths {
		code := doReq(r, p.method, p.path, "operator")
		if code != http.StatusForbidden {
			t.Fatalf("%s %s: operator want 403 got %d", p.method, p.path, code)
		}
	}
}

func TestAdminAllowedOnAdminRoutes(t *testing.T) {
	r := setupRBACRouter()
	paths := []struct {
		method string
		path   string
	}{
		{"GET", "/api/maintenance/export"},
		{"POST", "/api/modules/upload"},
		{"POST", "/api/modules/push"},
		{"POST", "/api/plugins/run"},
		{"POST", "/api/cmd"}, // admin is operator-or-above
		{"POST", "/api/processes/kill"},
	}
	for _, p := range paths {
		code := doReq(r, p.method, p.path, "admin")
		if code != http.StatusOK {
			t.Fatalf("%s %s: admin want 200 got %d", p.method, p.path, code)
		}
	}
}

func TestAdministratorAliasAllowed(t *testing.T) {
	r := setupRBACRouter()
	if code := doReq(r, "POST", "/api/modules/push", "administrator"); code != http.StatusOK {
		t.Fatalf("administrator alias want 200 got %d", code)
	}
	if code := doReq(r, "POST", "/api/modules/push", "break-glass-admin"); code != http.StatusOK {
		t.Fatalf("break-glass-admin alias want 200 got %d", code)
	}
}

func TestViewerAllowedOnReadRoutes(t *testing.T) {
	r := setupRBACRouter()
	if code := doReq(r, "GET", "/api/dashboard", "viewer"); code != http.StatusOK {
		t.Fatalf("viewer dashboard want 200 got %d", code)
	}
	if code := doReq(r, "GET", "/api/clients", "viewer"); code != http.StatusOK {
		t.Fatalf("viewer clients want 200 got %d", code)
	}
}
