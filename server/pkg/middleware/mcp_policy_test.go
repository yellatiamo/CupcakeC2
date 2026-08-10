package middleware

import (
	"net/http"
	"testing"
)

func TestMCPEndpointAllowlistReadOnly(t *testing.T) {
	cases := []struct {
		method   string
		path     string
		readonly bool
		allowed  bool
	}{
		// Read endpoints allowed in read-only mode
		{http.MethodGet, "/api/dashboard", true, true},
		{http.MethodGet, "/api/clients", true, true},
		{http.MethodGet, "/api/clients/history/abc", true, true},
		{http.MethodGet, "/api/listeners", true, true},
		{http.MethodGet, "/api/tunnel", true, true},
		{http.MethodGet, "/api/socks", true, true},
		{http.MethodGet, "/api/files/list", true, true},
		{http.MethodGet, "/api/files/read", true, true},
		{http.MethodGet, "/api/files/download", true, true},
		{http.MethodGet, "/api/processes/list", true, true},
		{http.MethodGet, "/api/plugins", true, true},
		{http.MethodGet, "/api/plugins/result/t1", true, true},
		{http.MethodGet, "/api/modules", true, true},
		{http.MethodGet, "/api/modules/pack/x", true, true},
		{http.MethodGet, "/api/resp", true, true},
		{http.MethodGet, "/api/ad/capabilities", true, true},
		{http.MethodGet, "/api/ad/tasks", true, true},
		{http.MethodGet, "/api/mcp/pending", true, true},
		{http.MethodGet, "/api/mcp/pending/abc", true, true},

		// Writes denied in read-only mode
		{http.MethodPost, "/api/cmd", true, false},
		{http.MethodPost, "/api/ad/exec", true, false},
		{http.MethodPost, "/api/ad/discover", true, false},
		{http.MethodPost, "/api/modules/push", true, false},
		{http.MethodPost, "/api/files/delete", true, false},
		{http.MethodPost, "/api/processes/kill", true, false},

		// Writes allowed when read-only off (still need panel confirm at gate)
		{http.MethodPost, "/api/cmd", false, true},
		{http.MethodPost, "/api/ad/exec", false, true},
		{http.MethodPost, "/api/ad/discover", false, true},
		{http.MethodPost, "/api/ad/ping", false, true},
		{http.MethodPost, "/api/modules/push", false, true},
		{http.MethodPost, "/api/modules/query", false, true},
		{http.MethodPost, "/api/files/delete", false, true},
		{http.MethodPost, "/api/processes/kill", false, true},
		{http.MethodPost, "/api/plugins/run", false, true},
		{http.MethodPost, "/api/tunnel/start", false, true},
		{http.MethodPost, "/api/socks/start", false, true},

		// Control plane still denied
		{http.MethodGet, "/api/settings/config", true, false},
		{http.MethodPost, "/api/settings/config", false, false},
		{http.MethodPost, "/api/maintenance/reset", false, false},
		{http.MethodGet, "/api/maintenance/export", false, false},
		{http.MethodPost, "/api/auth/login", false, false},
		{http.MethodPost, "/api/generate", false, false},
		{http.MethodGet, "/api/unknown", true, false},
	}

	for _, tc := range cases {
		allowed, _ := mcpEndpointAllowed(tc.method, tc.path, tc.readonly)
		if allowed != tc.allowed {
			t.Errorf("mcpEndpointAllowed(%s %s readonly=%v) = %v, want %v",
				tc.method, tc.path, tc.readonly, allowed, tc.allowed)
		}
	}
}

func TestMCPEndpointAllowlistDeniesManagementPaths(t *testing.T) {
	managementPaths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/settings/users"},
		{http.MethodPost, "/api/settings/users"},
		{http.MethodPost, "/api/settings/config"},
		{http.MethodPost, "/api/maintenance/reset"},
		{http.MethodGet, "/api/maintenance/export"},
		{http.MethodPost, "/api/auth/login"},
		{http.MethodPut, "/api/auth/password"},
		{http.MethodPost, "/api/generate"},
		{http.MethodGet, "/api/generate/stream"},
		{http.MethodGet, "/api/stager"},
		{http.MethodPost, "/api/agents/connect"},
	}

	for _, p := range managementPaths {
		allowed, _ := mcpEndpointAllowed(p.method, p.path, false)
		if allowed {
			t.Errorf("management path %s %s must never be MCP-accessible",
				p.method, p.path)
		}
	}
}

func TestRoleHelpers(t *testing.T) {
	if !IsAdminRole("admin") || !IsAdminRole("administrator") || !IsAdminRole("break-glass-admin") {
		t.Fatal("admin aliases should be admin")
	}
	if IsAdminRole("operator") || IsAdminRole("viewer") {
		t.Fatal("operator/viewer must not be admin")
	}
	if !IsOperatorOrAbove("operator") || !IsOperatorOrAbove("admin") {
		t.Fatal("operator/admin should be operator-or-above")
	}
	if IsOperatorOrAbove("viewer") {
		t.Fatal("viewer must not be operator-or-above")
	}
	if !IsViewerOrAbove("viewer") || !IsViewerOrAbove("operator") || !IsViewerOrAbove("admin") {
		t.Fatal("viewer/operator/admin should be viewer-or-above")
	}
	if IsViewerOrAbove("") || IsViewerOrAbove("mcp") {
		t.Fatal("empty/mcp must not be viewer-or-above")
	}
}
