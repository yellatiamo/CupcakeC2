package middleware

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/netip"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"cupcake-server/pkg/metrics"
	"cupcake-server/internal/model"
	"cupcake-server/internal/storage"
	"cupcake-server/pkg/wsticket"
)

const (
	principalContextKey = "auth.principal"
	mcpTokenSetting    = "mcp_api_token"
	mcpEnabledSetting  = "system_mcp_enabled"
	mcpCIDRSetting     = "mcp_allowed_cidrs"
	mcpReadOnlySetting = "mcp_read_only"
)

// Principal identifies the authenticated caller. MCP is deliberately not an
// administrator principal: it has a separately constrained capability policy.
type Principal struct {
	Kind     string
	Username string
	Role     string
}

type mcpPolicy struct {
	Token    string
	Enabled  bool
	CIDRs    string
	ReadOnly bool
}

var tokenCache struct {
	mu          sync.RWMutex
	policy      mcpPolicy
	lastLoaded  time.Time
	allowedIPs  string
	lastIPLoad  time.Time
}

// InvalidateAuthCache applies configuration and token rotations immediately.
func InvalidateAuthCache() {
	tokenCache.mu.Lock()
	tokenCache.lastLoaded = time.Time{}
	tokenCache.lastIPLoad = time.Time{}
	tokenCache.policy = mcpPolicy{}
	tokenCache.allowedIPs = ""
	tokenCache.mu.Unlock()
}

func loadMCPPolicy(now time.Time) mcpPolicy {
	tokenCache.mu.RLock()
	if !tokenCache.lastLoaded.IsZero() && now.Sub(tokenCache.lastLoaded) <= time.Minute {
		p := tokenCache.policy
		tokenCache.mu.RUnlock()
		return p
	}
	tokenCache.mu.RUnlock()

	tokenCache.mu.Lock()
	defer tokenCache.mu.Unlock()
	if !tokenCache.lastLoaded.IsZero() && now.Sub(tokenCache.lastLoaded) <= time.Minute {
		return tokenCache.policy
	}
	tokenCache.policy = mcpPolicy{
		Token:    store.GetSetting(mcpTokenSetting),
		Enabled:  store.GetSetting(mcpEnabledSetting) == "true",
		CIDRs:    store.GetSetting(mcpCIDRSetting),
		ReadOnly: store.GetSetting(mcpReadOnlySetting) != "false",
	}
	tokenCache.lastLoaded = now
	return tokenCache.policy
}

// GetCurrentToken is retained for integrations that need the MCP API token.
func GetCurrentToken() string {
	return loadMCPPolicy(time.Now()).Token
}

func loadPanelAllowedIPs(now time.Time) string {
	tokenCache.mu.RLock()
	if !tokenCache.lastIPLoad.IsZero() && now.Sub(tokenCache.lastIPLoad) <= time.Minute {
		v := tokenCache.allowedIPs
		tokenCache.mu.RUnlock()
		return v
	}
	tokenCache.mu.RUnlock()

	tokenCache.mu.Lock()
	defer tokenCache.mu.Unlock()
	if !tokenCache.lastIPLoad.IsZero() && now.Sub(tokenCache.lastIPLoad) <= time.Minute {
		return tokenCache.allowedIPs
	}
	tokenCache.allowedIPs = store.GetSetting("allowed_ips")
	tokenCache.lastIPLoad = now
	return tokenCache.allowedIPs
}

// ipAllowed accepts a comma-separated list of exact IPs or CIDRs. Empty is
// intentionally configurable by the caller because panel and MCP defaults differ.
func ipAllowed(clientIP, rules string, allowEmpty bool) bool {
	rules = strings.TrimSpace(rules)
	if rules == "" {
		return allowEmpty
	}
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}
	for _, raw := range strings.Split(rules, ",") {
		rule := strings.TrimSpace(raw)
		if rule == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(rule); err == nil && prefix.Contains(addr) {
			return true
		}
		if allowedAddr, err := netip.ParseAddr(rule); err == nil && allowedAddr == addr {
			return true
		}
	}
	return false
}

// ValidateIPRules validates the comma-separated IP/CIDR form accepted by both
// panel and MCP policies. Keeping this parser server-side avoids a UI-only gate.
func ValidateIPRules(rules string, allowEmpty bool) error {
	rules = strings.TrimSpace(rules)
	if rules == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("at least one IP or CIDR is required")
	}
	for _, raw := range strings.Split(rules, ",") {
		rule := strings.TrimSpace(raw)
		if rule == "" {
			continue
		}
		if _, err := netip.ParsePrefix(rule); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(rule); err == nil {
			continue
		}
		return fmt.Errorf("invalid IP or CIDR %q", rule)
	}
	return nil
}

func tokenEqual(a, b string) bool {
	if a == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// isWSUpgradePath is true for panel interactive WebSocket endpoints that must
// not accept a durable session bearer via the query string alone.
func isWSUpgradePath(path string) bool {
	return strings.HasPrefix(path, "/api/build/logs/") ||
		strings.HasPrefix(path, "/api/pty/") ||
		strings.HasPrefix(path, "/api/shell/")
}

// purposeFromPath maps a WS upgrade URL path to a wsticket purpose.
// Returns empty string when the path is not a known upgrade endpoint.
func purposeFromPath(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/pty/"):
		return wsticket.PurposePTY
	case strings.HasPrefix(path, "/api/shell/"):
		return wsticket.PurposeShell
	case strings.HasPrefix(path, "/api/build/logs/"):
		return wsticket.PurposeBuildLogs
	default:
		return ""
	}
}

// mcpEndpointPolicy is an explicit allowlist. MCP never falls through to
// "any GET is fine" — every accessible route is declared here with its
// capability. Write endpoints are only reachable when read-only mode is off.
type mcpEndpoint struct {
	method     string
	prefix     string
	write      bool
}

// mcpAllowlist: reads always (when MCP enabled); writes require mcp_read_only=false
// and still pass MCPConfirmGate (every mutation becomes a panel pending confirmation).
// Control-plane routes (settings/maintenance/auth/generate) are intentionally absent.
var mcpAllowlist = []mcpEndpoint{
	// --- reads ---
	{method: http.MethodGet, prefix: "/api/dashboard", write: false},
	{method: http.MethodGet, prefix: "/api/clients", write: false},
	{method: http.MethodGet, prefix: "/api/clients/history/", write: false},
	{method: http.MethodGet, prefix: "/api/listeners", write: false},
	{method: http.MethodGet, prefix: "/api/tunnel", write: false},
	{method: http.MethodGet, prefix: "/api/socks", write: false},
	{method: http.MethodGet, prefix: "/api/files/list", write: false},
	{method: http.MethodGet, prefix: "/api/files/read", write: false},
	{method: http.MethodGet, prefix: "/api/files/download", write: false},
	{method: http.MethodGet, prefix: "/api/processes/list", write: false},
	{method: http.MethodGet, prefix: "/api/plugins", write: false},
	{method: http.MethodGet, prefix: "/api/plugins/result/", write: false},
	{method: http.MethodGet, prefix: "/api/modules", write: false},
	{method: http.MethodGet, prefix: "/api/modules/pack/", write: false},
	{method: http.MethodGet, prefix: "/api/resp", write: false},
	{method: http.MethodGet, prefix: "/api/ad/capabilities", write: false},
	{method: http.MethodGet, prefix: "/api/ad/tasks", write: false},
	// MCP pending poll (result of write confirmations)
	{method: http.MethodGet, prefix: "/api/mcp/pending", write: false},

	// --- writes (mcp_read_only=false); all go through MCPConfirmGate ---
	{method: http.MethodPost, prefix: "/api/cmd", write: true},
	{method: http.MethodPost, prefix: "/api/ad/exec", write: true},
	{method: http.MethodPost, prefix: "/api/ad/discover", write: true},
	{method: http.MethodPost, prefix: "/api/ad/ping", write: true},
	{method: http.MethodDelete, prefix: "/api/ad/tasks/", write: true},
	{method: http.MethodPost, prefix: "/api/modules/push", write: true},
	{method: http.MethodPost, prefix: "/api/modules/query", write: true},
	{method: http.MethodDelete, prefix: "/api/modules/", write: true},
	{method: http.MethodPost, prefix: "/api/files/delete", write: true},
	{method: http.MethodPost, prefix: "/api/processes/kill", write: true},
	{method: http.MethodPost, prefix: "/api/plugins/run", write: true},
	{method: http.MethodDelete, prefix: "/api/plugins/", write: true},
	{method: http.MethodPost, prefix: "/api/tunnel/start", write: true},
	{method: http.MethodPost, prefix: "/api/tunnel/stop", write: true},
	{method: http.MethodPost, prefix: "/api/tunnel/delete", write: true},
	{method: http.MethodPost, prefix: "/api/socks/start", write: true},
	{method: http.MethodPost, prefix: "/api/socks/stop", write: true},
	{method: http.MethodPost, prefix: "/api/socks/delete", write: true},
}

// mcpEndpointAllowed returns (allowed, writeRequested). Unknown endpoints are
// denied by default; read-only mode rejects write endpoints.
func mcpEndpointAllowed(method, path string, readOnly bool) (bool, bool) {
	for _, e := range mcpAllowlist {
		if e.method != method {
			continue
		}
		if strings.HasPrefix(path, e.prefix) {
			if e.write && readOnly {
				return false, true
			}
			return true, e.write
		}
	}
	return false, false
}

func denyMCP(c *gin.Context, code string) {
	metrics.IncMCPDeny()
	log.Printf("[Security] MCP %s denied %s %s — %s", c.ClientIP(), c.Request.Method, c.Request.URL.Path, code)
	store.SaveAuditLog(&model.AuditLog{
		Principal: "mcp",
		Username:  "mcp",
		Role:      "mcp",
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
		ClientIP:  c.ClientIP(),
		Status:    "denied",
		ErrorCode: code,
		Message:   "mcp policy denied",
	})
	c.JSON(http.StatusForbidden, gin.H{"error": "mcp policy denied", "error_code": code})
	c.Abort()
}

func setPrincipal(c *gin.Context, principal Principal) {
	c.Set(principalContextKey, principal)
}

// SetPrincipalForTest injects a principal in unit tests (RBAC route table).
func SetPrincipalForTest(c *gin.Context, principal Principal) {
	setPrincipal(c, principal)
}

func currentPrincipal(c *gin.Context) (Principal, bool) {
	v, ok := c.Get(principalContextKey)
	if !ok {
		return Principal{}, false
	}
	p, ok := v.(Principal)
	return p, ok
}

// CurrentPrincipal returns the authenticated principal set by AuthMiddleware.
func CurrentPrincipal(c *gin.Context) (Principal, bool) {
	return currentPrincipal(c)
}

// normalizeRole lowercases and trims role strings for comparison.
func normalizeRole(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

// IsAdminRole reports whether role is an administrator (including aliases).
// Accepted: admin, administrator, break-glass-admin.
func IsAdminRole(role string) bool {
	switch normalizeRole(role) {
	case "admin", "administrator", "break-glass-admin":
		return true
	default:
		return false
	}
}

// IsOperatorOrAbove is true for operator and all admin aliases.
func IsOperatorOrAbove(role string) bool {
	if IsAdminRole(role) {
		return true
	}
	return normalizeRole(role) == "operator"
}

// IsViewerOrAbove is true for any recognized panel role (viewer, operator, admin*).
// Unknown / empty roles fail closed.
func IsViewerOrAbove(role string) bool {
	if IsOperatorOrAbove(role) {
		return true
	}
	return normalizeRole(role) == "viewer"
}

// RequireRole allows any of the listed roles (plus admin aliases when "admin" is listed).
// MCP principals are always rejected — role gates apply to panel users only.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	wantAdmin := false
	wantOperator := false
	wantViewer := false
	for _, r := range roles {
		switch normalizeRole(r) {
		case "admin", "administrator", "break-glass-admin":
			wantAdmin = true
		case "operator":
			wantOperator = true
		case "viewer":
			wantViewer = true
		default:
			allowed[normalizeRole(r)] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		principal, ok := currentPrincipal(c)
		if !ok || principal.Kind != "user" {
			metrics.IncRBACDeny()
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient role"})
			c.Abort()
			return
		}
		role := normalizeRole(principal.Role)
		okRole := false
		if wantAdmin && IsAdminRole(role) {
			okRole = true
		}
		if wantOperator && IsOperatorOrAbove(role) {
			okRole = true
		}
		if wantViewer && IsViewerOrAbove(role) {
			okRole = true
		}
		if _, hit := allowed[role]; hit {
			okRole = true
		}
		if !okRole {
			metrics.IncRBACDeny()
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient role"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireAdmin protects management-plane routes from ordinary operators.
// MCP principals are admitted only when AuthMiddleware already allowlisted the
// path (agent-plane writes). Control-plane routes are not in mcpAllowlist, so
// MCP never reaches those handlers.
//
// For panel-only actions (e.g. approve MCP pending), use RequirePanelAdmin.
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := currentPrincipal(c)
		if !ok {
			metrics.IncRBACDeny()
			c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
			c.Abort()
			return
		}
		if principal.Kind == "mcp" {
			c.Next()
			return
		}
		if principal.Kind != "user" || !IsAdminRole(principal.Role) {
			metrics.IncRBACDeny()
			c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequirePanelAdmin allows only interactive panel users with admin role.
// MCP tokens are always rejected — used for approve/deny of MCP pending requests.
func RequirePanelAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := currentPrincipal(c)
		if !ok || principal.Kind != "user" || !IsAdminRole(principal.Role) {
			metrics.IncRBACDeny()
			c.JSON(http.StatusForbidden, gin.H{"error": "panel admin role required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireOperator allows operator and admin panel users.
// MCP principals are also admitted: AuthMiddleware's mcpAllowlist is the MCP
// capability gate (high-risk operator writes are not allowlisted). This keeps
// POST /api/cmd reachable for MCP when read-only is off.
func RequireOperator() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := currentPrincipal(c)
		if !ok {
			metrics.IncRBACDeny()
			c.JSON(http.StatusForbidden, gin.H{"error": "operator role required"})
			c.Abort()
			return
		}
		if principal.Kind == "mcp" {
			c.Next()
			return
		}
		if principal.Kind != "user" || !IsOperatorOrAbove(principal.Role) {
			metrics.IncRBACDeny()
			c.JSON(http.StatusForbidden, gin.H{"error": "operator role required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireViewer allows any authenticated panel user with a recognized role.
// (Viewer routes normally rely on AuthMiddleware alone; this is an explicit gate.)
func RequireViewer() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := currentPrincipal(c)
		if !ok || principal.Kind != "user" || !IsViewerOrAbove(principal.Role) {
			metrics.IncRBACDeny()
			c.JSON(http.StatusForbidden, gin.H{"error": "viewer role required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		// Public / unauthenticated: login, stager delivery (/api/s/* and /api/stage2/*),
		// health probes (non-/api or explicit /api/healthz), and static UI.
		if path == "/api/auth/login" ||
			path == "/api/healthz" || path == "/api/readyz" ||
			strings.HasPrefix(path, "/api/s/") ||
			strings.HasPrefix(path, "/api/stage2/") ||
			!strings.HasPrefix(path, "/api") {
			c.Next()
			return
		}

		now := time.Now()
		clientIP := c.ClientIP()
		if !ipAllowed(clientIP, loadPanelAllowedIPs(now), true) {
			log.Printf("[Security] panel access denied for IP %s", clientIP)
			c.Status(http.StatusForbidden)
			c.Abort()
			return
		}

		token := ""
		if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}

		// Durable session (or MCP) bearer via Authorization header — existing path.
		// WS upgrade paths intentionally do NOT fall through to session LookupSession
		// for query ?token=; browsers mint a short-lived ?ticket= instead.
		if token != "" {
			policy := loadMCPPolicy(now)
			if tokenEqual(token, policy.Token) {
				if !policy.Enabled {
					denyMCP(c, "mcp_disabled")
					return
				}
				if !ipAllowed(clientIP, policy.CIDRs, false) {
					metrics.IncMCPDeny()
					log.Printf("[Security] MCP access denied for IP %s", clientIP)
					store.SaveAuditLog(&model.AuditLog{
						Principal: "mcp",
						Username:  "mcp",
						Role:      "mcp",
						Method:    c.Request.Method,
						Path:      path,
						ClientIP:  clientIP,
						Status:    "denied",
						ErrorCode: "mcp_ip_denied",
						Message:   "mcp IP not in allowlist",
					})
					c.Status(http.StatusForbidden)
					c.Abort()
					return
				}
				allowed, writeRequested := mcpEndpointAllowed(c.Request.Method, path, policy.ReadOnly)
				if !allowed {
					if writeRequested {
						denyMCP(c, "mcp_read_only")
					} else {
						denyMCP(c, "mcp_endpoint_denied")
					}
					return
				}
				setPrincipal(c, Principal{Kind: "mcp", Username: "mcp", Role: "mcp"})
				// Audit successful MCP auth (method/path); status filled after handler.
				c.Next()
				store.SaveAuditLog(&model.AuditLog{
					Principal: "mcp",
					Username:  "mcp",
					Role:      "mcp",
					Method:    c.Request.Method,
					Path:      path,
					ClientIP:  clientIP,
					Status:    fmt.Sprintf("%d", c.Writer.Status()),
					Message:   "mcp allowed",
				})
				return
			}

			// Panel users: look up hashed session (User.Token is no longer used for auth).
			sess, user, err := store.LookupSession(token)
			if err != nil || user == nil || !user.IsActive {
				log.Printf("[Security] invalid panel token from IP %s", clientIP)
				c.Status(http.StatusUnauthorized)
				c.Abort()
				return
			}
			if sess != nil {
				store.TouchSession(sess.ID)
			}
			setPrincipal(c, Principal{Kind: "user", Username: user.Username, Role: user.Role})
			c.Next()
			return
		}

		// No Authorization header: only WS upgrade paths may authenticate via
		// a short-lived, single-use ?ticket= (not durable ?token=).
		if isWSUpgradePath(path) {
			ticket := strings.TrimSpace(c.Query("ticket"))
			if ticket == "" {
				// Explicitly reject durable session via query (?token=) here.
				c.Status(http.StatusUnauthorized)
				c.Abort()
				return
			}
			purpose := purposeFromPath(path)
			if purpose == "" {
				c.Status(http.StatusUnauthorized)
				c.Abort()
				return
			}
			_, username, role, err := wsticket.Redeem(ticket, purpose)
			if err != nil {
				log.Printf("[Security] invalid WS ticket from IP %s path=%s: %v", clientIP, path, err)
				c.Status(http.StatusUnauthorized)
				c.Abort()
				return
			}
			setPrincipal(c, Principal{Kind: "user", Username: username, Role: role})
			c.Next()
			return
		}

		c.Status(http.StatusUnauthorized)
		c.Abort()
	}
}

