package controllers

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/middleware"
	"cupcake-server/pkg/model"
	"cupcake-server/pkg/store"
	"cupcake-server/pkg/wsticket"
	"cupcake-server/services"
)

// loginLock: after 5 failed attempts, lock IP for 5 minutes
const (
	loginMaxFails   = 5
	loginLockWindow = 5 * time.Minute
)

var loginLimiter = struct {
	mu       sync.Mutex
	fails    map[string]int       // consecutive failures
	lockedAt map[string]time.Time // when lock started (zero = not locked)
}{
	fails:    make(map[string]int),
	lockedAt: make(map[string]time.Time),
}

// loginLockRemaining returns remaining lock duration, or 0 if allowed.
func loginLockRemaining(ip string) time.Duration {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()
	now := time.Now()
	if t, ok := loginLimiter.lockedAt[ip]; ok && !t.IsZero() {
		until := t.Add(loginLockWindow)
		if now.Before(until) {
			return until.Sub(now)
		}
		// lock expired
		delete(loginLimiter.lockedAt, ip)
		loginLimiter.fails[ip] = 0
	}
	return 0
}

func recordLoginFailure(ip string) {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()
	loginLimiter.fails[ip]++
	if loginLimiter.fails[ip] >= loginMaxFails {
		loginLimiter.lockedAt[ip] = time.Now()
	}
}

func recordLoginSuccess(ip string) {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()
	loginLimiter.fails[ip] = 0
	delete(loginLimiter.lockedAt, ip)
}

// sensitive settings cannot be written via generic settings API
var blockedSettingKeys = map[string]bool{
	"system_api_token":  true,
	"mcp_api_token":     true,
	"system_mcp_enabled": true,
	"mcp_allowed_cidrs": true,
	"mcp_read_only":     true,
	"web_auth_password": true,
	"web_auth_user":     true,
	"admin_pass":        true,
	"admin_password":    true,
}

var sensitiveSettingKeys = map[string]bool{
	"system_api_token":  true,
	"mcp_api_token":     true,
	"web_auth_password": true,
	"web_auth_user":     true,
	"admin_pass":        true,
	"admin_password":    true,
}

// HandleLogin handles user authentication (panel form login only)
func HandleLogin(c *gin.Context) {
	ip := c.ClientIP()
	if rem := loginLockRemaining(ip); rem > 0 {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":       "too many failed logins, account locked",
			"retry_after": int(rem.Seconds()) + 1,
			"lock_min":    5,
		})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	user, err := store.GetUserByUsername(req.Username)
	if err != nil || user == nil || !store.CheckPasswordHash(req.Password, user.Password) {
		recordLoginFailure(ip)
		store.SaveLoginLog(&model.LoginLog{
			Username:  req.Username,
			IP:        ip,
			UserAgent: c.GetHeader("User-Agent"),
			Status:    "failed",
			Message:   "Invalid credentials",
		})
		// If just locked, tell client
		if rem := loginLockRemaining(ip); rem > 0 {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "too many failed logins, locked for 5 minutes",
				"retry_after": int(rem.Seconds()) + 1,
			})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "Account is disabled"})
		return
	}

	recordLoginSuccess(ip)
	store.SaveLoginLog(&model.LoginLog{
		Username:  req.Username,
		IP:        ip,
		UserAgent: c.GetHeader("User-Agent"),
		Status:    "success",
	})

	// Issue a panel session (store only sha256 hash; return raw token once).
	sessionToken := store.GenerateSecureToken(32)
	if _, err := store.CreateSession(user.ID, sessionToken, ip, c.GetHeader("User-Agent"), store.SessionTTL()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}
	// Stop using legacy User.Token for auth (column may remain for migration).
	if user.Token != "" {
		user.Token = ""
		_ = store.SaveUser(user)
	}

	c.JSON(http.StatusOK, gin.H{
		"token": sessionToken,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

// HandleGetUsers returns all operators
func HandleGetUsers(c *gin.Context) {
	users, err := store.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

// HandleAddUser creates a new operator
func HandleAddUser(c *gin.Context) {
	var user model.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashed, _ := store.HashPassword(user.Password)
	user.Password = hashed

	if err := store.SaveUser(&user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, user)
}

// HandleChangeMyPassword lets any authenticated user change their own password
// (does not require admin /settings/*).
func HandleChangeMyPassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new_password required"})
		return
	}
	// Resolve current user from bearer session (AuthMiddleware already validated)
	token := ""
	if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	_, user, err := store.LookupSession(token)
	if err != nil || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if req.OldPassword != "" && !store.CheckPasswordHash(req.OldPassword, user.Password) {
		// Allow empty old_password for bootstrap UX; if provided must match
		c.JSON(http.StatusForbidden, gin.H{"error": "old password incorrect"})
		return
	}
	hashed, err := store.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	user.Password = hashed
	user.Token = "" // legacy column unused
	if err := store.SaveUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Password change invalidates all existing sessions; issue a fresh one.
	_ = store.RevokeAllUserSessions(user.ID)
	newToken := store.GenerateSecureToken(32)
	if _, err := store.CreateSession(user.ID, newToken, c.ClientIP(), c.GetHeader("User-Agent"), store.SessionTTL()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password updated but session create failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "password updated", "token": newToken})
}

// HandleUpdateUser updates an existing operator's password or role
func HandleUpdateUser(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
		Role     string `json:"role"`
		IsActive *bool  `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	idStr := c.Param("id")
	var user model.User
	if err := store.DB.First(&user, idStr).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if req.Password != "" {
		user.Password, _ = store.HashPassword(req.Password)
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}

	store.SaveUser(&user)

	// Admin password reset or disable: drop all active sessions for that user.
	if req.Password != "" || (req.IsActive != nil && !*req.IsActive) {
		_ = store.RevokeAllUserSessions(user.ID)
		user.Token = ""
		_ = store.SaveUser(&user)
	}

	c.JSON(http.StatusOK, gin.H{"msg": "User updated"})
}

// HandleDeleteUser removes an operator
func HandleDeleteUser(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)
	_ = store.RevokeAllUserSessions(id)
	if err := store.DeleteUser(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "User deleted"})
}

// HandleGetLoginLogs returns recent panel/user login audit logs only.
// MCP principals never write LoginLog entries (they use bearer tokens + AuditLog).
// This endpoint is intentionally panel-only for the "登录审计流".
func HandleGetLoginLogs(c *gin.Context) {
	logs, err := store.GetLoginLogs(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Defensive filter: drop any rows that look like MCP (should never be present).
	filtered := make([]model.LoginLog, 0, len(logs))
	for _, l := range logs {
		if strings.EqualFold(strings.TrimSpace(l.Username), "mcp") {
			continue
		}
		filtered = append(filtered, l)
	}
	c.JSON(http.StatusOK, filtered)
}

// HandleGetSettings returns global config
func HandleGetSettings(c *gin.Context) {
	group := c.Query("group")
	if group == "mcp" {
		HandleGetMCPSettings(c)
		return
	}
	var settings []model.GlobalSetting
	if group != "" {
		settings, _ = store.GetSettingsByGroup(group)
	} else {
		store.DB.Find(&settings)
	}
	filtered := make([]model.GlobalSetting, 0, len(settings))
	for _, setting := range settings {
		if !sensitiveSettingKeys[setting.Key] {
			filtered = append(filtered, setting)
		}
	}
	c.JSON(http.StatusOK, filtered)
}

// HandleUpdateSettings updates global config (whitelist: rejects sensitive keys)
func HandleUpdateSettings(c *gin.Context) {
	var settings []model.GlobalSetting
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, s := range settings {
		if blockedSettingKeys[s.Key] {
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("setting key %q cannot be updated via generic endpoint", s.Key),
			})
			return
		}
		store.SetSetting(s.Key, s.Value, s.Group)
	}
	c.JSON(http.StatusOK, gin.H{"msg": "Settings updated"})
}

type mcpSettingsRequest struct {
	Enabled      *bool  `json:"enabled"`
	AllowedCIDRs string `json:"allowed_cidrs"`
	ReadOnly     *bool  `json:"read_only"`
}

// HandleGetMCPSettings deliberately returns policy metadata only. MCP tokens
// are write-only and revealed exactly once by the rotation endpoint.
func HandleGetMCPSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"enabled":          store.GetSetting("system_mcp_enabled") == "true",
		"allowed_cidrs":    store.GetSetting("mcp_allowed_cidrs"),
		"read_only":        store.GetSetting("mcp_read_only") != "false",
		"token_configured": store.GetSetting("mcp_api_token") != "",
	})
}

func HandleUpdateMCPSettings(c *gin.Context) {
	var req mcpSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid MCP settings"})
		return
	}
	if req.Enabled != nil {
		if *req.Enabled && middleware.ValidateIPRules(req.AllowedCIDRs, false) != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "MCP must have at least one valid source IP/CIDR when enabled"})
			return
		}
		value := "false"
		if *req.Enabled {
			value = "true"
		}
		_ = store.SetSetting("system_mcp_enabled", value, "mcp")
	}
	if req.AllowedCIDRs != "" {
		if err := middleware.ValidateIPRules(req.AllowedCIDRs, false); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		_ = store.SetSetting("mcp_allowed_cidrs", req.AllowedCIDRs, "mcp")
	}
	if req.ReadOnly != nil {
		value := "false"
		if *req.ReadOnly {
			value = "true"
		}
		_ = store.SetSetting("mcp_read_only", value, "mcp")
	}
	middleware.InvalidateAuthCache()
	HandleGetMCPSettings(c)
}

func HandleRotateMCPToken(c *gin.Context) {
	token := store.GenerateSecureToken(48)
	if err := store.SetSetting("mcp_api_token", token, "mcp"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate MCP token"})
		return
	}
	middleware.InvalidateAuthCache()
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// HandleGetWebhooks returns all notification hooks
func HandleGetWebhooks(c *gin.Context) {
	hooks, _ := store.GetAllWebhooks()
	c.JSON(http.StatusOK, hooks)
}

// HandleSaveWebhook creates or updates a hook
func HandleSaveWebhook(c *gin.Context) {
	var hook model.NotificationWebhook
	if err := c.ShouldBindJSON(&hook); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	store.SaveWebhook(&hook)
	c.JSON(http.StatusOK, hook)
}

// HandleDeleteWebhook removes a hook
func HandleDeleteWebhook(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)
	store.DeleteWebhook(id)
	c.JSON(http.StatusOK, gin.H{"msg": "Webhook deleted"})
}

// HandleMaintenanceReset clears sensitive history (admin role + confirmation required)
func HandleMaintenanceReset(c *gin.Context) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	confirm := req.Confirm
	if confirm == "" {
		confirm = c.GetHeader("X-Confirm-Reset")
	}
	if confirm != "RESET_ALL_AGENTS" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": `confirmation required: body {"confirm":"RESET_ALL_AGENTS"} or header X-Confirm-Reset`,
		})
		return
	}

	// RequireAdmin already gates this route; keep a belt-and-suspenders
	// principal check without depending on legacy User.Token.
	if p, ok := middleware.CurrentPrincipal(c); ok {
		if p.Kind != "user" || !middleware.IsAdminRole(p.Role) {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin role required for maintenance reset"})
			return
		}
	}

	store.DB.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&model.Agent{})
	store.DB.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&model.CommandLog{})

	globals.Clients.Range(func(key, value interface{}) bool {
		client := value.(*globals.Client)
		client.CloseOutputChannel()
		globals.Clients.Delete(key)
		return true
	})

	c.JSON(http.StatusOK, gin.H{"msg": "Database reset successful (Agents and Logs cleared)"})
}

// HandleLogout invalidates the current user session token.
func HandleLogout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token := strings.TrimSpace(authHeader[7:])
		_ = store.RevokeSession(token)
	}
	c.JSON(http.StatusOK, gin.H{"msg": "logged out"})
}

// HandleMintWSTicket issues a short-lived, single-use WebSocket upgrade ticket.
// Requires an authenticated panel user (session bearer via Authorization).
// purpose "pty" / "shell" need operator+; "build_logs" is any authenticated user.
func HandleMintWSTicket(c *gin.Context) {
	principal, ok := middleware.CurrentPrincipal(c)
	if !ok || principal.Kind != "user" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		Purpose string `json:"purpose"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	purpose := strings.ToLower(strings.TrimSpace(req.Purpose))
	if !wsticket.ValidPurpose(purpose) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid purpose", "allowed": []string{
			wsticket.PurposePTY, wsticket.PurposeShell, wsticket.PurposeBuildLogs,
		}})
		return
	}
	switch purpose {
	case wsticket.PurposePTY, wsticket.PurposeShell:
		if !middleware.IsOperatorOrAbove(principal.Role) {
			c.JSON(http.StatusForbidden, gin.H{"error": "operator role required"})
			return
		}
	case wsticket.PurposeBuildLogs:
		// Any authenticated panel user (viewer+).
		if !middleware.IsViewerOrAbove(principal.Role) {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient role"})
			return
		}
	}

	// Resolve user id from session (principal carries username/role only).
	token := ""
	if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	var userID uint
	if token != "" {
		if sess, user, err := store.LookupSession(token); err == nil && user != nil {
			userID = user.ID
			_ = sess
		}
	}
	if userID == 0 {
		if user, err := store.GetUserByUsername(principal.Username); err == nil && user != nil {
			userID = user.ID
		}
	}
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	raw, err := wsticket.Mint(userID, principal.Username, principal.Role, purpose, wsticket.DefaultTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to mint ticket"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ticket":     raw,
		"expires_in": int(wsticket.DefaultTTL.Seconds()),
		"purpose":    purpose,
	})
}

// HandleMaintenanceExport exports all data
func HandleMaintenanceExport(c *gin.Context) {
	var agents []model.Agent
	var logs []model.CommandLog
	store.DB.Find(&agents)
	store.DB.Find(&logs)
	agents = sanitizeAgentsForAPI(agents)

	exportData := gin.H{
		"agents":      agents,
		"logs":        logs,
		"export_time": time.Now(),
	}

	c.Header("Content-Disposition", "attachment; filename=cupcake_export.json")
	c.JSON(http.StatusOK, exportData)
}

// HandleUpdateTemplates triggers a rebuild of the v3.0.1 loader templates
func HandleUpdateTemplates(c *gin.Context) {
	logChan := make(chan string, 50)
	var logs []string
	
	// Collect logs in a separate goroutine
	done := make(chan bool)
	go func() {
		for l := range logChan {
			logs = append(logs, l)
		}
		done <- true
	}()

	err := services.RebuildTemplates(logChan)
	close(logChan)
	<-done

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  err.Error(),
			"logs":   logs,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"msg":    "v3.0.1 模板集更新完成",
		"logs":   logs,
	})
}
