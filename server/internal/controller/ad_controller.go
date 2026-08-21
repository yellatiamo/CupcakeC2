package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"cupcake-server/pkg/middleware"
	"cupcake-server/internal/model"
	"cupcake-server/internal/storage"
	"cupcake-server/internal/service"
)

// adCallerIdentity extracts role and MCP flag from the authenticated principal.
func adCallerIdentity(c *gin.Context) (role string, isMCP bool) {
	if p, ok := middleware.CurrentPrincipal(c); ok {
		if p.Kind == "mcp" {
			return "mcp", true
		}
		return strings.ToLower(strings.TrimSpace(p.Role)), false
	}
	// Fail closed: unknown principal is not admin
	return "", false
}

func writeAdDispatchError(c *gin.Context, err error) {
	if services.IsPolicyDenial(err) {
		code := "policy_denied"
		msg := err.Error()
		switch {
		case strings.Contains(msg, "mcp_high_risk_denied"):
			code = "mcp_high_risk_denied"
		case strings.Contains(msg, "access denied"):
			code = "insufficient_role"
		case strings.Contains(msg, "confirm"):
			code = "confirm_required"
		}
		c.JSON(http.StatusForbidden, gin.H{"error": msg, "error_code": code})
		return
	}
	if services.IsModuleRequired(err) {
		mod := services.ModuleRequiredID(err)
		if mod == "" {
			mod = "ad"
		}
		c.JSON(http.StatusConflict, gin.H{
			"error":      err.Error(),
			"error_code": "module_required",
			"code":       "module_required",
			"module":     mod,
			"hint":       "请先在受控端「模块」页推送 ad 模块（模块能力），再使用域渗透功能",
		})
		return
	}
	if strings.Contains(err.Error(), "agent offline") {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "error_code": "agent_offline", "code": "agent_offline"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

// HandleAdCapabilities GET /api/ad/capabilities
// Returns the list of available AD operations with their schema.
func HandleAdCapabilities(c *gin.Context) {
	caps := services.ListAdCapabilities()
	c.JSON(http.StatusOK, gin.H{
		"capabilities": caps,
		"count":        len(caps),
	})
}

// HandleAdExec POST /api/ad/exec
// Dispatches an AD module command to an agent.
// Request body:
//
//	{
//	  "uuid": "agent-uuid",
//	  "op": "ad_discover|kerberoast|dcsync|...",
//	  "params": { ... },
//	  "deadline_ms": 60000
//	}
func HandleAdExec(c *gin.Context) {
	var req struct {
		UUID       string                 `json:"uuid"`
		Op         string                 `json:"op"`
		Params     map[string]interface{} `json:"params"`
		DeadlineMs int64                  `json:"deadline_ms"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}
	if req.UUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uuid is required"})
		return
	}
	if req.Op == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "op is required"})
		return
	}

	// Validate op is a known AD command type
	commandType := req.Op
	if !services.IsAdCommand(commandType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unknown ad op: %s", req.Op)})
		return
	}

	// Serialize params to JSON string
	paramsJSON := "{}"
	if req.Params != nil {
		b, err := json.Marshal(req.Params)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid params: " + err.Error()})
			return
		}
		paramsJSON = string(b)
	}

	role, isMCP := adCallerIdentity(c)
	task, err := services.SendAdCommand(req.UUID, commandType, paramsJSON, req.DeadlineMs, role, isMCP)
	if err != nil {
		writeAdDispatchError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "dispatched",
		"task":   task,
	})
}

// HandleAdListTasks GET /api/ad/tasks
// Lists all AD tasks. Optional ?uuid= filter for agent-specific tasks.
// Tasks with risk_level=critical are only visible to admin.
func HandleAdListTasks(c *gin.Context) {
	agentUUID := strings.TrimSpace(c.Query("uuid"))
	role, _ := adCallerIdentity(c)

	var tasks []model.AdTask
	var err error

	if agentUUID != "" {
		tasks, err = store.ListAdTasksByAgent(agentUUID)
	} else {
		tasks, err = store.ListAdTasks()
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Filter critical tasks for non-admin viewers (admin aliases include break-glass-admin).
	if !middleware.IsAdminRole(role) {
		filtered := make([]model.AdTask, 0, len(tasks))
		for _, t := range tasks {
			if t.RiskLevel != "critical" {
				filtered = append(filtered, t)
			}
		}
		tasks = filtered
	}

	c.JSON(http.StatusOK, gin.H{
		"tasks": tasks,
		"count": len(tasks),
	})
}

// HandleAdGetTask GET /api/ad/tasks/:id
// Returns a single AD task by database ID.
func HandleAdGetTask(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	task, err := store.GetAdTaskByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	// Critical tasks: only admin can view details (break-glass-admin / administrator aliases).
	if task.RiskLevel == "critical" {
		role, _ := adCallerIdentity(c)
		if !middleware.IsAdminRole(role) {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin only"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"task": task})
}

// HandleAdDownloadTask GET /api/ad/tasks/:id/download
// Downloads artifact file for a task. Critical → admin only; Cache-Control: no-store.
func HandleAdDownloadTask(c *gin.Context) {
	task, ok := loadAdTaskForArtifact(c)
	if !ok {
		return
	}
	if task.ArtifactPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no artifact", "error_code": "artifact_missing"})
		return
	}
	abs, err := services.ResolveAdArtifactAbs(task.ArtifactPath)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.Header("Cache-Control", "no-store, private")
	c.FileAttachment(abs, filepath.Base(abs))
}

// loadAdTaskForArtifact shared authz for download / graph preview.
func loadAdTaskForArtifact(c *gin.Context) (*model.AdTask, bool) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return nil, false
	}
	task, err := store.GetAdTaskByID(uint(id))
	if err != nil || task == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return nil, false
	}
	role, _ := adCallerIdentity(c)
	if task.RiskLevel == "critical" && !middleware.IsAdminRole(role) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin only", "error_code": "insufficient_role"})
		return nil, false
	}
	if role != "" && !middleware.IsOperatorOrAbove(role) {
		c.JSON(http.StatusForbidden, gin.H{"error": "operator role required for download"})
		return nil, false
	}
	return task, true
}

// HandleAdTaskGraph GET /api/ad/tasks/:id/graph
// Cupcake force-graph preview. Tolerates legacy summary-only artifacts by
// reconstructing Domain→DC from summary + recent ad_discover.
func HandleAdTaskGraph(c *gin.Context) {
	task, ok := loadAdTaskForArtifact(c)
	if !ok {
		return
	}
	// Artifact optional: reconstruct path only needs summary / discover history.
	if task.ArtifactPath == "" && strings.TrimSpace(task.SummaryJSON) == "" && task.Op != "ad_graph_collect" {
		c.JSON(http.StatusNotFound, gin.H{
			"error":      "no graph data",
			"error_code": "artifact_missing",
			"hint":       "先执行「图采集」",
		})
		return
	}
	g, source, err := services.ResolveGraphForAdTask(task)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error":      err.Error(),
			"error_code": "graph_parse_failed",
			"hint":       "可先跑「域/DC 发现」再「图采集」；并确认 ad worker 已推送最新版",
		})
		return
	}
	preview := g.ToPreview()
	c.Header("Cache-Control", "no-store, private")
	c.JSON(http.StatusOK, gin.H{
		"task_id": task.ID,
		"op":      task.Op,
		"source":  source,
		"graph":   preview,
	})
}

// HandleAdDeleteTask DELETE /api/ad/tasks/:id
// Deletes an AD task record. Admin only.
func HandleAdDeleteTask(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	if err := store.DeleteAdTask(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// HandleAdDiscover POST /api/ad/discover
// Convenience endpoint for ad_discover with default params.
func HandleAdDiscover(c *gin.Context) {
	var req struct {
		UUID       string `json:"uuid"`
		Domain     string `json:"domain"`
		DeadlineMs int64  `json:"deadline_ms"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}
	if req.UUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uuid is required"})
		return
	}

	params := make(map[string]interface{})
	if req.Domain != "" {
		params["domain"] = req.Domain
	}

	b, _ := json.Marshal(params)
	role, isMCP := adCallerIdentity(c)
	task, err := services.SendAdCommand(req.UUID, "ad_discover", string(b), req.DeadlineMs, role, isMCP)
	if err != nil {
		writeAdDispatchError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "dispatched", "task": task})
}

// HandleAdPing POST /api/ad/ping
// Convenience endpoint for ad_ping (worker health check).
func HandleAdPing(c *gin.Context) {
	var req struct {
		UUID string `json:"uuid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}
	if req.UUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uuid is required"})
		return
	}

	role, isMCP := adCallerIdentity(c)
	task, err := services.SendAdCommand(req.UUID, "ad_ping", "{}", 15000, role, isMCP)
	if err != nil {
		writeAdDispatchError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "dispatched", "task": task})
}

