package controllers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"cupcake-server/pkg/middleware"
	"cupcake-server/internal/storage"
	"cupcake-server/internal/service"
)

// HandleListMcpPending GET /api/mcp/pending?status=pending|executed|denied|failed|expired
// Empty status returns all records (history retained forever after approve/deny/API auto-approve).
func HandleListMcpPending(c *gin.Context) {
	status := strings.TrimSpace(c.Query("status"))
	// History list needs more rows; pending is usually small.
	limit := 100
	if status == "" {
		limit = 200
	}
	rows, err := store.ListMcpPending(status, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	nPending, _ := store.CountMcpPending("pending")
	nAll, _ := store.CountMcpPending("")
	c.JSON(http.StatusOK, gin.H{
		"pending_count": nPending,
		"total_count":   nAll,
		"items":         rows,
		"count":         len(rows),
		// Records are never deleted on approve/deny/execute — status transitions only.
		"retention":     "permanent",
	})
}

// HandleGetMcpPending GET /api/mcp/pending/:id  (admin or MCP poll)
func HandleGetMcpPending(c *gin.Context) {
	id := c.Param("id")
	r, err := store.GetMcpPending(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found", "error_code": "not_found"})
		return
	}
	// Auto-expire view
	if r.Status == "pending" {
		_, _ = store.ExpireStaleMcpPending()
		r, err = store.GetMcpPending(id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"item": r})
}

// HandleApproveMcpPending POST /api/mcp/pending/:id/approve
func HandleApproveMcpPending(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		// Optional overrides merged into body (e.g. confirm / confirm_domain for dcsync)
		Confirm       *bool                  `json:"confirm"`
		ConfirmDomain string                 `json:"confirm_domain"`
		Domain        string                 `json:"domain"`
		Params        map[string]interface{} `json:"params"`
	}
	_ = c.ShouldBindJSON(&req)

	decidedBy := "admin"
	if p, ok := middleware.CurrentPrincipal(c); ok {
		if p.Username != "" {
			decidedBy = p.Username
		}
	}

	override := map[string]interface{}{}
	if req.Confirm != nil {
		override["confirm"] = *req.Confirm
	}
	if req.ConfirmDomain != "" {
		override["confirm_domain"] = req.ConfirmDomain
	}
	if req.Domain != "" {
		override["domain"] = req.Domain
	}
	if req.Params != nil {
		override["params"] = req.Params
	}
	// Also nest confirm into params for AD dcsync style
	if req.Confirm != nil || req.ConfirmDomain != "" || req.Domain != "" {
		pm, _ := override["params"].(map[string]interface{})
		if pm == nil {
			pm = map[string]interface{}{}
		}
		if req.Confirm != nil {
			pm["confirm"] = *req.Confirm
		}
		if req.ConfirmDomain != "" {
			pm["confirm_domain"] = req.ConfirmDomain
		}
		if req.Domain != "" {
			pm["domain"] = req.Domain
		}
		override["params"] = pm
	}
	if len(override) == 0 {
		override = nil
	}

	r, err := services.ApproveAndExecuteMCPPending(id, decidedBy, override)
	if err != nil {
		if r != nil {
			c.JSON(http.StatusOK, gin.H{
				"status": r.Status,
				"item":   r,
				"error":  err.Error(),
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "executed", "item": r})
}

// HandleDenyMcpPending POST /api/mcp/pending/:id/deny
func HandleDenyMcpPending(c *gin.Context) {
	id := c.Param("id")
	decidedBy := "admin"
	if p, ok := middleware.CurrentPrincipal(c); ok && p.Username != "" {
		decidedBy = p.Username
	}
	r, err := services.DenyMCPPending(id, decidedBy)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "denied", "item": r})
}

