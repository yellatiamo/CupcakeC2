package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/metrics"
	"cupcake-server/internal/model"
	"cupcake-server/internal/storage"
)

// HandleMetrics returns lightweight admin observability counters as JSON.
// Admin-only (wired with RequireAdmin). No public scrape endpoint.
//
// Example:
//
//	{
//	  "agents_online": 1,
//	  "agents_total": 3,
//	  "mcp_denies_total": 0,
//	  "rbac_denies_total": 2,
//	  "db_ok": true,
//	  "uptime_sec": 3600
//	}
func HandleMetrics(c *gin.Context) {
	online := 0
	globals.Clients.Range(func(_, _ interface{}) bool {
		online++
		return true
	})

	agentsTotal := 0
	if store.DB != nil {
		if agents, err := store.GetAllAgents(); err == nil {
			agentsTotal = len(agents)
		}
	}

	mcpDenies, rbacDenies, uptimeSec := metrics.Snapshot()

	c.JSON(http.StatusOK, gin.H{
		"agents_online":     online,
		"agents_total":      agentsTotal,
		"mcp_denies_total":  mcpDenies,
		"rbac_denies_total": rbacDenies,
		"db_ok":             dbPingOK(),
		"uptime_sec":        uptimeSec,
	})
}

// HandleGetAuditLogs returns recent MCP/panel authorization audit entries.
// Admin-only via settings group. Query: ?limit=100 (default 100, max 500).
func HandleGetAuditLogs(c *gin.Context) {
	limit := 100
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	logs, err := store.GetAuditLogs(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if logs == nil {
		logs = []model.AuditLog{}
	}
	c.JSON(http.StatusOK, logs)
}

func dbPingOK() bool {
	if store.DB == nil {
		return false
	}
	sqlDB, err := store.DB.DB()
	if err != nil {
		return false
	}
	return sqlDB.Ping() == nil
}

