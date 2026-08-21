package controllers

import (
	"net/http"

	"cupcake-server/internal/storage"

	"github.com/gin-gonic/gin"
)

// HandleHealthz is a liveness probe: process is up (no dependency checks).
// Unauthenticated. GET /healthz or /api/healthz → 200 {"status":"ok"}.
func HandleHealthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// HandleReadyz is a readiness probe: returns 200 when the DB is reachable, else 503.
// Unauthenticated. GET /readyz or /api/readyz.
func HandleReadyz(c *gin.Context) {
	if store.DB == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
			"reason": "db not initialized",
		})
		return
	}
	sqlDB, err := store.DB.DB()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
			"reason": err.Error(),
		})
		return
	}
	if err := sqlDB.Ping(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
			"reason": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

