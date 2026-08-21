package controllers

import (
	"cupcake-server/internal/service"
	"github.com/gin-gonic/gin"
	"net/http"
)

func ListProcesses(c *gin.Context) {
	uuid := c.Query("uuid")
	// Compatibility: some frontends call POST /api/ps/list with JSON body.
	if uuid == "" && c.Request.Method != http.MethodGet {
		var req struct {
			UUID       string `json:"uuid"`
			AgentUUID  string `json:"agent_uuid"`
			ClientUUID string `json:"client_uuid"`
		}
		if err := c.ShouldBindJSON(&req); err == nil {
			if req.UUID != "" {
				uuid = req.UUID
			} else if req.AgentUUID != "" {
				uuid = req.AgentUUID
			} else if req.ClientUUID != "" {
				uuid = req.ClientUUID
			}
		}
	}
	if uuid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uuid required"})
		return
	}

	procs, err := services.ListProcesses(uuid)
	if err != nil {
		if err.Error() == "offline" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Agent offline"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": procs})
}

func KillProcess(c *gin.Context) {
	var req struct {
		UUID string `json:"uuid"`
		Pid  int    `json:"pid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.UUID == "" || req.Pid == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uuid and pid are required"})
		return
	}

	if err := services.KillProcess(req.UUID, req.Pid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

