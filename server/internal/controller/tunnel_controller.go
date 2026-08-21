package controllers

import (
	"net/http"
	"strings"

	"cupcake-server/internal/service"

	"github.com/gin-gonic/gin"
)

// GET /api/socks (Alias for /api/tunnel)
func ListSocks(c *gin.Context) {
    ListTunnels(c)
}

// GET /api/tunnel
func ListTunnels(c *gin.Context) {
    tunnels := services.GetActiveTunnels()
    c.JSON(200, gin.H{"status": "success", "tunnels": tunnels})
}

// POST /api/socks/stop
func StopSocks(c *gin.Context) {
    StopTunnel(c)
}

// POST /api/tunnel/stop
func StopTunnel(c *gin.Context) {
    var req struct {
        Port string `json:"port"`
    }
    if err := c.BindJSON(&req); err != nil { 
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
        return 
    }
    if _, err := services.ValidateTunnelPort(req.Port); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
        return
    }

    if err := services.StopTunnel(req.Port); err != nil {
        c.JSON(400, gin.H{"status": "error", "message": err.Error()})
        return
    }
    c.JSON(200, gin.H{"status": "success", "message": "Tunnel stopped"})
}

func DeleteTunnelController(c *gin.Context) {
    var req struct {
        Port string `json:"port"`
    }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
        return
    }
    if _, err := services.ValidateTunnelPort(req.Port); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
        return
    }

    if err := services.DeleteTunnel(req.Port); err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }
    c.JSON(200, gin.H{"status": "success", "message": "Tunnel deleted"})
}

func StartSocks(c *gin.Context) {
    StartTunnel(c)
}

func StartTunnel(c *gin.Context) {
    var req struct {
        UUID     string `json:"uuid"`
        Port     string `json:"port"`
        Type     string `json:"type"` // "socks5" or "http"
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	if strings.TrimSpace(req.UUID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "agent uuid is required"})
		return
	}
	port, err := services.ValidateTunnelPort(req.Port)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	req.Port = port

    if req.Type == "" {
		req.Type = "socks5"
	}

    if err := services.StartTunnel(req.UUID, req.Port, req.Type, req.Username, req.Password); err != nil {
		// Invalid port / uuid already 400'd; listen/busy failures stay 500 or 400 if validation-like
		msg := err.Error()
		if strings.Contains(msg, "port is required") ||
			strings.Contains(msg, "invalid port") ||
			strings.Contains(msg, "port out of range") ||
			strings.Contains(msg, "agent uuid is required") {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": msg})
			return
		}
        c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": msg})
        return
    }

	online := services.AgentIsOnline(req.UUID)
	body := gin.H{
		"status":       "success",
		"message":      req.Type + " tunnel started on " + req.Port,
		"port":         req.Port,
		"agent_online": online,
	}
	if !online {
		body["warning"] = "agent offline; local listener is up, traffic will wait until agent connects"
	}
	c.JSON(http.StatusOK, body)
}

