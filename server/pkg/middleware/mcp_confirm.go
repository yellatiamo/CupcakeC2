package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

// MCPPendingView is the minimal view returned when a write is queued for panel confirm.
type MCPPendingView struct {
	ID        string
	Summary   string
	RiskLevel string
	Op        string
	AgentUUID string
	ExpiresAt time.Time
}

// Hooks registered from services at startup (avoids middleware↔services import cycle).
var (
	// MCPMutationRequired reports whether method/path must be confirmed (all writes).
	MCPMutationRequired func(method, path string) bool
	// CreateMCPPendingHook freezes the request and returns a pending view.
	CreateMCPPendingHook func(method, path, query, body, clientIP string) (*MCPPendingView, error)
)

// MCPConfirmGate intercepts MCP mutating requests and turns them into panel-pending confirmations.
// Default product policy: MCP may only read directly; every write needs admin approval on the web panel.
func MCPConfirmGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := currentPrincipal(c)
		if !ok || p.Kind != "mcp" {
			c.Next()
			return
		}
		if MCPMutationRequired == nil || CreateMCPPendingHook == nil {
			c.Next()
			return
		}
		if !MCPMutationRequired(c.Request.Method, c.Request.URL.Path) {
			c.Next()
			return
		}

		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			_ = c.Request.Body.Close()
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		if len(bodyBytes) > 2<<20 {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":      "request body too large for MCP confirm queue",
				"error_code": "body_too_large",
			})
			c.Abort()
			return
		}

		// Shell via MCP must include model-written purpose for panel operators.
		if strings.HasPrefix(c.Request.URL.Path, "/api/cmd") {
			var bodyMap map[string]interface{}
			_ = json.Unmarshal(bodyBytes, &bodyMap)
			purpose := ""
			if bodyMap != nil {
				for _, k := range []string{"purpose", "reason", "usage"} {
					if v, ok := bodyMap[k]; ok && v != nil {
						purpose = strings.TrimSpace(fmt.Sprint(v))
						if purpose != "" {
							break
						}
					}
				}
			}
			if purpose == "" || utf8.RuneCountInString(purpose) < 4 {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":      "shell via MCP requires purpose (model-written usage description)",
					"error_code": "purpose_required",
					"message":    "请让模型在 send_cmd 中填写 purpose：说明为何执行该 Shell、期望得到什么结果",
				})
				c.Abort()
				return
			}
		}

		pending, err := CreateMCPPendingHook(
			c.Request.Method,
			c.Request.URL.Path,
			c.Request.URL.RawQuery,
			string(bodyBytes),
			c.ClientIP(),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":      "failed to create confirmation request",
				"error_code": "pending_create_failed",
				"detail":     err.Error(),
			})
			c.Abort()
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"ok":         false,
			"status":     "pending_confirmation",
			"error_code": "pending_confirmation",
			"message":    "该操作需要在 Web 控制台由管理员确认后才会执行",
			"id":         pending.ID,
			"summary":    pending.Summary,
			"risk_level": pending.RiskLevel,
			"op":         pending.Op,
			"agent_uuid": pending.AgentUUID,
			"expires_at": pending.ExpiresAt,
			"poll_path":  "/api/mcp/pending/" + pending.ID,
			"hint":       "打开面板「MCP 待确认」批准或拒绝；MCP 可轮询 poll_path 获取结果",
		})
		c.Abort()
	}
}
