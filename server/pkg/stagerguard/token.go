package stagerguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	tokenSecretOnce sync.Once
	tokenSecret     []byte
)

// TokenSecret returns the HMAC key used to sign public stager URLs.
// CUPCAKE_STAGER_TOKEN_SECRET overrides; else CUPCAKE_WIRE_SEED; else a fixed lab placeholder.
func TokenSecret() []byte {
	tokenSecretOnce.Do(func() {
		if s := strings.TrimSpace(os.Getenv("CUPCAKE_STAGER_TOKEN_SECRET")); s != "" {
			tokenSecret = []byte(s)
			return
		}
		if s := strings.TrimSpace(os.Getenv("CUPCAKE_WIRE_SEED")); s != "" {
			tokenSecret = []byte(s)
			return
		}
		tokenSecret = []byte("stager-token-dev-only")
	})
	return tokenSecret
}

// SignStagerID returns a short hex token for cache id (first 16 hex chars of HMAC).
func SignStagerID(id string) string {
	mac := hmac.New(sha256.New, TokenSecret())
	mac.Write([]byte(id))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// VerifyStagerToken checks query `t` against HMAC(id).
func VerifyStagerToken(id, token string) bool {
	if id == "" || token == "" {
		return false
	}
	expect := SignStagerID(id)
	// Constant-time compare on equal-length hex
	if len(token) != len(expect) {
		return false
	}
	var diff byte
	for i := 0; i < len(expect); i++ {
		diff |= token[i] ^ expect[i]
	}
	return diff == 0
}

// TokenMiddleware requires ?t=<hmac> on public stager routes unless CUPCAKE_STAGER_OPEN=1.
func TokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.TrimSpace(os.Getenv("CUPCAKE_STAGER_OPEN")) == "1" {
			c.Next()
			return
		}
		id := c.Param("id")
		tok := c.Query("t")
		if tok == "" {
			tok = c.GetHeader("X-Stager-Token")
		}
		if !VerifyStagerToken(id, tok) {
			ip := c.ClientIP()
			Audit(ip, c.Request.URL.Path, id, "token_denied")
			c.Data(http.StatusForbidden, "text/plain", []byte("forbidden"))
			c.Abort()
			return
		}
		c.Next()
	}
}
