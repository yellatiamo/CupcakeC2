package controllers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strings"

	"cupcake-server/pkg/globals"
	"cupcake-server/internal/service"

	"github.com/gin-gonic/gin"
)

func isAgentOfflineMsg(msg string) bool {
	m := strings.ToLower(strings.TrimSpace(msg))
	return m == "offline" || m == "agent offline" || strings.Contains(m, "agent offline")
}

func writeAgentFSError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, services.ErrAgentOffline) || isAgentOfflineMsg(err.Error()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent offline", "code": "offline"})
		return
	}
	if errors.Is(err, services.ErrYamuxRequired) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "TCP Yamux session required for file transfer (no control-plane chunk fallback)",
			"code":  "yamux_required",
		})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

func writeAgentFSResponseError(c *gin.Context, msg string) {
	if isAgentOfflineMsg(msg) {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent offline", "code": "offline"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
}

func ReadFileController(c *gin.Context) {
	uuid := c.Query("uuid")
	path := c.Query("path")
	if uuid == "" || path == "" {
		c.JSON(400, gin.H{"error": "uuid and path are required"})
		return
	}

	resp, err := services.ReadFile(uuid, path)
	if err != nil {
		writeAgentFSError(c, err)
		return
	}

	if resp.Status == "error" {
		writeAgentFSResponseError(c, resp.Error)
		return
	}

	c.JSON(200, resp)
}

type DeleteRequest struct {
	UUID  string   `json:"uuid"`
	Paths []string `json:"paths"`
}

func DeleteFilesController(c *gin.Context) {
	var req DeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request body"})
		return
	}

	if req.UUID == "" || len(req.Paths) == 0 {
		c.JSON(400, gin.H{"error": "uuid and paths are required"})
		return
	}

	resp, err := services.DeleteFiles(req.UUID, req.Paths)
	if err != nil {
		writeAgentFSError(c, err)
		return
	}

	if resp.Status == "error" {
		writeAgentFSResponseError(c, resp.Error)
		return
	}

	c.JSON(200, gin.H{"status": "ok"})
}

func ListFilesController(c *gin.Context) {
	uuid := c.Query("uuid")
	path := c.Query("path")

	// Compatibility: the frontend calls POST /api/fs/ls with JSON body.
	// Keep GET query support for older clients.
	if uuid == "" && c.Request.Method != http.MethodGet {
		var req struct {
			UUID       string `json:"uuid"`
			AgentUUID  string `json:"agent_uuid"`
			ClientUUID string `json:"client_uuid"`
			Path       string `json:"path"`
			Dir        string `json:"dir"`
		}
		if err := c.ShouldBindJSON(&req); err == nil {
			if req.UUID != "" {
				uuid = req.UUID
			} else if req.AgentUUID != "" {
				uuid = req.AgentUUID
			} else if req.ClientUUID != "" {
				uuid = req.ClientUUID
			}

			if req.Path != "" {
				path = req.Path
			} else if req.Dir != "" {
				path = req.Dir
			}
		}
	}

	if uuid == "" {
		c.JSON(400, gin.H{"error": "uuid is required"})
		return
	}

	resp, err := services.GetFileList(uuid, path)
	if err != nil {
		writeAgentFSError(c, err)
		return
	}

	if resp.Status == "error" {
		writeAgentFSResponseError(c, resp.Error)
		return
	}

	c.JSON(200, resp)
}

func Upload(c *gin.Context) {
	// True streaming: MultipartReader pipes the file part over Yamux FILE (0x0E).
	// No FormFile full-buffer, no temp disk, no control-plane file_upload_chunk / base64.
	reader, err := c.Request.MultipartReader()
	if err != nil {
		c.JSON(400, gin.H{"error": "multipart read: " + err.Error()})
		return
	}

	uuid := ""
	targetPath := ""
	var filePart *multipart.Part

	for {
		part, perr := reader.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			c.JSON(400, gin.H{"error": "read part: " + perr.Error()})
			return
		}
		name := part.FormName()
		switch name {
		case "uuid":
			b, _ := io.ReadAll(part)
			uuid = string(b)
		case "path":
			b, _ := io.ReadAll(part)
			targetPath = string(b)
		case "file":
			filePart = part
			// file field is usually last; keep handle and stream immediately
			goto fileFound
		}
	}

fileFound:
	if uuid == "" {
		c.JSON(400, gin.H{"error": "missing form field: uuid"})
		return
	}
	if targetPath == "" {
		c.JSON(400, gin.H{"error": "missing form field: path (remote destination path)"})
		return
	}
	if filePart == nil {
		c.JSON(400, gin.H{"error": "missing form file field 'file'"})
		return
	}

	if _, ok := globals.Clients.Load(uuid); !ok {
		c.JSON(404, gin.H{"error": "Agent Offline", "code": "offline"})
		return
	}

	log.Printf("[upload] start yamux-FILE agent=%s path=%s", uuid, targetPath)

	written, errUp := services.UploadViaYamux(uuid, targetPath, filePart)
	if errUp != nil {
		if errors.Is(errUp, services.ErrYamuxRequired) {
			// ⚡ FALLBACK: WebSocket / DNS agents have no Yamux session — stream the
			// multipart body over the control-plane command channel (base64 chunks).
			log.Printf("[upload] yamux unavailable for agent=%s, using control-plane chunk fallback path=%s", uuid, targetPath)
			written, errUp = uploadViaControlPlane(uuid, targetPath, filePart)
		}
		if errUp != nil {
			log.Printf("[upload] FAIL agent=%s path=%s: %v", uuid, targetPath, errUp)
			if errors.Is(errUp, services.ErrAgentOffline) || isAgentOfflineMsg(errUp.Error()) {
				c.JSON(http.StatusNotFound, gin.H{"error": "agent offline", "code": "offline", "path": targetPath})
				return
			}
			if errors.Is(errUp, services.ErrYamuxRequired) {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "TCP Yamux session required for file upload (no control-plane chunk fallback)",
					"code":  "yamux_required",
					"path":  targetPath,
				})
				return
			}
			c.JSON(500, gin.H{
				"error":      "Agent upload failed: " + errUp.Error(),
				"bytes_sent": written,
				"path":       targetPath,
			})
			return
		}
	}

	log.Printf("[upload] OK agent=%s path=%s bytes=%d", uuid, targetPath, written)
	c.JSON(200, gin.H{"status": "upload_success", "bytes": written, "path": targetPath})
}

// uploadViaControlPlane streams a multipart file part to the agent as base64
// chunks over the command channel (WS/DNS fallback; no Yamux session needed).
// is_append=false on the first chunk, true afterwards.
func uploadViaControlPlane(uuid, targetPath string, filePart *multipart.Part) (int64, error) {
	// 512 KiB raw → ~683 KiB base64 — safe for encrypt/obfuscate frames.
	const chunkSize = 512 * 1024
	buffer := make([]byte, chunkSize)
	isAppend := false
	var total int64

	for {
		n, readErr := filePart.Read(buffer)
		if n > 0 {
			b64Data := base64.StdEncoding.EncodeToString(buffer[:n])
			if errSend := services.UploadChunk(uuid, targetPath, b64Data, isAppend); errSend != nil {
				return total, fmt.Errorf("agent upload failed at offset %d: %w", total, errSend)
			}
			total += int64(n)
			isAppend = true
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return total, fmt.Errorf("read stream error: %w", readErr)
		}
	}
	return total, nil
}

