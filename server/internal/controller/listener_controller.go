package controllers

import (
	"cupcake-server/pkg/globals"
	"cupcake-server/internal/model"
	"cupcake-server/internal/storage"
	"cupcake-server/internal/service"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// listenerView is the only listener shape exposed through the API. Listener
// credentials stay server-side so payload generation can use listener_id
// without pushing keys or private TLS material into browsers.
type listenerView struct {
	ID                string `json:"id"`
	BindIP            string `json:"bind_ip"`
	Port              int    `json:"port"`
	Protocol          string `json:"protocol"`
	PublicHost        string `json:"public_host"`
	Note              string `json:"note"`
	EncryptMode       string `json:"encrypt_mode"`
	ObfuscateMode     string `json:"obfuscate_mode"`
	CustomPath        string `json:"custom_path"`
	Profile           string `json:"profile"`
	ProfileStrict     bool   `json:"profile_strict"`
	NSDomain          string `json:"ns_domain"`
	PublicDNS         string `json:"public_dns"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
	HeartbeatJitter   int    `json:"heartbeat_jitter"`
	MaxRetry          int    `json:"max_retry"`
	EnableTLS         bool   `json:"enable_tls"`
	HasEncryptionKey  bool   `json:"has_encryption_key"`
	HasTLSKey         bool   `json:"has_tls_key"`
	Status            string `json:"status"`
}

func newListenerView(ln *globals.Listener) listenerView {
	return listenerView{
		ID: ln.ID, BindIP: ln.BindIP, Port: ln.Port, Protocol: ln.Protocol,
		PublicHost: ln.PublicHost, Note: ln.Note, EncryptMode: ln.EncryptMode,
		ObfuscateMode: ln.ObfuscateMode, CustomPath: ln.CustomPath, Profile: ln.Profile,
		ProfileStrict: ln.ProfileStrict, NSDomain: ln.NSDomain, PublicDNS: ln.PublicDNS,
		HeartbeatInterval: ln.HeartbeatInterval, HeartbeatJitter: ln.HeartbeatJitter,
		MaxRetry: ln.MaxRetry, EnableTLS: ln.EnableTLS, HasEncryptionKey: ln.EncryptKey != "",
		HasTLSKey: ln.TLSKeyPath != "" || ln.TLSKeyPEM != "", Status: ln.Status,
	}
}

func ListListeners(c *gin.Context) {
	list := make([]listenerView, 0)
	globals.Listeners.Range(func(k, v interface{}) bool {
		list = append(list, newListenerView(v.(*globals.Listener)))
		return true
	})
	c.JSON(http.StatusOK, list)
}

func CreateListener(c *gin.Context) {
	var req struct {
		BindIP         string `json:"bind_ip"`
		Port           int    `json:"port"`
		Note           string `json:"note"`
		Protocol       string `json:"protocol"`
		PublicHost     string `json:"public_host"`
		EncryptMode    string `json:"encrypt_mode"`
		EncryptKey     string `json:"encrypt_key"`
		EncryptionSalt string `json:"encryption_salt"`
		ObfuscateMode  string `json:"obfuscate_mode"`
		NSDomain       string `json:"ns_domain"`
		PublicDNS      string `json:"public_dns"`
		HeartbeatInterval int `json:"heartbeat_interval"`
		HeartbeatJitter   int `json:"heartbeat_jitter"`
		MaxRetry          int `json:"max_retry"`
		CustomPath        string `json:"custom_path"`
		Profile           string `json:"profile"`
		ProfileStrict     bool   `json:"profile_strict"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid input"})
		return
	}

	if req.Port == 8080 {
		c.JSON(400, gin.H{"error": "Port 8080 is reserved"})
		return
	}

	id := fmt.Sprintf("L-%d", req.Port)
	if _, ok := globals.Listeners.Load(id); ok {
		c.JSON(400, gin.H{"error": "Port already in use"})
		return
	}

	if req.BindIP == "" { req.BindIP = "0.0.0.0" }
	if req.Protocol == "" { req.Protocol = "WebSocket" }

	newListener := &globals.Listener{
		ID:                id,
		BindIP:            req.BindIP,
		Port:              req.Port,
		Protocol:          req.Protocol,
		PublicHost:        req.PublicHost,
		Note:              req.Note,
		EncryptMode:       req.EncryptMode,
		EncryptKey:        req.EncryptKey,
		EncryptionSalt:    req.EncryptionSalt,
		ObfuscateMode:     req.ObfuscateMode,
		CustomPath:        req.CustomPath,
		Profile:           req.Profile,
		ProfileStrict:     req.ProfileStrict,
		NSDomain:          req.NSDomain,
		PublicDNS:         req.PublicDNS,
		HeartbeatInterval: req.HeartbeatInterval,
		HeartbeatJitter:   req.HeartbeatJitter,
		MaxRetry:          req.MaxRetry,
		Status:            "Running",
	}

	if err := services.StartListenerInstance(newListener); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	globals.Listeners.Store(id, newListener)
	
	// DB Logic
	// 🔒 CRITICAL PERSISTENCE FIX: Save all security parameters to DB
	lModel := &model.Listener{
		ID:                id,
		BindIP:            req.BindIP,
		Port:              req.Port,
		Protocol:          req.Protocol,
		PublicHost:        req.PublicHost,
		Note:              req.Note,
		EncryptMode:       req.EncryptMode,
		EncryptKey:        req.EncryptKey,
		EncryptionSalt:    req.EncryptionSalt,
		ObfuscateMode:     req.ObfuscateMode,
		CustomPath:        req.CustomPath,
		Profile:           req.Profile,
		ProfileStrict:     req.ProfileStrict,
		NSDomain:          req.NSDomain,
		PublicDNS:         req.PublicDNS,
		HeartbeatInterval: req.HeartbeatInterval,
		HeartbeatJitter:   req.HeartbeatJitter,
		MaxRetry:          req.MaxRetry,
		Status:            "Running",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
	store.SaveListener(lModel)

	c.JSON(http.StatusOK, newListenerView(newListener))
}

func StopListener(c *gin.Context) {
	id := c.Param("id")
	val, ok := globals.Listeners.Load(id)
	if !ok {
		c.JSON(404, gin.H{"error": "Not found"})
		return
	}
	ln := val.(*globals.Listener)
	services.StopListenerInstance(ln)
	store.UpdateListenerStatus(id, "Stopped")
	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

func StartListener(c *gin.Context) {
	id := c.Param("id")
	val, ok := globals.Listeners.Load(id)
	if !ok {
		c.JSON(404, gin.H{"error": "Not found"})
		return
	}
	ln := val.(*globals.Listener)
	if err := services.StartListenerInstance(ln); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	ln.Status = "Running"
	store.UpdateListenerStatus(id, "Running")
	c.JSON(http.StatusOK, gin.H{"status": "started"})
}

func DeleteListener(c *gin.Context) {
	id := c.Param("id")
	if val, ok := globals.Listeners.Load(id); ok {
		services.StopListenerInstance(val.(*globals.Listener))
	}
	globals.Listeners.Delete(id)
	store.DeleteListener(id)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

