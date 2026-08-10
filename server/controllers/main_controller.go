package controllers

import (
	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/model"
	"cupcake-server/pkg/store"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

func GetDashboard(c *gin.Context) {
	v, _ := mem.VirtualMemory()
	cStats, _ := cpu.Percent(0, false)
	cpuPerc := 0.0
	if len(cStats) > 0 { cpuPerc = cStats[0] }
	dStats, _ := disk.Usage("/")
	hInfo, _ := host.Info()

	onlineCount := 0
	globals.Clients.Range(func(k, v interface{}) bool {
		onlineCount++
		return true
	})

	allAgents, _ := store.GetAllAgents()
	totalCount := len(allAgents)

	// Build Agent locations (Real Data for topology)
	type Location struct {
		UUID   string    `json:"uuid"`
		Name   string    `json:"name"`
		IP     string    `json:"ip"`
		OS     string    `json:"os"`
		Status string    `json:"status"`
		Pos    []float64 `json:"pos"`
	}
	var locations []Location
	for _, a := range allAgents {
		lat := 0.0
		lng := 0.0
		if a.IP != "" && a.IP != "127.0.0.1" {
			parts := strings.Split(a.IP, ".")
			if len(parts) == 4 {
				// Deterministic pseudo-random position
				h := 0
				for _, c := range a.UUID { h += int(c) }
				lat = (float64(h%140)) - 70 
				lng = (float64((h*13)%360)) - 180
			}
		}
		locations = append(locations, Location{
			UUID:   a.UUID,
			Name:   a.Hostname,
			IP:     a.IP,
			OS:     a.OS,
			Status: a.Status,
			Pos:    []float64{lng, lat},
		})
	}

	listenerCount := 0
	var activePorts []string
	globals.Listeners.Range(func(k, v interface{}) bool {
		listenerCount++
		if l, ok := v.(*globals.Listener); ok {
			activePorts = append(activePorts, fmt.Sprintf("%d", l.Port))
		}
		return true
	})

	// Fetch recent plugin logs (last 15)
	var pluginLogs []model.CommandLog
	store.DB.Where("type LIKE ?", "%plugin%").Or("type LIKE ?", "%bof%").Order("created_at desc").Limit(15).Find(&pluginLogs)

	// 检测模板就绪情况：只要存在 Windows 或 Linux 其中任一核心模板即认为可用
	winReady := false
	linReady := false
	if _, err := os.Stat("assets/client_template_windows.exe"); err == nil { winReady = true }
	if _, err := os.Stat("assets/client_template_linux"); err == nil { linReady = true }

	c.JSON(http.StatusOK, gin.H{
		"cpu_usage":       fmt.Sprintf("%.1f", cpuPerc),
		"mem_usage":       fmt.Sprintf("%.1f", v.UsedPercent),
		"disk_usage":      fmt.Sprintf("%.1f", dStats.UsedPercent),
		"uptime":          hInfo.Uptime,
		"listener_count":  listenerCount,
		"active_ports":    activePorts,
		"client_count":    totalCount,
		"online_count":    onlineCount,
		"locations":       locations,
		"plugin_logs":     pluginLogs,
		"hostname":        hInfo.Hostname,
		"os":              hInfo.OS,
		"templates_ready": winReady && linReady,
		"win_template":    winReady,
		"lin_template":    linReady,
	})
}

// sanitizeAgentForAPI trims NUL-padded / whitespace fields before JSON export.
func sanitizeAgentForAPI(a model.Agent) model.Agent {
	a.EncryptionSalt = strings.TrimRight(a.EncryptionSalt, "\x00")
	a.EncryptionSalt = strings.TrimSpace(a.EncryptionSalt)
	return a
}

func sanitizeAgentsForAPI(agents []model.Agent) []model.Agent {
	if agents == nil {
		return []model.Agent{}
	}
	out := make([]model.Agent, len(agents))
	for i := range agents {
		out[i] = sanitizeAgentForAPI(agents[i])
	}
	return out
}

func GetClients(c *gin.Context) {
	agents, err := store.GetAllAgents()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	agents = sanitizeAgentsForAPI(agents)
	// Optional pagination: ?page=1&page_size=50 (0/missing page_size = full list for compatibility)
	page := 0
	pageSize := 0
	fmt.Sscanf(c.Query("page"), "%d", &page)
	fmt.Sscanf(c.Query("page_size"), "%d", &pageSize)
	if pageSize > 0 {
		if page < 1 {
			page = 1
		}
		if pageSize > 500 {
			pageSize = 500
		}
		total := len(agents)
		start := (page - 1) * pageSize
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		c.JSON(http.StatusOK, gin.H{
			"items":     agents[start:end],
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		})
		return
	}
	c.JSON(http.StatusOK, agents)
}

func HandleGetAgentHistory(c *gin.Context) {
	uuid := c.Param("uuid")
	src := strings.TrimSpace(c.Query("source")) // "", "all", "panel", "mcp", "internal"
	limit := 100
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	history, _ := store.GetCommandHistoryFiltered(uuid, src, limit)
	c.JSON(http.StatusOK, history)
}

// HandleGetGlobalHistory returns auditable command/plugin/module history across agents.
// Query: source (all|panel|mcp|internal), uuid (empty = all agents), limit (1-500), type (all|plugin|module|shell|ad).
func HandleGetGlobalHistory(c *gin.Context) {
	uuid := strings.TrimSpace(c.Query("uuid"))
	src := strings.TrimSpace(c.Query("source"))
	typeFilter := strings.TrimSpace(c.Query("type"))
	limit := 100
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	// When type-filtering post-query, over-fetch then trim so limit still applies to filtered set.
	fetchLimit := limit
	if typeFilter != "" && !strings.EqualFold(typeFilter, "all") {
		fetchLimit = 500
	}
	history, err := store.GetCommandHistoryFiltered(uuid, src, fetchLimit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if typeFilter != "" && !strings.EqualFold(typeFilter, "all") {
		history = filterCommandHistoryByType(history, typeFilter)
		if len(history) > limit {
			history = history[:limit]
		}
	}
	c.JSON(http.StatusOK, history)
}

func filterCommandHistoryByType(logs []model.CommandLog, typeFilter string) []model.CommandLog {
	tf := strings.ToLower(strings.TrimSpace(typeFilter))
	out := make([]model.CommandLog, 0, len(logs))
	for _, l := range logs {
		t := strings.ToLower(strings.TrimSpace(l.Type))
		match := false
		switch tf {
		case "shell":
			match = t == "shell" || t == "shell_interactive" || t == "shell_exit"
		case "module":
			match = t == "module_stage" || t == "module_unload" || strings.HasPrefix(t, "module_")
		case "ad":
			match = strings.HasPrefix(t, "ad_") || t == "ad"
		case "plugin":
			// Plugin runs log as plugin name or payload kinds; exclude system/shell/module/ad.
			if t == "shell" || t == "shell_interactive" || t == "shell_exit" ||
				t == "migrate" || t == "heartbeat" ||
				strings.HasPrefix(t, "module_") || strings.HasPrefix(t, "ad_") ||
				strings.HasPrefix(t, "file_") || strings.HasPrefix(t, "process_") {
				match = false
			} else {
				match = t == "execute_assembly" || t == "bof_exec" || t == "native_exec" ||
					t == "plugin" || t != ""
			}
		default:
			// Exact type match fallback
			match = t == tf
		}
		if match {
			out = append(out, l)
		}
	}
	return out
}

func DeleteClient(c *gin.Context) {
	uuid := c.Param("uuid")
	// Remove from memory
	globals.Clients.Delete(uuid)
	// Remove from database
	if err := store.DeleteAgent(uuid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
