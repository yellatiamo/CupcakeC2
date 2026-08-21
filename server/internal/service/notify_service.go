package services

import (
	"bytes"
	"cupcake-server/internal/storage"
	"cupcake-server/pkg/utils"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func NotifyAgentOnline(uuid, hostname, ip, os, username string) {
	msg := fmt.Sprintf("🔔 [Cupcake C2] 新机器上线!\nHost: %s\nIP: %s\nOS: %s\nUser: %s\nUUID: %s\nTime: %s",
		hostname, ip, os, username, uuid, time.Now().Format("2006-01-02 15:04:05"))
	
	triggerWebhooks("agent_online", msg)
}

func NotifyAgentOffline(uuid, hostname string) {
	msg := fmt.Sprintf("💀 [Cupcake C2] 机器掉线!\nHost: %s\nUUID: %s\nTime: %s",
		hostname, uuid, time.Now().Format("2006-01-02 15:04:05"))
	
	triggerWebhooks("agent_offline", msg)
}

func triggerWebhooks(event, content string) {
	hooks, err := store.GetAllWebhooks()
	if err != nil {
		return
	}

	for _, hook := range hooks {
		if !hook.IsEnabled {
			continue
		}
		
		// Check if event is subscribed
		if !strings.Contains(hook.Events, event) {
			continue
		}

		go sendWebhook(hook.Type, hook.URL, content)
	}
}

func sendWebhook(hookType, url, content string) {
	var payload map[string]interface{}

	switch hookType {
	case "dingtalk":
		payload = map[string]interface{}{
			"msgtype": "text",
			"text": map[string]string{
				"content": content,
			},
		}
	case "feishu":
		payload = map[string]interface{}{
			"msg_type": "text",
			"content": map[string]string{
				"text": content,
			},
		}
	case "slack":
		payload = map[string]interface{}{
			"text": content,
		}
	default:
		// Generic or plain text
		payload = map[string]interface{}{
			"text": content,
		}
	}

	if err := utils.ValidateWebhookURL(url); err != nil {
		log.Printf("[Notify] blocked SSRF webhook %s: %v", url, err)
		return
	}

	jsonBytes, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		log.Printf("[Notify] Failed to send %s webhook: %v", hookType, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("[Notify] %s webhook returned status %d", hookType, resp.StatusCode)
	}
}

