package services

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/middleware"
	"cupcake-server/pkg/model"
	"cupcake-server/pkg/store"
)

// RegisterMCPConfirmHooks wires middleware confirm gate to this service (call from main).
func RegisterMCPConfirmHooks() {
	middleware.MCPMutationRequired = MCPConfirmRequired
	middleware.CreateMCPPendingHook = func(method, path, query, body, clientIP string) (*middleware.MCPPendingView, error) {
		r, err := CreateMCPPending(method, path, query, body, clientIP)
		if err != nil {
			return nil, err
		}
		return &middleware.MCPPendingView{
			ID:        r.ID,
			Summary:   r.Summary,
			RiskLevel: r.RiskLevel,
			Op:        r.Op,
			AgentUUID: r.AgentUUID,
			ExpiresAt: r.ExpiresAt,
		}, nil
	}
}

const (
	mcpPendingDefaultTTL = 180 * time.Second
	mcpConfirmTimeoutKey = "mcp_confirm_timeout_sec"
)

// ConfirmTimeout returns how long a pending MCP write waits for panel approval.
func ConfirmTimeout() time.Duration {
	raw := strings.TrimSpace(store.GetSetting(mcpConfirmTimeoutKey))
	if raw == "" {
		return mcpPendingDefaultTTL
	}
	var sec int
	if _, err := fmt.Sscanf(raw, "%d", &sec); err != nil || sec < 30 {
		return mcpPendingDefaultTTL
	}
	if sec > 3600 {
		sec = 3600
	}
	return time.Duration(sec) * time.Second
}

// IsMCPMutation reports whether the HTTP method mutates state (needs panel confirm for MCP).
func IsMCPMutation(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// MCPConfirmRequired is true for every MCP write (增删改). Reads never require confirm.
func MCPConfirmRequired(method, path string) bool {
	_ = path
	return IsMCPMutation(method)
}

// BuildMCPSummary produces a human-readable description for the panel.
// Shell commands MUST include the full command text.
func BuildMCPSummary(method, path, body string) (summary, risk, op, agentUUID string) {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	risk = "high"
	op = method + " " + path

	var m map[string]interface{}
	_ = json.Unmarshal([]byte(body), &m)
	if m == nil {
		m = map[string]interface{}{}
	}
	agentUUID = strField(m, "uuid")
	if agentUUID == "" {
		agentUUID = strField(m, "agent_uuid")
	}

	switch {
	case strings.HasPrefix(path, "/api/cmd"):
		cmd := strField(m, "cmd")
		if cmd == "" {
			cmd = strField(m, "command")
		}
		// Model-authored purpose shown on panel (purpose | reason | usage)
		purpose := strField(m, "purpose")
		if purpose == "" {
			purpose = strField(m, "reason")
		}
		if purpose == "" {
			purpose = strField(m, "usage")
		}
		op = "shell"
		risk = "high"
		if cmd == "" {
			summary = fmt.Sprintf("【Shell】在受控端 %s 执行命令（正文为空）", agentOrUnknown(agentUUID))
		} else if purpose != "" {
			summary = fmt.Sprintf(
				"【Shell】在受控端 %s\n用途: %s\n命令:\n%s",
				agentOrUnknown(agentUUID), purpose, cmd,
			)
		} else {
			summary = fmt.Sprintf(
				"【Shell】在受控端 %s 执行命令（未填写用途 purpose）\n命令:\n%s",
				agentOrUnknown(agentUUID), cmd,
			)
		}

	case strings.HasPrefix(path, "/api/ad/"):
		adOp := strField(m, "op")
		if strings.HasSuffix(path, "/discover") {
			adOp = "ad_discover"
		} else if strings.HasSuffix(path, "/ping") {
			adOp = "ad_ping"
		}
		if adOp == "" {
			adOp = "ad"
		}
		op = adOp
		risk = RiskLevelForOp(adOp)
		if risk == "" {
			risk = "low"
		}
		params := m["params"]
		domain := ""
		if pm, ok := params.(map[string]interface{}); ok {
			domain = strField(pm, "domain")
		}
		if domain == "" {
			domain = strField(m, "domain")
		}
		label := adOpLabel(adOp)
		summary = fmt.Sprintf("【AD/%s】%s\n目标受控端: %s\nop=%s", risk, label, agentOrUnknown(agentUUID), adOp)
		if domain != "" {
			summary += "\n域: " + domain
		}
		if params != nil {
			if b, err := json.Marshal(params); err == nil && string(b) != "null" && string(b) != "{}" {
				summary += "\n参数: " + string(b)
			}
		}

	case strings.HasPrefix(path, "/api/modules/push"):
		id := strField(m, "id")
		if id == "" {
			id = strField(m, "module_id")
		}
		op = "module_push"
		risk = "high"
		summary = fmt.Sprintf("【模块】向受控端 %s 推送/加载模块: %s", agentOrUnknown(agentUUID), id)

	case strings.HasPrefix(path, "/api/modules/upload"):
		op = "module_upload"
		risk = "high"
		summary = "【模块】上传并注册产品模块二进制（MCP 快照；批准后按已登记模块处理）"

	case strings.HasPrefix(path, "/api/modules/query"):
		op = "module_query"
		risk = "low"
		summary = fmt.Sprintf("【模块】查询受控端 %s 已加载模块状态", agentOrUnknown(agentUUID))

	case strings.HasPrefix(path, "/api/modules/"):
		op = "module_delete"
		risk = "high"
		summary = fmt.Sprintf("【模块】删除服务端模块: %s %s", method, path)

	case strings.HasPrefix(path, "/api/files/delete"):
		op = "files_delete"
		risk = "high"
		paths := pathListField(m, "paths")
		summary = fmt.Sprintf("【文件删除】受控端 %s\n路径:\n%s", agentOrUnknown(agentUUID), strings.Join(paths, "\n"))

	case strings.HasPrefix(path, "/api/files/upload"):
		op = "files_upload"
		risk = "high"
		summary = fmt.Sprintf("【文件上传】向受控端 %s 上传文件", agentOrUnknown(agentUUID))

	case strings.HasPrefix(path, "/api/processes/kill"):
		op = "process_kill"
		risk = "high"
		pid := m["pid"]
		summary = fmt.Sprintf("【杀进程】受控端 %s 结束 PID=%v", agentOrUnknown(agentUUID), pid)

	case strings.HasPrefix(path, "/api/plugins/run"):
		op = "plugin_run"
		risk = "high"
		pid := strField(m, "plugin_id")
		args := strField(m, "args")
		summary = fmt.Sprintf("【插件】在受控端 %s 运行插件 %s\n参数: %s", agentOrUnknown(agentUUID), pid, args)

	case strings.HasPrefix(path, "/api/plugins/upload"):
		op = "plugin_upload"
		risk = "high"
		summary = "【插件】上传武器库插件"

	case strings.HasPrefix(path, "/api/plugins/"):
		op = "plugin_delete"
		risk = "high"
		summary = fmt.Sprintf("【插件】删除插件 %s %s", method, path)

	case strings.HasPrefix(path, "/api/tunnel/") || strings.HasPrefix(path, "/api/socks/"):
		op = "tunnel"
		risk = "medium"
		port := strField(m, "port")
		typ := strField(m, "type")
		summary = fmt.Sprintf("【隧道】%s %s\n受控端: %s 端口: %s 类型: %s", method, path, agentOrUnknown(agentUUID), port, typ)

	case strings.HasPrefix(path, "/api/clients/"):
		op = "client_admin"
		risk = "critical"
		summary = fmt.Sprintf("【受控端管理】%s %s", method, path)

	default:
		summary = fmt.Sprintf("【MCP 写操作】%s %s\n目标: %s\n正文摘要: %s",
			method, path, agentOrUnknown(agentUUID), truncate(body, 400))
	}

	if summary == "" {
		summary = fmt.Sprintf("%s %s", method, path)
	}
	return summary, risk, op, agentUUID
}

func agentOrUnknown(u string) string {
	if strings.TrimSpace(u) == "" {
		return "(未指定 uuid)"
	}
	return u
}

func adOpLabel(op string) string {
	for _, c := range ListAdCapabilities() {
		if fmt.Sprint(c["op"]) == op {
			label := fmt.Sprint(c["label"])
			desc := fmt.Sprint(c["description"])
			if label != "" && desc != "" {
				return label + " — " + desc
			}
			if label != "" {
				return label
			}
		}
	}
	return op
}

func strField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func pathListField(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case []string:
		return t
	default:
		return []string{fmt.Sprint(t)}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// CreateMCPPending builds and stores a pending confirmation request.
func CreateMCPPending(method, path, query, body, clientIP string) (*model.McpPendingRequest, error) {
	summary, risk, op, agent := BuildMCPSummary(method, path, body)
	now := time.Now()
	r := &model.McpPendingRequest{
		ID:        uuid.NewString(),
		Method:    strings.ToUpper(method),
		Path:      path,
		Query:     query,
		BodyJSON:  body,
		Summary:   summary,
		RiskLevel: risk,
		Op:        op,
		AgentUUID: agent,
		Status:    "pending",
		ClientIP:  clientIP,
		CreatedAt: now,
		ExpiresAt: now.Add(ConfirmTimeout()),
		UpdatedAt: now,
	}
	if err := store.CreateMcpPending(r); err != nil {
		return nil, err
	}
	_ = store.SaveAuditLog(&model.AuditLog{
		Principal: "mcp",
		Username:  "mcp",
		Role:      "mcp",
		Method:    method,
		Path:      path,
		ClientIP:  clientIP,
		Status:    "pending", // size:32; keep short
		ErrorCode: "pending_confirmation",
		Message:   fmt.Sprintf("mcp pending %s: %s", r.ID, truncate(summary, 200)),
	})
	log.Printf("[MCP-Confirm] pending id=%s risk=%s op=%s path=%s", r.ID, risk, op, path)
	return r, nil
}

// DenyMCPPending rejects a pending request.
func DenyMCPPending(id, decidedBy string) (*model.McpPendingRequest, error) {
	r, err := store.GetMcpPending(id)
	if err != nil {
		return nil, err
	}
	if r.Status != "pending" {
		return nil, fmt.Errorf("request is not pending (status=%s)", r.Status)
	}
	if time.Now().After(r.ExpiresAt) {
		r.Status = "expired"
		r.ErrorCode = "expired"
		_ = store.SaveMcpPending(r)
		return nil, fmt.Errorf("request expired")
	}
	now := time.Now()
	r.Status = "denied"
	r.ErrorCode = "denied_by_panel"
	r.DecidedAt = &now
	r.DecidedBy = decidedBy
	r.UpdatedAt = now
	if err := store.SaveMcpPending(r); err != nil {
		return nil, err
	}
	_ = store.SaveAuditLog(&model.AuditLog{
		Principal: "user",
		Username:  decidedBy,
		Role:      "admin",
		Method:    "POST",
		Path:      "/api/mcp/pending/" + id + "/deny",
		Status:    "denied",
		ErrorCode: "denied_by_panel",
		Message:   "panel denied mcp pending " + id,
	})
	return r, nil
}

// ApproveAndExecuteMCPPending marks approved and runs the snapshot body via internal services.
// panelApproved path skips MCP hard-deny in CheckHighRiskCommand.
func ApproveAndExecuteMCPPending(id, decidedBy string, bodyOverride map[string]interface{}) (*model.McpPendingRequest, error) {
	r, err := store.GetMcpPending(id)
	if err != nil {
		return nil, err
	}
	if r.Status != "pending" {
		return nil, fmt.Errorf("request is not pending (status=%s)", r.Status)
	}
	if time.Now().After(r.ExpiresAt) {
		r.Status = "expired"
		r.ErrorCode = "expired"
		_ = store.SaveMcpPending(r)
		return nil, fmt.Errorf("request expired")
	}

	body := r.BodyJSON
	if bodyOverride != nil {
		// Merge override into existing JSON (e.g. confirm/confirm_domain for dcsync).
		var base map[string]interface{}
		_ = json.Unmarshal([]byte(body), &base)
		if base == nil {
			base = map[string]interface{}{}
		}
		for k, v := range bodyOverride {
			base[k] = v
		}
		// Nested params merge for AD
		if ovp, ok := bodyOverride["params"].(map[string]interface{}); ok {
			pm, _ := base["params"].(map[string]interface{})
			if pm == nil {
				pm = map[string]interface{}{}
			}
			for k, v := range ovp {
				pm[k] = v
			}
			base["params"] = pm
		}
		b, _ := json.Marshal(base)
		body = string(b)
		r.BodyJSON = body
		// Refresh summary after override
		sum, risk, op, agent := BuildMCPSummary(r.Method, r.Path, body)
		r.Summary = sum
		r.RiskLevel = risk
		r.Op = op
		r.AgentUUID = agent
	}

	now := time.Now()
	r.Status = "approved"
	r.DecidedAt = &now
	r.DecidedBy = decidedBy
	r.UpdatedAt = now
	_ = store.SaveMcpPending(r)

	resultStatus, resultBody, execErr := executeMCPPending(r)
	r.ResultStatus = resultStatus
	r.ResultBody = resultBody
	r.UpdatedAt = time.Now()
	if execErr != nil {
		r.Status = "failed"
		r.ErrorCode = "execute_failed"
		r.ResultBody = joinErrBody(resultBody, execErr.Error())
		_ = store.SaveMcpPending(r)
		_ = store.SaveAuditLog(&model.AuditLog{
			Principal: "mcp",
			Username:  decidedBy,
			Role:      "admin",
			Method:    r.Method,
			Path:      r.Path,
			Status:    "failed",
			ErrorCode: "execute_failed",
			Message:   fmt.Sprintf("mcp pending %s execute failed: %v", id, execErr),
		})
		return r, execErr
	}
	r.Status = "executed"
	r.ErrorCode = ""
	_ = store.SaveMcpPending(r)
	_ = store.SaveAuditLog(&model.AuditLog{
		Principal: "mcp",
		Username:  decidedBy,
		Role:      "admin",
		Method:    r.Method,
		Path:      r.Path,
		Status:    "executed",
		Message:   fmt.Sprintf("panel %s approved and executed mcp pending %s", decidedBy, id),
	})
	return r, nil
}

func joinErrBody(body, err string) string {
	if body == "" {
		return err
	}
	return body + "\n" + err
}

// executeMCPPending dispatches the frozen snapshot. Uses panelApproved=true for high-risk AD.
func executeMCPPending(r *model.McpPendingRequest) (status int, body string, err error) {
	path := r.Path
	var m map[string]interface{}
	_ = json.Unmarshal([]byte(r.BodyJSON), &m)
	if m == nil {
		m = map[string]interface{}{}
	}

	switch {
	case path == "/api/cmd" || strings.HasPrefix(path, "/api/cmd?"):
		return executeMCPShell(m)

	case strings.HasPrefix(path, "/api/ad/"):
		return executeMCPAd(path, m)

	case strings.HasPrefix(path, "/api/modules/push"):
		uuid := strField(m, "uuid")
		id := strField(m, "id")
		if id == "" {
			id = strField(m, "module_id")
		}
		if uuid == "" || id == "" {
			return 400, "", fmt.Errorf("uuid and id required")
		}
		// Platform gate in MCP confirm path as well.
		if val, ok := globals.Clients.Load(uuid); ok {
			if cl, ok2 := val.(*globals.Client); ok2 {
				if !IsModuleSupportedOnOS(id, cl.OS) {
					return 403, "", fmt.Errorf("module %s not supported on agent OS %q", id, cl.OS)
				}
			}
		}
		out, err := SendModuleStageWait(uuid, id, 25*time.Second)
		if err != nil {
			return 400, out, err
		}
		b, _ := json.Marshal(ginH{"status": "ok", "detail": out, "id": id, "loaded": true})
		return 200, string(b), nil

	case strings.HasPrefix(path, "/api/processes/kill"):
		uuid := strField(m, "uuid")
		pid := m["pid"]
		if uuid == "" || pid == nil {
			return 400, "", fmt.Errorf("uuid and pid required")
		}
		if err := KillProcess(uuid, toInt(pid)); err != nil {
			return 500, "", err
		}
		b, _ := json.Marshal(ginH{"status": "ok"})
		return 200, string(b), nil

	case strings.HasPrefix(path, "/api/files/delete"):
		uuid := strField(m, "uuid")
		paths := pathListField(m, "paths")
		if uuid == "" || len(paths) == 0 {
			return 400, "", fmt.Errorf("uuid and paths required")
		}
		if _, err := DeleteFiles(uuid, paths); err != nil {
			return 500, "", err
		}
		b, _ := json.Marshal(ginH{"status": "ok"})
		return 200, string(b), nil

	case strings.HasPrefix(path, "/api/plugins/run"):
		return executeMCPPluginRun(m)

	case strings.HasPrefix(path, "/api/tunnel/"), strings.HasPrefix(path, "/api/socks/"):
		return executeMCPTunnel(path, m)

	default:
		return 501, "", fmt.Errorf("pending execute not implemented for %s %s (approve recorded; use panel for this op type)", r.Method, path)
	}
}

func executeMCPShell(m map[string]interface{}) (int, string, error) {
	uuid := strField(m, "uuid")
	cmd := strField(m, "cmd")
	if cmd == "" {
		cmd = strField(m, "command")
	}
	if uuid == "" || cmd == "" {
		return 400, "", fmt.Errorf("uuid and cmd required")
	}
	reqID, err := SendCommandWithID(uuid, cmd)
	if err != nil {
		return 500, "", err
	}
	// Wait for agent stdout so panel history shows real output, not only dispatch ack.
	wait := 45 * time.Second
	row, waitErr := WaitCommandOutput(reqID, wait)
	purpose := strField(m, "purpose")
	if purpose == "" {
		purpose = strField(m, "reason")
	}
	if purpose == "" {
		purpose = strField(m, "usage")
	}
	result := ginH{
		"status":    "success",
		"kind":      "shell",
		"uuid":      uuid,
		"command":   cmd,
		"purpose":   purpose,
		"req_id":    reqID,
		"waited_ms": int(wait / time.Millisecond),
	}
	if row != nil {
		result["cmd_status"] = row.Status
		result["output"] = row.Output
		result["input"] = row.Input
		if row.Status == "completed" {
			result["dispatched"] = true
			result["completed"] = true
			b, _ := json.Marshal(result)
			return 200, string(b), nil
		}
	}
	if waitErr != nil {
		result["status"] = "partial"
		result["dispatched"] = true
		result["completed"] = false
		result["note"] = waitErr.Error() + "（命令已下发；回显超时，可稍后在主机命令历史中查看）"
		b, _ := json.Marshal(result)
		// Still success at dispatch layer — record is useful even without output yet.
		return 200, string(b), nil
	}
	result["dispatched"] = true
	b, _ := json.Marshal(result)
	return 200, string(b), nil
}

func executeMCPAd(path string, m map[string]interface{}) (int, string, error) {
	uuid := strField(m, "uuid")
	if uuid == "" {
		return 400, "", fmt.Errorf("uuid required")
	}
	op := strField(m, "op")
	if strings.HasSuffix(path, "/discover") {
		op = "ad_discover"
	} else if strings.HasSuffix(path, "/ping") {
		op = "ad_ping"
	}
	if op == "" {
		return 400, "", fmt.Errorf("op required")
	}
	paramsJSON := "{}"
	if p, ok := m["params"]; ok && p != nil {
		b, err := json.Marshal(p)
		if err != nil {
			return 400, "", err
		}
		paramsJSON = string(b)
	} else {
		// Allow top-level confirm fields for dcsync convenience
		extra := map[string]interface{}{}
		for _, k := range []string{"domain", "confirm", "confirm_domain", "dc", "user", "all_users", "format"} {
			if v, ok := m[k]; ok {
				extra[k] = v
			}
		}
		if len(extra) > 0 {
			b, _ := json.Marshal(extra)
			paramsJSON = string(b)
		}
	}
	var deadline int64
	if v, ok := m["deadline_ms"]; ok {
		deadline = int64(toInt(v))
	}
	// Panel-approved: execute as admin panel principal (isMCP=false) so MCP hard-deny is skipped.
	task, err := SendAdCommand(uuid, op, paramsJSON, deadline, "admin", false)
	if err != nil {
		if IsPolicyDenial(err) {
			return 403, "", err
		}
		return 500, "", err
	}

	// Wait briefly for AD worker response so history shows real summary/pong.
	wait := DefaultAdDeadline(op)
	if wait < 15*time.Second {
		wait = 15 * time.Second
	}
	if wait > 60*time.Second {
		wait = 60 * time.Second // don't block panel approve forever
	}
	final := task
	deadlineAt := time.Now().Add(wait)
	for time.Now().Before(deadlineAt) {
		t, e := store.GetAdTaskByReqID(task.ReqID)
		if e == nil && t != nil {
			final = t
			if t.Status == "completed" || t.Status == "failed" {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	result := ginH{
		"status":       final.Status,
		"kind":         "ad",
		"uuid":         uuid,
		"op":           op,
		"req_id":       final.ReqID,
		"task_id":      final.ID,
		"summary_json": final.SummaryJSON,
		"error_code":   final.ErrorCode,
		"params":       paramsJSON,
		"dispatched":   true,
	}
	b, _ := json.Marshal(result)
	if final.Status == "failed" {
		return 200, string(b), nil // still store body; status on pending remains executed if dispatch ok
	}
	return 200, string(b), nil
}

func executeMCPPluginRun(m map[string]interface{}) (int, string, error) {
	uuid := strField(m, "uuid")
	pluginID := strField(m, "plugin_id")
	args := strField(m, "args")
	if uuid == "" || pluginID == "" {
		return 400, "", fmt.Errorf("uuid and plugin_id required")
	}
	taskID, err := DeployPluginMCP(uuid, pluginID, args)
	if err != nil {
		return 500, "", err
	}
	b, _ := json.Marshal(ginH{"status": "ok", "task_id": taskID})
	return 200, string(b), nil
}

func executeMCPTunnel(path string, m map[string]interface{}) (int, string, error) {
	uuid := strField(m, "uuid")
	if uuid == "" {
		uuid = strField(m, "agent_id")
	}
	port := strField(m, "port")
	typ := strField(m, "type")
	if typ == "" {
		typ = "socks5"
	}
	user := strField(m, "username")
	pass := strField(m, "password")

	switch {
	case strings.Contains(path, "/start"):
		if err := StartTunnel(uuid, port, typ, user, pass); err != nil {
			return 500, "", err
		}
	case strings.Contains(path, "/stop"):
		if err := StopTunnel(port); err != nil {
			return 500, "", err
		}
	case strings.Contains(path, "/delete"):
		if err := DeleteTunnel(port); err != nil {
			return 500, "", err
		}
	default:
		return 501, "", fmt.Errorf("unknown tunnel path %s", path)
	}
	b, _ := json.Marshal(ginH{"status": "ok"})
	return 200, string(b), nil
}

func toInt(v interface{}) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	default:
		var i int
		_, _ = fmt.Sscanf(fmt.Sprint(v), "%d", &i)
		return i
	}
}

// ginH avoids importing gin in this package for small JSON maps.
type ginH map[string]interface{}

// StartMCPPendingJanitor expires stale pending rows periodically.
func StartMCPPendingJanitor() {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			n, err := store.ExpireStaleMcpPending()
			if err != nil {
				log.Printf("[MCP-Confirm] expire error: %v", err)
				continue
			}
			if n > 0 {
				log.Printf("[MCP-Confirm] expired %d pending request(s)", n)
			}
		}
	}()
}
