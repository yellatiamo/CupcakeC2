package model

import "time"

// McpPendingRequest is an MCP write that waits for panel admin confirmation.
// Status machine: pending → approved|denied|expired → executed|failed (after approve).
type McpPendingRequest struct {
	ID string `gorm:"primaryKey;size:64" json:"id"`

	Method string `gorm:"size:16" json:"method"`
	Path   string `gorm:"size:256;index" json:"path"`
	Query  string `gorm:"size:512" json:"query,omitempty"`
	// BodyJSON is the exact request body snapshot used at execute time.
	BodyJSON string `gorm:"type:text" json:"body_json,omitempty"`

	// Human-readable description shown on the panel (must include shell text when applicable).
	Summary   string `gorm:"type:text" json:"summary"`
	RiskLevel string `gorm:"size:16;index" json:"risk_level"` // low | medium | high | critical
	Op        string `gorm:"size:64;index" json:"op,omitempty"`
	AgentUUID string `gorm:"size:64;index" json:"agent_uuid,omitempty"`

	Status string `gorm:"size:24;index;default:pending" json:"status"` // pending|approved|denied|expired|executed|failed

	ResultStatus int    `json:"result_status,omitempty"`
	ResultBody   string `gorm:"type:text" json:"result_body,omitempty"`
	ErrorCode    string `gorm:"size:64" json:"error_code,omitempty"`

	ClientIP  string     `gorm:"size:64" json:"client_ip,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `gorm:"index" json:"expires_at"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	DecidedBy string     `gorm:"size:64" json:"decided_by,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
}
