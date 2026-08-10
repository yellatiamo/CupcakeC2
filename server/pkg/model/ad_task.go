package model

import "time"

// AdTask represents an AD module execution record (PR-06 scaffold).
// Tracks lifecycle: pending → running → collecting_artifact → completed / failed.
// High-risk ops (dcsync) are gated by admin role + confirm contract.
type AdTask struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AgentUUID string    `gorm:"index;size:64" json:"agent_uuid"`
	ReqID     string    `gorm:"uniqueIndex;size:64" json:"req_id"`
	Op        string    `gorm:"index;size:48" json:"op"`           // ad_discover, kerberoast, dcsync, …
	Status    string    `gorm:"size:24;default:pending" json:"status"` // pending | running | collecting_artifact | completed | failed | wiped
	RiskLevel string    `gorm:"size:16;default:low" json:"risk_level"` // low | medium | high | critical

	// Input parameters (JSON, may be truncated for display)
	ParamsJSON string `gorm:"type:text" json:"params_json,omitempty"`

	// Result summary (never contains full hash lines)
	SummaryJSON string `gorm:"type:text" json:"summary_json,omitempty"`

	// Artifact metadata (populated when result exceeds inline threshold)
	ArtifactPath   string `gorm:"size:512" json:"artifact_path,omitempty"`
	ArtifactSHA256 string `gorm:"size:64" json:"artifact_sha256,omitempty"`
	ArtifactBytes  int64  `json:"artifact_bytes,omitempty"`

	// Error code for diagnostics (not_implemented, access_denied, timeout, …)
	ErrorCode string `gorm:"size:48" json:"error_code,omitempty"`

	CreatedBy string    `gorm:"size:48" json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}