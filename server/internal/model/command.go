package model

import (
	"time"
)

type CommandLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AgentUUID string    `gorm:"index" json:"agent_uuid"`
	ReqID     string    `gorm:"index" json:"req_id"` // Added for correlation
	Type      string    `json:"type"`                // "shell", "file_ls", "process_list", etc.
	Input     string    `json:"input"`               // The command sent
	Output    string    `json:"output"`              // The result from Agent
	Status    string    `json:"status"`              // "pending", "completed", "failed"
	// Source distinguishes origin for audit/history classification: "panel" | "mcp" | "internal"
	Source string `gorm:"size:16;default:'panel'" json:"source,omitempty"`
	// CreatedBy records the principal (username for panel, "mcp" for automation)
	CreatedBy string    `gorm:"size:64" json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
