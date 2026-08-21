package model

import (
	"time"
)

type Tunnel struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Port      string    `gorm:"uniqueIndex" json:"port"`
	AgentID   string    `json:"agent_id"`
	Mode      string    `json:"mode"`   // "SOCKS5"
	Status    string    `json:"status"` // "Running", "Stopped"
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
