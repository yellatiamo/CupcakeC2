package model

import "time"

// Session is a panel-user bearer session. Only TokenHash is stored (sha256 hex
// of the raw bearer token). MCP API tokens are independent and not stored here.
type Session struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	TokenHash  string     `gorm:"uniqueIndex;size:64;not null" json:"-"`
	UserID     uint       `gorm:"index;not null" json:"user_id"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `gorm:"index" json:"expires_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	IP         string     `gorm:"size:64" json:"ip"`
	UserAgent  string     `gorm:"size:512" json:"user_agent"`
}
