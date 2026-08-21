package model

import (
    "time"
    "gorm.io/gorm"
)

type User struct {
    ID        uint           `gorm:"primaryKey" json:"id"`
    Username  string         `gorm:"uniqueIndex;size:100" json:"username"`
    Password  string         `json:"-"` // Never export hashed password
    Role      string         `gorm:"size:20;default:'operator'" json:"role"` // admin, operator, viewer (administrator / break-glass-admin = admin)
    Token     string         `gorm:"size:100;index" json:"-"` // Legacy; panel auth uses model.Session (token hash)
    IsActive  bool           `gorm:"default:true" json:"is_active"`
    CreatedAt time.Time      `json:"created_at"`
    UpdatedAt time.Time      `json:"updated_at"`
    DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type LoginLog struct {
    ID        uint      `gorm:"primaryKey" json:"id"`
    Username  string    `json:"username"`
    IP        string    `json:"ip"`
    UserAgent string    `json:"user_agent"`
    Status    string    `json:"status"` // success, failed
    Message   string    `json:"message"`
    CreatedAt time.Time `json:"created_at"`
}

// AuditLog records MCP (and future panel) authorization decisions.
// Status is "denied" or an HTTP status code string for allowed requests.
type AuditLog struct {
    ID        uint      `gorm:"primaryKey" json:"id"`
    Principal string    `gorm:"size:32;index" json:"principal"` // mcp | user
    Username  string    `gorm:"size:100;index" json:"username"`
    Role      string    `gorm:"size:40" json:"role"`
    Method    string    `gorm:"size:16" json:"method"`
    Path      string    `gorm:"size:512;index" json:"path"`
    ClientIP  string    `gorm:"size:64;index" json:"client_ip"`
    Status    string    `gorm:"size:32" json:"status"` // denied | "200" | "403" | ...
    ErrorCode string    `gorm:"size:64" json:"error_code"`
    Message   string    `gorm:"size:512" json:"message"`
    CreatedAt time.Time `json:"created_at"`
}
