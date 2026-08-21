package model

import (
    "time"
)

type GlobalSetting struct {
    Key       string    `gorm:"primaryKey;size:100" json:"key"`
    Value     string    `gorm:"type:text" json:"value"`
    Group     string    `gorm:"index;size:50" json:"group"` // opsec, notify, general
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}

type NotificationWebhook struct {
    ID        uint      `gorm:"primaryKey" json:"id"`
    Name      string    `json:"name"`
    Type      string    `json:"type"` // dingtalk, feishu, slack, telegram
    URL       string    `json:"url"`
    Secret    string    `json:"secret"` // Optional secret for HMAC
    IsEnabled bool      `gorm:"default:true" json:"is_enabled"`
    Events    string    `json:"events"` // comma separated: agent_online,agent_offline,error
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
