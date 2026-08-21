package model

import (
	"time"
)

type Agent struct {
	UUID          string    `gorm:"primaryKey" json:"uuid"`
	Hostname      string    `json:"hostname"`
	IP            string    `json:"ip"`
	OS            string    `json:"os"`
	Username      string    `json:"username"`
	Arch          string    `json:"arch"`
	Status        string    `json:"status"` // "active", "offline"
	LastSeen      time.Time `json:"last_seen"`
	EncryptionSalt  string `gorm:"type:varchar(64)" json:"encryption_salt"`
	ObfuscationMode string `gorm:"type:varchar(20)" json:"obfuscation_mode"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
