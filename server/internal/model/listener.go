package model

import (
	"time"
)

type Listener struct {
	ID                string    `gorm:"primaryKey" json:"id"`
	BindIP            string    `json:"bind_ip"`
	Port              int       `json:"port"`
	Protocol          string    `json:"protocol"`
	PublicHost        string    `json:"public_host"`
	Note              string    `json:"note"`
	EncryptMode       string    `json:"encrypt_mode"`
	EncryptKey        string    `json:"-"`
	EncryptionSalt    string    `json:"-"`
	ObfuscateMode     string    `json:"obfuscate_mode"`
	CustomPath        string    `json:"custom_path"`
	// Profile: malleable profile name (gmail|outlook|aws|github|default). Empty = no check.
	Profile           string    `json:"profile"`
	// ProfileStrict: when true, reject WS upgrades that fail profile header checks.
	ProfileStrict     bool      `json:"profile_strict" gorm:"default:false"`
	NSDomain          string    `json:"ns_domain"`
	PublicDNS         string    `json:"public_dns"`
	HeartbeatInterval int       `json:"heartbeat_interval"`
	HeartbeatJitter   int       `json:"heartbeat_jitter"`
	MaxRetry          int       `json:"max_retry"`
	Status            string    `json:"status"` // "Running", "Stopped", "Failed"
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`

	// 🔒 TLS Configuration (Phase 1 - Secure WebSocket)
	EnableTLS       bool   `json:"enable_tls" gorm:"default:false"`           // Enable wss:// protocol
	TLSCertPath     string `json:"tls_cert_path"`                             // Path to TLS certificate file
	TLSKeyPath      string `json:"-"`                                         // Path to TLS private key file
	TLSCertPEM      string `json:"-"`                                         // Inline PEM certificate (optional)
	TLSKeyPEM       string `json:"-"`                                          // Inline PEM private key (optional)
}
