package config

import (
	"encoding/json"
	"os"
	"strings"
)

type ServerConfig struct {
	AdminPort int    `json:"admin_port"`
	AdminUser string `json:"admin_user"`
	AdminPass string `json:"admin_pass"`
	// Bind address for admin panel (public panel: set 0.0.0.0 behind hardened edge)
	AdminBind string `json:"admin_bind"`
	// Optional TLS for admin panel (public HTTPS)
	AdminTLS       bool   `json:"admin_tls"`
	AdminTLSCert   string `json:"admin_tls_cert"`
	AdminTLSKey    string `json:"admin_tls_key"`
	AdminTLSAuto   bool   `json:"admin_tls_auto"` // generate self-signed if cert/key empty
	// DataDir overrides CUPCAKE_DATA_DIR when set
	DataDir string `json:"data_dir"`
	// Agent stale after this many seconds without LastSeen update
	AgentStaleSecs int `json:"agent_stale_secs"`
	// WireSeed must match agent builds (CUPCAKE_WIRE_SEED). Empty → generate once and persist.
	WireSeed string `json:"wire_seed"`
}

const configFileName = "config.json"

func defaultConfig() *ServerConfig {
	// Production-safe defaults: loopback bind, empty pass → random at first boot.
	// Public panel: set admin_bind/admin_pass (or TLS) in config.json explicitly.
	return &ServerConfig{
		AdminPort:      9999,
		AdminUser:      "admin",
		AdminPass:      "",
		AdminBind:      "127.0.0.1",
		AdminTLS:       false,
		AdminTLSAuto:   false,
		AgentStaleSecs: 180,
		WireSeed:       "",
	}
}

func LoadConfig() (*ServerConfig, error) {
	config := defaultConfig()

	if _, err := os.Stat(configFileName); os.IsNotExist(err) {
		if err := SaveConfig(config); err != nil {
			return config, nil // still return defaults if write fails
		}
		return config, nil
	}

	data, err := os.ReadFile(configFileName)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	if config.AdminBind == "" {
		config.AdminBind = "127.0.0.1"
	}
	if config.AgentStaleSecs <= 0 {
		config.AgentStaleSecs = 180
	}
	config.WireSeed = strings.TrimSpace(config.WireSeed)

	return config, nil
}

// SaveConfig writes config.json (preserves production wire_seed / bind after bootstrap).
func SaveConfig(cfg *ServerConfig) error {
	if cfg == nil {
		return nil
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(configFileName, data, 0600)
}
