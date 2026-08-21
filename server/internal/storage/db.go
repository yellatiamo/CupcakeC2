package store

import (
	"crypto/rand"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"cupcake-server/internal/model"
	"cupcake-server/pkg/paths"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var DB *gorm.DB

// applySQLitePragmas enforces WAL + busy_timeout after open (belt-and-suspenders vs DSN).
func applySQLitePragmas(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return err
	}
	if _, err := sqlDB.Exec("PRAGMA busy_timeout=5000;"); err != nil {
		return err
	}
	return nil
}

// JournalMode returns current SQLite journal_mode (for tests / diagnostics).
func JournalMode() string {
	if DB == nil {
		return ""
	}
	sqlDB, err := DB.DB()
	if err != nil {
		return ""
	}
	var mode string
	_ = sqlDB.QueryRow("PRAGMA journal_mode;").Scan(&mode)
	return mode
}

// BusyTimeoutMs returns PRAGMA busy_timeout in milliseconds.
func BusyTimeoutMs() int {
	if DB == nil {
		return 0
	}
	sqlDB, err := DB.DB()
	if err != nil {
		return 0
	}
	var ms int
	_ = sqlDB.QueryRow("PRAGMA busy_timeout;").Scan(&ms)
	return ms
}

func InitDB() {
	var err error
	paths.Init()
	dbPath := paths.Join("cupcake.db")
	
	// Create storage directory if not exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Fatalf("Failed to create storage directory: %v", err)
	}

	// Enable WAL + busy_timeout via DSN (glebarez/sqlite).
	// journal_mode=WAL improves concurrent readers; busy_timeout avoids SQLITE_BUSY under multi-goroutine writes.
	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	DB, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err := applySQLitePragmas(DB); err != nil {
		log.Printf("[DB] warning: pragma apply: %v", err)
	}

// Auto Migrate
		err = DB.AutoMigrate(
			&model.Agent{},
			&model.CommandLog{},
			&model.AdTask{},
			&model.McpPendingRequest{},
			&model.Listener{},
			&model.User{},
			&model.Session{},
			&model.LoginLog{},
			&model.AuditLog{},
			&model.GlobalSetting{},
			&model.NotificationWebhook{},
			&model.Tunnel{},
		)
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Initialize default admin if no users exist
	initDefaultAdmin()
}

func initDefaultAdmin() {
	// Do NOT seed a weak default password here.
	// Admin user is created by main.bootstrapAdminPassword (config / random / CUPCAKE_FORCE_DEV_PASS).

	// MCP gets a dedicated credential and a fail-closed default policy.
	// Legacy system_api_token is never reused as MCP token: a fresh random
	// token is generated on upgrade so old shared credentials stop working.
	var mcpTokenCount int64
	DB.Model(&model.GlobalSetting{}).Where("key = ?", "mcp_api_token").Count(&mcpTokenCount)
	if mcpTokenCount == 0 {
		newToken := GenerateSecureToken(32)
		_ = SetSetting("mcp_api_token", newToken, "mcp")
		if legacy := GetSetting("system_api_token"); legacy != "" {
			// Mark the legacy token unusable so it cannot be reused later.
			_ = SetSetting("system_api_token", "", "mcp")
			log.Printf("[mcp] generated new dedicated token; legacy system_api_token cleared")
		}
	}
	ensureSetting("system_mcp_enabled", "false", "mcp")
	ensureSetting("mcp_allowed_cidrs", "127.0.0.1/32,::1/128", "mcp")
	// Default: MCP may only query. Writes require mcp_read_only=false AND panel confirmation.
	ensureSetting("mcp_read_only", "true", "mcp")
	ensureSetting("mcp_confirm_timeout_sec", "180", "mcp")
}

func ensureSetting(key, value, group string) {
	var count int64
	DB.Model(&model.GlobalSetting{}).Where("key = ?", key).Count(&count)
	if count == 0 {
		_ = SetSetting(key, value, group)
	}
}

// IsBcryptHash reports whether s looks like a bcrypt hash (not plaintext).
func IsBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateSecureToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

