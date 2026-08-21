package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cupcake-server/pkg/paths"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestSQLiteWALAndBusyTimeout(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CUPCAKE_DATA_DIR", dir)
	paths.Init()

	dbPath := filepath.Join(dir, "pragma_test.db")
	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := applySQLitePragmas(db); err != nil {
		t.Fatalf("pragmas: %v", err)
	}

	// Assign to package DB so helpers work
	prev := DB
	DB = db
	t.Cleanup(func() {
		DB = prev
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
		_ = os.Remove(dbPath)
	})

	mode := strings.ToLower(JournalMode())
	if mode != "wal" {
		t.Fatalf("journal_mode=%q want wal", mode)
	}
	bt := BusyTimeoutMs()
	if bt < 5000 {
		t.Fatalf("busy_timeout=%d want >= 5000", bt)
	}
}
