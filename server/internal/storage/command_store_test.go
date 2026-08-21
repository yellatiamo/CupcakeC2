package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cupcake-server/internal/model"
	"cupcake-server/pkg/paths"
)

func TestTaskLogRetentionDaysDefault(t *testing.T) {
	t.Setenv("CUPCAKE_TASK_LOG_RETENTION_DAYS", "")
	if d := TaskLogRetentionDays(); d != TaskLogRetentionDaysDefault {
		t.Fatalf("got %d want %d", d, TaskLogRetentionDaysDefault)
	}
}

func TestTaskLogRetentionDaysEnv(t *testing.T) {
	t.Setenv("CUPCAKE_TASK_LOG_RETENTION_DAYS", "3")
	if d := TaskLogRetentionDays(); d != 3 {
		t.Fatalf("got %d want 3", d)
	}
	t.Setenv("CUPCAKE_TASK_LOG_RETENTION_DAYS", "0")
	if d := TaskLogRetentionDays(); d != TaskLogRetentionDaysDefault {
		t.Fatalf("invalid 0 should fall back, got %d", d)
	}
}

func TestPurgeExpiredTaskLogs(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CUPCAKE_DATA_DIR", tmp)
	paths.Init()

	// Fresh sqlite under tmp via production InitDB
	dbPath := paths.Join("cupcake.db")
	_ = os.MkdirAll(filepath.Dir(dbPath), 0755)
	InitDB()
	if DB == nil {
		t.Fatal("DB nil")
	}
	// Release file lock so TempDir cleanup succeeds on Windows.
	t.Cleanup(func() {
		if DB != nil {
			if sqlDB, err := DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
			DB = nil
		}
	})

	logDir := paths.Join("logs")
	_ = os.MkdirAll(logDir, 0755)

	oldFile := filepath.Join(logDir, "task_oldreq.txt")
	newFile := filepath.Join(logDir, "task_newreq.txt")
	if err := os.WriteFile(oldFile, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newFile, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	// Age the old file
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	// DB rows
	oldLog := model.CommandLog{
		AgentUUID: "a",
		ReqID:     "oldreq",
		Type:      "shell",
		Status:    "completed",
		CreatedAt: oldTime,
		UpdatedAt: oldTime,
	}
	newLog := model.CommandLog{
		AgentUUID: "a",
		ReqID:     "newreq",
		Type:      "shell",
		Status:    "completed",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := DB.Create(&oldLog).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Create(&newLog).Error; err != nil {
		t.Fatal(err)
	}

	files, _, err := PurgeExpiredTaskLogs(7 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if files < 1 {
		t.Fatalf("expected at least 1 file removed, got %d", files)
	}
}

func TestGetCommandHistoryFiltered_RealDB(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CUPCAKE_DATA_DIR", tmp)
	paths.Init()

	dbPath := paths.Join("cupcake.db")
	_ = os.MkdirAll(filepath.Dir(dbPath), 0755)
	InitDB()
	if DB == nil {
		t.Fatal("DB nil after InitDB")
	}
	t.Cleanup(func() {
		if DB != nil {
			if sqlDB, err := DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
			DB = nil
		}
	})

	// Seed mixed records: two agents, panel + mcp + internal sources
	now := time.Now()
	seed := []model.CommandLog{
		{AgentUUID: "agent-A", ReqID: "P1", Type: "shell", Input: "whoami", Status: "completed", Source: "panel", CreatedBy: "alice", CreatedAt: now.Add(-5 * time.Minute), UpdatedAt: now},
		{AgentUUID: "agent-A", ReqID: "M1", Type: "plugin", Input: "Args: -h 1.1.1.1", Status: "completed", Source: "mcp", CreatedBy: "mcp", CreatedAt: now.Add(-4 * time.Minute), UpdatedAt: now},
		{AgentUUID: "agent-A", ReqID: "I1", Type: "module_stage", Input: "ad", Status: "completed", Source: "internal", CreatedBy: "", CreatedAt: now.Add(-3 * time.Minute), UpdatedAt: now},
		{AgentUUID: "agent-B", ReqID: "P2", Type: "shell", Input: "ipconfig", Status: "completed", Source: "panel", CreatedBy: "bob", CreatedAt: now.Add(-2 * time.Minute), UpdatedAt: now},
		{AgentUUID: "agent-B", ReqID: "M2", Type: "ad_discover", Input: "{}", Status: "completed", Source: "mcp", CreatedBy: "mcp", CreatedAt: now.Add(-1 * time.Minute), UpdatedAt: now},
	}
	for i := range seed {
		if err := DB.Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	// Agent A, all sources
	allA, err := GetCommandHistoryFiltered("agent-A", "", 10)
	if err != nil {
		t.Fatalf("GetCommandHistoryFiltered A/all: %v", err)
	}
	if len(allA) != 3 {
		t.Fatalf("agent-A all: got %d want 3", len(allA))
	}

	// Agent A, only mcp
	mcpA, err := GetCommandHistoryFiltered("agent-A", "mcp", 10)
	if err != nil {
		t.Fatalf("GetCommandHistoryFiltered A/mcp: %v", err)
	}
	if len(mcpA) != 1 || mcpA[0].ReqID != "M1" {
		t.Fatalf("agent-A mcp: got %+v want single M1", mcpA)
	}

	// All agents, panel only
	panelAll, err := GetCommandHistoryFiltered("", "panel", 10)
	if err != nil {
		t.Fatalf("GetCommandHistoryFiltered ''/panel: %v", err)
	}
	if len(panelAll) != 2 {
		t.Fatalf("all+panel: got %d want 2", len(panelAll))
	}

	// All agents, all sources (limit)
	all, err := GetCommandHistoryFiltered("", "all", 5)
	if err != nil {
		t.Fatalf("GetCommandHistoryFiltered ''/all: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("all+all limited: got %d want 5", len(all))
	}
}

func TestPurgeExpiredTaskLogs_RowsAndFiles(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CUPCAKE_DATA_DIR", tmp)
	paths.Init()

	dbPath := paths.Join("cupcake.db")
	_ = os.MkdirAll(filepath.Dir(dbPath), 0755)
	InitDB()
	if DB == nil {
		t.Fatal("DB nil")
	}
	t.Cleanup(func() {
		if DB != nil {
			if sqlDB, err := DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
			DB = nil
		}
	})

	logDir := paths.Join("logs")
	_ = os.MkdirAll(logDir, 0755)

	oldFile := filepath.Join(logDir, "task_oldreq.txt")
	newFile := filepath.Join(logDir, "task_newreq.txt")
	if err := os.WriteFile(oldFile, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newFile, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	oldLog := model.CommandLog{
		AgentUUID: "a", ReqID: "oldreq", Type: "shell", Status: "completed",
		CreatedAt: oldTime, UpdatedAt: oldTime,
	}
	newLog := model.CommandLog{
		AgentUUID: "a", ReqID: "newreq", Type: "shell", Status: "completed",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := DB.Create(&oldLog).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Create(&newLog).Error; err != nil {
		t.Fatal(err)
	}

	files, rows, err := PurgeExpiredTaskLogs(7 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = rows // rows may be 0 or more depending on prior state in this test file; we only assert files here for this helper
	if files < 1 {
		t.Fatalf("expected at least 1 file removed, got %d", files)
	}
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Fatal("old file should be gone")
	}
	if _, err := os.Stat(newFile); err != nil {
		t.Fatal("new file should remain")
	}
	var count int64
	DB.Model(&model.CommandLog{}).Where("req_id = ?", "newreq").Count(&count)
	if count != 1 {
		t.Fatalf("new row should remain, count=%d", count)
	}
	DB.Model(&model.CommandLog{}).Where("req_id = ?", "oldreq").Count(&count)
	if count != 0 {
		t.Fatalf("old row should be gone, count=%d", count)
	}
}

