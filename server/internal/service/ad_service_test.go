package services

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cupcake-server/internal/model"
	"cupcake-server/pkg/paths"
	"cupcake-server/internal/storage"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// setupAdTestDB creates an isolated SQLite DB for AD tests.
func setupAdTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CUPCAKE_DATA_DIR", dir)
	paths.Init()

	dbPath := filepath.Join(dir, "ad_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.AdTask{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	prev := store.DB
	store.DB = db
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
		store.DB = prev
		_ = os.Remove(dbPath)
	})
}

func TestAdCommandTypes(t *testing.T) {
	// All documented AD command types must be recognized
	required := []string{
		"ad_discover",
		"ad_ldap_query",
		"ad_enum_users",
		"ad_enum_groups",
		"ad_enum_privileged_groups",
		"ad_enum_computers",
		"ad_enum_spns",
		"ad_enum_trusts",
		"ad_password_policy",
		"ad_enum_delegation",
		"ad_enum_gpo",
		"ad_collect_sessions",
		"kerberoast",
		"asrep_roast",
		"dcsync",
		"ad_check_replication_rights",
		"ad_graph_collect",
		"ad_acl_collect",
		"ad_ping",
	}
	for _, ct := range required {
		if !IsAdCommand(ct) {
			t.Errorf("IsAdCommand(%q) = false, want true", ct)
		}
	}
	// Non-AD commands must NOT be recognized
	rejected := []string{"shell", "file_list", "process_inject", "bof_exec", "", "ad_unknown"}
	for _, ct := range rejected {
		if IsAdCommand(ct) {
			t.Errorf("IsAdCommand(%q) = true, want false", ct)
		}
	}
}

func TestRiskLevelForOp(t *testing.T) {
	tests := []struct {
		op   string
		want string
	}{
		{"dcsync", "critical"},
		{"kerberoast", "high"},
		{"asrep_roast", "high"},
		{"ad_collect_sessions", "medium"},
		{"ad_discover", "low"},
		{"ad_ping", "low"},
		{"unknown_op", "low"},
	}
	for _, tt := range tests {
		got := RiskLevelForOp(tt.op)
		if got != tt.want {
			t.Errorf("RiskLevelForOp(%q) = %q, want %q", tt.op, got, tt.want)
		}
	}
}

func TestDefaultAdDeadline(t *testing.T) {
	tests := []struct {
		op   string
		want time.Duration
	}{
		{"ad_discover", 30 * time.Second},
		{"ad_ldap_query", 60 * time.Second},
		{"ad_enum_users", 120 * time.Second},
		{"ad_enum_trusts", 30 * time.Second},
		{"ad_password_policy", 15 * time.Second},
		{"kerberoast", 180 * time.Second},
		{"dcsync", 300 * time.Second},
		{"ad_graph_collect", 300 * time.Second},
		{"ad_ping", 15 * time.Second},
		{"unknown_op", 60 * time.Second},
	}
	for _, tt := range tests {
		got := DefaultAdDeadline(tt.op)
		if got != tt.want {
			t.Errorf("DefaultAdDeadline(%q) = %v, want %v", tt.op, got, tt.want)
		}
	}
}

func TestListAdCapabilities(t *testing.T) {
	caps := ListAdCapabilities()
	if len(caps) == 0 {
		t.Fatal("ListAdCapabilities returned empty list")
	}
	// Verify all required ops are present
	ops := make(map[string]bool)
	for _, c := range caps {
		op, ok := c["op"].(string)
		if !ok || op == "" {
			t.Errorf("capability missing op field: %v", c)
		}
		ops[op] = true
		// Verify tier, risk, label fields exist
		for _, field := range []string{"tier", "risk", "label"} {
			if _, ok := c[field]; !ok {
				t.Errorf("capability %q missing field %q", op, field)
			}
		}
	}
	required := []string{"ad_discover", "kerberoast", "dcsync", "ad_ping"}
	for _, op := range required {
		if !ops[op] {
			t.Errorf("capabilities missing required op: %s", op)
		}
	}
}

func TestAdStoreCreateAndQuery(t *testing.T) {
	setupAdTestDB(t)

	// Create a task
	task := &model.AdTask{
		AgentUUID:  "test-agent-uuid",
		ReqID:      "AD-42",
		Op:         "ad_ping",
		Status:     "pending",
		RiskLevel:  "low",
		ParamsJSON: `{"content":"test"}`,
		CreatedBy:  "test",
	}
	if err := store.CreateAdTask(task); err != nil {
		t.Fatalf("CreateAdTask: %v", err)
	}
	if task.ID == 0 {
		t.Fatal("CreateAdTask did not set ID")
	}

	// Query by reqID
	got, err := store.GetAdTaskByReqID("AD-42")
	if err != nil {
		t.Fatalf("GetAdTaskByReqID: %v", err)
	}
	if got.Op != "ad_ping" {
		t.Errorf("GetAdTaskByReqID op = %q, want %q", got.Op, "ad_ping")
	}
	if got.Status != "pending" {
		t.Errorf("GetAdTaskByReqID status = %q, want %q", got.Status, "pending")
	}

	// Update status
	if err := store.UpdateAdTaskStatus("AD-42", "running", ""); err != nil {
		t.Fatalf("UpdateAdTaskStatus: %v", err)
	}
	got, _ = store.GetAdTaskByReqID("AD-42")
	if got.Status != "running" {
		t.Errorf("after update status = %q, want %q", got.Status, "running")
	}

	// Update result
	if err := store.UpdateAdTaskResult("AD-42", `{"hash_count":0}`, "", "", 0); err != nil {
		t.Fatalf("UpdateAdTaskResult: %v", err)
	}
	got, _ = store.GetAdTaskByReqID("AD-42")
	if got.Status != "completed" {
		t.Errorf("after result status = %q, want %q", got.Status, "completed")
	}
	if got.SummaryJSON != `{"hash_count":0}` {
		t.Errorf("summary = %q, want %q", got.SummaryJSON, `{"hash_count":0}`)
	}

	// List by agent
	tasks, err := store.ListAdTasksByAgent("test-agent-uuid")
	if err != nil {
		t.Fatalf("ListAdTasksByAgent: %v", err)
	}
	if len(tasks) != 1 {
		t.Errorf("ListAdTasksByAgent count = %d, want 1", len(tasks))
	}

	// List all
	allTasks, err := store.ListAdTasks()
	if err != nil {
		t.Fatalf("ListAdTasks: %v", err)
	}
	if len(allTasks) == 0 {
		t.Error("ListAdTasks returned empty list")
	}

	// Get by ID
	byID, err := store.GetAdTaskByID(task.ID)
	if err != nil {
		t.Fatalf("GetAdTaskByID: %v", err)
	}
	if byID.ReqID != "AD-42" {
		t.Errorf("GetAdTaskByID req_id = %q, want %q", byID.ReqID, "AD-42")
	}

	// Delete
	if err := store.DeleteAdTask(task.ID); err != nil {
		t.Fatalf("DeleteAdTask: %v", err)
	}
	_, err = store.GetAdTaskByID(task.ID)
	if err == nil {
		t.Error("GetAdTaskByID after delete should return error")
	}
}

func TestAdPurgeExpired(t *testing.T) {
	setupAdTestDB(t)

	// Create two tasks
	task1 := &model.AdTask{
		AgentUUID: "purge-test",
		ReqID:     "AD-100",
		Op:        "ad_ping",
		Status:    "completed",
	}
	store.CreateAdTask(task1)

	task2 := &model.AdTask{
		AgentUUID: "purge-test",
		ReqID:     "AD-101",
		Op:        "ad_ping",
		Status:    "completed",
	}
	store.CreateAdTask(task2)

	// Purge with very large duration (100 years — nothing should be that old)
	count, err := store.PurgeExpiredAdTasks(100 * 365 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("PurgeExpiredAdTasks: %v", err)
	}
	if count != 0 {
		t.Errorf("purge large duration removed %d tasks, want 0", count)
	}

	// Purge with zero duration (should delete everything newer than epoch)
	count, err = store.PurgeExpiredAdTasks(0)
	if err != nil {
		t.Fatalf("PurgeExpiredAdTasks: %v", err)
	}
	if count != 2 {
		t.Errorf("purge removed %d tasks, want 2", count)
	}

	all, _ := store.ListAdTasks()
	if len(all) != 0 {
		t.Errorf("after purge, remaining tasks = %d, want 0", len(all))
	}
}

func TestAdCriticalTaskLifecycle(t *testing.T) {
	setupAdTestDB(t)

	// Create a critical task (dcsync)
	critical := &model.AdTask{
		AgentUUID: "admin-test",
		ReqID:     "AD-200",
		Op:        "dcsync",
		Status:    "completed",
		RiskLevel: "critical",
	}
	store.CreateAdTask(critical)

	// Create a low risk task
	low := &model.AdTask{
		AgentUUID: "admin-test",
		ReqID:     "AD-201",
		Op:        "ad_ping",
		Status:    "completed",
		RiskLevel: "low",
	}
	store.CreateAdTask(low)

	// List all — should include both
	all, _ := store.ListAdTasks()
	if len(all) != 2 {
		t.Errorf("ListAdTasks count = %d, want 2", len(all))
	}

	// Get by ID (critical)
	got, err := store.GetAdTaskByID(critical.ID)
	if err != nil {
		t.Fatalf("GetAdTaskByID critical: %v", err)
	}
	if got.RiskLevel != "critical" {
		t.Errorf("risk_level = %q, want %q", got.RiskLevel, "critical")
	}

	// Cleanup
	store.DeleteAdTask(critical.ID)
	store.DeleteAdTask(low.ID)
}
