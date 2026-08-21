package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cupcake-server/internal/model"
	"cupcake-server/pkg/paths"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupSessionTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CUPCAKE_DATA_DIR", dir)
	paths.Init()

	dbPath := filepath.Join(dir, "session_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	prev := DB
	DB = db
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
		DB = prev
		_ = os.Remove(dbPath)
	})
}

func seedUser(t *testing.T, username string, active bool) *model.User {
	t.Helper()
	u := &model.User{
		Username: username,
		Password: "hash",
		Role:     "operator",
		IsActive: active,
	}
	if err := DB.Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestHashSessionTokenStable(t *testing.T) {
	a := HashSessionToken("raw-token-abc")
	b := HashSessionToken("raw-token-abc")
	if a != b {
		t.Fatalf("hash not stable")
	}
	if len(a) != 64 {
		t.Fatalf("sha256 hex length want 64 got %d", len(a))
	}
	if HashSessionToken("other") == a {
		t.Fatalf("different tokens must not collide")
	}
}

func TestCreateAndLookupSession(t *testing.T) {
	setupSessionTestDB(t)
	u := seedUser(t, "alice", true)
	raw := "session-raw-token-1"
	sess, err := CreateSession(u.ID, raw, "127.0.0.1", "test-agent", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.TokenHash != HashSessionToken(raw) {
		t.Fatalf("stored hash mismatch")
	}
	if sess.TokenHash == raw {
		t.Fatalf("must not store raw token")
	}

	gotSess, gotUser, err := LookupSession(raw)
	if err != nil {
		t.Fatalf("LookupSession: %v", err)
	}
	if gotSess.ID != sess.ID || gotUser.ID != u.ID {
		t.Fatalf("lookup ids mismatch sess=%d user=%d", gotSess.ID, gotUser.ID)
	}
	if _, _, err := LookupSession("wrong-token"); err != ErrSessionInvalid {
		t.Fatalf("want ErrSessionInvalid got %v", err)
	}
}

func TestLookupSessionExpired(t *testing.T) {
	setupSessionTestDB(t)
	u := seedUser(t, "bob", true)
	raw := "expired-token"
	sess, err := CreateSession(u.ID, raw, "1.1.1.1", "ua", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Force expiry in the past
	if err := DB.Model(sess).Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("expire: %v", err)
	}
	if _, _, err := LookupSession(raw); err != ErrSessionInvalid {
		t.Fatalf("expired session should be invalid, got %v", err)
	}
}

func TestRevokeSession(t *testing.T) {
	setupSessionTestDB(t)
	u := seedUser(t, "carol", true)
	raw := "revoke-me"
	if _, err := CreateSession(u.ID, raw, "", "", time.Hour); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := RevokeSession(raw); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := LookupSession(raw); err != ErrSessionInvalid {
		t.Fatalf("revoked session should be invalid, got %v", err)
	}
}

func TestRevokeAllUserSessions(t *testing.T) {
	setupSessionTestDB(t)
	u := seedUser(t, "dave", true)
	raw1, raw2 := "tok-a", "tok-b"
	if _, err := CreateSession(u.ID, raw1, "", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateSession(u.ID, raw2, "", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := RevokeAllUserSessions(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LookupSession(raw1); err != ErrSessionInvalid {
		t.Fatalf("raw1 still valid")
	}
	if _, _, err := LookupSession(raw2); err != ErrSessionInvalid {
		t.Fatalf("raw2 still valid")
	}
}

func TestPasswordChangeInvalidatesOldToken(t *testing.T) {
	// Mirrors HandleChangeMyPassword session lifecycle at the store layer.
	setupSessionTestDB(t)
	u := seedUser(t, "erin", true)
	oldTok := "old-session-token"
	if _, err := CreateSession(u.ID, oldTok, "10.0.0.1", "ua", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LookupSession(oldTok); err != nil {
		t.Fatalf("old token should work before password change: %v", err)
	}

	// Change password side-effect: revoke all + create new session
	if err := RevokeAllUserSessions(u.ID); err != nil {
		t.Fatal(err)
	}
	newTok := "new-session-token"
	if _, err := CreateSession(u.ID, newTok, "10.0.0.1", "ua", time.Hour); err != nil {
		t.Fatal(err)
	}

	if _, _, err := LookupSession(oldTok); err != ErrSessionInvalid {
		t.Fatalf("old token must be invalid after password change, got %v", err)
	}
	if _, gotUser, err := LookupSession(newTok); err != nil || gotUser.ID != u.ID {
		t.Fatalf("new token should work: err=%v", err)
	}
}

func TestInactiveUserSessionRejected(t *testing.T) {
	setupSessionTestDB(t)
	u := seedUser(t, "frank", true)
	raw := "inactive-user-tok"
	if _, err := CreateSession(u.ID, raw, "", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := DB.Model(u).Update("is_active", false).Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := LookupSession(raw); err != ErrSessionInvalid {
		t.Fatalf("inactive user sessions must fail, got %v", err)
	}
}

func TestMaxConcurrentSessions(t *testing.T) {
	setupSessionTestDB(t)
	u := seedUser(t, "grace", true)
	tokens := make([]string, 0, MaxConcurrentSessions+2)
	for i := 0; i < MaxConcurrentSessions+2; i++ {
		tok := GenerateSecureToken(24)
		tokens = append(tokens, tok)
		if _, err := CreateSession(u.ID, tok, "", "", time.Hour); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	// Oldest two should be revoked
	if _, _, err := LookupSession(tokens[0]); err != ErrSessionInvalid {
		t.Fatalf("oldest session 0 should be revoked")
	}
	if _, _, err := LookupSession(tokens[1]); err != ErrSessionInvalid {
		t.Fatalf("oldest session 1 should be revoked")
	}
	// Newest should still be valid
	last := tokens[len(tokens)-1]
	if _, _, err := LookupSession(last); err != nil {
		t.Fatalf("newest session should be valid: %v", err)
	}
}

func TestSessionTTLEnv(t *testing.T) {
	t.Setenv("CUPCAKE_SESSION_TTL_HOURS", "")
	if SessionTTL() != time.Duration(DefaultSessionTTLHours)*time.Hour {
		t.Fatalf("default ttl")
	}
	t.Setenv("CUPCAKE_SESSION_TTL_HOURS", "12")
	if SessionTTL() != 12*time.Hour {
		t.Fatalf("want 12h got %v", SessionTTL())
	}
	t.Setenv("CUPCAKE_SESSION_TTL_HOURS", "0")
	if SessionTTL() != time.Duration(DefaultSessionTTLHours)*time.Hour {
		t.Fatalf("invalid 0 should fall back")
	}
}

func TestTouchSession(t *testing.T) {
	setupSessionTestDB(t)
	u := seedUser(t, "hank", true)
	raw := "touch-tok"
	sess, err := CreateSession(u.ID, raw, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Force last_seen into the past beyond throttle
	old := time.Now().Add(-2 * time.Minute)
	if err := DB.Model(sess).Update("last_seen_at", old).Error; err != nil {
		t.Fatal(err)
	}
	TouchSession(sess.ID)
	var updated model.Session
	if err := DB.First(&updated, sess.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !updated.LastSeenAt.After(old) {
		t.Fatalf("last_seen should advance")
	}
}

