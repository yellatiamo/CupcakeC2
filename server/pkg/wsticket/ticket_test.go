package wsticket

import (
	"testing"
	"time"
)

func TestMintRedeemOnce(t *testing.T) {
	ResetForTest()
	raw, err := Mint(7, "alice", "operator", PurposePTY, DefaultTTL)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if raw == "" {
		t.Fatal("expected non-empty ticket")
	}
	if CountForTest() != 1 {
		t.Fatalf("expected 1 stored ticket, got %d", CountForTest())
	}

	uid, user, role, err := Redeem(raw, PurposePTY)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if uid != "7" || user != "alice" || role != "operator" {
		t.Fatalf("got uid=%q user=%q role=%q", uid, user, role)
	}
	if CountForTest() != 0 {
		t.Fatalf("expected ticket deleted after redeem, got %d", CountForTest())
	}

	// Reuse must fail (single-use).
	if _, _, _, err := Redeem(raw, PurposePTY); err != ErrInvalid {
		t.Fatalf("reuse: want ErrInvalid, got %v", err)
	}
}

func TestRedeemWrongPurpose(t *testing.T) {
	ResetForTest()
	raw, err := Mint(1, "bob", "admin", PurposeShell, DefaultTTL)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, _, _, err := Redeem(raw, PurposePTY); err != ErrPurpose {
		t.Fatalf("want ErrPurpose, got %v", err)
	}
	// Wrong purpose does not consume the ticket; correct purpose still works once.
	uid, user, role, err := Redeem(raw, PurposeShell)
	if err != nil {
		t.Fatalf("correct purpose after mismatch: %v", err)
	}
	if uid != "1" || user != "bob" || role != "admin" {
		t.Fatalf("got uid=%q user=%q role=%q", uid, user, role)
	}
}

func TestRedeemExpired(t *testing.T) {
	ResetForTest()
	raw, err := Mint(2, "carol", "viewer", PurposeBuildLogs, time.Millisecond)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	time.Sleep(15 * time.Millisecond)
	if _, _, _, err := Redeem(raw, PurposeBuildLogs); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestRedeemMissing(t *testing.T) {
	ResetForTest()
	if _, _, _, err := Redeem("not-a-real-ticket", PurposePTY); err != ErrInvalid {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	if _, _, _, err := Redeem("", PurposePTY); err != ErrInvalid {
		t.Fatalf("empty: want ErrInvalid, got %v", err)
	}
}

func TestMintUnknownPurpose(t *testing.T) {
	ResetForTest()
	if _, err := Mint(1, "x", "admin", "desktop", DefaultTTL); err != ErrPurposeUnknown {
		t.Fatalf("want ErrPurposeUnknown, got %v", err)
	}
}

func TestMintTTLClamp(t *testing.T) {
	ResetForTest()
	// Over MaxTTL should still mint successfully (clamped).
	raw, err := Mint(1, "x", "admin", PurposePTY, 10*time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	uid, _, _, err := Redeem(raw, PurposePTY)
	if err != nil || uid != "1" {
		t.Fatalf("Redeem after clamp: uid=%q err=%v", uid, err)
	}
}

func TestValidPurpose(t *testing.T) {
	if !ValidPurpose("pty") || !ValidPurpose("SHELL") || !ValidPurpose(" build_logs ") {
		t.Fatal("expected known purposes valid")
	}

	if ValidPurpose("foo") || ValidPurpose("") {
		t.Fatal("expected unknown purposes invalid")
	}
}
