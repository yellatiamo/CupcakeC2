package services

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

const miB = int64(1) << 20

func TestRejectIfInsufficient(t *testing.T) {
	// free=50MiB, need=10MiB, min=100MiB → error (50 < 110)
	if err := RejectIfInsufficient(50*miB, 10*miB, 100*miB); err == nil {
		t.Fatal("expected reject when free < need+minFree")
	} else if !strings.Contains(err.Error(), "insufficient disk space") {
		t.Fatalf("unexpected error: %v", err)
	}

	// free=500MiB, need=10 → ok with default-style min=100
	if err := RejectIfInsufficient(500*miB, 10*miB, 100*miB); err != nil {
		t.Fatalf("expected ok: %v", err)
	}

	// exact boundary: free == need + minFree → ok
	if err := RejectIfInsufficient(110*miB, 10*miB, 100*miB); err != nil {
		t.Fatalf("boundary free==need+min should pass: %v", err)
	}

	// one byte short → reject
	if err := RejectIfInsufficient(110*miB-1, 10*miB, 100*miB); err == nil {
		t.Fatal("expected reject one byte under threshold")
	}

	// zero need still reserves minFree
	if err := RejectIfInsufficient(50*miB, 0, 100*miB); err == nil {
		t.Fatal("expected reject when free < minFree even with need=0")
	}
	if err := RejectIfInsufficient(100*miB, 0, 100*miB); err != nil {
		t.Fatalf("free==minFree with need=0 should pass: %v", err)
	}

	// negative inputs clamped
	if err := RejectIfInsufficient(-1, -5, 0); err != nil {
		t.Fatalf("all-zero after clamp should pass: %v", err)
	}
}

func TestMinFreeDiskBytesDefaultAndEnv(t *testing.T) {
	t.Setenv("CUPCAKE_MIN_FREE_DISK_MB", "")
	// Unset may not clear if already set empty; ensure default.
	_ = os.Unsetenv("CUPCAKE_MIN_FREE_DISK_MB")
	if got := MinFreeDiskBytes(); got != 100*miB {
		t.Fatalf("default MinFreeDiskBytes = %d want %d", got, 100*miB)
	}

	t.Setenv("CUPCAKE_MIN_FREE_DISK_MB", "50")
	if got := MinFreeDiskBytes(); got != 50*miB {
		t.Fatalf("env 50 MiB: got %d", got)
	}

	t.Setenv("CUPCAKE_MIN_FREE_DISK_MB", "0")
	if got := MinFreeDiskBytes(); got != 0 {
		t.Fatalf("env 0 should disable reserve: got %d", got)
	}

	t.Setenv("CUPCAKE_MIN_FREE_DISK_MB", "not-a-number")
	if got := MinFreeDiskBytes(); got != 100*miB {
		t.Fatalf("invalid env should fall back to 100 MiB: got %d", got)
	}
}

func TestValidateAgentUploadWithDisk(t *testing.T) {
	good := "550e8400-e29b-41d4-a716-446655440000"
	// Restore default min free for this test.
	t.Setenv("CUPCAKE_MIN_FREE_DISK_MB", "100")

	// MaxAgentUploadBytes still enforced before disk check.
	if st, msg := ValidateAgentUploadWithDisk(good, MaxAgentUploadBytes+1, 1<<40); st != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: status=%d msg=%s", st, msg)
	}

	// free=50MiB, need=10MiB, min=100MiB → 507
	if st, msg := ValidateAgentUploadWithDisk(good, 10*miB, 50*miB); st != http.StatusInsufficientStorage {
		t.Fatalf("disk reject: status=%d msg=%s", st, msg)
	} else if !strings.Contains(msg, "insufficient") {
		t.Fatalf("msg: %s", msg)
	}

	// free=500MiB, need=10 → ok
	if st, msg := ValidateAgentUploadWithDisk(good, 10*miB, 500*miB); st != 0 {
		t.Fatalf("disk ok: status=%d msg=%s", st, msg)
	}

	// MaxAgentUploadBytes constant contract
	if MaxAgentUploadBytes != 256<<20 {
		t.Fatalf("MaxAgentUploadBytes = %d", MaxAgentUploadBytes)
	}

	// Bad UUID still rejected
	if st, _ := ValidateAgentUploadWithDisk("bad", 10, 1<<40); st != http.StatusBadRequest {
		t.Fatalf("bad uuid status=%d", st)
	}
}

func TestCheckDiskForWriteSmoke(t *testing.T) {
	// Real free-space query against temp dir; tiny need with min=0 should pass.
	t.Setenv("CUPCAKE_MIN_FREE_DISK_MB", "0")
	tmp := t.TempDir()
	if err := CheckDiskForWrite(tmp, 1); err != nil {
		t.Fatalf("CheckDiskForWrite tiny need: %v", err)
	}
	// Absurd need must fail
	if err := CheckDiskForWrite(tmp, 1<<62); err == nil {
		t.Fatal("expected reject for absurd needBytes")
	}
}
