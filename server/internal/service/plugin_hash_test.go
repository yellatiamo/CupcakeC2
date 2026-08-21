package services

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestPluginFileSHA256(t *testing.T) {
	data := []byte("plugin-payload-bytes")
	got := PluginFileSHA256(data)
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if len(got) != 64 {
		t.Fatalf("hex len %d", len(got))
	}
}

func TestVerifyPluginHashMatch(t *testing.T) {
	data := []byte("trusted-plugin")
	meta := &PluginMetadata{
		ID:   "PL-1",
		Hash: PluginFileSHA256(data),
	}
	if err := VerifyPluginHash(meta, data); err != nil {
		t.Fatalf("expected match: %v", err)
	}
}

func TestVerifyPluginHashMismatch(t *testing.T) {
	meta := &PluginMetadata{
		ID:   "PL-1",
		Hash: PluginFileSHA256([]byte("original")),
	}
	err := VerifyPluginHash(meta, []byte("tampered"))
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if err != nil && !contains(err.Error(), "hash mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyPluginHashEmptyFailsClosed(t *testing.T) {
	t.Setenv("CUPCAKE_ALLOW_LEGACY_PLUGIN_HASH", "")
	meta := &PluginMetadata{ID: "legacy", Hash: ""}
	err := VerifyPluginHash(meta, []byte("any"))
	if err == nil {
		t.Fatal("empty hash must fail closed without CUPCAKE_ALLOW_LEGACY_PLUGIN_HASH")
	}
	if !contains(err.Error(), "hash missing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyPluginHashLegacyEmptyAllowedWithEnv(t *testing.T) {
	t.Setenv("CUPCAKE_ALLOW_LEGACY_PLUGIN_HASH", "1")
	meta := &PluginMetadata{ID: "legacy", Hash: ""}
	if err := VerifyPluginHash(meta, []byte("any")); err != nil {
		t.Fatalf("legacy empty hash should allow with env: %v", err)
	}
}

func TestVerifyPluginHashNilMeta(t *testing.T) {
	if err := VerifyPluginHash(nil, []byte("x")); err == nil {
		t.Fatal("nil meta should error")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}
