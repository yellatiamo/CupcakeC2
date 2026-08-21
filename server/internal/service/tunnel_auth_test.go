package services

import (
	"testing"

	"cupcake-server/internal/storage"
)

func TestStoreTunnelPasswordHashesPlaintext(t *testing.T) {
	// InitDB not required for HashPassword; use store helpers only
	h, err := storeTunnelPassword("s3cret-tunnel")
	if err != nil {
		t.Fatal(err)
	}
	if h == "" || h == "s3cret-tunnel" {
		t.Fatal("expected bcrypt hash, not plaintext")
	}
	if !store.IsBcryptHash(h) {
		t.Fatalf("not bcrypt: %s", h[:8])
	}
	// idempotent on already-hashed
	h2, err := storeTunnelPassword(h)
	if err != nil || h2 != h {
		t.Fatalf("rehash should be no-op: %v", err)
	}
}

func TestVerifyTunnelAuthBcrypt(t *testing.T) {
	h, err := storeTunnelPassword("p@ss")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyTunnelAuth("u1", "p@ss", "u1", h) {
		t.Fatal("valid creds should pass")
	}
	if verifyTunnelAuth("u1", "wrong", "u1", h) {
		t.Fatal("wrong pass should fail")
	}
	if verifyTunnelAuth("other", "p@ss", "u1", h) {
		t.Fatal("wrong user should fail")
	}
	// legacy plaintext row still accepted until rewritten
	if !verifyTunnelAuth("u", "plain", "u", "plain") {
		t.Fatal("legacy plaintext should pass")
	}
}

func TestStoreTunnelPasswordEmpty(t *testing.T) {
	h, err := storeTunnelPassword("")
	if err != nil || h != "" {
		t.Fatalf("empty should stay empty: %q %v", h, err)
	}
	if !verifyTunnelAuth("", "", "", "") {
		t.Fatal("no-auth tunnel should allow empty pair")
	}
}

