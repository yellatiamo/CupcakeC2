package services

import (
	"bytes"
	"testing"

	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/utils"
)

func TestPickSessionKeyPrefersNoise(t *testing.T) {
	var noise [32]byte
	for i := range noise {
		noise[i] = byte(i + 1)
	}
	static := make([]byte, 32)
	for i := range static {
		static[i] = 0xAA
	}
	got := pickSessionKey(noise, static)
	if !bytes.Equal(got, noise[:]) {
		t.Fatalf("expected noise key, got different material")
	}
	got2 := pickSessionKey([32]byte{}, static)
	if !bytes.Equal(got2, static) {
		t.Fatalf("expected static when noise zero")
	}
}

func TestResolveClientSessionKeyCaches(t *testing.T) {
	// Use short key; DeriveKey still returns 32 bytes
	c := &globals.Client{
		EncryptKey:     "test-aes-key-material-32bytes!!",
		EncryptionSalt: "salt-for-test-session-key-cache",
	}
	k1 := resolveClientSessionKey(c)
	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k1))
	}
	if len(c.SessionKey) != 32 {
		t.Fatalf("SessionKey not cached on client")
	}
	// Second call must return same cached slice contents without re-derive side effect
	k2 := resolveClientSessionKey(c)
	if !bytes.Equal(k1, k2) {
		t.Fatalf("cached key mismatch")
	}
	// Explicit derive matches first result for same inputs
	expected := deriveStaticSessionKey(c.EncryptKey, c.EncryptionSalt)
	if !bytes.Equal(k1, expected) {
		t.Fatalf("cached key != direct DeriveKey path")
	}
	// Noise wins over cache
	var noise [32]byte
	noise[0] = 0x42
	c.NoiseSessionKey = noise
	k3 := resolveClientSessionKey(c)
	if !bytes.Equal(k3, noise[:]) {
		t.Fatalf("NoiseSessionKey should take precedence")
	}
	// Sanity: DeriveKey pure function length
	dk := utils.DeriveKey([]byte("abc"), make([]byte, 32))
	if len(dk) != 32 {
		t.Fatalf("DeriveKey length %d", len(dk))
	}
}

func TestDeriveStaticSessionKeyStable(t *testing.T) {
	// Keys must be ≥32 bytes (agent-aligned; short keys normalize to empty).
	a := deriveStaticSessionKey("same-key-material-32bytes-long!!", "same-salt")
	b := deriveStaticSessionKey("same-key-material-32bytes-long!!", "same-salt")
	if !bytes.Equal(a, b) {
		t.Fatalf("deriveStaticSessionKey not deterministic")
	}
	c := deriveStaticSessionKey("other-key-material-32bytes-long!", "same-salt")
	if bytes.Equal(a, c) {
		t.Fatalf("different base keys must differ")
	}
}
