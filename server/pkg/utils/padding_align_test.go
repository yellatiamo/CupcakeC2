package utils

import (
	"bytes"
	"testing"
)

func TestTailoredPaddingRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key { key[i] = byte(i + 3) }
	pt := []byte(`{"type":"register","uuid":"test"}`)
	ct, err := EncryptAES(pt, key)
	if err != nil { t.Fatal(err) }
	wire := ObfuscatePacket(ct, "padding", nil)
	if len(wire) <= len(ct) {
		t.Fatalf("padding should grow frame: ct=%d wire=%d", len(ct), len(wire))
	}
	de := DeobfuscatePacket(wire, "padding", nil)
	if !bytes.Equal(de, ct) {
		t.Fatalf("deobf mismatch len de=%d ct=%d", len(de), len(ct))
	}
	out, err := DecryptAES(de, key)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(out, pt) {
		t.Fatal("plaintext mismatch")
	}
	// compat path: decrypt without deobf first
	out2, err := DecryptAESWithCompat(wire, key)
	if err != nil { t.Fatalf("compat: %v", err) }
	if !bytes.Equal(out2, pt) {
		t.Fatal("compat plaintext mismatch")
	}
}
