package services

import (
	"strings"
	"testing"

	"cupcake-server/pkg/trustchain"
)

func TestVerifyPluginTrustOK(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "plugin-trust-test-key-!!")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_PLUGIN", "")
	t.Setenv("CUPCAKE_TRUST_REQUIRE_SIG", "")
	ResetPluginRollbackForTest()

	data := []byte("signed-plugin-bytes")
	meta := &PluginMetadata{
		ID:      "PL-trust-1",
		Hash:    PluginFileSHA256(data),
		Version: "1.0.0",
		Signer:  "test-key-1",
	}
	if err := SignPluginMetadata(meta, data); err != nil {
		t.Fatalf("SignPluginMetadata: %v", err)
	}
	if meta.Signature == "" {
		t.Fatal("expected signature")
	}
	if err := VerifyPluginTrust(meta, data); err != nil {
		t.Fatalf("VerifyPluginTrust: %v", err)
	}
}

func TestVerifyPluginTrustWrongSigFails(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "plugin-trust-test-key-!!")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_PLUGIN", "")
	t.Setenv("CUPCAKE_TRUST_REQUIRE_SIG", "")
	ResetPluginRollbackForTest()

	data := []byte("plugin-payload")
	meta := &PluginMetadata{
		ID:      "PL-trust-2",
		Hash:    PluginFileSHA256(data),
		Version: "1.0.0",
		Signer:  "test-key-1",
	}
	if err := SignPluginMetadata(meta, data); err != nil {
		t.Fatal(err)
	}
	// Corrupt signature (still valid hex)
	meta.Signature = strings.Repeat("ab", 32)
	err := VerifyPluginTrust(meta, data)
	if err == nil {
		t.Fatal("wrong signature must fail")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestVerifyPluginTrustEmptySigFailsClosed(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "k")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_PLUGIN", "")
	t.Setenv("CUPCAKE_TRUST_REQUIRE_SIG", "")
	ResetPluginRollbackForTest()

	data := []byte("x")
	meta := &PluginMetadata{
		ID:   "PL-unsigned",
		Hash: PluginFileSHA256(data),
	}
	err := VerifyPluginTrust(meta, data)
	if err == nil {
		t.Fatal("empty signature must fail closed")
	}
	if !strings.Contains(err.Error(), "signature missing") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestVerifyPluginTrustUnsignedAllowedWithEnv(t *testing.T) {
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_PLUGIN", "1")
	t.Setenv("CUPCAKE_TRUST_REQUIRE_SIG", "")
	ResetPluginRollbackForTest()

	data := []byte("lab-plugin")
	meta := &PluginMetadata{
		ID:   "PL-lab",
		Hash: PluginFileSHA256(data),
	}
	if err := VerifyPluginTrust(meta, data); err != nil {
		t.Fatalf("unsigned allowed: %v", err)
	}
}

func TestVerifyPluginTrustRequireSigZero(t *testing.T) {
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_PLUGIN", "")
	t.Setenv("CUPCAKE_TRUST_REQUIRE_SIG", "0")
	ResetPluginRollbackForTest()

	data := []byte("lab2")
	meta := &PluginMetadata{
		ID:   "PL-lab2",
		Hash: PluginFileSHA256(data),
	}
	if err := VerifyPluginTrust(meta, data); err != nil {
		t.Fatalf("REQUIRE_SIG=0 should allow unsigned: %v", err)
	}
}

func TestVerifyPluginTrustRollback(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "plugin-trust-test-key-!!")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_PLUGIN", "")
	ResetPluginRollbackForTest()

	data := []byte("v-plugin")
	hash := PluginFileSHA256(data)
	signAt := func(ver string) *PluginMetadata {
		meta := &PluginMetadata{
			ID:      "PL-rb",
			Hash:    hash,
			Version: ver,
			Signer:  "test-key-1",
		}
		if err := SignPluginMetadata(meta, data); err != nil {
			t.Fatal(err)
		}
		return meta
	}
	if err := VerifyPluginTrust(signAt("2.0.0"), data); err != nil {
		t.Fatalf("2.0.0: %v", err)
	}
	err := VerifyPluginTrust(signAt("1.9.0"), data)
	if err == nil {
		t.Fatal("rollback must fail")
	}
	if !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("unexpected: %v", err)
	}
	if err := VerifyPluginTrust(signAt("2.0.1"), data); err != nil {
		t.Fatalf("2.0.1: %v", err)
	}
}

func TestVerifyPluginTrustMissingKeyFails(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "")
	t.Setenv("CUPCAKE_TRUST_DEV_KEYS", "")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_PLUGIN", "")
	t.Setenv("CUPCAKE_TRUST_REQUIRE_SIG", "")
	ResetPluginRollbackForTest()

	data := []byte("x")
	// Craft a signature with a local key, then clear env so GetTrustKey returns nil
	key := []byte("local-only-key")
	meta := &PluginMetadata{
		ID:      "PL-nokey",
		Hash:    PluginFileSHA256(data),
		Version: "1.0.0",
		Signer:  "s",
	}
	pm := trustchain.PackageMeta{
		ModuleID: meta.ID,
		Version:  meta.Version,
		SHA256:   meta.Hash,
		Signer:   meta.Signer,
	}
	sig, err := trustchain.Sign(pm, key)
	if err != nil {
		t.Fatal(err)
	}
	meta.Signature = sig
	// Ensure env yields no key
	if k := GetTrustKey(meta.Signer); len(k) != 0 {
		t.Fatalf("expected empty key, got %q", k)
	}
	err = VerifyPluginTrust(meta, data)
	if err == nil {
		t.Fatal("missing trust key must fail verify")
	}
}

func TestVerifyPluginTrustHashStillRequired(t *testing.T) {
	t.Setenv("CUPCAKE_ALLOW_LEGACY_PLUGIN_HASH", "")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_PLUGIN", "1")
	ResetPluginRollbackForTest()

	meta := &PluginMetadata{ID: "PL-nohash", Hash: ""}
	err := VerifyPluginTrust(meta, []byte("any"))
	if err == nil {
		t.Fatal("hash check must still fail closed")
	}
}

func TestSignPluginMetadataNoKeyIsNoop(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "")
	t.Setenv("CUPCAKE_TRUST_DEV_KEYS", "")
	data := []byte("d")
	meta := &PluginMetadata{
		ID:      "PL-x",
		Hash:    PluginFileSHA256(data),
		Version: "1.0.0",
	}
	if err := SignPluginMetadata(meta, data); err != nil {
		t.Fatal(err)
	}
	if meta.Signature != "" {
		t.Fatalf("expected no signature without key, got %s", meta.Signature)
	}
}
