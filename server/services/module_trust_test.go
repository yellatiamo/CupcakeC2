package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cupcake-server/pkg/trustchain"
)

func TestVerifyModulePackageOK(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "module-trust-test-key!!")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_MODULE", "")
	t.Setenv("CUPCAKE_TRUST_REQUIRE_SIG", "")
	ResetModuleRollbackForTest()

	payload := []byte("MZ-module-pe")
	sha := ModuleFileSHA256(payload)
	meta := &ModulePackageMeta{
		ID:      "inject",
		Version: "1.0.0",
		SHA256:  sha,
		Signer:  "test-key-1",
	}
	if err := SignModulePackage(meta); err != nil {
		t.Fatal(err)
	}
	if err := VerifyModulePackage(meta.ID, meta.Version, meta.SHA256, meta.Signature, meta.Signer); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyModulePackageWrongSigFails(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "module-trust-test-key!!")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_MODULE", "")
	ResetModuleRollbackForTest()

	sha := ModuleFileSHA256([]byte("pe"))
	meta := &ModulePackageMeta{
		ID:      "inject",
		Version: "1.0.0",
		SHA256:  sha,
		Signer:  "k",
	}
	if err := SignModulePackage(meta); err != nil {
		t.Fatal(err)
	}
	err := VerifyModulePackage(meta.ID, meta.Version, meta.SHA256, strings.Repeat("00", 32), meta.Signer)
	if err == nil {
		t.Fatal("wrong sig must fail")
	}
}

func TestVerifyModulePackageEmptyFailsClosed(t *testing.T) {
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_MODULE", "")
	t.Setenv("CUPCAKE_TRUST_REQUIRE_SIG", "")
	ResetModuleRollbackForTest()
	err := VerifyModulePackage("inject", "1.0.0", "aa", "", "s")
	if err == nil {
		t.Fatal("empty sig must fail")
	}
}

func TestVerifyModulePackageRollback(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "module-trust-test-key!!")
	ResetModuleRollbackForTest()

	sha := ModuleFileSHA256([]byte("img"))
	sign := func(ver string) (sig string) {
		meta := &ModulePackageMeta{
			ID: "bof", Version: ver, SHA256: sha, Signer: "k",
		}
		if err := SignModulePackage(meta); err != nil {
			t.Fatal(err)
		}
		return meta.Signature
	}
	if err := VerifyModulePackage("bof", "1.2.0", sha, sign("1.2.0"), "k"); err != nil {
		t.Fatal(err)
	}
	err := VerifyModulePackage("bof", "1.1.0", sha, sign("1.1.0"), "k")
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("expected rollback, got %v", err)
	}
}

func TestRegisterRawWithTrustAndBeforePush(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "module-trust-test-key!!")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_MODULE", "")
	ResetModuleRollbackForTest()

	dir := t.TempDir()
	ms := NewModuleServiceForTest(dir)
	pe := []byte("MZ\x00\x00fake-inject-module")
	meta := ModulePackageMeta{Version: "1.0.0", Signer: "test-key-1"}
	signed, err := ms.RegisterRawWithTrust("inject", pe, meta)
	if err != nil {
		t.Fatalf("RegisterRawWithTrust: %v", err)
	}
	if signed.Signature == "" {
		t.Fatal("expected non-empty signature after upload")
	}
	if _, err := os.Stat(filepath.Join(dir, "inject.trust.json")); err != nil {
		t.Fatalf("trust sidecar missing: %v", err)
	}
	if err := ms.VerifyModuleBeforePush("inject"); err != nil {
		t.Fatalf("VerifyModuleBeforePush: %v", err)
	}
	// Tamper trust signature on disk/memory
	stored, ok := getModuleTrust("inject")
	if !ok {
		t.Fatal("trust meta missing")
	}
	stored.Signature = strings.Repeat("ff", 32)
	_ = StoreModuleTrust(dir, stored)
	err = ms.VerifyModuleBeforePush("inject")
	if err == nil {
		t.Fatal("tampered signature must fail before push")
	}
}

// Upload must auto-sign + write sidecar even without CUPCAKE_TRUST_HMAC_KEY
// (uses durable local key under modules dir).
func TestRegisterRawWithTrustAutoLocalKey(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "")
	t.Setenv("CUPCAKE_TRUST_DEV_KEYS", "")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_MODULE", "")
	t.Setenv("CUPCAKE_TRUST_REQUIRE_SIG", "")
	ResetModuleRollbackForTest()

	dir := t.TempDir()
	ms := NewModuleServiceForTest(dir)
	pe := []byte("MZ\x00\x00auto-key-module")
	signed, err := ms.RegisterRawWithTrust("inject", pe, ModulePackageMeta{})
	if err != nil {
		t.Fatalf("RegisterRawWithTrust: %v", err)
	}
	if signed.Signature == "" || signed.Version == "" {
		t.Fatalf("expected signed meta, got %+v", signed)
	}
	if _, err := os.Stat(filepath.Join(dir, ".module_trust_hmac")); err != nil {
		t.Fatalf("local trust key file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "inject.trust.json")); err != nil {
		t.Fatalf("trust sidecar missing: %v", err)
	}
	if err := ms.VerifyModuleBeforePush("inject"); err != nil {
		t.Fatalf("push verify: %v", err)
	}
}

// Existing product bin without sidecar is signed on Ensure/Verify.
func TestEnsureModuleSignedOnDiskMissingSidecar(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "")
	t.Setenv("CUPCAKE_TRUST_DEV_KEYS", "")
	t.Setenv("CUPCAKE_ALLOW_UNSIGNED_MODULE", "")
	ResetModuleRollbackForTest()

	dir := t.TempDir()
	ms := NewModuleServiceForTest(dir)
	pe := []byte("MZ\x00\x00orphan-inject")
	if err := ms.RegisterRaw("inject", pe); err != nil {
		t.Fatal(err)
	}
	// No trust.json yet
	if _, err := os.Stat(filepath.Join(dir, "inject.trust.json")); err == nil {
		t.Fatal("unexpected trust file before ensure")
	}
	meta, err := ms.EnsureModuleSignedOnDisk("inject", pe)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Signature == "" {
		t.Fatal("expected signature")
	}
	if err := ms.VerifyModuleBeforePush("inject"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyModuleTrustAlias(t *testing.T) {
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "module-trust-test-key!!")
	ResetModuleRollbackForTest()
	sha := ModuleFileSHA256([]byte("x"))
	meta := &ModulePackageMeta{ID: "inject", Version: "3", SHA256: sha, Signer: "s"}
	if err := SignModulePackage(meta); err != nil {
		t.Fatal(err)
	}
	if err := VerifyModuleTrust(meta.ID, meta.Version, meta.SHA256, meta.Signature, meta.Signer); err != nil {
		t.Fatal(err)
	}
}

func TestModuleSignUsesRealTrustchain(t *testing.T) {
	// Ensures Sign/Verify are the shipped trustchain functions, not reimplemented.
	t.Setenv("CUPCAKE_TRUST_HMAC_KEY", "shared-key")
	ResetModuleRollbackForTest()
	key := trustchain.HMACKeyForSigner("s")
	pm := trustchain.PackageMeta{
		ModuleID: "inject",
		Version:  "1.0.0",
		SHA256:   ModuleFileSHA256([]byte("p")),
		Signer:   "s",
	}
	sig, err := trustchain.Sign(pm, key)
	if err != nil {
		t.Fatal(err)
	}
	pm.Signature = sig
	if err := trustchain.Verify(pm, key); err != nil {
		t.Fatal(err)
	}
	// Same via services wrapper
	if err := VerifyModulePackage(pm.ModuleID, pm.Version, pm.SHA256, sig, pm.Signer); err != nil {
		t.Fatal(err)
	}
}
