package services

import (
	"bytes"
	"testing"

	"cupcake-server/pkg/utils"
)

// utils used for wire package magic

func TestPackModuleRoundtrip(t *testing.T) {
	key := DefaultModuleKey()
	if len(key) != 32 {
		t.Fatalf("key len %d", len(key))
	}
	payload := []byte("hello-module-payload")
	blob, err := PackModule("shell", payload, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg := utils.GetWireIDs().PkgMagic
	if !bytes.HasPrefix(blob, pkg[:]) {
		t.Fatal("bad package magic")
	}
	if len(blob) < 32+len(payload) {
		t.Fatal("blob too short")
	}
}

// TestAgentModuleKeyPath documents the correct pack path:
// moduleHMAC = SHA256("cupcake-mod-key-v1" || DeriveKeyAgent(base, salt))
// NOT DeriveKey (Argon2) — that was the historical module HMAC failure.
func TestAgentModuleKeyPath(t *testing.T) {
	base := make([]byte, 32)
	copy(base, []byte("SYSTEM_CONFIG_DATA_ENCRYPT_BLOB_"))
	salt := make([]byte, 32)
	copy(salt, []byte("listener-salt"))

	agentAES := utils.DeriveKeyAgent(base, salt)
	modKey := DeriveModuleKey(agentAES)
	if len(modKey) != 32 {
		t.Fatalf("mod key len %d", len(modKey))
	}

	// Wrong historical path
	wrongAES := utils.DeriveKey(base, salt)
	wrongMod := DeriveModuleKey(wrongAES)
	if bytes.Equal(modKey, wrongMod) {
		t.Fatal("Argon2-based module key must differ from agent KDF module key")
	}

	payload := []byte("MZ\x90\x00fake-pe")
	blob, err := PackModule("bof", payload, modKey)
	if err != nil {
		t.Fatal(err)
	}
	// Manual verify: body = blob[:len-32], mac = last 32
	if len(blob) < 32 {
		t.Fatal("short")
	}
	body, mac := blob[:len(blob)-32], blob[len(blob)-32:]
	got := hmacSHA256(modKey, body)
	if !bytes.Equal(got, mac) {
		t.Fatal("self HMAC mismatch")
	}
	// Wrong key must fail
	gotWrong := hmacSHA256(wrongMod, body)
	if bytes.Equal(gotWrong, mac) {
		t.Fatal("wrong Argon2 module key should not verify")
	}
}

func TestSetAgentModulesStripsModeSuffix(t *testing.T) {
	ms := GetModuleService()
	uuid := "test-agent-mode-suffix"
	ms.SetAgentModules(uuid, "bof:mem, inject:worker, ad:worker")
	if !ms.AgentHasModule(uuid, "bof") {
		t.Fatal("bof should be marked after id:mode list")
	}
	if !ms.AgentHasModule(uuid, "inject") {
		t.Fatal("inject should be marked")
	}
	if !ms.AgentHasModule(uuid, "ad") {
		t.Fatal("ad should be marked")
	}
	// Must not keep the raw "bof:mem" token as the only key
	if ms.AgentHasModule(uuid, "bof:mem") {
		t.Fatal("raw id:mode token must not be stored as module id")
	}
	ms.ClearAgentModule(uuid, "bof")
	ms.ClearAgentModule(uuid, "inject")
	ms.ClearAgentModule(uuid, "ad")
}
