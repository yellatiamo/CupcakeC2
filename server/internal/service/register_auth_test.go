package services

import (
	"testing"

	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/utils"
)

// Exercises the same authenticateRegisterProof path used by WS/TCP register handlers.
func TestAuthenticateRegisterProof_AcceptsValidRejectsBareUUID(t *testing.T) {
	encryptKey := "test-listener-key-material"
	salt := "agent-salt-bytes-here-padded!!!!"
	uuid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	sessionKey := deriveStaticSessionKey(encryptKey, salt)
	if len(sessionKey) != 32 {
		t.Fatalf("session key len=%d", len(sessionKey))
	}

	proof := utils.ComputeRegisterProof(sessionKey, uuid)
	proofPayload := map[string]interface{}{
		"uuid":      uuid,
		"reg_proof": proof,
	}
	got, ok := authenticateRegisterProof(encryptKey, salt, uuid, proofPayload)
	if !ok {
		t.Fatal("valid proof rejected")
	}
	if len(got) != 32 {
		t.Fatalf("returned key len=%d", len(got))
	}

	// Bare UUID / no proof
	if _, ok := authenticateRegisterProof(encryptKey, salt, uuid, map[string]interface{}{
		"uuid": uuid,
	}); ok {
		t.Fatal("missing reg_proof must be rejected")
	}

	// Wrong proof
	if _, ok := authenticateRegisterProof(encryptKey, salt, uuid, map[string]interface{}{
		"uuid":      uuid,
		"reg_proof": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}); ok {
		t.Fatal("wrong proof must be rejected")
	}

	// Wrong uuid with valid proof for another id
	if _, ok := authenticateRegisterProof(encryptKey, salt, "other-id", proofPayload); ok {
		t.Fatal("proof for different uuid must be rejected")
	}

	// Empty uuid
	if _, ok := authenticateRegisterProof(encryptKey, salt, "", proofPayload); ok {
		t.Fatal("empty uuid must be rejected")
	}
}

func TestCloseOutputChannelIdempotent(t *testing.T) {
	client := &globals.Client{
		OutputChannel: make(chan string, 2),
	}
	client.CloseOutputChannel()
	// Second close must not panic (sync.Once).
	client.CloseOutputChannel()
	select {
	case _, open := <-client.OutputChannel:
		if open {
			t.Fatal("channel still open after CloseOutputChannel")
		}
	default:
		// closed and empty is fine
	}
}
