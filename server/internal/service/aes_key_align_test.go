package services

import (
	"bytes"
	"encoding/hex"
	"testing"

	"cupcake-server/pkg/utils"
)

// Aligns with Client get_aes_key_base / Noise PSK rules.
func TestNormalizeAESKeyMatchesAgentRules(t *testing.T) {
	if normalizeAESKey("") != nil {
		t.Fatal("empty must be nil (no zero-pad PSK)")
	}
	if normalizeAESKey("short") != nil {
		t.Fatal("short key must be rejected like agent base key")
	}
	exact := "01234567890123456789012345678901" // 32 ascii
	got := normalizeAESKey(exact)
	if !bytes.Equal(got, []byte(exact)) {
		t.Fatalf("32-byte ascii: got %q", got)
	}
	long := exact + "XXXX"
	got = normalizeAESKey(long)
	if !bytes.Equal(got, []byte(exact)) {
		t.Fatalf("truncate long: got len %d", len(got))
	}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	hx := hex.EncodeToString(raw)
	got = normalizeAESKey(hx)
	if !bytes.Equal(got, raw) {
		t.Fatalf("hex decode mismatch")
	}
}

func TestNoiseV2HandshakeServerPath(t *testing.T) {
	psk := normalizeAESKey("01234567890123456789012345678901")
	if len(psk) != 32 {
		t.Fatal("psk")
	}
	_, clientMsg, err := utils.NoiseInitiate(psk)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientMsg) != utils.NoiseMsgLen {
		t.Fatalf("client msg len %d want %d", len(clientMsg), utils.NoiseMsgLen)
	}
	resp, sk, err := utils.NoiseRespond(clientMsg, psk)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != utils.NoiseMsgLen || resp[0] != utils.NoiseVersion {
		t.Fatalf("bad server resp")
	}
	// Wrong PSK fails (server must not accept)
	if _, _, err := utils.NoiseRespond(clientMsg, normalizeAESKey("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")); err == nil {
		t.Fatal("wrong psk accepted")
	}
	// Encrypt with session key works
	ct, err := utils.NoiseEncrypt(sk, []byte("agent-register"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := utils.NoiseDecrypt(sk, ct)
	if err != nil || string(pt) != "agent-register" {
		t.Fatalf("session traffic broken: %v %q", err, pt)
	}
}

func TestModuleDescribeInjectMentionsStomping(t *testing.T) {
	_, desc, _, _ := ModuleDescribeEx("inject")
	if !bytes.Contains([]byte(desc), []byte("stomping")) {
		t.Fatalf("inject desc should document stomping method: %s", desc)
	}
	if !bytes.Contains([]byte(desc), []byte("apc")) {
		t.Fatalf("inject desc should document apc: %s", desc)
	}
}
