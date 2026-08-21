package stagerguard

import "testing"

func TestSignAndVerifyStagerToken(t *testing.T) {
	id := "abc123def456"
	tok := SignStagerID(id)
	if len(tok) != 16 {
		t.Fatalf("token len want 16 got %d (%s)", len(tok), tok)
	}
	if !VerifyStagerToken(id, tok) {
		t.Fatal("valid token rejected")
	}
	if VerifyStagerToken(id, "0000000000000000") {
		t.Fatal("wrong token accepted")
	}
	if VerifyStagerToken(id, "") {
		t.Fatal("empty token accepted")
	}
	if VerifyStagerToken("", tok) {
		t.Fatal("empty id accepted")
	}
}
