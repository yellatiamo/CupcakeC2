package services

import "testing"

func TestTransportKind_ListenerNames(t *testing.T) {
	cases := []struct {
		proto string
		tls   bool
		want  string
	}{
		{"WebSocket", false, "ws"},
		{"WEBSOCKET", false, "ws"},
		{"ws", false, "ws"},
		{"WebSocket", true, "wss"},
		{"wss", false, "wss"},
		{"TCP", false, "tcp"},
		{"Bind-TCP", false, "bind"},
		{"正向TCP", false, "bind"},
		{"DNS", false, "dns"},
	}
	for _, c := range cases {
		got := transportKind(c.proto, c.tls)
		if got != c.want {
			t.Fatalf("transportKind(%q, tls=%v)=%q want %q", c.proto, c.tls, got, c.want)
		}
	}
}

func TestBuildConnString_Schemes(t *testing.T) {
	if u := buildConnString("ws", "10.0.0.1", "8443", ""); u != "ws://10.0.0.1:8443/socket" {
		t.Fatalf("ws url: %s", u)
	}
	if u := buildConnString("wss", "c2.example", "443", ""); u != "wss://c2.example:443/socket" {
		t.Fatalf("wss url: %s", u)
	}
	if u := buildConnString("tcp", "10.0.0.1", "4444", ""); u != "tcp://10.0.0.1:4444" {
		t.Fatalf("tcp url: %s", u)
	}
	if u := buildConnString("bind", "", "9000", ""); u != "bind://0.0.0.0:9000" {
		t.Fatalf("bind url: %s", u)
	}
	if u := buildConnString("dns", "unused", "", "tunnel.example.com"); u != "dns://tunnel.example.com" {
		t.Fatalf("dns url: %s", u)
	}
}

func TestCargoFeaturesForKind(t *testing.T) {
	if cargoFeaturesForKind("ws") != "ws,minimal" {
		t.Fatal("ws features")
	}
	if cargoFeaturesForKind("wss") != "ws,ws-tls,minimal" {
		t.Fatal("wss features")
	}
	if cargoFeaturesForKind("tcp") != "tcp,minimal" {
		t.Fatal("tcp features")
	}
}

func TestVerifyPatchedConfigSource_AllowsComparisonSentinels(t *testing.T) {
	// Mimics post-patchConfig config.rs: const rewritten, comparison still has placeholder
	src := `
pub const AES_KEY: &str = "01234567890123456789012345678901";
pub const REMOTE_STUB: &str = "tcp://127.0.0.1:8888";
pub const ENCRYPTION_SALT: &str = "saltsaltsaltsaltsaltsalt";
pub const OBFUSCATION_MODE: &str = "padding";
pub const JITTER: &str = "30";
fn get() {
    if REMOTE_STUB != "REPLACE_ME_URL" {}
    if AES_KEY != "REPLACE_ME_AES_KEY" {}
}
`
	if err := verifyPatchedConfigSource(src); err != nil {
		t.Fatalf("should accept patched consts + sentinel comparisons: %v", err)
	}
	// Unpatched const must fail
	bad := `pub const REMOTE_STUB: &str = "REPLACE_ME_URL";
pub const AES_KEY: &str = "01234567890123456789012345678901";
if REMOTE_STUB != "REPLACE_ME_URL" {}
`
	if err := verifyPatchedConfigSource(bad); err == nil {
		t.Fatal("expected error when REMOTE_STUB const still placeholder")
	}
}
