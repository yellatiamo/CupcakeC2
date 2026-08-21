package controllers

import (
	"encoding/json"
	"testing"

	"cupcake-server/pkg/globals"
)

func TestListenerViewOmitsSecrets(t *testing.T) {
	ln := &globals.Listener{
		ID:           "L1",
		BindIP:       "0.0.0.0",
		Port:         443,
		Protocol:     "ws",
		EncryptKey:   "super-secret-key",
		EncryptionSalt: "salt",
		TLSKeyPath:   "/secret/key.pem",
		TLSKeyPEM:    "-----BEGIN PRIVATE KEY-----",
		TLSCertPEM:   "cert",
		Status:       "Running",
	}
	v := newListenerView(ln)
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// Secret values / field names must not appear (has_tls_key flag is OK)
	for _, bad := range []string{
		"super-secret-key",
		"\"encrypt_key\"",
		"encryption_salt",
		"tls_key_path",
		"tls_key_pem",
		"PRIVATE KEY",
		"/secret/key.pem",
	} {
		if containsFold(s, bad) {
			t.Fatalf("listener JSON must not contain %q; got %s", bad, s)
		}
	}
	if !v.HasEncryptionKey || !v.HasTLSKey {
		t.Fatalf("flags should indicate secrets present: %+v", v)
	}
}

func containsFold(s, sub string) bool {
	return len(sub) > 0 && (s == sub || len(s) >= len(sub) &&
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if equalFoldASCII(s[i:i+len(sub)], sub) {
					return true
				}
			}
			return false
		})())
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
