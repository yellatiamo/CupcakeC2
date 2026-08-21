package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cupcake-server/pkg/paths"
)

func TestParseAdSummaryAndSanitize(t *testing.T) {
	s, err := ParseAdSummary(`{"domain":"corp.local","kind":"kerberoast","hash_count":2,"artifact":true,"artifact_path":"cpx_ad_x.hashcat.txt","hashes":["$krb5tgs$23$*a$B$c*$00$11"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Artifact || s.HashCount != 2 {
		t.Fatalf("parse: %+v", s)
	}
	if !NeedsArtifactStorage(s, 10, DefaultAdStdoutInlineMax) {
		t.Fatal("expected artifact storage")
	}
	red := SanitizeSummaryForLog(`{"domain":"corp.local","kind":"kerberoast","hash_count":2,"artifact":true,"hashes":["$krb5tgs$SECRET"]}`)
	if strings.Contains(red, "$krb5tgs$SECRET") {
		t.Fatalf("hash must not remain in log summary: %s", red)
	}
	if !strings.Contains(red, "log_redacted") {
		t.Fatalf("expected redacted flag: %s", red)
	}
	// Inline (non-artifact) roast with hashes[] must also be stripped for CommandLog
	inline := SanitizeSummaryForLog(`{"domain":"corp.local","kind":"kerberoast","hash_count":1,"artifact":false,"hashes":["$krb5tgs$23$*inline$CORP$HTTP/x*$aabb$ccdd"]}`)
	if strings.Contains(inline, "$krb5tgs$") {
		t.Fatalf("inline hashes must not land in CommandLog: %s", inline)
	}
	// pong
	s2, err := ParseAdSummary("pong")
	if err != nil || s2 == nil {
		t.Fatal(err)
	}
}

func TestWriteAdArtifactLayout(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CUPCAKE_DATA_DIR", dir)
	paths.Init()

	rel, sha, n, err := WriteAdArtifact("agent-1", "42", "result.hashcat.txt", []byte("$krb5tgs$23$*x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || sha == "" {
		t.Fatalf("sha=%s n=%d", sha, n)
	}
	if !strings.Contains(rel, "ad") || !strings.Contains(rel, "agent-1") {
		t.Fatalf("rel path: %s", rel)
	}
	abs, err := ResolveAdArtifactAbs(rel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "$krb5tgs$") {
		t.Fatalf("content: %s", b)
	}
	if err := WriteAdMetaJSON("agent-1", "42", map[string]interface{}{"sha256": sha}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(AdStorageDir("agent-1", "42"), "meta.json")); err != nil {
		t.Fatal(err)
	}
}

func TestResolveAdArtifactRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CUPCAKE_DATA_DIR", dir)
	paths.Init()
	if _, err := ResolveAdArtifactAbs(`ad/../etc/passwd`); err == nil {
		t.Fatal("expected traversal deny")
	}
	if _, err := ResolveAdArtifactAbs(`logs/secret.txt`); err == nil {
		t.Fatal("expected outside ad deny")
	}
}
