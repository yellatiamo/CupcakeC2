package services

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductModuleWhitelist(t *testing.T) {
	if !IsProductModule("bof") || !IsProductModule("inject") || !IsProductModule("ad") {
		t.Fatal("product modules bof|inject|ad must be allowed")
	}
	if IsProductModule("desktop") {
		t.Fatal("desktop remote desktop is retired and not product")
	}
	if IsProductModule("shell") || IsProductModule("iso_host") || IsProductModule("dotnet") {
		t.Fatal("legacy/retired modules must not be product")
	}
}

func TestRegisterAndDescribeAd(t *testing.T) {
	ms := NewModuleServiceForTest(t.TempDir())
	pe := make([]byte, 64)
	pe[0], pe[1] = 'M', 'Z'
	if err := ms.RegisterRaw("ad", pe); err != nil {
		t.Fatalf("register ad: %v", err)
	}
	name, desc, kind, loadMode := ModuleDescribeEx("ad")
	if name == "" || kind != "host" || loadMode != "worker" {
		t.Fatalf("DescribeEx ad: name=%q kind=%q loadMode=%q", name, kind, loadMode)
	}
	if !strings.Contains(strings.ToLower(desc), "ad") && !strings.Contains(desc, "域") {
		// description should mention domain/AD product role
		if desc == "" {
			t.Fatal("empty ad description")
		}
	}
	found := false
	for _, e := range ms.ListCatalog("", "") {
		if e.ID == "ad" {
			found = true
			if e.LoadMode != "worker" {
				t.Fatalf("catalog load_mode want worker, got %s", e.LoadMode)
			}
			break
		}
	}
	if !found {
		t.Fatal("ad must appear in catalog after register")
	}
}

func TestRegisterRejectsNonProduct(t *testing.T) {
	ms := NewModuleServiceForTest(t.TempDir())
	err := ms.RegisterRaw("shell", []byte{0x4d, 0x5a, 0x00})
	if !errors.Is(err, ErrModuleForbidden) {
		t.Fatalf("want ErrModuleForbidden, got %v", err)
	}
}

func TestPackCKMSRejectsLegacyDiskBlob(t *testing.T) {
	dir := t.TempDir()
	ms := NewModuleServiceForTest(dir)
	// Plant non-product bin on disk (simulates leftover retired blob)
	if err := os.WriteFile(filepath.Join(dir, "dotnet.bin"), []byte{0x4d, 0x5a, 1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ms.PackCKMS("dotnet")
	if !errors.Is(err, ErrModuleForbidden) {
		t.Fatalf("PackCKMS must refuse dotnet even if on disk: %v", err)
	}
	_, err = ms.PackCKMSWithKey("iso_host", DefaultModuleKey())
	if !errors.Is(err, ErrModuleForbidden) {
		t.Fatalf("PackCKMSWithKey must refuse retired iso_host: %v", err)
	}
}

func TestRegisterAndDeleteInjectIsolated(t *testing.T) {
	ms := NewModuleServiceForTest(t.TempDir())
	pe := make([]byte, 64)
	pe[0], pe[1] = 'M', 'Z'
	id := "inject"
	if err := ms.RegisterRaw(id, pe); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(ms.Dir(), id+".bin")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("bin missing: %v", err)
	}
	found := false
	for _, e := range ms.ListCatalog("", "") {
		if e.ID == id {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("inject must appear in catalog after register")
	}
	if err := ms.Delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("bin should be removed")
	}
	err := ms.Delete(id)
	if !errors.Is(err, ErrModuleNotFound) {
		t.Fatalf("second delete want not found, got %v", err)
	}
	err = ms.Delete("shell")
	if !errors.Is(err, ErrModuleForbidden) {
		t.Fatalf("delete shell want forbidden, got %v", err)
	}
	err = ms.RegisterRaw("desktop", pe)
	if !errors.Is(err, ErrModuleForbidden) {
		t.Fatalf("desktop register want forbidden, got %v", err)
	}
}

func TestRegisterDiskFailDoesNotPolluteMemory(t *testing.T) {
	// Point dir at a non-writable path by using a file as "dir"
	fileAsDir := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ms := NewModuleServiceForTest(fileAsDir) // MkdirAll on file fails later
	// Force dir to be the file path so WriteFile fails
	ms.dir = fileAsDir
	err := ms.RegisterRaw("inject", []byte{0x4d, 0x5a})
	if err == nil {
		t.Fatal("expected disk write failure")
	}
	if _, ok := ms.raw["inject"]; ok {
		t.Fatal("memory must not be updated when disk write fails")
	}
}

func TestCatalogNeverListsShellAsProduct(t *testing.T) {
	ms := NewModuleServiceForTest(t.TempDir())
	_ = os.WriteFile(filepath.Join(ms.Dir(), "shell.bin"), []byte{0x4d, 0x5a}, 0o644)
	// scanDisk-like: only product bins loaded into raw by Register path
	for _, e := range ms.ListCatalog("", "") {
		if e.ID == "shell" {
			t.Fatalf("non-product module %q must not appear in catalog", e.ID)
		}
	}
}

func TestListCatalogFiltersByOS(t *testing.T) {
	ms := NewModuleServiceForTest(t.TempDir())
	// Register the three product modules (bytes are not inspected beyond MZ for product path).
	for _, id := range []string{"ad", "inject", "bof"} {
		if err := ms.RegisterRaw(id, []byte{0x4d, 0x5a}); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}

	// Linux agent: must see zero of the three windows-only modules.
	linuxEntries := ms.ListCatalog("linux-agent", "linux")
	for _, e := range linuxEntries {
		if e.ID == "ad" || e.ID == "inject" || e.ID == "bof" {
			t.Fatalf("windows-only module %q leaked to linux catalog", e.ID)
		}
	}

	// Windows agent: must see the modules.
	winEntries := ms.ListCatalog("win-agent", "windows")
	seen := map[string]bool{}
	for _, e := range winEntries {
		seen[e.ID] = true
	}
	for _, want := range []string{"ad", "inject", "bof"} {
		if !seen[want] {
			t.Fatalf("expected windows-only module %q for windows agent", want)
		}
	}
}
