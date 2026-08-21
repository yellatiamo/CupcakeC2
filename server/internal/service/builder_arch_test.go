package services

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNormalizeBuildArch(t *testing.T) {
	cases := map[string]string{
		"":              "amd64",
		"x64":           "amd64",
		"amd64":         "amd64",
		"x86_64":        "amd64",
		"windows_amd64": "amd64",
		"linux_amd64":   "amd64",
		"X64":           "amd64",
		"x86":           "386",
		"i386":          "386",
		"windows_i386":  "386",
		"arm64":         "arm64",
		"aarch64":       "arm64",
		"linux_arm64":   "arm64",
		"arm":           "arm",
		"armv7":         "arm",
	}
	for in, want := range cases {
		if got := normalizeBuildArch(in); got != want {
			t.Errorf("normalizeBuildArch(%q)=%q want %q", in, got, want)
		}
	}
}

func TestResolveCargoTargetWindowsX64Aliases(t *testing.T) {
	// UI "x64" and "amd64" must both resolve to a windows triple (not empty).
	for _, arch := range []string{"x64", "amd64", "windows_amd64"} {
		norm := normalizeBuildArch(arch)
		got := resolveCargoTarget("windows", norm, "linux")
		if got != "x86_64-pc-windows-gnu" {
			t.Errorf("linux host windows/%s → %q want x86_64-pc-windows-gnu", arch, got)
		}
		got = resolveCargoTarget("windows", norm, "windows")
		if got != "x86_64-pc-windows-msvc" {
			t.Errorf("windows host windows/%s → %q want x86_64-pc-windows-msvc", arch, got)
		}
	}
}

func TestIsCargoCrossCompile(t *testing.T) {
	// Same host windows/amd64 with UI x64 → not cross.
	if isCargoCrossCompile("windows", normalizeBuildArch("x64"), "windows", "amd64") {
		t.Fatal("windows/x64 on windows/amd64 should not be cross")
	}
	// Linux host building windows → cross.
	if !isCargoCrossCompile("windows", "amd64", "linux", "amd64") {
		t.Fatal("linux→windows should be cross")
	}
	// Windows host building linux → cross.
	if !isCargoCrossCompile("linux", "amd64", "windows", "amd64") {
		t.Fatal("windows→linux should be cross")
	}
}

func TestFindCargoAgentBinaryPrefersCupcakeAgent(t *testing.T) {
	dir := t.TempDir()
	rel := filepath.Join(dir, "release")
	if err := os.MkdirAll(rel, 0o755); err != nil {
		t.Fatal(err)
	}
	agent := cargoAgentBinName
	legacy := cargoAgentBinLegacy
	if runtime.GOOS == "windows" {
		agent += ".exe"
		legacy += ".exe"
	}
	// Only legacy present → still found.
	legacyPath := filepath.Join(rel, legacy)
	if err := os.WriteFile(legacyPath, []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := findCargoAgentBinary(dir, "", false, runtime.GOOS == "windows")
	if err != nil {
		t.Fatal(err)
	}
	if got != legacyPath {
		t.Fatalf("got %s want legacy %s", got, legacyPath)
	}

	// Prefer cupcake-agent when both exist.
	agentPath := filepath.Join(rel, agent)
	if err := os.WriteFile(agentPath, []byte("agent"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = findCargoAgentBinary(dir, "", false, runtime.GOOS == "windows")
	if err != nil {
		t.Fatal(err)
	}
	if got != agentPath {
		t.Fatalf("got %s want agent %s", got, agentPath)
	}
}

func TestFindCargoAgentBinaryCrossPath(t *testing.T) {
	dir := t.TempDir()
	triple := "x86_64-pc-windows-gnu"
	crossRel := filepath.Join(dir, triple, "release")
	if err := os.MkdirAll(crossRel, 0o755); err != nil {
		t.Fatal(err)
	}
	name := cargoAgentBinName + ".exe"
	want := filepath.Join(crossRel, name)
	if err := os.WriteFile(want, []byte("pe"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := findCargoAgentBinary(dir, triple, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestFindCargoAgentBinaryMissing(t *testing.T) {
	_, err := findCargoAgentBinary(t.TempDir(), "", false, true)
	if err == nil {
		t.Fatal("expected error when binary missing")
	}
}
