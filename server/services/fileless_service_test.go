package services

import (
	"testing"
)

func TestResolveStagerStage2URL(t *testing.T) {
	u := ResolveStagerStage2URL("http://10.0.0.1:9999", "abc12def")
	if u != "http://10.0.0.1:9999/api/stage2/abc12def" {
		t.Fatalf("got %s", u)
	}
	u2 := ResolveStagerStage2URL("panel.local:8080", "id1")
	if u2 != "http://panel.local:8080/api/stage2/id1" {
		t.Fatalf("got %s", u2)
	}
}

func TestStage2CacheRoundTrip(t *testing.T) {
	body := []byte{0x90, 0x90, 0xC3, 0x01, 0x02}
	StoreStage2("test-stage2-id", body, "x64", "ln1", "tcp://1.2.3.4:443")
	got, meta, err := LoadStage2("test-stage2-id")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(body) {
		t.Fatalf("len %d != %d", len(got), len(body))
	}
	for i := range body {
		if got[i] != body[i] {
			t.Fatalf("byte mismatch at %d", i)
		}
	}
	if meta.Arch != "x64" || meta.Listener != "ln1" {
		t.Fatalf("meta %+v", meta)
	}
	if _, _, err := LoadStage2("missing-id"); err == nil {
		t.Fatal("expected missing error")
	}
	if !Stage2Exists("test-stage2-id") {
		t.Fatal("expected Stage2Exists true")
	}
	if Stage2Exists("missing-id") {
		t.Fatal("expected Stage2Exists false for missing")
	}
}

func TestConsumeStage2MaxHits(t *testing.T) {
	id := "test-stage2-max-hits"
	body := []byte{0x41, 0x42, 0x43, 0x44}
	// Override process-wide counter max by re-storing and consuming up to stage2Hits.Max().
	StoreStage2(id, body, "x64", "ln1", "tcp://1.2.3.4:443")
	max := stage2Hits.Max()
	for i := 0; i < max; i++ {
		got, _, status, err := ConsumeStage2(id)
		if err != nil || status != "ok" {
			t.Fatalf("consume %d: err=%v status=%s", i+1, err, status)
		}
		if len(got) != len(body) {
			t.Fatalf("consume %d: bad len", i+1)
		}
	}
	_, _, status, err := ConsumeStage2(id)
	if err == nil || status != "max_hits" {
		t.Fatalf("expected max_hits, got status=%s err=%v", status, err)
	}
	// Entry removed after max
	if Stage2Exists(id) {
		t.Fatal("cache entry should be gone after max hits")
	}
}

// Donut-linked conversion tests live in fileless_donut_test.go (!nodonut).
// Default / safe suite (-tags nodonut) only exercises cache + input validation.

func TestBuildFilelessStage2RejectsGarbage(t *testing.T) {
	if _, err := BuildFilelessStage2(nil, "x64"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := BuildFilelessStage2([]byte("MZ"), "x64"); err == nil {
		t.Fatal("expected error for tiny buffer")
	}
	// Non-PE should fail before or at converter (stub or real donut)
	if _, err := BuildFilelessStage2([]byte("not-a-pe-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), "x64"); err == nil {
		t.Fatal("expected reject non-PE")
	}
}

func TestModuleDescribeLoadMode(t *testing.T) {
	_, _, _, mode := ModuleDescribeEx("bof")
	if mode != "mem" {
		t.Fatalf("bof load_mode=%s", mode)
	}
	name, _, kind, mode := ModuleDescribeEx("inject")
	if mode != "worker" || kind != "runtime" {
		t.Fatalf("inject name=%s kind=%s mode=%s", name, kind, mode)
	}
	// Retired desktop + other non-product ids are legacy/ignored
	_, _, kind, _ = ModuleDescribeEx("desktop")
	if kind != "legacy" {
		t.Fatalf("desktop should be legacy kind after retirement, got %s", kind)
	}
	_, _, kind, _ = ModuleDescribeEx("shell")
	if kind != "legacy" {
		t.Fatalf("shell should be legacy kind, got %s", kind)
	}
}
