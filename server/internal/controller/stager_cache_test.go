package controllers

import (
	"testing"
	"time"

	"cupcake-server/pkg/stagerguard"
)

func TestStagerCacheConsumeMaxHits(t *testing.T) {
	// Isolate from process default: use a tiny max via temporary hit counter.
	old := stagerHits
	stagerHits = stagerguard.NewHitCounter(2)
	t.Cleanup(func() { stagerHits = old })

	id := "stager-hit-test-id"
	stagerCacheStore(id, StagerConfig{OS: "windows", Arch: "x64", ListenerID: "L1"})

	for i := 0; i < 2; i++ {
		cfg, status, ok := stagerCacheConsume(id)
		if !ok || status != stagerguard.StatusOK {
			t.Fatalf("hit %d: ok=%v status=%s", i+1, ok, status)
		}
		if cfg.OS != "windows" {
			t.Fatalf("cfg: %+v", cfg)
		}
	}
	_, status, ok := stagerCacheConsume(id)
	if ok || status != stagerguard.StatusMaxHits {
		t.Fatalf("want max_hits, got ok=%v status=%s", ok, status)
	}
	// Further load should miss
	if _, ok := stagerCacheLoad(id); ok {
		t.Fatal("entry should be deleted after max hits")
	}
}

func TestStagerCacheExpire(t *testing.T) {
	id := "stager-ttl-test-id"
	StagerCache.Store(id, stagerCacheEntry{
		cfg:       StagerConfig{OS: "linux"},
		expiresAt: time.Now().Add(-time.Second),
	})
	_, status, ok := stagerCacheConsume(id)
	if ok || status != stagerguard.StatusExpired {
		t.Fatalf("want expired, got ok=%v status=%s", ok, status)
	}
}

func TestStagerCacheNotFound(t *testing.T) {
	_, status, ok := stagerCacheConsume("no-such-stager-id-zzzz")
	if ok || status != stagerguard.StatusNotFound {
		t.Fatalf("want not_found, got ok=%v status=%s", ok, status)
	}
}
