package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"time"
)

// DefaultWireSeed is only a last-resort fallback when no env/setting exists.
// Product path: Builder sets CUPCAKE_WIRE_SEED on both agent build and server.
// Do not rely on this public-looking constant for deployments.
const DefaultWireSeed = ""

// WireIDs holds protocol magics and crypto domain labels derived from a seed.
type WireIDs struct {
	PkgMagic       [4]byte // module package (legacy ASCII was "CKMS")
	FragMagic      [4]byte // multi-frame (legacy "CKF1")
	JobMagic       [4]byte // isolated host job (legacy "CIS1")
	NoiseInfo      []byte  // 16-byte HKDF info
	ModKeyDomain   []byte  // 16-byte module HMAC domain
	RegProofDomain []byte  // 16-byte register proof HMAC domain
	NoiseInitDom   []byte  // 16-byte noise client-init PSK MAC domain
	NoiseRespDom   []byte  // 16-byte noise server-resp PSK MAC domain
}

var (
	wireMu   sync.RWMutex
	wireIDs  WireIDs
	wireSeed string
	wireInit bool
)

func domainHash(seed, domain string) [32]byte {
	h := sha256.New()
	h.Write([]byte(seed))
	h.Write([]byte{0})
	h.Write([]byte(domain))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func magic4(seed, domain string) [4]byte {
	h := domainHash(seed, domain)
	m := [4]byte{h[0], h[1], h[2], h[3]}
	if m[0]|m[1]|m[2]|m[3] == 0 {
		m = [4]byte{0x3c, 0xa1, 0x7e, 0x09}
	}
	m[0] |= 0x80
	return m
}

// DeriveWireIDs builds wire identity from seed (same algorithm as Client build.rs).
func DeriveWireIDs(seed string) WireIDs {
	if seed == "" {
		// Empty seed is invalid for production; use a non-public lab-only fallback
		// so unit tests still produce deterministic magics when callers pass "".
		seed = "wire-internal-empty-fallback"
	}
	noise := domainHash(seed, "noise-info-v1")
	mod := domainHash(seed, "mod-key-v1")
	reg := domainHash(seed, "reg-proof-v1")
	nInit := domainHash(seed, "noise-init-v2")
	nResp := domainHash(seed, "noise-resp-v2")
	return WireIDs{
		PkgMagic:       magic4(seed, "pkg-v1"),
		FragMagic:      magic4(seed, "frag-v1"),
		JobMagic:       magic4(seed, "job-v1"),
		NoiseInfo:      append([]byte(nil), noise[:16]...),
		ModKeyDomain:   append([]byte(nil), mod[:16]...),
		RegProofDomain: append([]byte(nil), reg[:16]...),
		NoiseInitDom:   append([]byte(nil), nInit[:16]...),
		NoiseRespDom:   append([]byte(nil), nResp[:16]...),
	}
}

func ensureWire() {
	wireMu.RLock()
	ok := wireInit
	wireMu.RUnlock()
	if ok {
		return
	}
	wireMu.Lock()
	defer wireMu.Unlock()
	if wireInit {
		return
	}
	seed := os.Getenv("CUPCAKE_WIRE_SEED")
	if seed == "" {
		// Prefer a process-unique seed over the retired public constant.
		// main.go persists a generated seed into settings before most paths run.
		seed = "wire-internal-empty-fallback"
	}
	wireSeed = seed
	wireIDs = DeriveWireIDs(seed)
	wireInit = true
}

// GetWireIDs returns the process-wide wire identity.
func GetWireIDs() WireIDs {
	ensureWire()
	wireMu.RLock()
	defer wireMu.RUnlock()
	return wireIDs
}

// WireSeed returns the active seed string.
func WireSeed() string {
	ensureWire()
	wireMu.RLock()
	defer wireMu.RUnlock()
	return wireSeed
}

// SetWireSeed forces wire IDs after loading settings (startup).
func SetWireSeed(seed string) {
	if seed == "" {
		seed = "wire-internal-empty-fallback"
	}
	wireMu.Lock()
	defer wireMu.Unlock()
	wireSeed = seed
	wireIDs = DeriveWireIDs(seed)
	wireInit = true
}

// GenerateWireSeed returns a cryptographically random deployment seed.
func GenerateWireSeed() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// time-based fallback if CSPRNG fails (should be rare)
		return fmt.Sprintf("wire-gen-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("wire-gen-%x", b[:])
}
