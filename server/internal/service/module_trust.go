package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cupcake-server/pkg/paths"
	"cupcake-server/pkg/trustchain"
)

// ModulePackageMeta is optional trust metadata stored beside a module binary
// (or kept in memory after upload).
type ModulePackageMeta struct {
	ID         string `json:"id"`
	Version    string `json:"version,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Signature  string `json:"signature,omitempty"`
	Signer     string `json:"signer,omitempty"`
	ABIVersion int    `json:"abi_version,omitempty"`
	Target     string `json:"target,omitempty"`
}

const moduleTrustKeyFileName = ".module_trust_hmac"

var (
	moduleRollback  = trustchain.NewRollbackGuard()
	moduleTrustMu   sync.RWMutex
	moduleTrustByID = make(map[string]ModulePackageMeta)

	// Local durable HMAC key (when env/dev keys are unset).
	moduleTrustKeyMu    sync.Mutex
	moduleTrustKeyDir   string
	moduleTrustKeyCache []byte
)

func allowUnsignedModule() bool {
	return os.Getenv("CUPCAKE_ALLOW_UNSIGNED_MODULE") == "1" ||
		os.Getenv("CUPCAKE_TRUST_REQUIRE_SIG") == "0"
}

// SetModuleTrustKeyDir sets the directory for the auto-generated trust HMAC key file.
// Called from ModuleService init / tests so keys stay next to module blobs.
func SetModuleTrustKeyDir(dir string) {
	moduleTrustKeyMu.Lock()
	defer moduleTrustKeyMu.Unlock()
	if strings.TrimSpace(dir) == "" {
		return
	}
	if moduleTrustKeyDir != dir {
		moduleTrustKeyDir = dir
		moduleTrustKeyCache = nil
	}
}

// ModuleFileSHA256 returns lowercase hex SHA-256 of data.
func ModuleFileSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// resolveModuleTrustKey returns HMAC material for module package trust.
// Priority:
//  1. CUPCAKE_TRUST_HMAC_KEY / CUPCAKE_TRUST_DEV_KEYS (trustchain.HMACKeyForSigner)
//  2. Durable auto key under modules dir (.module_trust_hmac) — created on first use
func resolveModuleTrustKey(signer string) []byte {
	if k := trustchain.HMACKeyForSigner(signer); len(k) > 0 {
		return k
	}
	return loadOrCreateLocalModuleTrustKey()
}

func loadOrCreateLocalModuleTrustKey() []byte {
	moduleTrustKeyMu.Lock()
	defer moduleTrustKeyMu.Unlock()
	if len(moduleTrustKeyCache) >= 16 {
		return moduleTrustKeyCache
	}
	dir := moduleTrustKeyDir
	if dir == "" {
		dir = paths.Join("modules")
	}
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, moduleTrustKeyFileName)
	if b, err := os.ReadFile(path); err == nil {
		if key, ok := parseModuleTrustKeyFile(b); ok {
			moduleTrustKeyCache = key
			return key
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Printf("[Module] trust key: rand failed: %v", err)
		return nil
	}
	// Persist as hex for easy ops; HMAC uses decoded raw bytes.
	if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		log.Printf("[Module] warn: cannot persist %s: %v", path, err)
	} else {
		log.Printf("[Module] created local trust HMAC key: %s", path)
	}
	moduleTrustKeyCache = raw
	return raw
}

// parseModuleTrustKeyFile accepts hex (64 chars) or raw bytes (>=16).
func parseModuleTrustKeyFile(b []byte) ([]byte, bool) {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, false
	}
	// Prefer hex decode when looks like hex
	if len(s) >= 32 && len(s)%2 == 0 {
		if decoded, err := hex.DecodeString(s); err == nil && len(decoded) >= 16 {
			return decoded, true
		}
	}
	if len(b) >= 16 {
		// raw file content (trim trailing whitespace/newlines only)
		key := []byte(s)
		if len(key) >= 16 {
			return key, true
		}
	}
	return nil, false
}

// VerifyModulePackage checks HMAC signature and anti-rollback for a module package.
// Empty signature fails closed unless CUPCAKE_ALLOW_UNSIGNED_MODULE=1 or
// CUPCAKE_TRUST_REQUIRE_SIG=0.
func VerifyModulePackage(id, version, sha256Hex, signature, signer string) error {
	id = strings.TrimSpace(id)
	signature = strings.TrimSpace(signature)
	if signature == "" {
		if allowUnsignedModule() {
			return nil
		}
		return fmt.Errorf("module signature missing: refuse (set CUPCAKE_ALLOW_UNSIGNED_MODULE=1 or CUPCAKE_TRUST_REQUIRE_SIG=0 for lab)")
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return fmt.Errorf("module version missing: signed packages require version")
	}
	if signer == "" {
		signer = "default"
	}
	sha256Hex = strings.ToLower(strings.TrimSpace(sha256Hex))
	pm := trustchain.PackageMeta{
		ModuleID:  id,
		Version:   version,
		SHA256:    sha256Hex,
		Signer:    signer,
		Signature: signature,
	}
	// Preserve ABI/Target if stored
	if stored, ok := getModuleTrust(id); ok {
		pm.ABIVersion = stored.ABIVersion
		pm.Target = stored.Target
	}
	key := resolveModuleTrustKey(signer)
	if err := trustchain.Verify(pm, key); err != nil {
		return fmt.Errorf("module signature verify failed: %w", err)
	}
	if err := moduleRollback.CheckAndCommit(id, version); err != nil {
		return err
	}
	return nil
}

// VerifyModuleTrust is an alias used by push/upload paths with full meta.
func VerifyModuleTrust(id, version, sha256Hex, signature, signer string) error {
	return VerifyModulePackage(id, version, sha256Hex, signature, signer)
}

// SignModulePackage fills HMAC signature. Always auto-signs using env key or
// durable local key under the modules directory. Fails if no key material can
// be resolved (should be rare after local key auto-create).
func SignModulePackage(meta *ModulePackageMeta) error {
	if meta == nil {
		return fmt.Errorf("nil module package meta")
	}
	signer := strings.TrimSpace(meta.Signer)
	if signer == "" {
		signer = "default"
	}
	key := resolveModuleTrustKey(signer)
	if len(key) == 0 {
		return fmt.Errorf("trust key missing: cannot sign module (configure CUPCAKE_TRUST_HMAC_KEY or allow modules dir write for auto key)")
	}
	meta.Signer = signer
	if strings.TrimSpace(meta.Version) == "" {
		meta.Version = "0.0.1"
	}
	pm := trustchain.PackageMeta{
		ModuleID:   meta.ID,
		Version:    meta.Version,
		SHA256:     strings.ToLower(strings.TrimSpace(meta.SHA256)),
		Target:     meta.Target,
		ABIVersion: meta.ABIVersion,
		Signer:     signer,
	}
	sig, err := trustchain.Sign(pm, key)
	if err != nil {
		return err
	}
	meta.Signature = sig
	return nil
}

func getModuleTrust(id string) (ModulePackageMeta, bool) {
	moduleTrustMu.RLock()
	defer moduleTrustMu.RUnlock()
	m, ok := moduleTrustByID[sanitizeID(id)]
	return m, ok
}

// StoreModuleTrust keeps meta in memory and optionally persists next to the binary.
func StoreModuleTrust(dir string, meta ModulePackageMeta) error {
	id := sanitizeID(meta.ID)
	if id == "" {
		return fmt.Errorf("empty module id in trust meta")
	}
	meta.ID = id
	moduleTrustMu.Lock()
	moduleTrustByID[id] = meta
	moduleTrustMu.Unlock()
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, id+".trust.json")
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadModuleTrustFile reads {id}.trust.json from dir if present.
func LoadModuleTrustFile(dir, id string) (ModulePackageMeta, error) {
	id = sanitizeID(id)
	path := filepath.Join(dir, id+".trust.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return ModulePackageMeta{}, err
	}
	var meta ModulePackageMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return ModulePackageMeta{}, err
	}
	meta.ID = id
	moduleTrustMu.Lock()
	moduleTrustByID[id] = meta
	moduleTrustMu.Unlock()
	return meta, nil
}

// EnsureModuleTrustFromDisk loads sidecar trust file into memory if missing.
func EnsureModuleTrustFromDisk(dir, id string) {
	id = sanitizeID(id)
	if _, ok := getModuleTrust(id); ok {
		return
	}
	if _, err := LoadModuleTrustFile(dir, id); err != nil {
		// silent — unsigned path or missing sidecar
		_ = err
	}
}

// EnsureModuleSignedOnDisk loads or creates {id}.trust.json with a valid HMAC.
// Used on upload and when scanning pre-existing product modules without a sidecar.
func (m *ModuleService) EnsureModuleSignedOnDisk(id string, pe []byte) (ModulePackageMeta, error) {
	id = sanitizeID(id)
	if id == "" || len(pe) == 0 {
		return ModulePackageMeta{}, fmt.Errorf("invalid module id or empty payload")
	}
	SetModuleTrustKeyDir(m.dir)
	sha := ModuleFileSHA256(pe)
	EnsureModuleTrustFromDisk(m.dir, id)
	if meta, ok := getModuleTrust(id); ok {
		sigOK := strings.TrimSpace(meta.Signature) != ""
		// Hash mismatch (binary replaced without sidecar update) → re-sign below.
		hashMismatch := meta.SHA256 != "" && !strings.EqualFold(meta.SHA256, sha)
		if sigOK && !hashMismatch {
			// Keep existing signature so tamper/wrong-key still fails at Verify.
			if meta.SHA256 == "" {
				meta.SHA256 = sha
				_ = StoreModuleTrust(m.dir, meta)
			}
			return meta, nil
		}
		if hashMismatch {
			log.Printf("[Module] trust meta hash mismatch for %s — re-signing", id)
		}
	}
	meta := ModulePackageMeta{
		ID:      id,
		Version: "0.0.1",
		SHA256:  sha,
		Signer:  "default",
	}
	if prev, ok := getModuleTrust(id); ok {
		if v := strings.TrimSpace(prev.Version); v != "" {
			meta.Version = v
		}
		if s := strings.TrimSpace(prev.Signer); s != "" {
			meta.Signer = s
		}
		meta.ABIVersion = prev.ABIVersion
		meta.Target = prev.Target
	}
	if err := SignModulePackage(&meta); err != nil {
		return ModulePackageMeta{}, err
	}
	if err := StoreModuleTrust(m.dir, meta); err != nil {
		return ModulePackageMeta{}, fmt.Errorf("store trust meta: %w", err)
	}
	log.Printf("[Module] signed trust sidecar id=%s version=%s sha256=%s… file=%s.trust.json",
		id, meta.Version, trimSHA(meta.SHA256), id)
	return meta, nil
}

func trimSHA(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// VerifyModuleBeforePush loads bytes + trust meta and runs VerifyModulePackage.
// Used by the module stage/push path. Missing/stale sidecars are auto-signed once.
func (m *ModuleService) VerifyModuleBeforePush(id string) error {
	id = sanitizeID(id)
	pe, err := m.resolveRaw(id)
	if err != nil {
		return err
	}
	SetModuleTrustKeyDir(m.dir)
	meta, err := m.EnsureModuleSignedOnDisk(id, pe)
	if err != nil {
		// Fall through to strict verify for clear error if unsigned allowed etc.
		if !allowUnsignedModule() {
			return fmt.Errorf("module trust check failed: %w", err)
		}
		return nil
	}
	sha := ModuleFileSHA256(pe)
	if meta.SHA256 != "" && !strings.EqualFold(meta.SHA256, sha) {
		return fmt.Errorf("module hash mismatch vs trust meta: expected %s got %s", meta.SHA256, sha)
	}
	useSHA := meta.SHA256
	if useSHA == "" {
		useSHA = sha
	}
	return VerifyModulePackage(id, meta.Version, useSHA, meta.Signature, meta.Signer)
}

// RegisterRawWithTrust stores PE and always auto-signs + persists {id}.trust.json.
func (m *ModuleService) RegisterRawWithTrust(id string, pe []byte, meta ModulePackageMeta) (ModulePackageMeta, error) {
	if err := m.RegisterRaw(id, pe); err != nil {
		return ModulePackageMeta{}, err
	}
	id = sanitizeID(id)
	SetModuleTrustKeyDir(m.dir)
	meta.ID = id
	meta.SHA256 = ModuleFileSHA256(pe)
	if strings.TrimSpace(meta.Version) == "" {
		meta.Version = "0.0.1"
	}
	if strings.TrimSpace(meta.Signer) == "" {
		meta.Signer = "default"
	}
	if err := SignModulePackage(&meta); err != nil {
		return ModulePackageMeta{}, fmt.Errorf("sign module package: %w", err)
	}
	if strings.TrimSpace(meta.Signature) == "" {
		return ModulePackageMeta{}, fmt.Errorf("sign module package: empty signature after sign")
	}
	if err := StoreModuleTrust(m.dir, meta); err != nil {
		return ModulePackageMeta{}, fmt.Errorf("store trust meta: %w", err)
	}
	log.Printf("[Module] upload signed id=%s version=%s sha256=%s… → %s.trust.json",
		id, meta.Version, trimSHA(meta.SHA256), id)
	return meta, nil
}

// signProductModulesOnDisk ensures every registered product module has a trust sidecar.
func (m *ModuleService) signProductModulesOnDisk() {
	SetModuleTrustKeyDir(m.dir)
	m.mu.RLock()
	ids := make([]string, 0, len(m.raw))
	for id := range m.raw {
		ids = append(ids, id)
	}
	m.mu.RUnlock()
	for _, id := range ids {
		if !IsProductModule(id) {
			continue
		}
		m.mu.RLock()
		pe := m.raw[id]
		m.mu.RUnlock()
		if len(pe) == 0 {
			continue
		}
		if _, err := m.EnsureModuleSignedOnDisk(id, pe); err != nil {
			log.Printf("[Module] auto-sign %s: %v", id, err)
		}
	}
}

// ResetModuleRollbackForTest clears anti-rollback state (unit tests only).
func ResetModuleRollbackForTest() {
	moduleRollback.Reset()
	moduleTrustMu.Lock()
	moduleTrustByID = make(map[string]ModulePackageMeta)
	moduleTrustMu.Unlock()
	moduleTrustKeyMu.Lock()
	moduleTrustKeyCache = nil
	moduleTrustKeyDir = ""
	moduleTrustKeyMu.Unlock()
}
