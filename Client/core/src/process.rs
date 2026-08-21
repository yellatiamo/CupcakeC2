// 进程管理模块
//
// 通过 YamuxStreamPROCESS (YAMUX_STREAM_PROCESS) 处理进程操作：列出进程和终止进程

use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use yamux::Stream;

/// 进程操作请求
#[derive(Serialize, Deserialize, Debug)]
struct ProcRequest {
    action: String, // "ps" 或 "kill"
    pid: Option<u32>,
}

/// 进程信息条目
#[derive(Serialize, Deserialize, Debug)]
struct ProcessEntry {
    pid: u32,
    ppid: u32,
    name: String,
}

/// 进程操作响应
#[derive(Serialize, Deserialize, Debug)]
struct ProcResponse {
    status: String,
    error: Option<String>,
    processes: Option<Vec<ProcessEntry>>,
}

/// 处理进程管理请求
///
/// # 协议格式
///
/// 请求：JSON 格式的 ProcRequest
/// 响应：JSON 格式的 ProcResponse
///
/// # 支持的操作
///
/// - "ps": 列出所有进程
/// - "kill": 终止指定 PID 的进程
pub async fn handle_stream(stream: Stream) {
    info!("[PROCESS] Starting process management session");

    let (mut reader, mut writer) = tokio::io::split(stream.compat());

    // 🛡️ FIX: Max request buffer (1MB) to prevent OOM from malicious data
    const MAX_BUF: usize = 1024 * 1024;

    // 1. 读取请求（处理分段）
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let req = loop {
        let n = match reader.read(&mut chunk).await {
            Ok(0) => {
                warn!("[PROCESS] Empty request received");
                break None;
            }
            Ok(n) => {
                debug!("[PROCESS] Received {} bytes", n);
                n
            }
            Err(e) => {
                error!("[PROCESS] Failed to read request: {}", e);
                break None;
            }
        };

        buf.extend_from_slice(&chunk[..n]);

        // 🛡️ FIX: Prevent unbounded memory growth — reject requests over 1MB
        if buf.len() > MAX_BUF {
            error!("[PROCESS] Request too large (>{})", MAX_BUF);
            break None;
        }
        match serde_json::from_slice::<ProcRequest>(&buf) {
            Ok(r) => break Some(r),
            Err(e) if e.is_eof() => continue,
            Err(e) => {
                error!("[PROCESS] Failed to parse request: {}", e);
                let error_response = ProcResponse {
                    status: "error".to_string(),
                    error: Some(format!("Invalid JSON: {}", e)),
                    processes: None,
                };
                let resp_str = serde_json::to_string(&error_response).unwrap_or_default();
                let _ = writer.write_all(resp_str.as_bytes()).await;
                // ⚡️ FIX: Flush and Shutdown explicitly
                let _ = writer.flush().await;
                let _ = writer.shutdown().await;
                break None;
            }
        }
    };

    let Some(req) = req else {
        return;
    };

    // 2. 执行操作
    let response = match req.action.as_str() {
        "ps" => {
            info!("[PROCESS] Listing processes");
            handle_ps()
        }
        "kill" => {
            let pid = req.pid.unwrap_or(0);
            info!("[PROCESS] Killing process PID: {}", pid);
            handle_kill(pid)
        }
        _ => {
            warn!("[PROCESS] Unknown action: {}", req.action);
            ProcResponse {
                status: "error".to_string(),
                error: Some(format!("Unknown action: {}", req.action)),
                processes: None,
            }
        }
    };

    // 3. 发送响应
    let resp_str = match serde_json::to_string(&response) {
        Ok(s) => s,
        Err(e) => {
            error!("[PROCESS] Failed to serialize response: {}", e);
            return;
        }
    };

    if let Err(e) = writer.write_all(resp_str.as_bytes()).await {
        error!("[PROCESS] Failed to send response: {}", e);
        return;
    }

    // ⚡️ FIX: Flush and Shutdown explicitly
    let _ = writer.flush().await;
    let _ = writer.shutdown().await; // Sends FIN, server sees EOF

    debug!("[PROCESS] Response sent successfully");
    info!("[PROCESS] Process management session completed");
}

/// 列出所有进程 (time-bounded Toolhelp / NT)
fn handle_ps() -> ProcResponse {
    match crate::native::list_processes_bounded(std::time::Duration::from_secs(8)) {
        Ok(list) => {
            info!("[PROCESS] Found {} processes", list.len());
            let processes = list
                .into_iter()
                .map(|p| ProcessEntry {
                    pid: p.pid,
                    ppid: p.ppid,
                    name: p.name,
                })
                .collect();
            ProcResponse {
                status: "ok".to_string(),
                error: None,
                processes: Some(processes),
            }
        }
        Err(e) => ProcResponse {
            status: "error".to_string(),
            error: Some(e),
            processes: None,
        },
    }
}

/// 终止指定进程 (Windows: NtOpenProcess + NtTerminateProcess)
fn handle_kill(pid_u32: u32) -> ProcResponse {
    if pid_u32 == 0 {
        return ProcResponse {
            status: "error".to_string(),
            error: Some("Invalid PID".to_string()),
            processes: None,
        };
    }

    #[cfg(target_os = "windows")]
    {
        match crate::native::terminate_process(pid_u32) {
            Ok(()) => {
                info!("[PROCESS] Successfully killed process PID: {}", pid_u32);
                ProcResponse {
                    status: "ok".to_string(),
                    error: None,
                    processes: None,
                }
            }
            Err(e) => ProcResponse {
                status: "error".to_string(),
                error: Some(e),
                processes: None,
            },
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SIGTERM (15) — cooperative kill
        let rc = unsafe { libc::kill(pid_u32 as i32, 15) };
        if rc == 0 {
            info!("[PROCESS] kill(SIGTERM) pid={}", pid_u32);
            ProcResponse {
                status: "ok".to_string(),
                error: None,
                processes: None,
            }
        } else {
            let err = std::io::Error::last_os_error();
            ProcResponse {
                status: "error".to_string(),
                error: Some(format!("kill failed: {err}")),
                processes: None,
            }
        }
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
    {
        ProcResponse {
            status: "error".to_string(),
            error: Some("Kill not implemented on this platform".to_string()),
            processes: None,
        }
    }
}
