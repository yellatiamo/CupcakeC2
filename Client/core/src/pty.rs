// Interactive terminal over Yamux stream YAMUX_STREAM_PTY.
//
// Default: HybridSession (Mode A) — builtins + direct exe spawn with streamed pipes.
// No cmd.exe / powershell by default.
//
// Compatibility: set env APP_PTY_MODE=cmd for legacy pipe-to-cmd shell.

use log::{debug, error, info};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_util::compat::FuturesAsyncReadCompatExt;

/// Handle interactive session on a yamux stream.
pub async fn handle_stream(stream: yamux::Stream) {
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let mode = std::env::var("APP_PTY_MODE")
        .unwrap_or_default()
        .to_ascii_lowercase();

    if mode == "cmd" || mode == "legacy" {
        info!("[PTY] Legacy cmd pipe mode (APP_PTY_MODE={})", mode);
        handle_legacy_cmd_pty(stream).await;
    } else {
        info!("[PTY] HybridSession Mode A (no cmd/powershell)");
        handle_hybrid_session(stream).await;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mode A — Hybrid interactive command session
// ═══════════════════════════════════════════════════════════════════════════════

async fn handle_hybrid_session(stream: yamux::Stream) {
    let (mut net_r, net_w) = tokio::io::split(stream.compat());
    let net_w = Arc::new(Mutex::new(net_w));

    let mut cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut line_buf: Vec<u8> = Vec::with_capacity(512);

    // Shared: Ctrl+C requested / a child is currently running
    let interrupt = Arc::new(AtomicBool::new(false));
    let busy = Arc::new(AtomicBool::new(false));

    write_banner_and_prompt(&net_w, &cwd).await;

    let mut read_buf = [0u8; 4096];
    loop {
        match net_r.read(&mut read_buf).await {
            Ok(0) => break,
            Ok(n) => {
                let chunk = &read_buf[..n];
                for &b in chunk {
                    // ── Ctrl+C ─────────────────────────────────────────────
                    if b == 0x03 {
                        if busy.load(Ordering::SeqCst) {
                            // Signal running child; do NOT reprint prompt here
                            // (run_hybrid_line will finish and caller prints prompt).
                            interrupt.store(true, Ordering::SeqCst);
                        } else {
                            // Idle: cancel current line, show ^C + prompt
                            line_buf.clear();
                            interrupt.store(false, Ordering::SeqCst);
                            let mut w = net_w.lock().await;
                            let _ = w.write_all(b"^C\r\n").await;
                            let prompt = crate::executor::format_prompt(&cwd);
                            let _ = w.write_all(prompt.as_bytes()).await;
                            let _ = w.flush().await;
                        }
                        continue;
                    }

                    // Ignore input while a child is running (except Ctrl+C above)
                    if busy.load(Ordering::SeqCst) {
                        continue;
                    }

                    // Backspace
                    if b == 0x7f || b == 0x08 {
                        if !line_buf.is_empty() {
                            line_buf.pop();
                        }
                        continue;
                    }

                    // Enter → run line
                    if b == b'\r' || b == b'\n' {
                        if b == b'\n' && line_buf.is_empty() {
                            continue; // swallow LF after CR
                        }
                        let line = String::from_utf8_lossy(&line_buf).trim().to_string();
                        line_buf.clear();

                        {
                            let mut w = net_w.lock().await;
                            let _ = w.write_all(b"\r\n").await;
                            let _ = w.flush().await;
                        }

                        if !line.is_empty() {
                            interrupt.store(false, Ordering::SeqCst);
                            busy.store(true, Ordering::SeqCst);
                            run_hybrid_line(
                                &line,
                                &mut cwd,
                                net_w.clone(),
                                interrupt.clone(),
                                &mut net_r,
                                &busy,
                            )
                            .await;
                            busy.store(false, Ordering::SeqCst);
                            interrupt.store(false, Ordering::SeqCst);
                        }

                        // Always restore a single clean prompt after a command
                        {
                            let mut w = net_w.lock().await;
                            let prompt = crate::executor::format_prompt(&cwd);
                            let _ = w.write_all(prompt.as_bytes()).await;
                            let _ = w.flush().await;
                        }
                        continue;
                    }

                    // Accumulate printable / high-bit bytes
                    if b >= 0x20 || b >= 0x80 {
                        line_buf.push(b);
                    }
                }
            }
            Err(e) => {
                error!("[Hybrid] network read error: {}", e);
                break;
            }
        }
    }

    debug!("[Hybrid] session closed");
}

async fn write_banner_and_prompt(
    net_w: &Arc<Mutex<impl AsyncWriteExt + Unpin>>,
    cwd: &std::path::Path,
) {
    let mut w = net_w.lock().await;
    let _ = w
        .write_all(
            b"\r\nMicrosoft Windows [Hybrid Shell]\r\n\
(c) Hybrid agent terminal. Type HELP for a list of commands.\r\n\
Ctrl+C interrupts a running program.\r\n",
        )
        .await;
    let prompt = crate::executor::format_prompt(cwd);
    let _ = w.write_all(prompt.as_bytes()).await;
    let _ = w.flush().await;
}

/// Run one command; while external process runs, also poll net for Ctrl+C.
async fn run_hybrid_line<R>(
    line: &str,
    cwd: &mut PathBuf,
    net_w: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    interrupt: Arc<AtomicBool>,
    net_r: &mut R,
    busy: &AtomicBool,
) where
    R: AsyncReadExt + Unpin,
{
    // Built-in first (fast, no child)
    if let Some(r) = crate::executor::try_builtin(line, cwd) {
        let mut w = net_w.lock().await;
        if !r.stdout.is_empty() {
            let _ = w.write_all(normalize_newlines(&r.stdout).as_bytes()).await;
        }
        if !r.stderr.is_empty() {
            let _ = w.write_all(normalize_newlines(&r.stderr).as_bytes()).await;
        }
        let _ = w.flush().await;
        return;
    }

    // External process with concurrent Ctrl+C monitoring
    let cwd_snap = cwd.clone();
    let line_owned = line.to_string();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let interrupt_flag = interrupt.clone();

    let exec_task = tokio::spawn(async move {
        crate::executor::exec_direct_stream(
            &line_owned,
            &cwd_snap,
            move |chunk| {
                let _ = tx.send(chunk.to_vec());
            },
            move || interrupt_flag.load(Ordering::SeqCst),
        )
        .await
    });

    let mut net_buf = [0u8; 256];
    let mut exec_done = false;
    let mut exec_result: Option<Result<i32, String>> = None;

    while !exec_done {
        tokio::select! {
            // Child output
            data = rx.recv() => {
                match data {
                    Some(data) => {
                        let text = normalize_newlines(&String::from_utf8_lossy(&data));
                        let mut w = net_w.lock().await;
                        let _ = w.write_all(text.as_bytes()).await;
                        let _ = w.flush().await;
                    }
                    None => {
                        // Channel closed: exec finished (or dropped tx)
                        // Fall through to join below
                        exec_done = true;
                    }
                }
            }
            // Network input while busy — only honor Ctrl+C
            n = net_r.read(&mut net_buf) => {
                match n {
                    Ok(0) => {
                        // Peer closed — still wait for child cleanup
                        interrupt.store(true, Ordering::SeqCst);
                        exec_done = true;
                    }
                    Ok(n) => {
                        if net_buf[..n].iter().any(|&b| b == 0x03) {
                            interrupt.store(true, Ordering::SeqCst);
                            let mut w = net_w.lock().await;
                            let _ = w.write_all(b"^C\r\n").await;
                            let _ = w.flush().await;
                        }
                        // discard other keys while child runs
                    }
                    Err(_) => {
                        interrupt.store(true, Ordering::SeqCst);
                        exec_done = true;
                    }
                }
            }
            // Periodic check so we don't hang if channel already closed
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                if exec_task.is_finished() {
                    exec_done = true;
                }
            }
        }
    }

    // Drain remaining output
    while let Ok(data) = rx.try_recv() {
        let text = normalize_newlines(&String::from_utf8_lossy(&data));
        let mut w = net_w.lock().await;
        let _ = w.write_all(text.as_bytes()).await;
        let _ = w.flush().await;
    }

    // Join with timeout so a stuck wait never freezes the session
    match tokio::time::timeout(std::time::Duration::from_secs(3), exec_task).await {
        Ok(Ok(Ok(_code))) => {}
        Ok(Ok(Err(e))) => {
            let mut w = net_w.lock().await;
            let _ = w.write_all(normalize_newlines(&e).as_bytes()).await;
            let _ = w.flush().await;
        }
        Ok(Err(e)) => {
            let mut w = net_w.lock().await;
            let _ = w
                .write_all(format!("exec join error: {}\r\n", e).as_bytes())
                .await;
            let _ = w.flush().await;
        }
        Err(_) => {
            // Timed out joining — session continues anyway
            let mut w = net_w.lock().await;
            let _ = w
                .write_all(b"\r\n[!] process interrupted (cleanup timeout)\r\n")
                .await;
            let _ = w.flush().await;
        }
    }

    let _ = busy;
    let _ = exec_result;
}

fn normalize_newlines(s: &str) -> String {
    s.replace('\n', "\r\n").replace("\r\r\n", "\r\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Legacy Mode C — pipe to cmd.exe / sh
// ═══════════════════════════════════════════════════════════════════════════════

async fn handle_legacy_cmd_pty(stream: yamux::Stream) {
    use std::process::Stdio;

    let (mut net_r, mut net_w) = tokio::io::split(stream.compat());
    let (tx_to_net, mut rx_from_pty) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (tx_to_pty, rx_from_net) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    let mut child = match spawn_pipe_shell(tx_to_net, rx_from_net).await {
        Ok(c) => c,
        Err(e) => {
            error!("[PTY] PipeShell failed: {}", e);
            let _ = net_w
                .write_all(format!("\r\n[!] Pipe shell failed: {}\r\n", e).as_bytes())
                .await;
            return;
        }
    };

    let net_read = async {
        let mut buf = [0u8; 8192];
        loop {
            match net_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = normalize_input_for_shell(&buf[..n]);
                    if tx_to_pty.send(chunk).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("[PTY] Network read error: {}", e);
                    break;
                }
            }
        }
    };

    let net_write = async {
        while let Some(data) = rx_from_pty.recv().await {
            if net_w.write_all(&data).await.is_err() {
                break;
            }
            let _ = net_w.flush().await;
            tokio::task::yield_now().await;
        }
    };

    tokio::select! {
        _ = net_read => {},
        _ = net_write => {},
    }

    let _ = child.kill().await;
    debug!("[PTY] Legacy session terminated");
}

fn normalize_input_for_shell(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    for &b in data {
        if b == b'\r' {
            out.push(b'\r');
            out.push(b'\n');
        } else if b == b'\n' {
            if out.last() != Some(&b'\n') {
                out.push(b'\n');
            }
        } else {
            out.push(b);
        }
    }
    out
}

async fn spawn_pipe_shell(
    tx_to_net: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut rx_from_net: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<tokio::process::Child, String> {
    use tokio::process::Command;

    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd.exe");
        c.arg("/Q");
        #[cfg(windows)]
        c.creation_flags(0x0800_0000);
        c
    } else {
        Command::new("sh")
    };

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("TERM", "xterm-256color")
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to spawn shell: {}", e))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Failed to take stdin".to_string())?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed to take stdout".to_string())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Failed to take stderr".to_string())?;

    let _ = tx_to_net
        .send(b"\r\n[+] Legacy pipe shell (cmd/sh).\r\n\r\n".to_vec())
        .await;

    let tx_out = tx_to_net.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx_out.send(decode_output(&buf[..n])).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let tx_err = tx_to_net;
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx_err.send(decode_output(&buf[..n])).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        while let Some(data) = rx_from_net.recv().await {
            if stdin.write_all(&data).await.is_err() {
                break;
            }
            let _ = stdin.flush().await;
        }
    });

    Ok(child)
}

fn decode_output(data: &[u8]) -> Vec<u8> {
    #[cfg(all(windows, feature = "encoding-support"))]
    {
        let (res, _, has_error) = encoding_rs::GBK.decode(data);
        if !has_error {
            return res.as_bytes().to_vec();
        }
    }
    data.to_vec()
}

use std::process::Stdio;

#[cfg(test)]
mod tests {
    use super::normalize_input_for_shell;

    #[test]
    fn cr_becomes_crlf() {
        assert_eq!(normalize_input_for_shell(b"dir\r"), b"dir\r\n");
    }

    #[test]
    fn crlf_not_doubled() {
        assert_eq!(normalize_input_for_shell(b"dir\r\n"), b"dir\r\n");
    }
}
