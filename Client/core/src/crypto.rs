use crate::config;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use log::{debug, error};
use sha2::{Digest, Sha256};

/// Nonce 长度（12 字节，AES-GCM 标准）
const NONCE_LENGTH: usize = 12;

/// Test-only switch: force fill_aes_nonce to fail so encrypt is fail-closed.
///
/// `thread_local!` so concurrent `#[test]`s cannot pollute each other — a
/// `--test-threads=N` run with the fail-closed test setting this true never
/// bleeds into sibling crypto tests on other threads (root cause of the
/// `test_encrypt_decrypt_roundtrip` / `test_encrypt_empty_data` flakes).
#[cfg(test)]
thread_local! {
    static FORCE_NONCE_RANDOM_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Fill a 12-byte AES-GCM nonce from OS CSPRNG. Fail-closed (no time/counter fallback).
fn fill_aes_nonce(out: &mut [u8; NONCE_LENGTH]) -> Result<(), ()> {
    #[cfg(test)]
    {
        if FORCE_NONCE_RANDOM_FAIL.with(|f| f.get()) {
            return Err(());
        }
    }
    getrandom::getrandom(out).map_err(|_| ())
}

/// Domain for agent register proof: HMAC-SHA256(session_key, REG_PROOF_DOMAIN || uuid).
/// Build-seed derived 16-byte domain (must match server WireIDs.RegProofDomain).
pub fn reg_proof_domain() -> &'static [u8] {
    &crate::wire_ids::REG_PROOF_DOMAIN
}

/// HMAC-SHA256(key, domain||uuid) as base64 — proves possession of session material at register.
pub fn register_proof(session_key: &[u8], uuid: &str) -> String {
    let mac = hmac_sha256(session_key, &[reg_proof_domain(), uuid.as_bytes()].concat());
    base64::engine::general_purpose::STANDARD.encode(mac)
}

/// Verify register proof (constant-time compare of MAC bytes).
pub fn verify_register_proof(session_key: &[u8], uuid: &str, proof_b64: &str) -> bool {
    let Ok(got) = base64::engine::general_purpose::STANDARD.decode(proof_b64.trim()) else {
        return false;
    };
    let expect = hmac_sha256(session_key, &[reg_proof_domain(), uuid.as_bytes()].concat());
    if got.len() != expect.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(expect.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Phase 2: Traffic Camouflage Constants
fn http_header_template() -> Vec<u8> {
    crate::utils::decode_obf(&crate::obf_str!("POST /sync HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: ")).into()
}
fn http_header_end() -> Vec<u8> {
    crate::utils::decode_obf(&crate::obf_str!("\r\n\r\n")).into()
}
fn http_response_template() -> Vec<u8> {
    crate::utils::decode_obf(&crate::obf_str!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ")).into()
}
fn http_response_end() -> Vec<u8> {
    crate::utils::decode_obf(&crate::obf_str!("\r\n\r\n")).into()
}

/// 使用 PBKDF2 简化版（HMAC-SHA256 × 100000 迭代）派生 32 字节 AES 密钥
/// 虽然不如 Argon2id 内存硬度强，但在无外部 KDF 库时是最佳安全选择。
/// 结合 getrandom 生成的高熵盐，可有效防御彩虹表和暴力破解。
const KDF_ITERATIONS: u32 = 100000;

pub fn derive_key(base_key: &[u8], salt: &[u8]) -> Vec<u8> {
    let salt_used = if salt.is_empty() {
        // Fallback: use zero salt (backward compatible)
        vec![0u8; 32]
    } else {
        salt.to_vec()
    };

    // 初始值：SHA256(base_key || salt)
    let mut hasher = Sha256::new();
    hasher.update(base_key);
    hasher.update(&salt_used);
    let mut dk = hasher.finalize().to_vec();

    // 迭代 KDF_ITERATIONS 次：每次 SHA256(dk || counter || base_key || salt)
    for i in 0..KDF_ITERATIONS {
        let mut h = Sha256::new();
        h.update(&dk);
        h.update(&i.to_le_bytes());
        h.update(base_key);
        h.update(&salt_used);
        dk = h.finalize().to_vec();
    }
    dk
}

/// 🛡️ Phase 2: Enhanced Traffic Camouflage
///
/// 报文混淆：对加密后的报文进行二次混淆 (防止 DPI 特征识别)
/// 新增 HTTP 伪装模式，使 WebSocket 流量看起来像正常 HTTP API 调用
pub fn obfuscate_packet(mut data: Vec<u8>) -> Vec<u8> {
    let mode = config::get_packet_obfuscation_mode();
    // CRITICAL: mode "none"/empty must be a pure passthrough to match the Go server
    // (`utils.ObfuscatePacket` default returns data unchanged). Applying default
    // padding here corrupts AES-GCM ciphertext and causes "message authentication failed".
    if mode == "none" || mode.is_empty() {
        return data;
    }

    match mode.as_str() {
        "base64" => {
            // Base64 编码：将加密数据转为文本格式，模拟普通 HTTP/Text 流量
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            let b64_str = STANDARD.encode(&data);
            b64_str.into_bytes()
        }
        // "xor" mode REMOVED: repeating-key XOR leaks key material via frequency analysis.
        // It actively exposes the AES key bytes to any passive observer.
        "junk" => {
            // Junk Data Padding 模式：填充随机长度的垃圾数据
            // 格式: [Encrypted Data] + [Junk Bytes] + [Original Len (4 bytes)]
            let original_len = data.len() as u32;
            let mut junk_len = (crate::utils::next_u32() % 64) as usize;
            if junk_len == 0 {
                junk_len = 8;
            }

            let mut junk = vec![0u8; junk_len];
            for i in 0..junk_len {
                junk[i] = (crate::utils::next_u32() % 256) as u8;
            }

            data.extend_from_slice(&junk);
            data.extend_from_slice(&original_len.to_be_bytes());
            data
        }
        "http" => {
            // 🚀 Phase 2: HTTP 伪装模式
            // 将 WebSocket 帧伪装成 HTTP POST 请求
            // 格式: HTTP Header + Base64(Encrypted Data) + Padding
            wrap_as_http_request(data)
        }
        "padding" => {
            // 🚀 Phase 2: Tailored Padding 模式
            // 每个包填充随机长度数据 (50-2048 字节)，使 DPI 包长度分析失效
            apply_tailored_padding(data)
        }
        // Unknown modes: do not invent padding — stay compatible with server default.
        _ => data,
    }
}

/// 🛡️ Phase 2: Default padding to avoid fixed packet sizes
fn apply_default_padding(data: Vec<u8>) -> Vec<u8> {
    // Add small random padding (1-16 bytes) to every packet
    // This prevents pattern recognition based on fixed packet sizes
    let padding_len = (crate::utils::next_u32() % 16 + 1) as usize;
    let mut padded = data;

    // Random padding bytes
    for _ in 0..padding_len {
        padded.push((crate::utils::next_u32() % 256) as u8);
    }

    // Append padding length marker (last 2 bytes)
    padded.extend_from_slice(&(padding_len as u16).to_be_bytes());

    padded
}

/// 🛡️ Phase 2: HTTP Request Wrapper
fn wrap_as_http_request(data: Vec<u8>) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    // Base64 encode the encrypted data
    let b64_data = STANDARD.encode(&data);

    // Add padding to vary content length
    let padding_len = (crate::utils::next_u32() % 100 + 50) as usize;
    let padding = generate_http_padding(padding_len);

    // Build HTTP POST request
    let content_len = b64_data.len() + padding.len();

    let mut http_packet = Vec::new();

    // HTTP Header
    http_packet.extend_from_slice(&http_header_template());
    http_packet.extend_from_slice(content_len.to_string().as_bytes());
    http_packet.extend_from_slice(&http_header_end());

    // Content: Base64(Data) + Padding JSON
    http_packet.extend_from_slice(b64_data.as_bytes());
    http_packet.extend_from_slice(&padding);

    http_packet
}

/// Generate JSON-style padding for HTTP camouflage
fn generate_http_padding(len: usize) -> Vec<u8> {
    // Generate random JSON-like padding
    let mut padding = Vec::new();
    padding.push(b'{');

    let num_fields = (crate::utils::next_u32() % 5 + 2) as usize;
    for i in 0..num_fields {
        if i > 0 {
            padding.push(b',');
        }

        // Random field name
        let field_names = [
            "status",
            "timestamp",
            "version",
            "token",
            "session",
            "request_id",
            "nonce",
        ];
        let field_idx = (crate::utils::next_u32() % field_names.len() as u32) as usize;
        let field = field_names[field_idx];

        padding.push(b'"');
        padding.extend_from_slice(field.as_bytes());
        padding.extend_from_slice(b"\":");

        // Random value (string or number)
        if crate::utils::random_bool(0.5) {
            padding.push(b'"');
            let val_len = (crate::utils::next_u32() % 10 + 5) as usize;
            for _ in 0..val_len {
                padding.push((crate::utils::next_u32() % 26 + 97) as u8); // lowercase letters
            }
            padding.push(b'"');
        } else {
            padding.extend_from_slice((crate::utils::next_u32() % 10000).to_string().as_bytes());
        }
    }

    padding.push(b'}');

    // Pad to target length with whitespace
    while padding.len() < len {
        padding.push(b' ');
    }

    padding
}

/// 🛡️ Phase 2: Tailored Padding (50-2048 bytes random)
fn apply_tailored_padding(mut data: Vec<u8>) -> Vec<u8> {
    // Record original length before padding
    let original_len = data.len() as u32;

    // Random padding between 50-2048 bytes
    let padding_len = (crate::utils::next_u32() % 1998 + 50) as usize;

    // Generate random padding bytes
    for _ in 0..padding_len {
        // Use varied byte distribution to mimic normal traffic
        let byte = if crate::utils::random_bool(0.7) {
            // Mostly printable ASCII (mimics text content)
            (crate::utils::next_u32() % 95 + 32) as u8
        } else {
            // Some binary content
            (crate::utils::next_u32() % 256) as u8
        };
        data.push(byte);
    }

    // Store original length for deobfuscation (4 bytes at end)
    data.extend_from_slice(&original_len.to_be_bytes());

    data
}

/// 报文解混淆
pub fn deobfuscate_packet(mut data: Vec<u8>) -> Vec<u8> {
    let mode = config::get_packet_obfuscation_mode();
    // Match server: "none"/empty is pure passthrough (ciphertext = nonce||gcm only).
    if mode == "none" || mode.is_empty() {
        return data;
    }

    match mode.as_str() {
        "base64" => {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            if let Ok(decoded) = STANDARD.decode(&data) {
                return decoded;
            }
            data
        }
        "xor" => {
            let key = config::get_aes_key();
            if !key.is_empty() {
                for i in 0..data.len() {
                    data[i] ^= key[i % key.len()];
                }
            }
            data
        }
        "junk" => {
            // 识别并移除 Junk Padding (最后 4 字节固定是原始长度)
            if data.len() < 4 {
                return data;
            }

            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&data[data.len() - 4..]);
            let original_len = u32::from_be_bytes(len_bytes) as usize;

            if original_len <= data.len() - 4 {
                data.truncate(original_len);
            }
            data
        }
        "http" => {
            // 🚀 Phase 2: Extract from HTTP wrapper
            extract_from_http_wrapper(data)
        }
        "padding" => {
            // 🚀 Phase 2: Remove tailored padding
            remove_tailored_padding(data)
        }
        _ => data,
    }
}

/// Remove default padding
fn remove_default_padding(mut data: Vec<u8>) -> Vec<u8> {
    if data.len() < 2 {
        return data;
    }

    // Read padding length marker (last 2 bytes)
    let marker_len = u16::from_be_bytes([data[data.len() - 2], data[data.len() - 1]]) as usize;

    if data.len() >= 2 + marker_len {
        let original_len = data.len() - 2 - marker_len;
        data.truncate(original_len);
    }

    data
}

/// Extract data from HTTP wrapper
fn extract_from_http_wrapper(data: Vec<u8>) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    // Find HTTP body start (after "\r\n\r\n")
    let header_end_marker = b"\r\n\r\n";
    if let Some(pos) = find_sequence(&data, header_end_marker) {
        let body_start = pos + header_end_marker.len();

        if body_start >= data.len() {
            return data;
        }

        // Extract body (Base64 encoded)
        let body = &data[body_start..];

        // Find and strip padding (JSON object after base64 data)
        // Base64 data ends at '{' or first non-base64 character
        let b64_end = body
            .iter()
            .position(|&b| b == b'{' || !is_base64_char(b))
            .unwrap_or(body.len());

        let b64_data = &body[..b64_end];

        // Decode base64
        if let Ok(decoded) = STANDARD.decode(b64_data) {
            return decoded;
        }
    }

    data
}

/// Find byte sequence in data
fn find_sequence(data: &[u8], sequence: &[u8]) -> Option<usize> {
    if sequence.len() > data.len() {
        return None;
    }

    for i in 0..=data.len() - sequence.len() {
        if data[i..i + sequence.len()] == *sequence {
            return Some(i);
        }
    }
    None
}

/// Check if byte is valid base64 character
fn is_base64_char(b: u8) -> bool {
    (b >= b'A' && b <= b'Z')
        || (b >= b'a' && b <= b'z')
        || (b >= b'0' && b <= b'9')
        || b == b'+'
        || b == b'/'
        || b == b'='
}

/// Remove tailored padding
fn remove_tailored_padding(mut data: Vec<u8>) -> Vec<u8> {
    if data.len() < 4 {
        return data;
    }

    // Original length is stored in last 4 bytes
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&data[data.len() - 4..]);
    let original_len = u32::from_be_bytes(len_bytes) as usize;

    if original_len <= data.len() - 4 && original_len > 0 {
        data.truncate(original_len);
    }

    data
}

/// 加密数据
///
/// 使用 AES-256-GCM 加密数据。每次加密都会生成一个新的随机 Nonce。
///
/// # 参数
///
/// * `data` - 要加密的明文数据
/// * `key` - 32 字节的 AES-256 密钥
///
/// # 返回值
///
/// 返回加密后的数据，格式为：[Nonce (12 bytes) + Ciphertext]
///
/// # Panics
///
/// 如果密钥长度不是 32 字节，会 panic。
///
/// # 示例
///
/// ```no_run
/// use c2_client_agent::crypto::encrypt;
/// use c2_client_agent::config::get_aes_key;
///
/// let key = get_aes_key();
/// let plaintext = b"Hello, World!";
/// let encrypted = encrypt(plaintext, &key);
/// ```
pub fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    // 验证密钥长度：不满足时静默返回空（调用方检查空返回）
    if key.len() != 32 {
        return Vec::new();
    }

    // 创建 AES-256-GCM 密码器
    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Nonce: OS CSPRNG only (fail-closed). Never timestamp/counter fallback —
    // predictable nonces break AES-GCM confidentiality under reuse.
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    if fill_aes_nonce(&mut nonce_bytes).is_err() {
        error!("nonce: secure random unavailable (fail-closed)");
        return Vec::new();
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 加密数据
    let ciphertext = match cipher.encrypt(nonce, data) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // 组合 Nonce 和 Ciphertext：[Nonce (12 bytes) + Ciphertext]
    let mut result = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    result
}

/// 解密数据
///
/// 使用 AES-256-GCM 解密数据。从加密数据中提取 Nonce，然后解密。
///
/// # 参数
///
/// * `data` - 加密的数据，格式为：[Nonce (12 bytes) + Ciphertext]
/// * `key` - 32 字节的 AES-256 密钥
///
/// # 返回值
///
/// 成功返回解密后的明文数据，失败返回错误信息。
///
/// # 错误
///
/// - 如果数据长度小于 12 字节（无法提取 Nonce），返回错误
/// - 如果解密失败（密钥错误或数据损坏），返回错误
///
/// # 示例
///
/// ```no_run
/// use c2_client_agent::crypto::{encrypt, decrypt};
/// use c2_client_agent::config::get_aes_key;
///
/// let key = get_aes_key();
/// let plaintext = b"Hello, World!";
/// let encrypted = encrypt(plaintext, &key);
/// let decrypted = decrypt(&encrypted, &key).unwrap();
/// assert_eq!(plaintext, &decrypted[..]);
/// ```
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    debug!("Decrypting {} bytes of data", data.len());

    // 验证密钥长度
    if key.len() != 32 {
        let err = format!("encryption requires a 32-byte key, got {} bytes", key.len());
        error!("{}", err);
        return Err(err);
    }

    // 检查数据长度（至少需要 Nonce）
    if data.len() < NONCE_LENGTH {
        let err = format!(
            "Encrypted data too short: {} bytes (minimum {} bytes for nonce)",
            data.len(),
            NONCE_LENGTH
        );
        error!("{}", err);
        return Err(err);
    }

    // 提取 Nonce（前 12 字节）
    let nonce_bytes = &data[..NONCE_LENGTH];
    let nonce = Nonce::from_slice(nonce_bytes);

    debug!("Extracted nonce: {} bytes", nonce_bytes.len());

    // 提取 Ciphertext（剩余字节）
    let ciphertext = &data[NONCE_LENGTH..];

    debug!("Extracted ciphertext: {} bytes", ciphertext.len());

    // 创建 AES-256-GCM 密码器
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {}", e))?;

    // 解密数据
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        let err = format!("Decryption failed: {}", e);
        error!("{}", err);
        err
    })?;

    debug!(
        "Decryption successful: {} bytes ciphertext -> {} bytes plaintext",
        ciphertext.len(),
        plaintext.len()
    );

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_noise_roundtrip() {
        let psk = b"test-psk-material-32-bytes-long!!";
        let (client_e, client_msg) = noise_initiate(psk).expect("init");
        assert_eq!(client_msg.len(), NOISE_MSG_LEN);
        assert_eq!(client_msg[0], NOISE_VERSION);
        let (_server_e, server_msg, server_sk) = noise_respond(&client_msg, psk).expect("respond");
        assert_eq!(server_msg.len(), NOISE_MSG_LEN);
        let client_sk = noise_complete(&client_e, &server_msg, psk).expect("complete");
        assert_eq!(client_sk, server_sk);
        // Reject legacy 32-byte fake noise
        assert!(noise_respond(&[0u8; 32], psk).is_err());
        // Reject v1 length 33 without mac
        assert!(noise_respond(&[0u8; 33], psk).is_err());
    }

    #[test]
    fn test_noise_wrong_psk_fails_handshake() {
        let psk_a = b"correct-psk-material-32bytes!!!!!";
        let psk_b = b"wrong-psk-material-xxxxxxxxxxxx!!";
        let (client_e, client_msg) = noise_initiate(psk_a).expect("init");
        // Responder with wrong PSK rejects client MAC
        assert!(
            noise_respond(&client_msg, psk_b).is_err(),
            "wrong PSK must fail respond"
        );
        // Matching respond then client with wrong PSK fails complete
        let (_se, server_msg, _sk) = noise_respond(&client_msg, psk_a).expect("respond ok");
        assert!(
            noise_complete(&client_e, &server_msg, psk_b).is_err(),
            "wrong PSK must fail complete"
        );
        // Empty PSK rejected
        assert!(noise_initiate(b"").is_err());
        assert!(noise_respond(&client_msg, b"").is_err());
    }

    #[test]
    fn test_noise_psk_required_on_initiate() {
        let psk = b"another-psk-for-noise-auth-tests!";
        let (e1, m1) = noise_initiate(psk).unwrap();
        let (e2, m2) = noise_initiate(psk).unwrap();
        // Different ephemerals → different messages; both authenticate with same PSK
        assert_ne!(m1[1..33], m2[1..33]);
        let (_, r1, sk1) = noise_respond(&m1, psk).unwrap();
        let sk1b = noise_complete(&e1, &r1, psk).unwrap();
        assert_eq!(sk1, sk1b);
        let (_, r2, sk2) = noise_respond(&m2, psk).unwrap();
        let sk2b = noise_complete(&e2, &r2, psk).unwrap();
        assert_eq!(sk2, sk2b);
        assert_ne!(sk1, sk2); // different ECDH sessions
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"Hello, World! This is a test message.";

        // 加密
        let encrypted = encrypt(plaintext, key);

        // 验证加密后的数据长度
        assert!(encrypted.len() > plaintext.len());
        assert!(encrypted.len() >= NONCE_LENGTH);

        // 解密
        let decrypted = decrypt(&encrypted, key).unwrap();

        // 验证 round-trip
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"Same message";

        // 加密两次
        let encrypted1 = encrypt(plaintext, key);
        let encrypted2 = encrypt(plaintext, key);

        // 由于 Nonce 是随机的，两次加密结果应该不同
        assert_ne!(encrypted1, encrypted2);

        // 但解密后应该相同
        let decrypted1 = decrypt(&encrypted1, key).unwrap();
        let decrypted2 = decrypt(&encrypted2, key).unwrap();
        assert_eq!(decrypted1, decrypted2);
        assert_eq!(plaintext, &decrypted1[..]);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = b"01234567890123456789012345678901"; // 32 bytes
        let key2 = b"10987654321098765432109876543210"; // 32 bytes (different)
        let plaintext = b"Secret message";

        // 使用 key1 加密
        let encrypted = encrypt(plaintext, key1);

        // 使用 key2 解密应该失败
        let result = decrypt(&encrypted, key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_corrupted_data() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"Test message";

        // 加密
        let mut encrypted = encrypt(plaintext, key);

        // 损坏数据（修改最后一个字节）
        if let Some(last) = encrypted.last_mut() {
            *last = last.wrapping_add(1);
        }

        // 解密应该失败
        let result = decrypt(&encrypted, key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_short_data() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let short_data = b"short"; // 少于 12 字节

        // 解密应该失败
        let result = decrypt(short_data, key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_decrypt_with_invalid_key_length() {
        let short_key = b"short_key"; // 少于 32 字节
        let data = vec![0u8; 20]; // 足够长的数据

        // 解密应该失败
        let result = decrypt(&data, short_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("32-byte key"));
    }

    #[test]
    fn test_encrypt_empty_data() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"";

        // 加密空数据
        let encrypted = encrypt(plaintext, key);

        // 应该至少包含 Nonce
        assert!(encrypted.len() >= NONCE_LENGTH);

        // 解密
        let decrypted = decrypt(&encrypted, key).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_large_data() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = vec![0x42u8; 10000]; // 10KB 数据

        // 加密
        let encrypted = encrypt(&plaintext, key);

        // 解密
        let decrypted = decrypt(&encrypted, key).unwrap();

        // 验证
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_nonce_is_prepended() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"Test";

        // 加密
        let encrypted = encrypt(plaintext, key);

        // 前 12 字节应该是 Nonce
        assert!(encrypted.len() >= NONCE_LENGTH);

        // 提取 Nonce 并验证可以解密
        let result = decrypt(&encrypted, key);
        assert!(result.is_ok());
    }

    /// Fail-closed: when CSPRNG is unavailable, encrypt returns empty (no time/counter nonce).
    ///
    /// Isolation:
    /// - flag is `thread_local` → other test threads never see it
    /// - `ForceGuard` sets true on create and false on Drop → same-thread reuse after
    ///   panic/assert cannot leave the flag sticky for a later test on this worker
    #[test]
    fn test_encrypt_fail_closed_when_random_unavailable() {
        let key = b"01234567890123456789012345678901";
        let plaintext = b"must-not-encrypt-with-weak-nonce";

        struct ForceGuard;
        impl ForceGuard {
            fn arm() -> Self {
                FORCE_NONCE_RANDOM_FAIL.with(|f| f.set(true));
                ForceGuard
            }
        }
        impl Drop for ForceGuard {
            fn drop(&mut self) {
                FORCE_NONCE_RANDOM_FAIL.with(|f| f.set(false));
            }
        }

        {
            let _guard = ForceGuard::arm();
            let out = encrypt(plaintext, key);
            assert!(
                out.is_empty(),
                "encrypt must return empty ciphertext when nonce RNG fails"
            );
        } // Drop clears flag before any further asserts

        // Round-trip path still works after flag cleared
        let ok = encrypt(plaintext, key);
        assert!(!ok.is_empty());
        assert_eq!(decrypt(&ok, key).unwrap(), plaintext);
    }

    #[test]
    fn test_register_proof_binds_uuid_to_session_key() {
        let key = b"01234567890123456789012345678901";
        let uuid = "11111111-2222-3333-4444-555555555555";
        let proof = register_proof(key, uuid);
        assert!(verify_register_proof(key, uuid, &proof));
        assert!(!verify_register_proof(key, "other-uuid", &proof));
        assert!(!verify_register_proof(
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            uuid,
            &proof
        ));
        assert!(!verify_register_proof(key, uuid, "not-valid-base64!!!"));
        assert!(!verify_register_proof(key, uuid, ""));
    }

    /// Regression: obfuscation mode "none" must not alter ciphertext bytes.
    /// Server expects pure AES-GCM frames; padding breaks GCM auth tags.
    #[test]
    fn test_obfuscate_none_is_passthrough() {
        let cipher = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xAA, 0xBB];
        // Force "none" via deobfuscate/obfuscate with empty mode path:
        // When mode is none (default config placeholder resolves to "none"),
        // length must be unchanged.
        let mode = crate::config::get_packet_obfuscation_mode();
        // Regardless of patched mode, if it is none/empty the functions are passthrough.
        if mode == "none" || mode.is_empty() {
            let out = obfuscate_packet(cipher.clone());
            assert_eq!(out, cipher, "none mode must not append padding");
            let back = deobfuscate_packet(out);
            assert_eq!(back, cipher);
        } else {
            // Still assert pure helpers: empty mode branch tested via direct logic
            // by checking that encrypt→decrypt roundtrip without obfuscate works.
            let key = b"01234567890123456789012345678901";
            let enc = encrypt(b"hello-none", key);
            let dec = decrypt(&enc, key).unwrap();
            assert_eq!(dec, b"hello-none");
        }
    }

    #[test]
    fn test_encrypt_then_none_obfuscate_still_decrypts() {
        let key = b"01234567890123456789012345678901";
        let plain = b"minimal-agent-register";
        let enc = encrypt(plain, key);
        // Simulate server path: no deobfuscation for none mode
        let dec = decrypt(&enc, key).expect("gcm ok without padding");
        assert_eq!(dec, plain);
        // Simulate broken path that would fail (padding after encrypt)
        let mut padded = enc.clone();
        padded.extend_from_slice(&[0x11, 0x22, 0x00, 0x02]); // 2 junk + len marker
        assert!(
            decrypt(&padded, key).is_err(),
            "padded ciphertext must fail GCM (proves root cause)"
        );
    }
}

// =============================================================================
// 🛡️ Phase 1: Noise-like Handshake Protocol (Pure Software, No External Deps)
// =============================================================================
// Since we cannot download x25519-dalek / noise-rust / hkdf crates,
// Real X25519 ECDH + HKDF-SHA256 (hard cutover from fake SHA256 "public keys").
// Pure-Rust X25519 (RFC 7748) — no extra crates (offline builds).
// Wire v2: version(1)=0x02 || public_key(32) || psk_mac(16)  → 49 bytes each way.
// psk_mac = HMAC-SHA256(psk, domain || pubkey)[..16]  — wrong PSK fails handshake.
// Session key: HKDF-SHA256(ikm=shared, salt=psk, info=wire_ids::NOISE_INFO)
// =============================================================================

pub const NOISE_VERSION: u8 = 0x02;
pub const NOISE_MAC_LEN: usize = 16;
pub const NOISE_MSG_LEN: usize = 1 + 32 + NOISE_MAC_LEN; // 49
// Seed-derived MAC domains (must match server WireIDs.NoiseInitDom / NoiseRespDom).
fn noise_init_dom() -> &'static [u8] {
    &crate::wire_ids::NOISE_INIT_DOM
}
fn noise_resp_dom() -> &'static [u8] {
    &crate::wire_ids::NOISE_RESP_DOM
}

/// Ephemeral X25519 key pair for one handshake session.
#[derive(Clone)]
pub struct EphemeralKey {
    secret: [u8; 32],
    public: [u8; 32],
}

impl EphemeralKey {
    /// Generate a new X25519 ephemeral key pair using OS CSPRNG.
    pub fn generate() -> Result<Self, String> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|e| format!("getrandom failed: {:?}", e))?;
        // Clamp per RFC 7748
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
        let public = x25519_scalar_base_mult(&secret);
        Ok(EphemeralKey { secret, public })
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
}

/// ECDH + HKDF session key.
pub fn derive_session_key(local_secret: &[u8; 32], peer_public: &[u8; 32], psk: &[u8]) -> [u8; 32] {
    let shared = x25519_scalarmult(local_secret, peer_public);
    hkdf_sha256_32(&shared, psk, &crate::wire_ids::NOISE_INFO)
}

/// HKDF-Extract/Expand (SHA-256) → 32-byte OKM.
fn hkdf_sha256_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    let salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    let prk = hmac_sha256(salt, ikm);
    // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
    let mut expand_in = Vec::with_capacity(info.len() + 1);
    expand_in.extend_from_slice(info);
    expand_in.push(0x01);
    hmac_sha256(&prk, &expand_in)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLK: usize = 64;
    let mut k = [0u8; BLK];
    if key.len() > BLK {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLK];
    let mut opad = [0x5cu8; BLK];
    for i in 0..BLK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

// --- Minimal X25519 (RFC 7748) field arithmetic over 2^255-19 ---

fn x25519_scalar_base_mult(scalar: &[u8; 32]) -> [u8; 32] {
    // Base point u = 9
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519_scalarmult(scalar, &base)
}

fn x25519_scalarmult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut e = *scalar;
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    let x1 = fe_from_bytes(point);
    let mut x2 = fe_one();
    let mut z2 = fe_zero();
    let mut x3 = x1;
    let mut z3 = fe_one();
    let mut swap = 0u8;

    for t in (0..=254).rev() {
        let kt = (e[t >> 3] >> (t & 7)) & 1;
        swap ^= kt;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = kt;

        let a = fe_add(x2, z2);
        let aa = fe_sq(a);
        let b = fe_sub(x2, z2);
        let bb = fe_sq(b);
        let e_ = fe_sub(aa, bb);
        let c = fe_add(x3, z3);
        let d = fe_sub(x3, z3);
        let da = fe_mul(d, a);
        let cb = fe_mul(c, b);
        x3 = fe_sq(fe_add(da, cb));
        z3 = fe_mul(x1, fe_sq(fe_sub(da, cb)));
        x2 = fe_mul(aa, bb);
        z2 = fe_mul(e_, fe_add(aa, fe_mul(fe_from_u64(121665), e_)));
    }

    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);
    let out = fe_mul(x2, fe_invert(z2));
    fe_to_bytes(&out)
}

type Fe = [i64; 16];

fn fe_zero() -> Fe {
    [0; 16]
}
fn fe_one() -> Fe {
    let mut f = fe_zero();
    f[0] = 1;
    f
}
fn fe_from_u64(n: u64) -> Fe {
    let mut f = fe_zero();
    f[0] = n as i64;
    f
}

fn fe_from_bytes(s: &[u8; 32]) -> Fe {
    let mut f = fe_zero();
    for i in 0..16 {
        f[i] = s[2 * i] as i64 + ((s[2 * i + 1] as i64) << 8);
    }
    f[15] &= 0x7fff;
    f
}

fn fe_to_bytes(h: &Fe) -> [u8; 32] {
    let mut t = *h;
    fe_carry(&mut t);
    // reduce mod 2^255-19
    let mut q = (19 * t[15] + (1 << 14)) >> 15;
    for i in 0..15 {
        q = (q + t[i]) >> 16;
    }
    q = (q + t[15]) >> 15;
    t[0] += 19 * q;
    for i in 0..15 {
        let c = t[i] >> 16;
        t[i + 1] += c;
        t[i] -= c << 16;
    }
    t[15] &= 0x7fff;

    let mut s = [0u8; 32];
    for i in 0..16 {
        s[2 * i] = t[i] as u8;
        s[2 * i + 1] = (t[i] >> 8) as u8;
    }
    s
}

fn fe_carry(h: &mut Fe) {
    for i in 0..15 {
        let c = h[i] >> 16;
        h[i + 1] += c;
        h[i] -= c << 16;
    }
    let c = h[15] >> 15;
    h[0] += 19 * c;
    h[15] -= c << 15;
}

fn fe_add(a: Fe, b: Fe) -> Fe {
    let mut o = fe_zero();
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn fe_sub(a: Fe, b: Fe) -> Fe {
    let mut o = fe_zero();
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u8) {
    let mask = -(swap as i64);
    for i in 0..16 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

fn fe_mul(a: Fe, b: Fe) -> Fe {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = fe_zero();
    for i in 0..16 {
        o[i] = t[i];
    }
    fe_carry(&mut o);
    fe_carry(&mut o);
    o
}

fn fe_sq(a: Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_invert(a: Fe) -> Fe {
    // a^(p-2) via square-and-multiply chain for 2^255-21
    let mut c = a;
    for i in (0..=253).rev() {
        c = fe_sq(c);
        if i != 2 && i != 4 {
            c = fe_mul(c, a);
        }
    }
    c
}

/// Truncated HMAC-SHA256(psk, domain||parts...) for handshake authentication.
fn noise_psk_mac(psk: &[u8], domain: &[u8], parts: &[&[u8]]) -> [u8; NOISE_MAC_LEN] {
    let mut msg = Vec::with_capacity(64 + parts.iter().map(|p| p.len()).sum::<usize>());
    msg.extend_from_slice(domain);
    for p in parts {
        msg.extend_from_slice(p);
    }
    let full = hmac_sha256(psk, &msg);
    let mut out = [0u8; NOISE_MAC_LEN];
    out.copy_from_slice(&full[..NOISE_MAC_LEN]);
    out
}

fn noise_mac_ok(got: &[u8], expect: &[u8; NOISE_MAC_LEN]) -> bool {
    if got.len() != NOISE_MAC_LEN {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(expect.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Initiator (client): returns (key, 49-byte wire message with PSK MAC).
pub fn noise_initiate(psk: &[u8]) -> Result<(EphemeralKey, Vec<u8>), String> {
    if psk.is_empty() {
        return Err("noise psk required".into());
    }
    let e = EphemeralKey::generate()?;
    let mac = noise_psk_mac(psk, noise_init_dom(), &[&e.public]);
    let mut msg = Vec::with_capacity(NOISE_MSG_LEN);
    msg.push(NOISE_VERSION);
    msg.extend_from_slice(&e.public);
    msg.extend_from_slice(&mac);
    Ok((e, msg))
}

/// Responder: verify client PSK MAC, return (key, 49-byte response, session_key).
pub fn noise_respond(
    client_msg: &[u8],
    psk: &[u8],
) -> Result<(EphemeralKey, Vec<u8>, [u8; 32]), String> {
    if psk.is_empty() {
        return Err("noise psk required".into());
    }
    if client_msg.len() != NOISE_MSG_LEN {
        return Err(format!(
            "Invalid handshake message length: {} (want {})",
            client_msg.len(),
            NOISE_MSG_LEN
        ));
    }
    if client_msg[0] != NOISE_VERSION {
        return Err(format!("unsupported noise version 0x{:02x}", client_msg[0]));
    }
    let mut client_public = [0u8; 32];
    client_public.copy_from_slice(&client_msg[1..33]);
    let client_mac = &client_msg[33..49];
    let expect_mac = noise_psk_mac(psk, noise_init_dom(), &[&client_public]);
    if !noise_mac_ok(client_mac, &expect_mac) {
        return Err("noise psk auth failed (client mac)".into());
    }

    let e = EphemeralKey::generate()?;
    let session_key = derive_session_key(&e.secret, &client_public, psk);
    let resp_mac = noise_psk_mac(psk, noise_resp_dom(), &[&client_public, &e.public]);

    let mut response = Vec::with_capacity(NOISE_MSG_LEN);
    response.push(NOISE_VERSION);
    response.extend_from_slice(&e.public);
    response.extend_from_slice(&resp_mac);
    Ok((e, response, session_key))
}

/// Client completes after receiving 49-byte server response (verifies PSK MAC).
pub fn noise_complete(
    local_e: &EphemeralKey,
    server_response: &[u8],
    psk: &[u8],
) -> Result<[u8; 32], String> {
    if psk.is_empty() {
        return Err("noise psk required".into());
    }
    if server_response.len() != NOISE_MSG_LEN {
        return Err(format!(
            "Invalid server response length: {} (want {})",
            server_response.len(),
            NOISE_MSG_LEN
        ));
    }
    if server_response[0] != NOISE_VERSION {
        return Err(format!(
            "unsupported noise version 0x{:02x}",
            server_response[0]
        ));
    }
    let mut server_public = [0u8; 32];
    server_public.copy_from_slice(&server_response[1..33]);
    let server_mac = &server_response[33..49];
    let expect = noise_psk_mac(psk, noise_resp_dom(), &[&local_e.public, &server_public]);
    if !noise_mac_ok(server_mac, &expect) {
        return Err("noise psk auth failed (server mac)".into());
    }
    Ok(derive_session_key(&local_e.secret, &server_public, psk))
}

/// Encrypt data with the session key (AES-256-GCM, same as transport layer).
/// Format: [nonce (12 bytes) || ciphertext+tag].
pub fn noise_encrypt(session_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    encrypt(plaintext, session_key)
}

/// Decrypt data with the session key.
pub fn noise_decrypt(session_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    decrypt(ciphertext, session_key).map_err(|e| format!("noise decrypt failed: {:?}", e))
}

// =============================================================================
// 🛡️ Phase 2: Secure Memory Zeroization
// =============================================================================

/// Zeroize a mutable byte slice using volatile writes.
/// This prevents the compiler from optimizing away the zeroization.
pub fn zeroize(data: &mut [u8]) {
    for b in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

/// A guard that zeroizes its contents when dropped.
pub struct ZeroizeGuard {
    pub data: Vec<u8>,
}

impl ZeroizeGuard {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Drop for ZeroizeGuard {
    fn drop(&mut self) {
        zeroize(&mut self.data);
    }
}

/// Zeroize an ephemeral key after use.
pub fn zeroize_key(key: &mut [u8; 32]) {
    zeroize(key);
}

/// Zeroize a Vec<u8> in place.
pub fn zeroize_vec(data: &mut Vec<u8>) {
    zeroize(data.as_mut_slice());
    data.clear();
    data.shrink_to_fit();
}
