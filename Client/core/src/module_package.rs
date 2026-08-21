// Module package format (CKMS) — pack / verify / unpack.
// Used by Stage0 loader and server-side packaging.

use sha2::{Digest, Sha256};

use crate::wire_ids::PKG_MAGIC;

/// Package magic (build-seed derived; not a product brand string).
pub fn package_magic() -> &'static [u8; 4] {
    &PKG_MAGIC
}

pub const FORMAT_VERSION: u16 = 1;
/// HMAC key size (derived or configured 32-byte key)
pub const KEY_LEN: usize = 32;

/// CKMS flags (u16 LE at offset 6).
pub const FLAG_PREF_MEM_MAP: u16 = 1 << 0;
/// Fail closed if Manual-Map is unavailable / fails (no disk LoadLibrary).
pub const FLAG_REQUIRE_MEM_MAP: u16 = 1 << 1;
// bit 2 reserved: compressed payload

/// Build a signed module blob: MAGIC | ver | flags | id_len | id | pay_len | payload | hmac32
pub fn pack_module(id: &str, payload: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    pack_module_with_flags(id, payload, key, 0)
}

/// Pack with explicit CKMS flags (see `FLAG_*`).
pub fn pack_module_with_flags(
    id: &str,
    payload: &[u8],
    key: &[u8],
    flags: u16,
) -> Result<Vec<u8>, String> {
    if id.is_empty() || id.len() > 64 {
        return Err("invalid module id length".into());
    }
    if key.len() < 16 {
        return Err("module key too short".into());
    }
    let mut body = Vec::with_capacity(4 + 2 + 2 + 2 + id.len() + 4 + payload.len() + 32);
    body.extend_from_slice(package_magic());
    body.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    let id_bytes = id.as_bytes();
    body.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
    body.extend_from_slice(id_bytes);
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(payload);
    let mac = hmac_sha256(key, &body);
    body.extend_from_slice(&mac);
    Ok(body)
}

/// Verify HMAC and return (module_id, payload).
pub fn unpack_and_verify(blob: &[u8], key: &[u8]) -> Result<(String, Vec<u8>), String> {
    unpack_and_verify_ex(blob, key).map(|(id, payload, _flags)| (id, payload))
}

/// Verify HMAC and return (module_id, payload, flags).
pub fn unpack_and_verify_ex(blob: &[u8], key: &[u8]) -> Result<(String, Vec<u8>, u16), String> {
    if blob.len() < 4 + 2 + 2 + 2 + 4 + 32 {
        return Err("blob too short".into());
    }
    if &blob[0..4] != package_magic().as_slice() {
        return Err("bad package header".into());
    }
    let ver = u16::from_le_bytes([blob[4], blob[5]]);
    if ver != FORMAT_VERSION {
        return Err(format!("unsupported format version {ver}"));
    }
    let flags = u16::from_le_bytes([blob[6], blob[7]]);
    let id_len = u16::from_le_bytes([blob[8], blob[9]]) as usize;
    let id_start = 10;
    let id_end = id_start + id_len;
    if id_end + 4 + 32 > blob.len() {
        return Err("truncated id".into());
    }
    let id = std::str::from_utf8(&blob[id_start..id_end])
        .map_err(|_| "id not utf8")?
        .to_string();
    let pay_len = u32::from_le_bytes([
        blob[id_end],
        blob[id_end + 1],
        blob[id_end + 2],
        blob[id_end + 3],
    ]) as usize;
    let pay_start = id_end + 4;
    let pay_end = pay_start + pay_len;
    if pay_end + 32 != blob.len() {
        return Err(format!(
            "length mismatch: pay_end+32={} blob={}",
            pay_end + 32,
            blob.len()
        ));
    }
    let payload = blob[pay_start..pay_end].to_vec();
    let body = &blob[..pay_end];
    let expect = &blob[pay_end..];
    let got = hmac_sha256(key, body);
    if got.as_slice() != expect {
        return Err("HMAC verify failed".into());
    }
    Ok((id, payload, flags))
}

/// HMAC-SHA256 with key padding (RFC 2104 simplified)
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&out);
    mac
}

/// Default module key material for **dev/tests only**.
/// Production agents must derive the key from the agent AES key via `derive_module_key`.
/// In release builds this panics if called — prevents silent shared default HMAC key.
pub fn default_module_key() -> [u8; 32] {
    #[cfg(any(debug_assertions, test))]
    {
        // Dev-only; not a product brand string in release (release panics).
        *b"DEV_ONLY_MODULE_KEY_V1_DO_NOT___" // 32 bytes
    }
    #[cfg(not(any(debug_assertions, test)))]
    {
        panic!("module key must be derived from agent key material");
    }
}

/// Whether the hard-coded default module key is available (debug/test only).
pub fn default_module_key_allowed() -> bool {
    cfg!(any(debug_assertions, test))
}

/// Derive module key from agent AES key bytes (domain label is build-seed derived).
pub fn derive_module_key(aes_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(crate::wire_ids::MOD_KEY_DOMAIN);
    h.update(aes_key);
    let d = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let key = default_module_key();
        let payload = b"hello-module-payload";
        let blob = pack_module("shell", payload, &key).unwrap();
        let (id, pay) = unpack_and_verify(&blob, &key).unwrap();
        assert_eq!(id, "shell");
        assert_eq!(pay, payload);
    }

    #[test]
    fn tamper_fails_hmac() {
        let key = default_module_key();
        let mut blob = pack_module("shell", b"x", &key).unwrap();
        let n = blob.len();
        blob[n / 2] ^= 0xff;
        assert!(unpack_and_verify(&blob, &key).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let blob = pack_module("shell", b"x", &default_module_key()).unwrap();
        let mut bad = default_module_key();
        bad[0] ^= 1;
        assert!(unpack_and_verify(&blob, &bad).is_err());
    }

    #[test]
    fn pack_with_flags_roundtrip() {
        let key = default_module_key();
        let flags = FLAG_PREF_MEM_MAP | FLAG_REQUIRE_MEM_MAP;
        let blob = pack_module_with_flags("shell", b"payload", &key, flags).unwrap();
        let (id, pay, got) = unpack_and_verify_ex(&blob, &key).unwrap();
        assert_eq!(id, "shell");
        assert_eq!(pay, b"payload");
        assert_eq!(got, flags);
    }
}
