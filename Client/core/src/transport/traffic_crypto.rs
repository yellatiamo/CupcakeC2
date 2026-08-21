// Shared session-key crypto + optional fragmentation for all transports.
// After Noise handshake, traffic MUST use the session key (never static AES).

use crate::crypto;
use crate::error::{ClientError, Result};
use crate::transport::fragment::{
    fragment_message, reassemble_message, should_fragment, Fragment, DEFAULT_MAX_FRAGMENT_SIZE,
};

/// Magic prefix for multi-fragment wire frames (build-seed derived).
pub fn frag_magic() -> &'static [u8; 4] {
    &crate::wire_ids::FRAG_MAGIC
}

/// Prefer Noise session key; only fall back to static when Noise was not established.
/// An empty static key is never accepted as "cleartext mode" in production builds —
/// callers must configure a 32-byte key or establish a Noise session.
pub fn traffic_key<'a>(noise: Option<&'a [u8; 32]>, static_aes: &'a [u8]) -> Result<&'a [u8]> {
    if let Some(sk) = noise {
        return Ok(&sk[..]);
    }
    if static_aes.len() == 32 {
        return Ok(static_aes);
    }
    Err(ClientError::ConnectionError("key setup failed".into()))
}

/// Encrypt + obfuscate for the wire. Fragments large payloads into CKF1 frames.
/// Returns one or more wire payloads to send in order.
/// An empty key is rejected — production never sends cleartext.
pub fn seal_for_wire(plaintext: &[u8], key: &[u8], max_frag: usize) -> Result<Vec<Vec<u8>>> {
    if key.is_empty() {
        return Err(ClientError::ConnectionError("key setup failed".into()));
    }
    if key.len() != 32 {
        return Err(ClientError::ConnectionError("key setup failed".into()));
    }

    let max_frag = if max_frag == 0 {
        DEFAULT_MAX_FRAGMENT_SIZE
    } else {
        max_frag
    };

    if should_fragment(plaintext.len(), max_frag) {
        let frags = fragment_message(plaintext, key, max_frag)?;
        let mut out = Vec::with_capacity(frags.len());
        for f in frags {
            let mut wire = Vec::with_capacity(4 + f.data.len());
            wire.extend_from_slice(frag_magic());
            wire.extend_from_slice(&f.data);
            // Outer obfuscation (base64/junk) applied per frame for DPI variance
            out.push(crypto::obfuscate_packet(wire));
        }
        Ok(out)
    } else {
        let encrypted = crypto::encrypt(plaintext, key);
        if encrypted.is_empty() && !plaintext.is_empty() {
            return Err(ClientError::ConnectionError(
                "encrypt failed (empty ciphertext)".into(),
            ));
        }
        Ok(vec![crypto::obfuscate_packet(encrypted)])
    }
}

/// Open one wire frame. If it's a CKF1 fragment, returns Frag partial; if complete message, returns Plain.
pub enum OpenResult {
    /// Full plaintext message
    Complete(Vec<u8>),
    /// Need more fragments (caller should store and call again with next frames)
    NeedMore,
}

/// Reassembly state for multi-frame messages.
#[derive(Default)]
pub struct FragReassembler {
    parts: Vec<Vec<u8>>,
    expected_total: Option<u32>,
}

impl FragReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.parts.clear();
        self.expected_total = None;
    }

    /// Feed one deobfuscated wire buffer (after deobfuscate_packet).
    pub fn push(&mut self, frame: Vec<u8>, key: &[u8]) -> Result<OpenResult> {
        if key.is_empty() {
            return Err(ClientError::ConnectionError("key setup failed".into()));
        }

        // Fragmented frame?
        if frame.len() >= 4 + 9 && &frame[0..4] == frag_magic().as_slice() {
            let frag_body = frame[4..].to_vec();
            if frag_body.len() < 9 {
                return Err(ClientError::ConnectionError("short fragment".into()));
            }
            let total =
                u32::from_be_bytes([frag_body[4], frag_body[5], frag_body[6], frag_body[7]]);
            let seq = u32::from_be_bytes([frag_body[0], frag_body[1], frag_body[2], frag_body[3]]);

            // Cap fragment count to avoid OOM from malicious total (e.g. u32::MAX)
            const MAX_FRAGMENTS: u32 = 4096;
            if total == 0 || total > MAX_FRAGMENTS {
                self.clear();
                return Err(ClientError::ConnectionError(format!(
                    "fragment total {total} out of range (1..={MAX_FRAGMENTS})"
                )));
            }

            if self.expected_total.is_none() {
                self.expected_total = Some(total);
                self.parts = vec![Vec::new(); total as usize];
            }
            if self.expected_total != Some(total) {
                self.clear();
                return Err(ClientError::ConnectionError(
                    "fragment total mismatch".into(),
                ));
            }
            if seq as usize >= self.parts.len() {
                self.clear();
                return Err(ClientError::ConnectionError("fragment seq OOB".into()));
            }
            self.parts[seq as usize] = frag_body;

            if self.parts.iter().all(|p| !p.is_empty()) {
                let plain = reassemble_message(&self.parts, key)?;
                self.clear();
                return Ok(OpenResult::Complete(plain));
            }
            return Ok(OpenResult::NeedMore);
        }

        // Legacy single-frame: deobfuscated ciphertext = encrypt(plaintext)
        if !self.parts.is_empty() {
            self.clear();
            return Err(ClientError::ConnectionError(
                "unexpected non-fragment during reassembly".into(),
            ));
        }
        let plain = crypto::decrypt(&frame, key)
            .map_err(|e| ClientError::ConnectionError(format!("decrypt failed: {e}")))?;
        Ok(OpenResult::Complete(plain))
    }
}

/// Helper: open a single obfuscated wire blob (handles non-fragment only; multi needs state).
pub fn open_wire_frame(obfuscated: Vec<u8>, key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(ClientError::ConnectionError("key setup failed".into()));
    }
    let deobf = crypto::deobfuscate_packet(obfuscated);
    if deobf.len() >= 4 && &deobf[0..4] == frag_magic().as_slice() {
        return Err(ClientError::ConnectionError(
            "fragment frame requires reassembler state".into(),
        ));
    }
    crypto::decrypt(&deobf, key).map_err(|e| ClientError::ConnectionError(format!("decrypt: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_small_uses_session_key() {
        let key = b"01234567890123456789012345678901";
        let pt = b"hello-noise-session";
        let frames = seal_for_wire(pt, key, 4096).unwrap();
        assert_eq!(frames.len(), 1);
        let mut ra = FragReassembler::new();
        let deobf = crypto::deobfuscate_packet(frames[0].clone());
        match ra.push(deobf, key).unwrap() {
            OpenResult::Complete(p) => assert_eq!(p, pt),
            _ => panic!("expected complete"),
        }
    }

    #[test]
    fn seal_open_large_fragments() {
        let key = b"01234567890123456789012345678901";
        let pt = vec![0xABu8; 5000];
        let frames = seal_for_wire(&pt, key, 512).unwrap();
        assert!(frames.len() > 1);
        let mut ra = FragReassembler::new();
        let mut done = None;
        for f in frames {
            let deobf = crypto::deobfuscate_packet(f);
            match ra.push(deobf, key).unwrap() {
                OpenResult::Complete(p) => done = Some(p),
                OpenResult::NeedMore => {}
            }
        }
        assert_eq!(done.unwrap(), pt);
    }

    #[test]
    fn traffic_key_prefers_noise() {
        let noise = [7u8; 32];
        let static_k = [9u8; 32];
        let k = traffic_key(Some(&noise), &static_k).unwrap();
        assert_eq!(k[0], 7);
    }

    #[test]
    fn seal_8kb_produces_multiple_frames() {
        let key = b"01234567890123456789012345678901";
        let pt = vec![0xCDu8; 8192];
        let frames = seal_for_wire(&pt, key, 1024).unwrap();
        assert!(
            frames.len() >= 2,
            "8KB payload should fragment into ≥2 frames, got {}",
            frames.len()
        );
        let mut ra = FragReassembler::new();
        let mut done = None;
        for f in frames {
            let deobf = crypto::deobfuscate_packet(f);
            match ra.push(deobf, key).unwrap() {
                OpenResult::Complete(p) => done = Some(p),
                OpenResult::NeedMore => {}
            }
        }
        assert_eq!(done.unwrap(), pt);
    }

    #[test]
    fn reassembly_rejects_missing_fragment() {
        let key = b"01234567890123456789012345678901";
        let pt = vec![1u8; 3000];
        let frames = seal_for_wire(&pt, key, 512).unwrap();
        assert!(frames.len() > 2);
        // Feed only first frame — must stay incomplete (no plaintext leak)
        let mut ra = FragReassembler::new();
        let deobf0 = crypto::deobfuscate_packet(frames[0].clone());
        match ra.push(deobf0, key).unwrap() {
            OpenResult::NeedMore => {}
            OpenResult::Complete(_) => panic!("should need more after first fragment"),
        }
        // Feed last only (middle still missing) — still must not complete
        let last = crypto::deobfuscate_packet(frames[frames.len() - 1].clone());
        match ra.push(last, key).unwrap() {
            OpenResult::NeedMore => {}
            OpenResult::Complete(_) => panic!("must not complete with missing middle fragment"),
        }
    }

    #[test]
    fn empty_key_rejected_for_seal() {
        let pt = b"sensitive-data";
        let result = seal_for_wire(pt, &[], 4096);
        assert!(result.is_err(), "seal_for_wire must reject empty key");
    }

    #[test]
    fn empty_key_rejected_for_traffic_key() {
        let result = traffic_key(None, &[]);
        assert!(result.is_err(), "traffic_key must reject empty static key");
    }

    #[test]
    fn empty_key_rejected_for_open_wire_frame() {
        let result = open_wire_frame(vec![0u8; 16], &[]);
        assert!(result.is_err(), "open_wire_frame must reject empty key");
    }

    #[test]
    fn empty_key_rejected_for_reassembler_push() {
        let mut ra = FragReassembler::new();
        let result = ra.push(vec![0u8; 16], &[]);
        assert!(result.is_err(), "FragReassembler::push must reject empty key");
    }
}
