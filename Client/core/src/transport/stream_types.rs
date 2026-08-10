//! Yamux first-byte stream type tags (agent ↔ server).
//!
//! These are **not** HTTP malleable profiles (`profile.rs`) and **not** SOCKS5
//! wire protocol bytes. Only the single type byte written/read after
//! `yamux::Session::Open` / `next_stream`.
//!
//! Keep numeric values identical to `server/pkg/utils/stream_types.go`.
//!
//! Binary file transfer: Yamux **FILE (0x0E)** — put/get with chunked raw bytes
//! (see `crate::file_stream`). FS (0x03) remains list/read/rm JSON control.

/// Interactive PTY / hybrid shell stream.
pub const YAMUX_STREAM_PTY: u8 = 0x01;
/// SOCKS / general tunnel data plane stream.
pub const YAMUX_STREAM_SOCKS: u8 = 0x02;
/// File manager stream (list / read / rm JSON).
pub const YAMUX_STREAM_FS: u8 = 0x03;
/// Process list / kill stream.
pub const YAMUX_STREAM_PROCESS: u8 = 0x04;
/// Binary file transfer stream (put/get; not PROCESS 0x04).
pub const YAMUX_STREAM_FILE: u8 = 0x0E;
/// Reserved — reject / future extension; do not assign product streams.
pub const YAMUX_STREAM_RESERVED: u8 = 0xFF;

/// Canonical table for tests / parity scripts (name, value).
pub const YAMUX_STREAM_TYPE_TABLE: &[(&str, u8)] = &[
    ("PTY", YAMUX_STREAM_PTY),
    ("SOCKS", YAMUX_STREAM_SOCKS),
    ("FS", YAMUX_STREAM_FS),
    ("PROCESS", YAMUX_STREAM_PROCESS),
    ("FILE", YAMUX_STREAM_FILE),
    ("RESERVED", YAMUX_STREAM_RESERVED),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_yamux_stream_type_values() {
        assert_eq!(YAMUX_STREAM_PTY, 0x01);
        assert_eq!(YAMUX_STREAM_SOCKS, 0x02);
        assert_eq!(YAMUX_STREAM_FS, 0x03);
        assert_eq!(YAMUX_STREAM_PROCESS, 0x04);
        assert_eq!(YAMUX_STREAM_FILE, 0x0E);
        assert_eq!(YAMUX_STREAM_RESERVED, 0xFF);
    }

    #[test]
    fn table_matches_named_constants() {
        let mut map = std::collections::HashMap::new();
        for &(n, v) in YAMUX_STREAM_TYPE_TABLE {
            map.insert(n, v);
        }
        assert_eq!(map["PTY"], YAMUX_STREAM_PTY);
        assert_eq!(map["SOCKS"], YAMUX_STREAM_SOCKS);
        assert_eq!(map["FS"], YAMUX_STREAM_FS);
        assert_eq!(map["PROCESS"], YAMUX_STREAM_PROCESS);
        assert_eq!(map["FILE"], YAMUX_STREAM_FILE);
        assert_eq!(map["RESERVED"], YAMUX_STREAM_RESERVED);
    }
}
