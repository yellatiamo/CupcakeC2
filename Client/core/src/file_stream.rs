//! Yamux **FILE (0x0E)** binary transfer stream (agent half).
//!
//! # Wire protocol (must match server)
//!
//! Server opens a Yamux stream and writes type byte `0x0E` first. The agent
//! dispatcher consumes that byte, then hands the stream to [`handle_stream`].
//!
//! ## Request (server → agent)
//! ```text
//! op:        u8      // 1 = put/upload, 2 = get/download
//! path_len:  u16 BE
//! path:      [path_len] UTF-8
//! ```
//!
//! ## Put body (server → agent)
//! ```text
//! repeat:
//!   chunk_len: u32 BE   // 0 = end of file
//!   chunk:     [chunk_len] raw bytes
//! ```
//! Agent writes to `path + ".part"`, renames to `path` on chunk_len=0.
//!
//! ## Put response (agent → server)
//! ```text
//! status:   u8      // 0 = ok, 1 = error
//! written:  u64 BE  // bytes written
//! msg_len:  u16 BE
//! msg:      [msg_len] UTF-8
//! ```
//!
//! ## Get response (agent → server)
//! ```text
//! status:   u8
//! if status != 0:
//!   msg_len: u16 BE + msg
//! if status == 0:
//!   size: u64 BE
//!   then exactly `size` raw file bytes
//! ```
//!
//! FS stream **0x03** still handles list / read / rm (JSON). Product control-plane
//! `file_upload_chunk` is deprecated in favor of this stream.

use log::{error, info, warn};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use yamux::Stream;

/// Put / upload.
pub const OP_PUT: u8 = 1;
/// Get / download.
pub const OP_GET: u8 = 2;

/// Success status.
pub const STATUS_OK: u8 = 0;
/// Error status.
pub const STATUS_ERR: u8 = 1;

const PART_SUFFIX: &str = crate::wire_ids::STAGING_FILE_SUFFIX;
/// Reject single chunks larger than this (DoS / OOM guard).
const MAX_CHUNK: u32 = 16 * 1024 * 1024;
/// Max path length (matches u16, with a practical cap).
const MAX_PATH_LEN: u16 = 4096;

// ── Framing (pure; unit-tested) ─────────────────────────────────────────────

/// Encode request header: `op | path_len BE | path`.
pub fn encode_request_header(op: u8, path: &str) -> Result<Vec<u8>, String> {
    let path_bytes = path.as_bytes();
    if path_bytes.len() > u16::MAX as usize {
        return Err("path too long".into());
    }
    let path_len = path_bytes.len() as u16;
    let mut out = Vec::with_capacity(1 + 2 + path_bytes.len());
    out.push(op);
    out.extend_from_slice(&path_len.to_be_bytes());
    out.extend_from_slice(path_bytes);
    Ok(out)
}

/// Decode request header from a full buffer.
///
/// Returns `(op, path, bytes_consumed)`.
pub fn decode_request_header(buf: &[u8]) -> Result<(u8, String, usize), String> {
    if buf.len() < 3 {
        return Err("request header too short".into());
    }
    let op = buf[0];
    let path_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    if path_len > MAX_PATH_LEN as usize {
        return Err(format!("path_len {} exceeds max {}", path_len, MAX_PATH_LEN));
    }
    let need = 3 + path_len;
    if buf.len() < need {
        return Err("request header incomplete".into());
    }
    let path = std::str::from_utf8(&buf[3..need])
        .map_err(|e| format!("path not utf-8: {}", e))?
        .to_string();
    Ok((op, path, need))
}

/// Encode put chunk length prefix (u32 BE). `0` means end-of-file.
pub fn encode_chunk_len(len: u32) -> [u8; 4] {
    len.to_be_bytes()
}

/// Decode put chunk length from 4 bytes.
pub fn decode_chunk_len(buf: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*buf)
}

/// Encode put response: `status | written BE | msg_len BE | msg`.
pub fn encode_put_response(status: u8, written: u64, msg: &str) -> Result<Vec<u8>, String> {
    let msg_bytes = msg.as_bytes();
    if msg_bytes.len() > u16::MAX as usize {
        return Err("msg too long".into());
    }
    let msg_len = msg_bytes.len() as u16;
    let mut out = Vec::with_capacity(1 + 8 + 2 + msg_bytes.len());
    out.push(status);
    out.extend_from_slice(&written.to_be_bytes());
    out.extend_from_slice(&msg_len.to_be_bytes());
    out.extend_from_slice(msg_bytes);
    Ok(out)
}

/// Decode put response. Returns `(status, written, msg)`.
pub fn decode_put_response(buf: &[u8]) -> Result<(u8, u64, String), String> {
    if buf.len() < 1 + 8 + 2 {
        return Err("put response too short".into());
    }
    let status = buf[0];
    let written = u64::from_be_bytes(buf[1..9].try_into().unwrap());
    let msg_len = u16::from_be_bytes([buf[9], buf[10]]) as usize;
    let need = 11 + msg_len;
    if buf.len() < need {
        return Err("put response msg incomplete".into());
    }
    let msg = std::str::from_utf8(&buf[11..need])
        .map_err(|e| format!("msg not utf-8: {}", e))?
        .to_string();
    Ok((status, written, msg))
}

/// Encode get error response: `status(!=0) | msg_len BE | msg`.
pub fn encode_get_error(msg: &str) -> Result<Vec<u8>, String> {
    let msg_bytes = msg.as_bytes();
    if msg_bytes.len() > u16::MAX as usize {
        return Err("msg too long".into());
    }
    let msg_len = msg_bytes.len() as u16;
    let mut out = Vec::with_capacity(1 + 2 + msg_bytes.len());
    out.push(STATUS_ERR);
    out.extend_from_slice(&msg_len.to_be_bytes());
    out.extend_from_slice(msg_bytes);
    Ok(out)
}

/// Encode get success header: `status(0) | size BE` (file body follows separately).
pub fn encode_get_ok_header(size: u64) -> [u8; 9] {
    let mut out = [0u8; 9];
    out[0] = STATUS_OK;
    out[1..9].copy_from_slice(&size.to_be_bytes());
    out
}

/// Decode get response status byte and branch.
///
/// On error (`status != 0`): expects `msg_len + msg` after status → `(status, None, Some(msg))`.
/// On ok: expects `size` after status → `(0, Some(size), None)`.
/// `buf` is the full response without file body.
pub fn decode_get_response_header(buf: &[u8]) -> Result<(u8, Option<u64>, Option<String>), String> {
    if buf.is_empty() {
        return Err("get response empty".into());
    }
    let status = buf[0];
    if status != STATUS_OK {
        if buf.len() < 3 {
            return Err("get error response too short".into());
        }
        let msg_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let need = 3 + msg_len;
        if buf.len() < need {
            return Err("get error msg incomplete".into());
        }
        let msg = std::str::from_utf8(&buf[3..need])
            .map_err(|e| format!("msg not utf-8: {}", e))?
            .to_string();
        return Ok((status, None, Some(msg)));
    }
    if buf.len() < 9 {
        return Err("get ok header too short".into());
    }
    let size = u64::from_be_bytes(buf[1..9].try_into().unwrap());
    Ok((STATUS_OK, Some(size), None))
}

// ── Async I/O helpers ───────────────────────────────────────────────────────

async fn read_exact_n<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    n: usize,
) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn read_request_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(u8, String), String> {
    let mut fixed = [0u8; 3];
    reader
        .read_exact(&mut fixed)
        .await
        .map_err(|e| format!("read request header: {}", e))?;
    let op = fixed[0];
    let path_len = u16::from_be_bytes([fixed[1], fixed[2]]);
    if path_len > MAX_PATH_LEN {
        return Err(format!("path_len {} exceeds max {}", path_len, MAX_PATH_LEN));
    }
    let path_bytes = read_exact_n(reader, path_len as usize)
        .await
        .map_err(|e| format!("read path: {}", e))?;
    let path = String::from_utf8(path_bytes).map_err(|e| format!("path not utf-8: {}", e))?;
    // Validate by re-parsing through production decoder (keeps encode/decode in lockstep).
    let mut check = Vec::with_capacity(3 + path.len());
    check.push(op);
    check.extend_from_slice(&path_len.to_be_bytes());
    check.extend_from_slice(path.as_bytes());
    let (op2, path2, _) = decode_request_header(&check)?;
    debug_assert_eq!(op, op2);
    Ok((op2, path2))
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("path is empty".into());
    }
    if path.contains('\0') {
        return Err("path contains NUL".into());
    }
    Ok(())
}

fn staging_path(final_path: &str) -> String {
    format!("{final_path}{PART_SUFFIX}")
}

fn ensure_parent_dirs(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| format!("create_dir_all: {}", e))?;
        }
    }
    Ok(())
}

fn commit_part_to_final(part: &str, final_path: &str) -> Result<(), String> {
    if Path::new(final_path).exists() {
        let _ = fs::remove_file(final_path);
    }
    fs::rename(part, final_path).map_err(|e| format!("rename part→final: {}", e))
}

// ── Stream handler ──────────────────────────────────────────────────────────

/// Handle an inbound FILE (0x0E) Yamux stream (type byte already consumed).
pub async fn handle_stream(stream: Stream) {
    info!("[FILE] binary transfer stream start");
    let (mut reader, mut writer) = tokio::io::split(stream.compat());

    let (op, path) = match read_request_header(&mut reader).await {
        Ok(v) => v,
        Err(e) => {
            error!("[FILE] bad request header: {}", e);
            // Best-effort put-style error if we can still write
            if let Ok(resp) = encode_put_response(STATUS_ERR, 0, &e) {
                let _ = writer.write_all(&resp).await;
                let _ = writer.flush().await;
            }
            let _ = writer.shutdown().await;
            return;
        }
    };

    if let Err(e) = validate_path(&path) {
        warn!("[FILE] invalid path: {}", e);
        write_op_error(&mut writer, op, &e).await;
        return;
    }

    match op {
        OP_PUT => handle_put(&mut reader, &mut writer, &path).await,
        OP_GET => handle_get(&mut writer, &path).await,
        other => {
            let msg = format!("unknown FILE op: {}", other);
            warn!("[FILE] {}", msg);
            write_op_error(&mut writer, other, &msg).await;
        }
    }
}

async fn write_op_error<W: AsyncWriteExt + Unpin>(writer: &mut W, op: u8, msg: &str) {
    let bytes = if op == OP_GET {
        encode_get_error(msg).unwrap_or_else(|_| vec![STATUS_ERR, 0, 0])
    } else {
        encode_put_response(STATUS_ERR, 0, msg).unwrap_or_else(|_| {
            let mut v = vec![STATUS_ERR];
            v.extend_from_slice(&0u64.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v
        })
    };
    let _ = writer.write_all(&bytes).await;
    let _ = writer.flush().await;
    let _ = writer.shutdown().await;
}

async fn handle_put<R, W>(reader: &mut R, writer: &mut W, path: &str)
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    info!("[FILE] put → {}", path);
    if let Err(e) = ensure_parent_dirs(path) {
        write_put_response(writer, STATUS_ERR, 0, &e).await;
        return;
    }
    let part = staging_path(path);
    if let Err(e) = ensure_parent_dirs(&part) {
        write_put_response(writer, STATUS_ERR, 0, &e).await;
        return;
    }

    let mut file = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&part)
    {
        Ok(f) => f,
        Err(e) => {
            write_put_response(writer, STATUS_ERR, 0, &format!("open part: {}", e)).await;
            return;
        }
    };

    let mut written: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut len_buf).await {
            drop(file); // Windows: must close handle before remove_file
            let _ = fs::remove_file(&part);
            write_put_response(writer, STATUS_ERR, written, &format!("read chunk_len: {}", e))
                .await;
            return;
        }
        let chunk_len = decode_chunk_len(&len_buf);
        if chunk_len == 0 {
            break;
        }
        if chunk_len > MAX_CHUNK {
            drop(file); // Windows: must close handle before remove_file
            let _ = fs::remove_file(&part);
            write_put_response(
                writer,
                STATUS_ERR,
                written,
                &format!("chunk_len {} exceeds max {}", chunk_len, MAX_CHUNK),
            )
            .await;
            return;
        }
        let chunk = match read_exact_n(reader, chunk_len as usize).await {
            Ok(c) => c,
            Err(e) => {
                drop(file); // Windows: must close handle before remove_file
                let _ = fs::remove_file(&part);
                write_put_response(writer, STATUS_ERR, written, &format!("read chunk: {}", e))
                    .await;
                return;
            }
        };
        if let Err(e) = file.write_all(&chunk) {
            drop(file); // Windows: must close handle before remove_file
            let _ = fs::remove_file(&part);
            write_put_response(writer, STATUS_ERR, written, &format!("write: {}", e)).await;
            return;
        }
        written = written.saturating_add(chunk.len() as u64);
    }

    if let Err(e) = file.flush() {
        drop(file); // Windows: must close handle before remove_file
        let _ = fs::remove_file(&part);
        write_put_response(writer, STATUS_ERR, written, &format!("flush: {}", e)).await;
        return;
    }
    drop(file);

    if let Err(e) = commit_part_to_final(&part, path) {
        let _ = fs::remove_file(&part);
        write_put_response(writer, STATUS_ERR, written, &e).await;
        return;
    }

    info!("[FILE] put ok {} ({} bytes)", path, written);
    write_put_response(writer, STATUS_OK, written, "").await;
}

async fn write_put_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    status: u8,
    written: u64,
    msg: &str,
) {
    match encode_put_response(status, written, msg) {
        Ok(bytes) => {
            let _ = writer.write_all(&bytes).await;
            let _ = writer.flush().await;
            let _ = writer.shutdown().await;
        }
        Err(e) => {
            error!("[FILE] encode put response: {}", e);
            let _ = writer.shutdown().await;
        }
    }
}

async fn handle_get<W: AsyncWriteExt + Unpin>(writer: &mut W, path: &str) {
    info!("[FILE] get ← {}", path);
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        write_get_error(writer, &format!("file not found: {}", path)).await;
        return;
    }
    if !path_obj.is_file() {
        write_get_error(writer, &format!("not a file: {}", path)).await;
        return;
    }

    let mut file = match File::open(path_obj) {
        Ok(f) => f,
        Err(e) => {
            write_get_error(writer, &format!("open: {}", e)).await;
            return;
        }
    };
    let size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            write_get_error(writer, &format!("metadata: {}", e)).await;
            return;
        }
    };

    let header = encode_get_ok_header(size);
    if writer.write_all(&header).await.is_err() {
        return;
    }

    const READ_CHUNK: usize = 512 * 1024;
    let mut buf = vec![0u8; READ_CHUNK];
    let mut sent: u64 = 0;
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                error!("[FILE] get read err: {}", e);
                let _ = writer.shutdown().await;
                return;
            }
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            return;
        }
        if writer.flush().await.is_err() {
            return;
        }
        sent = sent.saturating_add(n as u64);
    }

    if sent != size {
        warn!(
            "[FILE] get size mismatch declared={} sent={} path={}",
            size, sent, path
        );
    }
    let _ = writer.shutdown().await;
    info!("[FILE] get ok {} ({} bytes)", path, sent);
}

async fn write_get_error<W: AsyncWriteExt + Unpin>(writer: &mut W, msg: &str) {
    match encode_get_error(msg) {
        Ok(bytes) => {
            let _ = writer.write_all(&bytes).await;
            let _ = writer.flush().await;
            let _ = writer.shutdown().await;
        }
        Err(e) => {
            error!("[FILE] encode get error: {}", e);
            let _ = writer.shutdown().await;
        }
    }
}

// ── Unit tests (real framing functions) ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_header_roundtrip_put() {
        let enc = encode_request_header(OP_PUT, r"C:\tmp\payload.bin").unwrap();
        let (op, path, n) = decode_request_header(&enc).unwrap();
        assert_eq!(op, OP_PUT);
        assert_eq!(path, r"C:\tmp\payload.bin");
        assert_eq!(n, enc.len());
    }

    #[test]
    fn request_header_roundtrip_get_utf8() {
        let enc = encode_request_header(OP_GET, "/tmp/测试.bin").unwrap();
        let (op, path, n) = decode_request_header(&enc).unwrap();
        assert_eq!(op, OP_GET);
        assert_eq!(path, "/tmp/测试.bin");
        assert_eq!(n, enc.len());
        // op + u16 + utf8
        assert_eq!(enc[0], OP_GET);
        let plen = u16::from_be_bytes([enc[1], enc[2]]) as usize;
        assert_eq!(plen, "/tmp/测试.bin".len());
    }

    #[test]
    fn request_header_incomplete() {
        assert!(decode_request_header(&[OP_PUT, 0x00]).is_err());
        // claims path_len=5 but only 2 path bytes
        assert!(decode_request_header(&[OP_PUT, 0x00, 0x05, b'a', b'b']).is_err());
    }

    #[test]
    fn chunk_len_roundtrip() {
        for &len in &[0u32, 1, 512, 1024 * 1024, u32::MAX] {
            let b = encode_chunk_len(len);
            assert_eq!(decode_chunk_len(&b), len);
        }
        // wire: big-endian
        assert_eq!(encode_chunk_len(0x0102_0304), [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(decode_chunk_len(&[0x00, 0x00, 0x00, 0x00]), 0);
    }

    #[test]
    fn put_response_ok_roundtrip() {
        let enc = encode_put_response(STATUS_OK, 12345, "").unwrap();
        let (st, written, msg) = decode_put_response(&enc).unwrap();
        assert_eq!(st, STATUS_OK);
        assert_eq!(written, 12345);
        assert_eq!(msg, "");
        assert_eq!(enc[0], STATUS_OK);
        assert_eq!(&enc[1..9], &12345u64.to_be_bytes());
        assert_eq!(&enc[9..11], &0u16.to_be_bytes());
    }

    #[test]
    fn put_response_err_roundtrip() {
        let enc = encode_put_response(STATUS_ERR, 0, "disk full").unwrap();
        let (st, written, msg) = decode_put_response(&enc).unwrap();
        assert_eq!(st, STATUS_ERR);
        assert_eq!(written, 0);
        assert_eq!(msg, "disk full");
        let msg_len = u16::from_be_bytes([enc[9], enc[10]]) as usize;
        assert_eq!(msg_len, "disk full".len());
        assert_eq!(&enc[11..], b"disk full");
    }

    #[test]
    fn put_response_too_short() {
        assert!(decode_put_response(&[STATUS_OK]).is_err());
        assert!(decode_put_response(&[STATUS_OK; 10]).is_err());
    }

    #[test]
    fn get_ok_header_and_decode() {
        let hdr = encode_get_ok_header(0x1122_3344_5566_7788);
        assert_eq!(hdr[0], STATUS_OK);
        assert_eq!(&hdr[1..], &0x1122_3344_5566_7788u64.to_be_bytes());
        let (st, size, msg) = decode_get_response_header(&hdr).unwrap();
        assert_eq!(st, STATUS_OK);
        assert_eq!(size, Some(0x1122_3344_5566_7788));
        assert!(msg.is_none());
    }

    #[test]
    fn get_error_roundtrip() {
        let enc = encode_get_error("permission denied").unwrap();
        assert_eq!(enc[0], STATUS_ERR);
        let (st, size, msg) = decode_get_response_header(&enc).unwrap();
        assert_eq!(st, STATUS_ERR);
        assert!(size.is_none());
        assert_eq!(msg.as_deref(), Some("permission denied"));
    }

    #[test]
    fn get_header_incomplete() {
        assert!(decode_get_response_header(&[]).is_err());
        assert!(decode_get_response_header(&[STATUS_OK, 0, 0]).is_err());
        assert!(decode_get_response_header(&[STATUS_ERR, 0x00, 0x05, b'a']).is_err());
    }

    #[test]
    fn op_and_status_constants() {
        assert_eq!(OP_PUT, 1);
        assert_eq!(OP_GET, 2);
        assert_eq!(STATUS_OK, 0);
        assert_eq!(STATUS_ERR, 1);
    }

    #[test]
    fn staging_suffix() {
        let p = staging_path("/tmp/a.bin");
        assert!(p.starts_with("/tmp/a.bin."));
        assert!(p.ends_with(".part"));
        // Must not use the old fixed brand suffix
        assert!(!p.ends_with(".part"));
    }
}
