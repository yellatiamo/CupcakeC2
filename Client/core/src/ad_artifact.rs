//! Stage0-local AD artifact wipe (no L2 worker).
//!
//! Design: only files under the process temp directory whose names start with
//! `cpx_ad_` may be deleted. Path traversal and absolute paths outside temp
//! are rejected.

use std::path::{Component, Path, PathBuf};

/// Validate and delete an AD artifact path produced by the worker pipeline.
///
/// Allowed:
/// - Absolute or relative path that resolves under `std::env::temp_dir()`
/// - Final file name starts with `cpx_ad_`
///
/// Returns Ok(deleted_path_display) or Err(stable error string for stderr).
pub fn wipe_ad_artifact(path: &str) -> Result<String, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("invalid_params: empty path".into());
    }
    if path.contains('\0') {
        return Err("invalid_params: nul in path".into());
    }

    // Reject obvious traversal tokens before join
    let p = Path::new(path);
    for c in p.components() {
        if matches!(c, Component::ParentDir) {
            return Err("access_denied: path traversal".into());
        }
    }

    let candidate = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::temp_dir().join(p)
    };

    let temp = std::env::temp_dir();
    if !path_is_under_temp(&candidate, &temp) {
        return Err("access_denied: path outside temp".into());
    }

    let name = candidate
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if !name.starts_with("cpx_ad_") {
        return Err("access_denied: name must start with cpx_ad_".into());
    }

    if !candidate.exists() {
        // Idempotent wipe: missing file is success for pipeline cleanup
        return Ok(candidate.display().to_string());
    }
    if candidate.is_dir() {
        return Err("access_denied: refusing directory wipe".into());
    }

    std::fs::remove_file(&candidate).map_err(|e| format!("wipe_failed: {e}"))?;
    Ok(candidate.display().to_string())
}

fn path_is_under_temp(candidate: &Path, temp: &Path) -> bool {
    // Normalize by components without requiring the file to exist.
    let cand = normalize_lexically(candidate);
    let tmp = normalize_lexically(temp);
    cand.starts_with(&tmp)
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Normal(s) => out.push(s),
        }
    }
    out
}

/// Extract wipe path from command content JSON or bare string.
pub fn parse_wipe_path(command_content: &str, path_field: Option<&str>) -> Result<String, String> {
    if let Some(p) = path_field.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(p.to_string());
    }
    let content = command_content.trim();
    if content.is_empty() {
        return Err("invalid_params: missing path".into());
    }
    if content.starts_with('{') {
        let v: serde_json::Value =
            serde_json::from_str(content).map_err(|e| format!("invalid_params: {e}"))?;
        if let Some(p) = v.get("path").and_then(|x| x.as_str()) {
            if !p.is_empty() {
                return Ok(p.to_string());
            }
        }
        return Err("invalid_params: missing path".into());
    }
    Ok(content.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rejects_parent_traversal() {
        let err = wipe_ad_artifact("../cpx_ad_x.out").unwrap_err();
        assert!(err.contains("traversal") || err.contains("outside"), "{err}");
    }

    #[test]
    fn rejects_wrong_prefix() {
        let temp = std::env::temp_dir();
        let p = temp.join("not_allowed.txt");
        let err = wipe_ad_artifact(p.to_str().unwrap()).unwrap_err();
        assert!(err.contains("cpx_ad_"), "{err}");
    }

    #[test]
    fn accepts_and_deletes_cpx_ad_under_temp() {
        let temp = std::env::temp_dir();
        let p = temp.join(format!(
            "cpx_ad_test_{}.out",
            std::process::id()
        ));
        {
            let mut f = std::fs::File::create(&p).unwrap();
            f.write_all(b"secret-hash-line").unwrap();
        }
        assert!(p.exists());
        let ok = wipe_ad_artifact(p.to_str().unwrap()).unwrap();
        assert!(ok.contains("cpx_ad_"));
        assert!(!p.exists());
        // second wipe is idempotent
        let _ = wipe_ad_artifact(p.to_str().unwrap()).unwrap();
    }

    #[test]
    fn parse_path_from_json_and_field() {
        assert_eq!(
            parse_wipe_path(r#"{"path":"cpx_ad_1.out"}"#, None).unwrap(),
            "cpx_ad_1.out"
        );
        assert_eq!(
            parse_wipe_path("{}", Some("cpx_ad_2.out")).unwrap(),
            "cpx_ad_2.out"
        );
        assert!(parse_wipe_path("{}", None).unwrap_err().contains("missing"));
    }
}
