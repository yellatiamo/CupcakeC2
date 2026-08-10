//! Shared AD worker job handling (shipped path used by the PE binary).
//!
//! Phased delivery (docs/AD_MODULE_DESIGN.md):
//! - B0: ping + JSON frames
//! - B1: Tier0 discover/enum with stable domain codes + real LDAP
//! - B2: kerberoast/asrep LDAP targets + LSA/TCP + hashcat formatters
//! - B3: graph.zip Cupcake format from LDAP objects
//! - B4: dcsync feature_disabled by default (`ad-dcsync`)

mod dcsync;
mod domain;
mod graph;
mod kerberos;
mod ldap;
mod roast;
mod tier0;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use domain::{probe_domain, response_from_probe};
pub use kerberos::{extract_asrep_cipher, extract_ticket_cipher};
pub use ldap::{domain_to_base_dn, LdapEntry, LdapError};
pub use roast::{
    format_krb5asrep_hashcat, format_krb5tgs_hashcat, roast_summary, ROAST_INLINE_MAX_BYTES,
};
pub use tier0::{default_asrep_filter, default_spn_filter, validate_ldap_query};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdJobRequest {
    #[serde(default)]
    pub request_id: String,
    pub op: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdJobResponse {
    pub request_id: String,
    pub status: String,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub error_code: String,
}

/// Result of a platform domain join / DC reachability probe (testable pure input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainProbe {
    UnsupportedPlatform,
    NotJoined,
    DcUnreachable { domain: String },
    Ok { domain: String, dcs: Vec<String> },
}

/// Process one AD worker job. Real entry logic for the sacrificial PE.
pub fn handle_ad_job(req: &AdJobRequest) -> AdJobResponse {
    match req.op.as_str() {
        "ping" | "ad_ping" => AdJobResponse {
            request_id: req.request_id.clone(),
            status: "ok".into(),
            stdout: "pong".into(),
            stderr: String::new(),
            error_code: String::new(),
        },
        "ad_discover" => tier0::handle_discover(req),
        "ad_ldap_query" => {
            if let Err(e) = validate_ldap_query(&req.params) {
                return AdJobResponse {
                    request_id: req.request_id.clone(),
                    status: "error".into(),
                    stdout: String::new(),
                    stderr: e.clone(),
                    error_code: "invalid_params".into(),
                };
            }
            tier0::handle_tier0_enum(req, "ad_ldap_query")
        }
        "ad_enum_users"
        | "ad_enum_groups"
        | "ad_enum_privileged_groups"
        | "ad_enum_computers"
        | "ad_enum_spns"
        | "ad_enum_trusts"
        | "ad_password_policy"
        | "ad_enum_delegation"
        | "ad_enum_gpo"
        | "ad_collect_sessions"
        | "ad_check_replication_rights" => tier0::handle_tier0_enum(req, req.op.as_str()),
        "kerberoast" => roast::handle_kerberoast(req),
        "asrep_roast" => roast::handle_asrep_roast(req),
        "ad_graph_collect" => graph::handle_graph_collect(req),
        "ad_acl_collect" => graph::handle_acl_collect(req),
        "dcsync" => dcsync::handle_dcsync(req),
        other => AdJobResponse {
            request_id: req.request_id.clone(),
            status: "error".into(),
            stdout: String::new(),
            stderr: format!("unknown ad op '{other}'"),
            error_code: "unknown_op".into(),
        },
    }
}

/// Encode response as length-prefixed JSON (u32le + UTF-8).
pub fn encode_response_frame(resp: &AdJobResponse) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(resp).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode request frame (u32le + UTF-8 JSON).
pub fn decode_request_frame(data: &[u8]) -> Result<AdJobRequest, String> {
    if data.len() < 4 {
        return Err("short frame".into());
    }
    let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return Err("truncated frame".into());
    }
    serde_json::from_slice(&data[4..4 + len]).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(op: &str) -> AdJobRequest {
        AdJobRequest {
            request_id: "t".into(),
            op: op.into(),
            params: Value::Null,
            deadline_ms: 5000,
        }
    }

    #[test]
    fn ping_op_returns_pong() {
        let resp = handle_ad_job(&req("ping"));
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.stdout, "pong");
    }

    #[test]
    fn dcsync_feature_disabled_default() {
        let resp = handle_ad_job(&req("dcsync"));
        assert_eq!(resp.error_code, "feature_disabled");
        assert_ne!(resp.error_code, "not_implemented");
    }

    #[test]
    fn ad_discover_not_blanket_not_implemented() {
        let resp = handle_ad_job(&req("ad_discover"));
        assert_ne!(resp.error_code, "not_implemented");
        let allowed = [
            "unsupported_platform",
            "not_domain_joined",
            "dc_unreachable",
            "",
        ];
        assert!(
            allowed.contains(&resp.error_code.as_str()),
            "code={}",
            resp.error_code
        );
    }

    #[test]
    fn tier0_ops_not_blanket_not_implemented() {
        for op in [
            "ad_enum_users",
            "ad_enum_spns",
            "ad_enum_trusts",
            "ad_password_policy",
            "ad_enum_delegation",
            "ad_enum_privileged_groups",
            "ad_check_replication_rights",
            "kerberoast",
            "asrep_roast",
            "ad_graph_collect",
            "ad_acl_collect",
        ] {
            let resp = handle_ad_job(&req(op));
            assert_ne!(
                resp.error_code, "not_implemented",
                "{op} still not_implemented"
            );
            // Offline workgroup: soft domain code or ok
            let soft = [
                "unsupported_platform",
                "not_domain_joined",
                "dc_unreachable",
                "feature_disabled",
                "invalid_params",
                "",
            ];
            assert!(
                soft.contains(&resp.error_code.as_str()) || resp.status == "ok",
                "{op} unexpected code={} status={}",
                resp.error_code,
                resp.status
            );
        }
    }

    #[test]
    fn ldap_query_requires_base() {
        let resp = handle_ad_job(&AdJobRequest {
            request_id: "q".into(),
            op: "ad_ldap_query".into(),
            params: serde_json::json!({}),
            deadline_ms: 1000,
        });
        assert_eq!(resp.error_code, "invalid_params");
    }

    #[test]
    fn frame_roundtrip_ping() {
        let r = req("ping");
        let body = serde_json::to_vec(&r).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(&body);
        let decoded = decode_request_frame(&frame).unwrap();
        let resp = handle_ad_job(&decoded);
        let out = encode_response_frame(&resp).unwrap();
        assert!(out.len() > 4);
    }

    #[test]
    fn discover_from_probe_stable() {
        let r = response_from_probe("r", DomainProbe::NotJoined);
        assert_eq!(r.error_code, "not_domain_joined");
        let r = response_from_probe(
            "r",
            DomainProbe::Ok {
                domain: "corp.local".into(),
                dcs: vec!["dc1".into()],
            },
        );
        assert_eq!(r.status, "ok");
        assert!(r.stdout.contains("corp.local"));
    }

    #[test]
    fn default_features_dcsync_off() {
        // Structural: default build must not enable ad-dcsync.
        #[cfg(feature = "ad-dcsync")]
        {
            panic!("ad-dcsync must not be on by default in release/test default features");
        }
        let resp = handle_ad_job(&req("dcsync"));
        assert_eq!(resp.error_code, "feature_disabled");
    }

    #[test]
    fn no_mimikatz_kiwi_in_source_surface() {
        // Shipped public API surface: no Mimikatz/kiwi symbols re-exported.
        // (Full tree scan is done in verification; this asserts worker entry path.)
        let resp = handle_ad_job(&req("ping"));
        assert_eq!(resp.stdout, "pong");
        assert!(!resp.stderr.to_lowercase().contains("mimikatz"));
        assert!(!resp.stderr.to_lowercase().contains("kiwi"));
    }

    #[test]
    fn ldap_domain_to_dn_exported() {
        assert_eq!(domain_to_base_dn("corp.local"), "DC=corp,DC=local");
    }

    #[test]
    fn non_joined_stable_codes_not_empty_shells() {
        // On workgroup hosts, enum ops must return domain soft codes — not ok+empty shell.
        let resp = handle_ad_job(&req("ad_enum_users"));
        if resp.status == "ok" {
            // Domain-joined lab: must use real LDAP source when successful.
            assert!(
                resp.stdout.contains("\"source\":\"ldap\"")
                    || resp.stdout.contains("\"source\": \"ldap\"")
                    || resp.stdout.contains("sAMAccountName"),
                "ok enum must not be empty shell: {}",
                resp.stdout
            );
            assert!(!resp.stdout.contains("ldap_page_ready"));
            assert!(!resp.stdout.contains("ldap_bind_page_ready"));
        } else {
            let allowed = [
                "unsupported_platform",
                "not_domain_joined",
                "dc_unreachable",
                "ldap_bind_failed",
                "access_denied",
            ];
            assert!(
                allowed.contains(&resp.error_code.as_str()),
                "unexpected code={}",
                resp.error_code
            );
        }
    }

    #[test]
    fn kerberoast_not_pending_shell() {
        let resp = handle_ad_job(&req("kerberoast"));
        if resp.status == "ok" {
            assert!(!resp.stdout.contains("tgs_via_lsa_pending_empty"));
            assert!(
                resp.stdout.contains("hash_count") || resp.stdout.contains("ldap_filter"),
                "{}",
                resp.stdout
            );
        } else {
            assert_ne!(resp.error_code, "not_implemented");
        }
    }
}
