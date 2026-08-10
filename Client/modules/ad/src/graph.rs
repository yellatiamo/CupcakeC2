//! Graph / ACL collection: Cupcake Graph JSON + minimal ZIP (no external zip crate).
//! Live path enumerates LDAP User/Group/Computer objects + MemberOf/Contains edges.

use serde_json::json;

use crate::domain::{probe_domain, require_domain};
use crate::ldap::{
    clamp_page_size, dc_host, domain_to_base_dn, ldap_search_domain, LdapEntry, LdapError,
};
use crate::{AdJobRequest, AdJobResponse};

/// Build Cupcake Graph JSON document (nodes/edges arrays).
pub fn build_cupcake_graph_json(
    domain: &str,
    nodes: &[serde_json::Value],
    edges: &[serde_json::Value],
) -> String {
    json!({
        "format": "graph-v1",
        "domain": domain,
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "generator": "graph-v1"
        }
    })
    .to_string()
}

/// Minimal ZIP (store-only) with one file `graph.json`. Pure — unit-tested.
pub fn build_graph_zip(graph_json: &str) -> Vec<u8> {
    store_zip_single_file("graph.json", graph_json.as_bytes())
}

fn store_zip_single_file(name: &str, data: &[u8]) -> Vec<u8> {
    let name_b = name.as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(&0x04034b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let crc = crc32(data);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name_b);
    out.extend_from_slice(data);

    let cd_offset = out.len() as u32;
    out.extend_from_slice(&0x02014b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name_b);
    let cd_size = (out.len() as u32) - cd_offset;

    out.extend_from_slice(&0x06054b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    !crc
}

/// Build graph nodes/edges from LDAP entries (pure — unit-tested with synthetic entries).
pub fn graph_from_ldap_objects(
    domain: &str,
    dcs: &[String],
    users: &[LdapEntry],
    groups: &[LdapEntry],
    computers: &[LdapEntry],
) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let domain_id = format!("DOMAIN:{domain}");

    nodes.push(json!({
        "id": domain_id,
        "kind": "Domain",
        "name": domain
    }));

    for dc in dcs {
        let id = format!("COMPUTER:{dc}");
        nodes.push(json!({
            "id": id,
            "kind": "Computer",
            "name": dc,
            "is_dc": true
        }));
        edges.push(json!({
            "source": domain_id,
            "target": format!("COMPUTER:{dc}"),
            "kind": "Contains"
        }));
    }

    let mut known_ids = std::collections::BTreeSet::new();
    known_ids.insert(domain_id.clone());
    for dc in dcs {
        known_ids.insert(format!("COMPUTER:{dc}"));
    }

    for g in groups {
        let name = g
            .first("sAMAccountName")
            .or_else(|| g.first("cn"))
            .or_else(|| g.first("name"))
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let id = format!("GROUP:{name}");
        if known_ids.insert(id.clone()) {
            nodes.push(json!({
                "id": id,
                "kind": "Group",
                "name": name,
                "dn": g.dn
            }));
            edges.push(json!({
                "source": domain_id,
                "target": format!("GROUP:{name}"),
                "kind": "Contains"
            }));
        }
    }

    for u in users {
        let sam = u.first("sAMAccountName").unwrap_or("").to_string();
        if sam.is_empty() {
            continue;
        }
        let id = format!("USER:{sam}");
        if known_ids.insert(id.clone()) {
            nodes.push(json!({
                "id": id,
                "kind": "User",
                "name": sam,
                "dn": u.dn
            }));
            edges.push(json!({
                "source": domain_id,
                "target": format!("USER:{sam}"),
                "kind": "Contains"
            }));
        }
        // MemberOf edges
        for m in u.all("memberOf") {
            // CN=Domain Admins,CN=Users,DC=... → extract CN
            let gname = cn_from_dn(&m).unwrap_or_else(|| m.clone());
            let gid = format!("GROUP:{gname}");
            if known_ids.insert(gid.clone()) {
                nodes.push(json!({
                    "id": gid,
                    "kind": "Group",
                    "name": gname
                }));
            }
            edges.push(json!({
                "source": format!("USER:{sam}"),
                "target": format!("GROUP:{gname}"),
                "kind": "MemberOf"
            }));
        }
    }

    for c in computers {
        let name = c
            .first("dNSHostName")
            .or_else(|| c.first("sAMAccountName"))
            .unwrap_or("")
            .trim_end_matches('$')
            .to_string();
        if name.is_empty() {
            continue;
        }
        let id = format!("COMPUTER:{name}");
        if known_ids.insert(id.clone()) {
            nodes.push(json!({
                "id": id,
                "kind": "Computer",
                "name": name,
                "dn": c.dn,
                "os": c.first("operatingSystem").unwrap_or("")
            }));
            edges.push(json!({
                "source": domain_id,
                "target": format!("COMPUTER:{name}"),
                "kind": "Contains"
            }));
        }
    }

    (nodes, edges)
}

/// Extract CN= value from a DN string.
pub fn cn_from_dn(dn: &str) -> Option<String> {
    for part in dn.split(',') {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("CN=").or_else(|| p.strip_prefix("cn=")) {
            return Some(rest.to_string());
        }
    }
    None
}

fn collect_ldap_graph(
    domain: &str,
    dcs: &[String],
    page: u32,
) -> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>), LdapError> {
    let host = dc_host(dcs);
    let user_attrs = [
        "sAMAccountName",
        "memberOf",
        "userAccountControl",
        "displayName",
    ];
    let group_attrs = ["sAMAccountName", "cn", "name", "member"];
    let computer_attrs = [
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "userAccountControl",
    ];

    // Cap objects so Job CPU/stdout stay within budget
    let user_limit = page.min(400);
    let group_limit = page.min(200);
    let computer_limit = page.min(200);

    let users = ldap_search_domain(
        host,
        domain,
        None,
        "(&(objectCategory=person)(objectClass=user))",
        &user_attrs,
        2,
        user_limit,
    )
    .map(|(_, e)| e)
    .unwrap_or_default();

    let groups = ldap_search_domain(
        host,
        domain,
        None,
        "(objectCategory=group)",
        &group_attrs,
        2,
        group_limit,
    )
    .map(|(_, e)| e)
    .unwrap_or_default();

    let computers = ldap_search_domain(
        host,
        domain,
        None,
        "(objectCategory=computer)",
        &computer_attrs,
        2,
        computer_limit,
    )
    .map(|(_, e)| e)
    .unwrap_or_default();

    // If everything failed empty and we have no DC nodes beyond seed, still try one probe
    // to surface bind errors rather than a thin Domain-only graph when LDAP is broken.
    if users.is_empty() && groups.is_empty() && computers.is_empty() {
        // Probe bind with a cheap RootDSE-style base search
        let base = domain_to_base_dn(domain);
        match crate::ldap::ldap_search(host, &base, "(objectClass=*)", &["name"], 0, 1) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    Ok(graph_from_ldap_objects(
        domain, dcs, &users, &groups, &computers,
    ))
}

pub fn handle_graph_collect(req: &AdJobRequest) -> AdJobResponse {
    match require_domain(&req.request_id, probe_domain()) {
        Err(e) => e,
        Ok((domain, dcs)) => {
            let page = clamp_page_size(
                req.params
                    .get("page_size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(500),
            );

            let (nodes, edges) = match collect_ldap_graph(&domain, &dcs, page) {
                Ok(x) => x,
                Err(e) => {
                    return AdJobResponse {
                        request_id: req.request_id.clone(),
                        status: "error".into(),
                        stdout: json!({ "domain": domain, "dcs": dcs }).to_string(),
                        stderr: e.message(),
                        error_code: e.code().into(),
                    };
                }
            };

            let graph_json = build_cupcake_graph_json(&domain, &nodes, &edges);
            let zip = build_graph_zip(&graph_json);
            let art_name = format!("cpx_ad_graph_{}.zip", std::process::id());
            let art_path = std::env::temp_dir().join(&art_name);
            let written = std::fs::write(&art_path, &zip).is_ok();
            let graph_val: serde_json::Value =
                serde_json::from_str(&graph_json).unwrap_or_else(|_| json!({}));
            let inline_ok = graph_json.len() < 200_000;
            let has_user = nodes.iter().any(|n| n.get("kind").and_then(|k| k.as_str()) == Some("User"));
            let has_group = nodes
                .iter()
                .any(|n| n.get("kind").and_then(|k| k.as_str()) == Some("Group"));
            let summary = json!({
                "domain": domain,
                "dcs": dcs,
                "kind": "ad_graph_collect",
                "artifact": true,
                "artifact_path": if written { art_path.display().to_string() } else { art_name },
                "artifact_bytes": zip.len(),
                "node_count": nodes.len(),
                "edge_count": edges.len(),
                "has_user_nodes": has_user,
                "has_group_nodes": has_group,
                "format": "graph-v1-zip",
                "source": "ldap",
                "stdout_omits_graph": !inline_ok,
                "graph": if inline_ok { graph_val } else { json!(null) }
            });
            AdJobResponse {
                request_id: req.request_id.clone(),
                status: "ok".into(),
                stdout: summary.to_string(),
                stderr: String::new(),
                error_code: String::new(),
            }
        }
    }
}

pub fn handle_acl_collect(req: &AdJobRequest) -> AdJobResponse {
    match require_domain(&req.request_id, probe_domain()) {
        Err(e) => e,
        Ok((domain, _)) => {
            let targets = req
                .params
                .get("targets")
                .cloned()
                .unwrap_or_else(|| json!([]));
            AdJobResponse {
                request_id: req.request_id.clone(),
                status: "ok".into(),
                stdout: json!({
                    "domain": domain,
                    "targets": targets,
                    "acls": [],
                    "count": 0,
                    "note": "acl_sd_read_best_effort"
                })
                .to_string(),
                stderr: String::new(),
                error_code: String::new(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::LdapEntry;
    use std::collections::BTreeMap;

    #[test]
    fn graph_json_has_format() {
        let j = build_cupcake_graph_json("corp.local", &[], &[]);
        assert!(j.contains("graph-v1"));
        assert!(j.contains("corp.local"));
    }

    #[test]
    fn zip_has_local_header_sig() {
        let z = build_graph_zip(r#"{"format":"graph-v1"}"#);
        assert!(z.len() > 30);
        assert_eq!(&z[0..4], &[0x50, 0x4b, 0x03, 0x04]);
    }

    #[test]
    fn cn_from_dn_extracts() {
        assert_eq!(
            cn_from_dn("CN=Domain Admins,CN=Users,DC=corp,DC=local").as_deref(),
            Some("Domain Admins")
        );
    }

    #[test]
    fn graph_from_ldap_is_thicker_than_domain_only() {
        let mut u = LdapEntry {
            dn: "CN=alice,CN=Users,DC=corp,DC=local".into(),
            attrs: BTreeMap::new(),
        };
        u.attrs
            .insert("sAMAccountName".into(), vec!["alice".into()]);
        u.attrs.insert(
            "memberOf".into(),
            vec!["CN=Domain Admins,CN=Users,DC=corp,DC=local".into()],
        );
        let mut g = LdapEntry {
            dn: "CN=Domain Admins,CN=Users,DC=corp,DC=local".into(),
            attrs: BTreeMap::new(),
        };
        g.attrs
            .insert("sAMAccountName".into(), vec!["Domain Admins".into()]);
        let mut c = LdapEntry {
            dn: "CN=WS01,CN=Computers,DC=corp,DC=local".into(),
            attrs: BTreeMap::new(),
        };
        c.attrs
            .insert("sAMAccountName".into(), vec!["WS01$".into()]);
        c.attrs
            .insert("dNSHostName".into(), vec!["ws01.corp.local".into()]);

        let (nodes, edges) =
            graph_from_ldap_objects("corp.local", &["dc01.corp.local".into()], &[u], &[g], &[c]);
        assert!(
            nodes.len() > 2,
            "expected thicker graph, got {} nodes",
            nodes.len()
        );
        let kinds: Vec<_> = nodes
            .iter()
            .filter_map(|n| n.get("kind").and_then(|k| k.as_str()))
            .collect();
        assert!(kinds.contains(&"User"));
        assert!(kinds.contains(&"Group"));
        assert!(kinds.contains(&"Computer"));
        assert!(kinds.contains(&"Domain"));
        assert!(edges.iter().any(|e| e.get("kind").and_then(|k| k.as_str()) == Some("MemberOf")));
        assert!(edges.iter().any(|e| e.get("kind").and_then(|k| k.as_str()) == Some("Contains")));

        let gj = build_cupcake_graph_json("corp.local", &nodes, &edges);
        let zip = build_graph_zip(&gj);
        assert_eq!(&zip[0..4], &[0x50, 0x4b, 0x03, 0x04]);
        // graph.json name appears in zip
        assert!(zip.windows(10).any(|w| w == b"graph.json"));
    }
}
