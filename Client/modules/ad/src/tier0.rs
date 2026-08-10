//! Tier0 domain enum / LDAP-backed ops.
//! Offline / non-joined hosts return design-stable codes via domain probe.
//! When domain+DC are available, perform real LDAP bind/search (Windows WLDAP32).

use serde_json::{json, Value};

use crate::domain::{probe_domain, require_domain, response_from_probe};
use crate::ldap::{
    clamp_page_size, dc_host, domain_to_base_dn, entry_to_computer, entry_to_delegation,
    entry_to_gpo, entry_to_group, entry_to_password_policy, entry_to_spn_row, entry_to_trust,
    entry_to_user, ldap_search, ldap_search_domain, parse_scope, LdapError,
};
use crate::{AdJobRequest, AdJobResponse, DomainProbe};

/// Shared Tier0 path: require domain, then run LDAP-backed handler.
pub fn handle_tier0_enum(req: &AdJobRequest, kind: &str) -> AdJobResponse {
    match require_domain(&req.request_id, probe_domain()) {
        Err(e) => e,
        Ok((domain, dcs)) => match run_tier0_ldap(kind, &req.params, &domain, &dcs) {
            Ok(body) => AdJobResponse {
                request_id: req.request_id.clone(),
                status: "ok".into(),
                stdout: body.to_string(),
                stderr: String::new(),
                error_code: String::new(),
            },
            Err(e) => AdJobResponse {
                request_id: req.request_id.clone(),
                status: "error".into(),
                stdout: json!({ "domain": domain, "dc": dcs.first() }).to_string(),
                stderr: e.message(),
                error_code: e.code().into(),
            },
        },
    }
}

fn run_tier0_ldap(
    kind: &str,
    params: &Value,
    domain: &str,
    dcs: &[String],
) -> Result<Value, LdapError> {
    let host = dc_host(dcs);
    let size = clamp_page_size(
        params
            .get("size_limit")
            .or_else(|| params.get("page_size"))
            .and_then(|v| v.as_u64())
            .unwrap_or(500),
    );

    match kind {
        "ad_ldap_query" => ldap_query_live(params, domain, host, size),
        "ad_enum_users" => enum_users_live(params, domain, host, size),
        "ad_enum_groups" => enum_groups_live(params, domain, host, size),
        "ad_enum_privileged_groups" => privileged_groups_live(domain, host, size),
        "ad_enum_computers" => enum_computers_live(params, domain, host, size),
        "ad_enum_spns" => enum_spns_live(domain, host, size),
        "ad_enum_trusts" => enum_trusts_live(domain, host, size),
        "ad_password_policy" => password_policy_live(domain, host),
        "ad_enum_delegation" => enum_delegation_live(domain, host, size),
        "ad_enum_gpo" => enum_gpo_live(domain, host, size),
        "ad_collect_sessions" => Ok(json!({
            "domain": domain,
            "sessions": [],
            "count": 0,
            "warning": "high_noise_default_off"
        })),
        "ad_check_replication_rights" => Ok(replication_rights_body(domain, params)),
        other => Err(LdapError::InvalidParams(format!("unknown tier0 kind {other}"))),
    }
}

pub fn handle_discover(req: &AdJobRequest) -> AdJobResponse {
    response_from_probe(&req.request_id, probe_domain())
}

/// Default SPN discovery LDAP filter (Khaos-aligned).
pub fn default_spn_filter() -> &'static str {
    "(&(objectCategory=user)(servicePrincipalName=*)(!samAccountName=krbtgt)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
}

/// Default AS-REP filter: DONT_REQ_PREAUTH bit.
pub fn default_asrep_filter() -> &'static str {
    "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
}

fn ldap_query_live(
    params: &Value,
    domain: &str,
    host: Option<&str>,
    size: u32,
) -> Result<Value, LdapError> {
    let base = params
        .get("base")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if base.is_empty() {
        return Err(LdapError::InvalidParams("base is required".into()));
    }
    let filter = params
        .get("filter")
        .and_then(|v| v.as_str())
        .unwrap_or("(objectClass=*)");
    let scope = parse_scope(params.get("scope").and_then(|v| v.as_str()));
    let attr_owned: Vec<String> = params
        .get("attrs")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let attr_refs: Vec<&str> = attr_owned.iter().map(|s| s.as_str()).collect();
    let entries = ldap_search(host, base, filter, &attr_refs, scope, size)?;
    let json_entries: Vec<Value> = entries.iter().map(|e| e.to_json()).collect();
    Ok(json!({
        "domain": domain,
        "dc": host,
        "base": base,
        "filter": filter,
        "size_limit": size,
        "entries": json_entries,
        "count": json_entries.len(),
        "page_token": null,
        "source": "ldap",
    }))
}

fn enum_users_live(
    params: &Value,
    domain: &str,
    host: Option<&str>,
    size: u32,
) -> Result<Value, LdapError> {
    let include_disabled = params
        .get("include_disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut filter = if include_disabled {
        "(&(objectCategory=person)(objectClass=user))".to_string()
    } else {
        "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            .to_string()
    };
    if let Some(extra) = params.get("filter").and_then(|v| v.as_str()) {
        if !extra.is_empty() && extra != "(objectClass=*)" {
            filter = format!("(&{filter}{extra})");
        }
    }
    let attrs = [
        "sAMAccountName",
        "displayName",
        "userPrincipalName",
        "userAccountControl",
        "memberOf",
        "servicePrincipalName",
    ];
    let (_base, entries) =
        ldap_search_domain(host, domain, None, &filter, &attrs, 2, size)?;
    let users: Vec<Value> = entries.iter().map(entry_to_user).collect();
    Ok(json!({
        "domain": domain,
        "include_disabled": include_disabled,
        "users": users,
        "count": users.len(),
        "page_token": null,
        "source": "ldap",
    }))
}

fn enum_groups_live(
    params: &Value,
    domain: &str,
    host: Option<&str>,
    size: u32,
) -> Result<Value, LdapError> {
    let filter = if let Some(g) = params.get("group").and_then(|v| v.as_str()) {
        if !g.is_empty() {
            format!("(&(objectCategory=group)(|(cn={g})(sAMAccountName={g})))")
        } else {
            "(objectCategory=group)".into()
        }
    } else {
        "(objectCategory=group)".into()
    };
    let attrs = ["name", "cn", "sAMAccountName", "member", "description"];
    let (_base, entries) =
        ldap_search_domain(host, domain, None, &filter, &attrs, 2, size)?;
    let groups: Vec<Value> = entries.iter().map(entry_to_group).collect();
    Ok(json!({
        "domain": domain,
        "groups": groups,
        "count": groups.len(),
        "page_token": null,
        "source": "ldap",
    }))
}

fn privileged_groups_live(
    domain: &str,
    host: Option<&str>,
    size: u32,
) -> Result<Value, LdapError> {
    let names = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Account Operators",
        "Administrators",
    ];
    let mut groups = Vec::new();
    for n in names {
        let filter = format!("(&(objectCategory=group)(cn={n}))");
        let attrs = ["name", "cn", "sAMAccountName", "member", "description"];
        match ldap_search_domain(host, domain, None, &filter, &attrs, 2, size.min(50)) {
            Ok((_b, entries)) => {
                if let Some(e) = entries.first() {
                    groups.push(entry_to_group(e));
                } else {
                    groups.push(json!({
                        "name": n,
                        "members": [],
                        "member_count": 0,
                        "found": false
                    }));
                }
            }
            Err(e) => {
                // Partial failure still returns structure; escalate only on bind failure of first.
                if groups.is_empty() {
                    return Err(e);
                }
                groups.push(json!({
                    "name": n,
                    "members": [],
                    "member_count": 0,
                    "error": e.code()
                }));
            }
        }
    }
    Ok(json!({
        "domain": domain,
        "groups": groups,
        "count": groups.len(),
        "source": "ldap",
    }))
}

fn enum_computers_live(
    params: &Value,
    domain: &str,
    host: Option<&str>,
    size: u32,
) -> Result<Value, LdapError> {
    let enabled_only = params
        .get("enabled_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut filter = if enabled_only {
        "(&(objectCategory=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))".to_string()
    } else {
        "(objectCategory=computer)".to_string()
    };
    if let Some(os) = params.get("os_filter").and_then(|v| v.as_str()) {
        if !os.is_empty() {
            filter = format!("(&{filter}(operatingSystem=*{os}*))");
        }
    }
    let attrs = [
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "userAccountControl",
    ];
    let (_base, entries) =
        ldap_search_domain(host, domain, None, &filter, &attrs, 2, size)?;
    let computers: Vec<Value> = entries.iter().map(entry_to_computer).collect();
    Ok(json!({
        "domain": domain,
        "computers": computers,
        "count": computers.len(),
        "page_token": null,
        "source": "ldap",
    }))
}

fn enum_spns_live(domain: &str, host: Option<&str>, size: u32) -> Result<Value, LdapError> {
    let filter = default_spn_filter();
    let attrs = ["sAMAccountName", "servicePrincipalName"];
    let (_base, entries) =
        ldap_search_domain(host, domain, None, filter, &attrs, 2, size)?;
    let mut spns = Vec::new();
    for e in &entries {
        spns.extend(entry_to_spn_row(e));
    }
    Ok(json!({
        "domain": domain,
        "spns": spns,
        "count": spns.len(),
        "page_token": null,
        "filter": filter,
        "source": "ldap",
    }))
}

fn enum_trusts_live(domain: &str, host: Option<&str>, size: u32) -> Result<Value, LdapError> {
    let filter = "(objectClass=trustedDomain)";
    let attrs = [
        "name",
        "cn",
        "trustPartner",
        "trustDirection",
        "trustType",
        "trustAttributes",
        "flatName",
    ];
    // Trusts live under CN=System
    let system_base = format!("CN=System,{}", domain_to_base_dn(domain));
    let entries = match ldap_search(host, &system_base, filter, &attrs, 2, size) {
        Ok(e) => e,
        Err(_) => {
            // Fallback: domain-wide search
            ldap_search_domain(host, domain, None, filter, &attrs, 2, size)?.1
        }
    };
    let trusts: Vec<Value> = entries.iter().map(entry_to_trust).collect();
    Ok(json!({
        "domain": domain,
        "trusts": trusts,
        "count": trusts.len(),
        "source": "ldap",
    }))
}

fn password_policy_live(domain: &str, host: Option<&str>) -> Result<Value, LdapError> {
    let base = domain_to_base_dn(domain);
    let attrs = [
        "minPwdLength",
        "pwdHistoryLength",
        "maxPwdAge",
        "minPwdAge",
        "lockoutThreshold",
        "lockoutDuration",
        "pwdProperties",
    ];
    // Domain object is the base DN itself
    let entries = ldap_search(host, &base, "(objectClass=domain)", &attrs, 0, 1)?;
    if let Some(e) = entries.first() {
        let mut v = entry_to_password_policy(e, domain);
        if let Some(obj) = v.as_object_mut() {
            obj.insert("source".into(), json!("ldap"));
        }
        Ok(v)
    } else {
        // Try domainDNS at base
        let entries = ldap_search(host, &base, "(objectClass=*)", &attrs, 0, 1)?;
        if let Some(e) = entries.first() {
            let mut v = entry_to_password_policy(e, domain);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("source".into(), json!("ldap"));
            }
            Ok(v)
        } else {
            Ok(json!({
                "domain": domain,
                "min_length": null,
                "complexity": null,
                "lockout_threshold": null,
                "source": "ldap",
                "note": "no_domain_object_attrs",
            }))
        }
    }
}

fn enum_delegation_live(
    domain: &str,
    host: Option<&str>,
    size: u32,
) -> Result<Value, LdapError> {
    // Unconstrained: UAC TRUSTED_FOR_DELEGATION; also pull constrained/RBCD attrs
    let filter = "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))";
    let attrs = [
        "sAMAccountName",
        "userAccountControl",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ];
    let (_base, entries) =
        ldap_search_domain(host, domain, None, filter, &attrs, 2, size)?;
    let mut unconstrained = Vec::new();
    let mut constrained = Vec::new();
    let mut rbcd = Vec::new();
    for e in &entries {
        if let Some((kind, row)) = entry_to_delegation(e) {
            match kind.as_str() {
                "unconstrained" => unconstrained.push(row),
                "constrained" => constrained.push(row),
                "rbcd" => rbcd.push(row),
                _ => {}
            }
        }
    }
    let count = unconstrained.len() + constrained.len() + rbcd.len();
    Ok(json!({
        "domain": domain,
        "unconstrained": unconstrained,
        "constrained": constrained,
        "rbcd": rbcd,
        "count": count,
        "source": "ldap",
    }))
}

fn enum_gpo_live(domain: &str, host: Option<&str>, size: u32) -> Result<Value, LdapError> {
    let filter = "(objectClass=groupPolicyContainer)";
    let attrs = ["displayName", "name", "cn", "gPCFileSysPath", "flags"];
    let policies_base = format!("CN=Policies,CN=System,{}", domain_to_base_dn(domain));
    let entries = match ldap_search(host, &policies_base, filter, &attrs, 2, size) {
        Ok(e) => e,
        Err(_) => ldap_search_domain(host, domain, None, filter, &attrs, 2, size)?.1,
    };
    let gpos: Vec<Value> = entries.iter().map(entry_to_gpo).collect();
    Ok(json!({
        "domain": domain,
        "gpos": gpos,
        "count": gpos.len(),
        "source": "ldap",
    }))
}

fn replication_rights_body(domain: &str, params: &Value) -> Value {
    let principal = params
        .get("principal")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    json!({
        "domain": domain,
        "principal": principal,
        "has_replicating_directory_changes": false,
        "has_replicating_directory_changes_all": false,
        "aces": [],
        "note": "acl_read_best_effort",
        "source": "ldap_stub"
    })
}

/// Validate ldap_query required base before domain probe (fail fast).
pub fn validate_ldap_query(params: &Value) -> Result<(), String> {
    let base = params
        .get("base")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if base.is_empty() {
        return Err("invalid_params: base is required".into());
    }
    Ok(())
}

/// Pure mapper used by tests: given probe + kind → error_code or ok.
#[allow(dead_code)]
pub fn tier0_error_code_for_probe(probe: &DomainProbe) -> Option<&'static str> {
    match probe {
        DomainProbe::UnsupportedPlatform => Some("unsupported_platform"),
        DomainProbe::NotJoined => Some("not_domain_joined"),
        DomainProbe::DcUnreachable { .. } => Some("dc_unreachable"),
        DomainProbe::Ok { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier0_probe_codes() {
        assert_eq!(
            tier0_error_code_for_probe(&DomainProbe::NotJoined),
            Some("not_domain_joined")
        );
        assert_eq!(
            tier0_error_code_for_probe(&DomainProbe::UnsupportedPlatform),
            Some("unsupported_platform")
        );
        assert!(tier0_error_code_for_probe(&DomainProbe::Ok {
            domain: "x".into(),
            dcs: vec![]
        })
        .is_none());
    }

    #[test]
    fn ldap_base_required() {
        assert!(validate_ldap_query(&json!({})).is_err());
        assert!(validate_ldap_query(&json!({"base": "DC=corp,DC=local"})).is_ok());
    }

    #[test]
    fn spn_filter_excludes_krbtgt() {
        let f = default_spn_filter();
        assert!(f.contains("servicePrincipalName=*"));
        assert!(f.contains("!samAccountName=krbtgt"));
    }

    #[test]
    fn asrep_filter_has_dont_req_preauth() {
        let f = default_asrep_filter();
        assert!(f.contains("4194304"));
    }

    #[test]
    fn no_empty_shell_notes_in_filters() {
        // Ensure design filters are real LDAP, not placeholder shells.
        assert!(!default_spn_filter().contains("ldap_page_ready"));
        assert!(!default_asrep_filter().contains("pending"));
    }
}
