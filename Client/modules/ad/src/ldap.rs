//! Native LDAP client for AD worker (Windows WLDAP32).
//! Pure helpers are unit-tested offline; live bind/search is Windows-only.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Stable error codes for LDAP failures (design matrix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapError {
    BindFailed(String),
    AccessDenied(String),
    SearchFailed(String),
    InvalidParams(String),
    UnsupportedPlatform,
}

impl LdapError {
    pub fn code(&self) -> &'static str {
        match self {
            LdapError::BindFailed(_) => "ldap_bind_failed",
            LdapError::AccessDenied(_) => "access_denied",
            LdapError::SearchFailed(_) => "ldap_bind_failed",
            LdapError::InvalidParams(_) => "invalid_params",
            LdapError::UnsupportedPlatform => "unsupported_platform",
        }
    }

    pub fn message(&self) -> String {
        match self {
            LdapError::BindFailed(m)
            | LdapError::AccessDenied(m)
            | LdapError::SearchFailed(m)
            | LdapError::InvalidParams(m) => m.clone(),
            LdapError::UnsupportedPlatform => "unsupported_platform".into(),
        }
    }
}

/// One LDAP entry: DN + multi-valued attributes (UTF-8 best-effort).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapEntry {
    pub dn: String,
    pub attrs: BTreeMap<String, Vec<String>>,
}

impl LdapEntry {
    pub fn first(&self, name: &str) -> Option<&str> {
        self.attrs
            .get(name)
            .or_else(|| {
                // case-insensitive attribute lookup
                self.attrs
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v)
            })
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    pub fn all(&self, name: &str) -> Vec<String> {
        self.attrs
            .get(name)
            .cloned()
            .or_else(|| {
                self.attrs
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.clone())
            })
            .unwrap_or_default()
    }

    /// JSON object for ad_ldap_query entries[].
    pub fn to_json(&self) -> Value {
        let mut attrs = Map::new();
        for (k, vals) in &self.attrs {
            if vals.len() == 1 {
                attrs.insert(k.clone(), json!(vals[0]));
            } else {
                attrs.insert(k.clone(), json!(vals));
            }
        }
        json!({
            "dn": self.dn,
            "attributes": attrs
        })
    }
}

/// Convert DNS domain `corp.local` → LDAP base `DC=corp,DC=local`.
pub fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",")
}

/// Prefer explicit base, else `DC=…` from domain DNS name.
#[allow(dead_code)]
pub fn resolve_base_dn(base: Option<&str>, domain: &str) -> String {
    let b = base.unwrap_or("").trim();
    if b.is_empty() {
        domain_to_base_dn(domain)
    } else {
        b.to_string()
    }
}

pub fn map_ldap_result_code(code: u32) -> LdapError {
    match code {
        0x31 | 0x30 => LdapError::BindFailed(format!("ldap result 0x{code:x}")),
        0x32 => LdapError::AccessDenied(format!("ldap result 0x{code:x}")),
        0x07 => LdapError::BindFailed("ldap_auth_method_not_supported".into()),
        other => LdapError::SearchFailed(format!("ldap result 0x{other:x}")),
    }
}

/// Scope: 0=base, 1=one, 2=subtree (LDAP_SCOPE_*).
pub fn parse_scope(s: Option<&str>) -> u32 {
    match s.unwrap_or("subtree").to_ascii_lowercase().as_str() {
        "base" | "0" => 0,
        "one" | "onelevel" | "1" => 1,
        _ => 2,
    }
}

/// Build user JSON from LDAP entry (MVP attrs).
pub fn entry_to_user(e: &LdapEntry) -> Value {
    let uac = e
        .first("userAccountControl")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let disabled = (uac & 0x2) != 0;
    json!({
        "dn": e.dn,
        "sAMAccountName": e.first("sAMAccountName").unwrap_or(""),
        "displayName": e.first("displayName").unwrap_or(""),
        "userPrincipalName": e.first("userPrincipalName").unwrap_or(""),
        "userAccountControl": uac,
        "disabled": disabled,
        "memberOf": e.all("memberOf"),
        "servicePrincipalName": e.all("servicePrincipalName"),
    })
}

pub fn entry_to_computer(e: &LdapEntry) -> Value {
    json!({
        "dn": e.dn,
        "sAMAccountName": e.first("sAMAccountName").unwrap_or(""),
        "dNSHostName": e.first("dNSHostName").unwrap_or(""),
        "operatingSystem": e.first("operatingSystem").unwrap_or(""),
        "operatingSystemVersion": e.first("operatingSystemVersion").unwrap_or(""),
        "userAccountControl": e.first("userAccountControl").and_then(|s| s.parse::<u32>().ok()),
    })
}

pub fn entry_to_group(e: &LdapEntry) -> Value {
    let members = e.all("member");
    json!({
        "dn": e.dn,
        "name": e.first("name").or_else(|| e.first("cn")).or_else(|| e.first("sAMAccountName")).unwrap_or(""),
        "sAMAccountName": e.first("sAMAccountName").unwrap_or(""),
        "members": members,
        "member_count": e.all("member").len(),
        "description": e.first("description").unwrap_or(""),
    })
}

pub fn entry_to_spn_row(e: &LdapEntry) -> Vec<Value> {
    let sam = e.first("sAMAccountName").unwrap_or("").to_string();
    e.all("servicePrincipalName")
        .into_iter()
        .map(|spn| {
            json!({
                "sAMAccountName": sam,
                "spn": spn,
                "dn": e.dn,
            })
        })
        .collect()
}

pub fn entry_to_trust(e: &LdapEntry) -> Value {
    json!({
        "dn": e.dn,
        "name": e.first("name").or_else(|| e.first("cn")).unwrap_or(""),
        "trustPartner": e.first("trustPartner").unwrap_or(""),
        "trustDirection": e.first("trustDirection").and_then(|s| s.parse::<i32>().ok()),
        "trustType": e.first("trustType").and_then(|s| s.parse::<i32>().ok()),
        "trustAttributes": e.first("trustAttributes").and_then(|s| s.parse::<u32>().ok()),
        "flatName": e.first("flatName").unwrap_or(""),
    })
}

pub fn entry_to_gpo(e: &LdapEntry) -> Value {
    json!({
        "dn": e.dn,
        "displayName": e.first("displayName").unwrap_or(""),
        "name": e.first("name").or_else(|| e.first("cn")).unwrap_or(""),
        "gPCFileSysPath": e.first("gPCFileSysPath").unwrap_or(""),
        "flags": e.first("flags").and_then(|s| s.parse::<u32>().ok()),
    })
}

/// Password policy attrs from domain object (domainDNS).
pub fn entry_to_password_policy(e: &LdapEntry, domain: &str) -> Value {
    fn i64_attr(e: &LdapEntry, name: &str) -> Option<i64> {
        e.first(name).and_then(|s| s.parse::<i64>().ok())
    }
    // pwdHistoryLength / minPwdLength are integers; lockoutThreshold too.
    // maxPwdAge is 100-ns intervals (negative FILETIME duration).
    json!({
        "domain": domain,
        "dn": e.dn,
        "min_length": i64_attr(e, "minPwdLength"),
        "history_length": i64_attr(e, "pwdHistoryLength"),
        "max_pwd_age_raw": i64_attr(e, "maxPwdAge"),
        "min_pwd_age_raw": i64_attr(e, "minPwdAge"),
        "lockout_threshold": i64_attr(e, "lockoutThreshold"),
        "lockout_duration_raw": i64_attr(e, "lockoutDuration"),
        "complexity": i64_attr(e, "pwdProperties").map(|p| (p & 1) != 0),
        "pwd_properties": i64_attr(e, "pwdProperties"),
    })
}

/// Delegation classification from UAC + msDS-AllowedTo* attrs.
pub fn entry_to_delegation(e: &LdapEntry) -> Option<(String, Value)> {
    let uac = e
        .first("userAccountControl")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let sam = e.first("sAMAccountName").unwrap_or("").to_string();
    let dn = e.dn.clone();
    // TRUSTED_FOR_DELEGATION = 0x80000
    const UAC_TRUSTED_FOR_DELEGATION: u32 = 0x80000;
    // TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    const UAC_TRUSTED_TO_AUTH: u32 = 0x1000000;
    let allowed = e.all("msDS-AllowedToDelegateTo");
    let rbcd = e.all("msDS-AllowedToActOnBehalfOfOtherIdentity");
    if (uac & UAC_TRUSTED_FOR_DELEGATION) != 0 {
        Some((
            "unconstrained".into(),
            json!({ "sAMAccountName": sam, "dn": dn, "userAccountControl": uac }),
        ))
    } else if !allowed.is_empty() || (uac & UAC_TRUSTED_TO_AUTH) != 0 {
        Some((
            "constrained".into(),
            json!({
                "sAMAccountName": sam,
                "dn": dn,
                "userAccountControl": uac,
                "msDS-AllowedToDelegateTo": allowed,
            }),
        ))
    } else if !rbcd.is_empty() {
        Some((
            "rbcd".into(),
            json!({
                "sAMAccountName": sam,
                "dn": dn,
                "msDS-AllowedToActOnBehalfOfOtherIdentity": true,
            }),
        ))
    } else {
        None
    }
}

/// Cap page size to design limits.
pub fn clamp_page_size(n: u64) -> u32 {
    n.clamp(1, 5000) as u32
}

/// Search LDAP (live on Windows; stub elsewhere).
/// `host`: DC hostname (optional — NULL uses default locator path via empty host).
pub fn ldap_search(
    host: Option<&str>,
    base: &str,
    filter: &str,
    attrs: &[&str],
    scope: u32,
    size_limit: u32,
) -> Result<Vec<LdapEntry>, LdapError> {
    #[cfg(not(windows))]
    {
        let _ = (host, base, filter, attrs, scope, size_limit);
        Err(LdapError::UnsupportedPlatform)
    }
    #[cfg(windows)]
    {
        windows_ldap_search(host, base, filter, attrs, scope, size_limit)
    }
}

/// Fetch defaultNamingContext from RootDSE.
pub fn ldap_default_naming_context(host: Option<&str>) -> Result<String, LdapError> {
    let entries = ldap_search(
        host,
        "",
        "(objectClass=*)",
        &["defaultNamingContext"],
        0, // base
        1,
    )?;
    entries
        .first()
        .and_then(|e| e.first("defaultNamingContext").map(|s| s.to_string()))
        .ok_or_else(|| LdapError::SearchFailed("no defaultNamingContext".into()))
}

/// Convenience: resolve base then search.
pub fn ldap_search_domain(
    host: Option<&str>,
    domain: &str,
    base_override: Option<&str>,
    filter: &str,
    attrs: &[&str],
    scope: u32,
    size_limit: u32,
) -> Result<(String, Vec<LdapEntry>), LdapError> {
    let base = if let Some(b) = base_override.map(str::trim).filter(|s| !s.is_empty()) {
        b.to_string()
    } else {
        match ldap_default_naming_context(host) {
            Ok(nc) => nc,
            Err(_) => domain_to_base_dn(domain),
        }
    };
    let entries = ldap_search(host, &base, filter, attrs, scope, size_limit)?;
    Ok((base, entries))
}

// ─── Windows WLDAP32 ────────────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use super::{map_ldap_result_code, LdapEntry, LdapError};
    use std::collections::BTreeMap;
    use std::ffi::{c_void, CStr, CString};
    use std::os::raw::c_char;
    use std::ptr;

    pub type Ldap = c_void;
    pub type LdapMessage = c_void;
    pub type BerElement = c_void;

    pub const LDAP_PORT: u32 = 389;
    pub const LDAP_VERSION3: u32 = 3;
    pub const LDAP_OPT_PROTOCOL_VERSION: i32 = 0x0011;
    pub const LDAP_OPT_SIZELIMIT: i32 = 0x0003;
    pub const LDAP_OPT_TIMELIMIT: i32 = 0x0004;
    pub const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;
    pub const LDAP_SUCCESS: u32 = 0;
    pub const LDAP_NO_LIMIT: u32 = 0;

    #[link(name = "Wldap32")]
    extern "system" {
        fn ldap_initA(host: *const c_char, port: u32) -> *mut Ldap;
        fn ldap_set_option(ld: *mut Ldap, option: i32, value: *const c_void) -> u32;
        fn ldap_bind_sA(
            ld: *mut Ldap,
            dn: *const c_char,
            cred: *const c_char,
            method: u32,
        ) -> u32;
        fn ldap_search_sA(
            ld: *mut Ldap,
            base: *const c_char,
            scope: u32,
            filter: *const c_char,
            attrs: *const *const c_char,
            attrsonly: u32,
            res: *mut *mut LdapMessage,
        ) -> u32;
        fn ldap_first_entry(ld: *mut Ldap, res: *mut LdapMessage) -> *mut LdapMessage;
        fn ldap_next_entry(ld: *mut Ldap, entry: *mut LdapMessage) -> *mut LdapMessage;
        fn ldap_get_dnA(ld: *mut Ldap, entry: *mut LdapMessage) -> *mut c_char;
        fn ldap_first_attributeA(
            ld: *mut Ldap,
            entry: *mut LdapMessage,
            ptr: *mut *mut BerElement,
        ) -> *mut c_char;
        fn ldap_next_attributeA(
            ld: *mut Ldap,
            entry: *mut LdapMessage,
            ptr: *mut BerElement,
        ) -> *mut c_char;
        fn ldap_get_valuesA(
            ld: *mut Ldap,
            entry: *mut LdapMessage,
            attr: *const c_char,
        ) -> *mut *mut c_char;
        fn ldap_value_freeA(vals: *mut *mut c_char) -> u32;
        fn ldap_memfreeA(p: *mut c_char);
        fn ldap_msgfree(res: *mut LdapMessage) -> u32;
        fn ldap_unbind(ld: *mut Ldap) -> u32;
        fn ldap_count_entries(ld: *mut Ldap, res: *mut LdapMessage) -> u32;
    }

    struct LdapConn {
        ld: *mut Ldap,
    }

    impl Drop for LdapConn {
        fn drop(&mut self) {
            if !self.ld.is_null() {
                unsafe {
                    ldap_unbind(self.ld);
                }
                self.ld = ptr::null_mut();
            }
        }
    }

    pub fn search(
        host: Option<&str>,
        base: &str,
        filter: &str,
        attrs: &[&str],
        scope: u32,
        size_limit: u32,
    ) -> Result<Vec<LdapEntry>, LdapError> {
        let host_c = match host {
            Some(h) if !h.is_empty() => {
                let cleaned = h.trim_start_matches('\\');
                Some(CString::new(cleaned).map_err(|e| LdapError::InvalidParams(e.to_string()))?)
            }
            _ => None,
        };
        let host_ptr = host_c
            .as_ref()
            .map(|c| c.as_ptr())
            .unwrap_or(ptr::null());

        let ld = unsafe { ldap_initA(host_ptr, LDAP_PORT) };
        if ld.is_null() {
            return Err(LdapError::BindFailed("ldap_init failed".into()));
        }
        let conn = LdapConn { ld };

        unsafe {
            let ver = LDAP_VERSION3;
            let _ = ldap_set_option(
                conn.ld,
                LDAP_OPT_PROTOCOL_VERSION,
                &ver as *const u32 as *const c_void,
            );
            if size_limit > 0 {
                let lim = size_limit;
                let _ = ldap_set_option(
                    conn.ld,
                    LDAP_OPT_SIZELIMIT,
                    &lim as *const u32 as *const c_void,
                );
            }
            let tl: u32 = 60;
            let _ = ldap_set_option(
                conn.ld,
                LDAP_OPT_TIMELIMIT,
                &tl as *const u32 as *const c_void,
            );
        }

        let bind_rc = unsafe { ldap_bind_sA(conn.ld, ptr::null(), ptr::null(), LDAP_AUTH_NEGOTIATE) };
        if bind_rc != LDAP_SUCCESS {
            return Err(map_ldap_result_code(bind_rc));
        }

        let base_c = CString::new(base).map_err(|e| LdapError::InvalidParams(e.to_string()))?;
        let filter_c =
            CString::new(filter).map_err(|e| LdapError::InvalidParams(e.to_string()))?;

        // NULL-terminated attribute list; empty means all user attrs (pass null).
        let attr_cstrings: Vec<CString> = attrs
            .iter()
            .filter(|a| !a.is_empty())
            .map(|a| CString::new(*a).unwrap_or_default())
            .collect();
        let mut attr_ptrs: Vec<*const c_char> =
            attr_cstrings.iter().map(|c| c.as_ptr()).collect();
        let attrs_arg: *const *const c_char = if attr_ptrs.is_empty() {
            ptr::null()
        } else {
            attr_ptrs.push(ptr::null());
            attr_ptrs.as_ptr()
        };

        let mut res: *mut LdapMessage = ptr::null_mut();
        let search_rc = unsafe {
            ldap_search_sA(
                conn.ld,
                base_c.as_ptr(),
                scope,
                filter_c.as_ptr(),
                attrs_arg,
                0,
                &mut res,
            )
        };

        // Sizelimit exceeded still returns partial results — accept partial on 0x04.
        const LDAP_SIZELIMIT_EXCEEDED: u32 = 0x04;
        if search_rc != LDAP_SUCCESS && search_rc != LDAP_SIZELIMIT_EXCEEDED {
            if !res.is_null() {
                unsafe {
                    ldap_msgfree(res);
                }
            }
            return Err(map_ldap_result_code(search_rc));
        }

        let mut out = Vec::new();
        if res.is_null() {
            return Ok(out);
        }

        unsafe {
            let mut entry = ldap_first_entry(conn.ld, res);
            while !entry.is_null() {
                let mut map = BTreeMap::new();
                let dn_ptr = ldap_get_dnA(conn.ld, entry);
                let dn = if dn_ptr.is_null() {
                    String::new()
                } else {
                    let s = CStr::from_ptr(dn_ptr).to_string_lossy().into_owned();
                    ldap_memfreeA(dn_ptr);
                    s
                };

                let mut ber: *mut BerElement = ptr::null_mut();
                let mut attr = ldap_first_attributeA(conn.ld, entry, &mut ber);
                while !attr.is_null() {
                    let name = CStr::from_ptr(attr).to_string_lossy().into_owned();
                    let vals_ptr = ldap_get_valuesA(conn.ld, entry, attr);
                    let mut vals = Vec::new();
                    if !vals_ptr.is_null() {
                        let mut i = 0isize;
                        loop {
                            let p = *vals_ptr.offset(i);
                            if p.is_null() {
                                break;
                            }
                            vals.push(CStr::from_ptr(p).to_string_lossy().into_owned());
                            i += 1;
                            if i > 10_000 {
                                break;
                            }
                        }
                        ldap_value_freeA(vals_ptr);
                    }
                    map.insert(name, vals);
                    // ldap_first/next_attribute returns mem that must be freed
                    ldap_memfreeA(attr);
                    attr = ldap_next_attributeA(conn.ld, entry, ber);
                }
                // ber is freed by ldap when iteration ends (WLDAP32 docs)

                out.push(LdapEntry { dn, attrs: map });
                if size_limit > 0 && out.len() >= size_limit as usize {
                    break;
                }
                entry = ldap_next_entry(conn.ld, entry);
            }
            ldap_msgfree(res);
        }

        let _ = LDAP_NO_LIMIT;
        let _ = ldap_count_entries;
        Ok(out)
    }
}

#[cfg(windows)]
fn windows_ldap_search(
    host: Option<&str>,
    base: &str,
    filter: &str,
    attrs: &[&str],
    scope: u32,
    size_limit: u32,
) -> Result<Vec<LdapEntry>, LdapError> {
    win::search(host, base, filter, attrs, scope, size_limit)
}

/// DC host for LDAP: first locator DC, cleaned of leading backslashes.
pub fn dc_host(dcs: &[String]) -> Option<&str> {
    dcs.first().map(|s| s.trim_start_matches('\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_to_dn_basic() {
        assert_eq!(domain_to_base_dn("corp.local"), "DC=corp,DC=local");
        assert_eq!(domain_to_base_dn("a.b.c"), "DC=a,DC=b,DC=c");
    }

    #[test]
    fn resolve_base_prefers_explicit() {
        assert_eq!(
            resolve_base_dn(Some("OU=Users,DC=corp,DC=local"), "corp.local"),
            "OU=Users,DC=corp,DC=local"
        );
        assert_eq!(
            resolve_base_dn(None, "corp.local"),
            "DC=corp,DC=local"
        );
    }

    #[test]
    fn entry_to_user_maps_uac() {
        let mut e = LdapEntry {
            dn: "CN=Alice,DC=corp,DC=local".into(),
            attrs: BTreeMap::new(),
        };
        e.attrs
            .insert("sAMAccountName".into(), vec!["alice".into()]);
        e.attrs
            .insert("userAccountControl".into(), vec!["514".into()]); // disabled
        let j = entry_to_user(&e);
        assert_eq!(j["sAMAccountName"], "alice");
        assert_eq!(j["disabled"], true);
    }

    #[test]
    fn entry_to_spn_rows() {
        let mut e = LdapEntry {
            dn: "CN=sql,DC=x".into(),
            attrs: BTreeMap::new(),
        };
        e.attrs
            .insert("sAMAccountName".into(), vec!["sqlsvc".into()]);
        e.attrs.insert(
            "servicePrincipalName".into(),
            vec!["MSSQLSvc/db:1433".into(), "MSSQLSvc/db".into()],
        );
        let rows = entry_to_spn_row(&e);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["spn"], "MSSQLSvc/db:1433");
    }

    #[test]
    fn entry_json_round() {
        let mut e = LdapEntry {
            dn: "CN=x".into(),
            attrs: BTreeMap::new(),
        };
        e.attrs.insert("cn".into(), vec!["x".into()]);
        let j = e.to_json();
        assert_eq!(j["dn"], "CN=x");
        assert_eq!(j["attributes"]["cn"], "x");
    }

    #[test]
    fn clamp_page() {
        assert_eq!(clamp_page_size(0), 1);
        assert_eq!(clamp_page_size(10), 10);
        assert_eq!(clamp_page_size(99999), 5000);
    }

    #[test]
    fn password_policy_complexity_bit() {
        let mut e = LdapEntry::default();
        e.attrs.insert("minPwdLength".into(), vec!["8".into()]);
        e.attrs.insert("pwdProperties".into(), vec!["1".into()]);
        let j = entry_to_password_policy(&e, "corp.local");
        assert_eq!(j["min_length"], 8);
        assert_eq!(j["complexity"], true);
    }

    #[test]
    fn error_codes_stable() {
        assert_eq!(LdapError::BindFailed("x".into()).code(), "ldap_bind_failed");
        assert_eq!(LdapError::AccessDenied("x".into()).code(), "access_denied");
    }

    #[test]
    fn ldap_path_is_not_empty_shell() {
        // Structural: converters produce real business fields, not ldap_page_ready notes.
        let mut e = LdapEntry {
            dn: "CN=bob,DC=corp,DC=local".into(),
            attrs: BTreeMap::new(),
        };
        e.attrs
            .insert("sAMAccountName".into(), vec!["bob".into()]);
        e.attrs
            .insert("userAccountControl".into(), vec!["512".into()]);
        let u = entry_to_user(&e);
        let s = u.to_string();
        assert!(s.contains("bob"));
        assert!(!s.contains("ldap_page_ready"));
        assert!(!s.contains("ldap_bind_page_ready"));
    }
}
