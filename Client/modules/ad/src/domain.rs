//! Domain join / DC locator probes shared by Tier0+ ops.

use serde_json::json;

use crate::{AdJobResponse, DomainProbe};

/// Map a domain probe into the AD worker JSON error/ok contract.
pub fn response_from_probe(request_id: &str, probe: DomainProbe) -> AdJobResponse {
    match probe {
        DomainProbe::UnsupportedPlatform => AdJobResponse {
            request_id: request_id.to_string(),
            status: "error".into(),
            stdout: String::new(),
            stderr: "unsupported_platform".into(),
            error_code: "unsupported_platform".into(),
        },
        DomainProbe::NotJoined => AdJobResponse {
            request_id: request_id.to_string(),
            status: "error".into(),
            stdout: String::new(),
            stderr: "not_domain_joined".into(),
            error_code: "not_domain_joined".into(),
        },
        DomainProbe::DcUnreachable { domain } => AdJobResponse {
            request_id: request_id.to_string(),
            status: "error".into(),
            stdout: json!({ "domain": domain }).to_string(),
            stderr: "dc_unreachable".into(),
            error_code: "dc_unreachable".into(),
        },
        DomainProbe::Ok { domain, dcs } => AdJobResponse {
            request_id: request_id.to_string(),
            status: "ok".into(),
            stdout: json!({
                "domain": domain,
                "dcs": dcs,
                "sites": [],
                "functional_level": null,
                "note": "tier0_discover_locator_only",
            })
            .to_string(),
            stderr: String::new(),
            error_code: String::new(),
        },
    }
}

/// If probe is not Ok, return an error response; else None and (domain, dcs).
pub fn require_domain(request_id: &str, probe: DomainProbe) -> Result<(String, Vec<String>), AdJobResponse> {
    match probe {
        DomainProbe::Ok { domain, dcs } => Ok((domain, dcs)),
        other => Err(response_from_probe(request_id, other)),
    }
}

/// Probe domain join state (platform-specific).
pub fn probe_domain() -> DomainProbe {
    #[cfg(not(windows))]
    {
        DomainProbe::UnsupportedPlatform
    }
    #[cfg(windows)]
    {
        probe_domain_windows()
    }
}

#[cfg(windows)]
fn probe_domain_windows() -> DomainProbe {
    let domain = match dns_domain_name() {
        Some(d) if !d.is_empty() => d,
        _ => return DomainProbe::NotJoined,
    };
    match locate_domain_controller(&domain) {
        Some(dc) => DomainProbe::Ok {
            domain,
            dcs: vec![dc],
        },
        None => DomainProbe::DcUnreachable { domain },
    }
}

#[cfg(windows)]
fn dns_domain_name() -> Option<String> {
    const COMPUTER_NAME_DNS_DOMAIN: u32 = 2;
    extern "system" {
        fn GetComputerNameExW(name_type: u32, buffer: *mut u16, size: *mut u32) -> i32;
    }
    unsafe {
        let mut size: u32 = 0;
        let _ = GetComputerNameExW(COMPUTER_NAME_DNS_DOMAIN, std::ptr::null_mut(), &mut size);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u16; size as usize];
        let ok = GetComputerNameExW(COMPUTER_NAME_DNS_DOMAIN, buf.as_mut_ptr(), &mut size);
        if ok == 0 {
            return None;
        }
        let n = size as usize;
        if n == 0 {
            return None;
        }
        let s = String::from_utf16_lossy(&buf[..n.min(buf.len())]);
        let s = s.trim_end_matches('\0').trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    }
}

#[cfg(windows)]
fn locate_domain_controller(domain: &str) -> Option<String> {
    #[repr(C)]
    struct DomainControllerInfoW {
        domain_controller_name: *mut u16,
        domain_controller_address: *mut u16,
        domain_controller_address_type: u32,
        domain_guid: [u8; 16],
        domain_name: *mut u16,
        dns_forest_name: *mut u16,
        flags: u32,
        dc_site_name: *mut u16,
        client_site_name: *mut u16,
    }

    #[link(name = "Netapi32")]
    extern "system" {
        fn DsGetDcNameW(
            computer_name: *const u16,
            domain_name: *const u16,
            domain_guid: *const u8,
            site_name: *const u16,
            flags: u32,
            domain_controller_info: *mut *mut DomainControllerInfoW,
        ) -> u32;
        fn NetApiBufferFree(buffer: *mut core::ffi::c_void) -> u32;
    }

    const DS_RETURN_DNS_NAME: u32 = 0x4000_0000;
    const DS_ONLY_LDAP_NEEDED: u32 = 0x0000_8000;

    let domain_w: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();
    let mut info: *mut DomainControllerInfoW = std::ptr::null_mut();
    let status = unsafe {
        DsGetDcNameW(
            std::ptr::null(),
            domain_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            DS_RETURN_DNS_NAME | DS_ONLY_LDAP_NEEDED,
            &mut info,
        )
    };
    if status != 0 || info.is_null() {
        return None;
    }
    unsafe {
        let ptr = (*info).domain_controller_name;
        let out = if ptr.is_null() {
            None
        } else {
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
                if len > 1024 {
                    break;
                }
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let s = s.trim_start_matches('\\').trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        };
        NetApiBufferFree(info as *mut core::ffi::c_void);
        out
    }
}
