// Per-build wire identity + string obfuscation seed.
// Server must use the same BUILD_WIRE_SEED (or default) so CKMS/CKF1/Noise/module labels match.
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Minimal SHA-256 (public domain style) for build-time deterministic IDs.
mod sha256 {
    type W = [u32; 64];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    fn rotr(x: u32, n: u32) -> u32 {
        (x >> n) | (x << (32 - n))
    }
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let bit_len = (data.len() as u64) * 8;
        let mut msg = data.to_vec();
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());
        for chunk in msg.chunks(64) {
            let mut w: W = [0; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];
            let mut f = h[5];
            let mut g = h[6];
            let mut hh = h[7];
            for i in 0..64 {
                let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }
        let mut out = [0u8; 32];
        for (i, v) in h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

fn domain_hash(seed: &str, domain: &str) -> [u8; 32] {
    let mut buf = Vec::with_capacity(seed.len() + 1 + domain.len());
    buf.extend_from_slice(seed.as_bytes());
    buf.push(0);
    buf.extend_from_slice(domain.as_bytes());
    sha256::hash(&buf)
}

fn magic4(seed: &str, domain: &str) -> [u8; 4] {
    let h = domain_hash(seed, domain);
    let mut m = [h[0], h[1], h[2], h[3]];
    // Avoid accidental ASCII brand collisions and all-zero
    if m.iter().all(|&b| b == 0) {
        m = [0x3c, 0xa1, 0x7e, 0x09];
    }
    // Force high bit on first byte so tools don't treat as pure text "CKMS"-like
    m[0] |= 0x80;
    m
}

fn main() {
    // --- string obfuscation key ---
    let seed_raw = env::var("BUILD_OBF_SEED").unwrap_or_else(|_| {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xA5A5_5A5A_C3C3_3C3C);
        let mix = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        let mut h = t ^ 0x9E3779B97F4A7C15;
        for b in mix.bytes() {
            h = h.wrapping_mul(0x100000001B3).wrapping_add(b as u64);
        }
        format!("{:016x}", h)
    });

    let mut obf_key = [0u8; 8];
    if seed_raw.len() >= 16 {
        for i in 0..8 {
            let byte = u8::from_str_radix(&seed_raw[i * 2..i * 2 + 2], 16).unwrap_or(0x42);
            obf_key[i] = byte;
        }
    } else {
        for (i, b) in seed_raw.bytes().take(8).enumerate() {
            obf_key[i] = b;
        }
        for b in obf_key.iter_mut() {
            if *b == 0 {
                *b = 0x5A;
            }
        }
    }

    // --- wire identity (must match server utils.WireIDs) ---
    // Prefer BUILD_WIRE_SEED; else generate a per-build seed (never the public
    // fixed "wire-v1-default-2026"). Builder / compile_windows.ps1 MUST set the
    // same seed as server/config.json — random seeds make Noise/reg-proof fail
    // (agent connects TCP/WS then handshake auth fails → appears as "无法回连").
    // Accept BUILD_WIRE_SEED or CUPCAKE_WIRE_SEED (compile scripts / server set the latter).
    let wire_seed = match env::var("BUILD_WIRE_SEED")
        .or_else(|_| env::var("CUPCAKE_WIRE_SEED"))
    {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0xC0FFEE_u64);
            let mix = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
            let mut h = t ^ 0x9E3779B97F4A7C15;
            for b in mix.bytes() {
                h = h.wrapping_mul(0x100000001B3).wrapping_add(b as u64);
            }
            // Extra entropy from OUT_DIR path (unique per target)
            if let Ok(out) = env::var("OUT_DIR") {
                for b in out.bytes() {
                    h = h.wrapping_mul(0x100000001B3).wrapping_add(b as u64);
                }
            }
            let generated = format!("wire-build-{:016x}", h);
            println!(
                "cargo:warning=BUILD_WIRE_SEED unset — using ephemeral {} (agent will NOT reconnect to server unless server uses the same seed; set env or server/config.json wire_seed)",
                generated
            );
            generated
        }
    };

    // Brand material derived from wire_seed (not fixed product strings).
    let staging_suffix = {
        let h = domain_hash(&wire_seed, "staging-suffix-v1");
        format!(".{:016x}.part", u64::from_le_bytes(h[..8].try_into().unwrap()))
    };
    let uuid_seed_xor: [u8; 16] = domain_hash(&wire_seed, "uuid-seed-xor-v1")[..16]
        .try_into()
        .unwrap();
    let uuid_chk_dom: [u8; 16] = domain_hash(&wire_seed, "uuid-chk-v1")[..16]
        .try_into()
        .unwrap();
    let uuid_magic_bytes: [u8; 4] = magic4(&wire_seed, "uuid-file-magic-v1");

    let m_ckms = magic4(&wire_seed, "pkg-v1");
    let m_ckf1 = magic4(&wire_seed, "frag-v1");
    let m_job = magic4(&wire_seed, "job-v1");
    let noise = domain_hash(&wire_seed, "noise-info-v1");
    let mod_lab = domain_hash(&wire_seed, "mod-key-v1");
    let reg_proof = domain_hash(&wire_seed, "reg-proof-v1");
    let noise_init = domain_hash(&wire_seed, "noise-init-v2");
    let noise_resp = domain_hash(&wire_seed, "noise-resp-v2");
    let noise_info: [u8; 16] = noise[..16].try_into().unwrap();
    let mod_key_domain: [u8; 16] = mod_lab[..16].try_into().unwrap();
    let reg_proof_domain: [u8; 16] = reg_proof[..16].try_into().unwrap();
    let noise_init_dom: [u8; 16] = noise_init[..16].try_into().unwrap();
    let noise_resp_dom: [u8; 16] = noise_resp[..16].try_into().unwrap();

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    let obf_dest = out.join("obf_seed.rs");
    fs::write(
        &obf_dest,
        format!(
            "/// Per-build XOR key injected by build.rs\npub const OBF_BUILD_KEY: [u8; 8] = {:?};\n",
            obf_key
        ),
    )
    .expect("write obf_seed.rs");

    let wire_dest = out.join("wire_ids.rs");
    let wire_content = format!(
        r#"// Auto-generated by build.rs — do not edit.
// Aligned with server pkg/utils/wire_ids.go (BUILD_WIRE_SEED).

/// Module package magic
pub const MAGIC_PKG: [u8; 4] = {m_ckms:?};
/// Fragment frame magic
pub const MAGIC_FRAG: [u8; 4] = {m_ckf1:?};
/// Isolated host job frame magic
pub const MAGIC_JOB: [u8; 4] = {m_job:?};
/// Noise HKDF info (16 raw bytes)
pub const NOISE_INFO: [u8; 16] = {noise_info:?};
/// Module HMAC domain label (16 raw bytes)
pub const MOD_KEY_DOMAIN: [u8; 16] = {mod_key_domain:?};
/// Register proof HMAC domain (16 raw bytes)
pub const REG_PROOF_DOMAIN: [u8; 16] = {reg_proof_domain:?};
/// Noise client-init PSK MAC domain
pub const NOISE_INIT_DOM: [u8; 16] = {noise_init_dom:?};
/// Noise server-resp PSK MAC domain
pub const NOISE_RESP_DOM: [u8; 16] = {noise_resp_dom:?};
#[allow(dead_code)]
pub const WIRE_SEED_NOTE: &str = "";
/// Staging file suffix (seed-derived)
pub const STAGING_FILE_SUFFIX: &str = "{staging_suffix}";
/// UUID seed XOR material (seed-derived 16 bytes)
pub const UUID_SEED_XOR: [u8; 16] = {uuid_seed_xor:?};
/// UUID seed file magic (seed-derived 4 bytes)
pub const UUID_FILE_MAGIC: [u8; 4] = {uuid_magic_bytes:?};
/// UUID checksum domain (seed-derived 16 bytes)
pub const UUID_CHK_DOMAIN: [u8; 16] = {uuid_chk_dom:?};
"#,
        m_ckms = m_ckms,
        m_ckf1 = m_ckf1,
        m_job = m_job,
        noise_info = noise_info,
        mod_key_domain = mod_key_domain,
        reg_proof_domain = reg_proof_domain,
        noise_init_dom = noise_init_dom,
        noise_resp_dom = noise_resp_dom,
        staging_suffix = staging_suffix,
        uuid_seed_xor = uuid_seed_xor,
        uuid_magic_bytes = uuid_magic_bytes,
        uuid_chk_dom = uuid_chk_dom,
    );
    fs::write(&wire_dest, wire_content).expect("write wire_ids.rs");

    println!("cargo:rerun-if-env-changed=BUILD_OBF_SEED");
    println!("cargo:rerun-if-env-changed=BUILD_WIRE_SEED");
    println!("cargo:rerun-if-env-changed=CUPCAKE_WIRE_SEED");
    println!("cargo:rerun-if-changed=build.rs");
}
