// Beacon API Implementation
//
// 实现完整的 Cobalt Strike Beacon API，用于 BOF 插件调用
// 参考: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm

use log::warn;
use std::cell::RefCell;
use std::ffi::CStr;
use std::sync::Mutex;

// NOTE: BOF output state must stay in a plain global (not `thread_local!`):
// product modules (app_rt.dll) are Manual-Mapped into the agent process, and
// pe_map refuses images carrying a TLS directory (a thread_local in this file
// is what used to add one). BOF execution is single-threaded per invocation,
// so a Mutex is equivalent and keeps the module TLS-free.
static BOF_OUTPUT: Mutex<String> = Mutex::new(String::new());

/// Beacon 数据解析器
/// 用于解析从服务器传递给 BOF 的参数
#[repr(C)]
pub struct BeaconDataParser {
    /// 原始数据指针
    original: *const u8,
    /// 当前读取位置
    buffer: *const u8,
    /// 剩余长度
    length: i32,
    /// 数据大小
    size: i32,
}

impl BeaconDataParser {
    /// 创建新的数据解析器
    pub fn new(buffer: *const u8, size: i32) -> Self {
        Self {
            original: buffer,
            buffer,
            length: size,
            size,
        }
    }

    /// 读取一个 short (2 字节)
    pub fn extract_short(&mut self) -> i16 {
        if self.length < 2 {
            warn!("[!] datap: short read (i16)");
            return 0;
        }

        unsafe {
            let value = i16::from_be_bytes([*self.buffer, *self.buffer.add(1)]);
            self.buffer = self.buffer.add(2);
            self.length -= 2;
            value
        }
    }

    /// 读取一个 int (4 字节)
    pub fn extract_int(&mut self) -> i32 {
        if self.length < 4 {
            warn!("[!] datap: short read (i32)");
            return 0;
        }

        unsafe {
            let value = i32::from_be_bytes([
                *self.buffer,
                *self.buffer.add(1),
                *self.buffer.add(2),
                *self.buffer.add(3),
            ]);
            self.buffer = self.buffer.add(4);
            self.length -= 4;
            value
        }
    }

    /// 读取一个字符串 (长度前缀)
    pub fn extract_string(&mut self) -> *const u8 {
        let length = self.extract_int();
        if length <= 0 || self.length < length {
            warn!("[!] datap: invalid str length");
            return std::ptr::null();
        }

        unsafe {
            let str_ptr = self.buffer;
            self.buffer = self.buffer.add(length as usize);
            self.length -= length;
            str_ptr
        }
    }

    /// 读取一个宽字符串 (长度前缀, UTF-16)
    pub fn extract_wstring(&mut self) -> *const u16 {
        let length = self.extract_int();
        if length <= 0 || self.length < length {
            warn!("[!] datap: invalid wstr length");
            return std::ptr::null();
        }

        unsafe {
            let wstr_ptr = self.buffer as *const u16;
            self.buffer = self.buffer.add(length as usize);
            self.length -= length;
            wstr_ptr
        }
    }

    /// 提取指定长度的字节数组（length 为**输入**长度）
    pub fn extract_bytes(&mut self, length: i32) -> *const u8 {
        if length <= 0 || self.length < length {
            warn!("[!] datap: invalid bytes length");
            return std::ptr::null();
        }

        unsafe {
            let bytes_ptr = self.buffer;
            self.buffer = self.buffer.add(length as usize);
            self.length -= length;
            bytes_ptr
        }
    }

    /// CS-compatible extract: read 4-byte BE length, then that many bytes.
    /// Writes the length into `out_size` when non-null (CS `BeaconDataExtract` contract).
    pub fn extract_data(&mut self, out_size: *mut i32) -> *const u8 {
        let length = self.extract_int();
        if length <= 0 {
            if !out_size.is_null() {
                unsafe {
                    *out_size = 0;
                }
            }
            return std::ptr::null();
        }
        if !out_size.is_null() {
            unsafe {
                *out_size = length;
            }
        }
        self.extract_bytes(length)
    }

    /// 获取剩余数据长度
    pub fn length(&self) -> i32 {
        self.length
    }
}

/// Beacon 格式化输出缓冲区
#[repr(C)]
pub struct BeaconFormatBuffer {
    /// 原始缓冲区指针
    original: *mut u8,
    /// 当前写入位置
    buffer: *mut u8,
    /// 已写入长度
    length: i32,
    /// 缓冲区大小
    size: i32,
}

impl BeaconFormatBuffer {
    /// 创建新的格式化缓冲区
    pub fn new(max_size: i32) -> Self {
        #[cfg(target_os = "windows")]
        let buffer =
            crate::native::nt_alloc_rw(max_size as usize, true).unwrap_or(std::ptr::null_mut());

        #[cfg(not(target_os = "windows"))]
        let buffer = unsafe {
            extern "C" {
                fn malloc(size: usize) -> *mut u8;
            }
            malloc(max_size as usize)
        };

        Self {
            original: buffer,
            buffer,
            length: 0,
            size: max_size,
        }
    }

    /// 追加一个 int
    pub fn append_int(&mut self, value: i32) {
        if self.length + 4 > self.size {
            warn!("[!] fmtbuf: overflow");
            return;
        }

        unsafe {
            let bytes = value.to_be_bytes();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer, 4);
            self.buffer = self.buffer.add(4);
            self.length += 4;
        }
    }

    /// 追加一个 short
    pub fn append_short(&mut self, value: i16) {
        if self.length + 2 > self.size {
            warn!("[!] fmtbuf: overflow");
            return;
        }

        unsafe {
            let bytes = value.to_be_bytes();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer, 2);
            self.buffer = self.buffer.add(2);
            self.length += 2;
        }
    }

    /// 追加一个字符串 (带长度前缀) — used by Data packing helpers
    pub fn append_string(&mut self, str_ptr: *const u8, length: i32) {
        if self.length + 4 + length > self.size {
            warn!("[!] fmtbuf: overflow");
            return;
        }

        self.append_int(length);

        unsafe {
            std::ptr::copy_nonoverlapping(str_ptr, self.buffer, length as usize);
            self.buffer = self.buffer.add(length as usize);
            self.length += length;
        }
    }

    /// CS `BeaconFormatAppend`: raw byte append **without** length prefix.
    pub fn append_raw(&mut self, data: *const u8, length: i32) {
        if length <= 0 || data.is_null() {
            return;
        }
        if self.length + length > self.size {
            warn!("[!] fmtbuf: overflow");
            return;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(data, self.buffer, length as usize);
            self.buffer = self.buffer.add(length as usize);
            self.length += length;
        }
    }

    /// 追加一个宽字符串 (带长度前缀)
    pub fn append_wstring(&mut self, wstr_ptr: *const u16, length: i32) {
        if self.length + 4 + length > self.size {
            warn!("[!] fmtbuf: overflow");
            return;
        }

        self.append_int(length);

        unsafe {
            std::ptr::copy_nonoverlapping(wstr_ptr as *const u8, self.buffer, length as usize);
            self.buffer = self.buffer.add(length as usize);
            self.length += length;
        }
    }

    /// 获取缓冲区指针
    pub fn get_buffer(&self) -> *mut u8 {
        self.original
    }

    /// 获取已写入长度
    pub fn get_length(&self) -> i32 {
        self.length
    }

    /// 释放缓冲区
    pub fn free(self) {
        if !self.original.is_null() {
            #[cfg(target_os = "windows")]
            {
                crate::native::nt_free(self.original);
            }

            #[cfg(not(target_os = "windows"))]
            unsafe {
                extern "C" {
                    fn free(ptr: *mut u8);
                }
                free(self.original);
            }
        }
    }
}

// --- Beacon API C 导出函数 ---

/// BeaconDataParse - 初始化数据解析器
pub extern "C" fn BeaconDataParse(parser: *mut BeaconDataParser, buffer: *const u8, size: i32) {
    if parser.is_null() {
        return;
    }
    unsafe {
        *parser = BeaconDataParser::new(buffer, size);
    }
}

/// BeaconDataInt - 从解析器读取 int
pub extern "C" fn BeaconDataInt(parser: *mut BeaconDataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    unsafe { (*parser).extract_int() }
}

/// BeaconDataShort - 从解析器读取 short
pub extern "C" fn BeaconDataShort(parser: *mut BeaconDataParser) -> i16 {
    if parser.is_null() {
        return 0;
    }
    unsafe { (*parser).extract_short() }
}

/// BeaconDataLength - 获取解析器剩余数据长度
pub extern "C" fn BeaconDataLength(parser: *mut BeaconDataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    unsafe { (*parser).length() }
}

/// BeaconDataExtract — CS contract: `char *BeaconDataExtract(datap *parser, int *size)`
/// Reads a 4-byte big-endian length from the buffer, then that many bytes, and writes
/// the length into `*size` when non-null.
pub extern "C" fn BeaconDataExtract(parser: *mut BeaconDataParser, size: *mut i32) -> *const u8 {
    if parser.is_null() {
        return std::ptr::null();
    }
    unsafe { (*parser).extract_data(size) }
}

/// BeaconFormatAlloc - 分配格式化缓冲区
pub extern "C" fn BeaconFormatAlloc(format: *mut *mut BeaconFormatBuffer, max_size: i32) {
    if format.is_null() {
        return;
    }
    unsafe {
        let buffer = Box::into_raw(Box::new(BeaconFormatBuffer::new(max_size)));
        *format = buffer;
    }
}

/// BeaconFormatReset - 重置格式化缓冲区
pub extern "C" fn BeaconFormatReset(format: *mut BeaconFormatBuffer) {
    if format.is_null() {
        return;
    }
    unsafe {
        (*format).buffer = (*format).original;
        (*format).length = 0;
    }
}

/// BeaconFormatFree - 释放格式化缓冲区
pub extern "C" fn BeaconFormatFree(format: *mut BeaconFormatBuffer) {
    if format.is_null() {
        return;
    }
    unsafe {
        let buffer = Box::from_raw(format);
        buffer.free();
    }
}

/// BeaconFormatAppend - raw append (CS: no length prefix)
pub extern "C" fn BeaconFormatAppend(
    format: *mut BeaconFormatBuffer,
    data: *const u8,
    length: i32,
) {
    if format.is_null() || data.is_null() {
        return;
    }
    unsafe {
        (*format).append_raw(data, length);
    }
}

/// BeaconFormatPrintf — mini printf with up to 8 fixed trailing args (stable ABI).
/// Supports %s %d %i %u %x %X %p %c %% (enough for most BOFs).
pub unsafe extern "C" fn BeaconFormatPrintf(
    format: *mut BeaconFormatBuffer,
    fmt: *const i8,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
) {
    if format.is_null() || fmt.is_null() {
        return;
    }
    let args = [a1, a2, a3, a4, a5, a6, a7, a8];
    let rendered = mini_printf(fmt, &args);
    let bytes = rendered.as_bytes();
    (*format).append_raw(bytes.as_ptr(), bytes.len() as i32);
}

/// BeaconFormatToString - 获取格式化缓冲区内容
pub extern "C" fn BeaconFormatToString(format: *mut BeaconFormatBuffer, size: *mut i32) -> *mut u8 {
    if format.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        if !size.is_null() {
            *size = (*format).get_length();
        }
        (*format).get_buffer()
    }
}

/// BeaconFormatInt - 追加 int 到格式化缓冲区
pub extern "C" fn BeaconFormatInt(format: *mut BeaconFormatBuffer, value: i32) {
    if format.is_null() {
        return;
    }
    unsafe {
        (*format).append_int(value);
    }
}

/// BeaconPrintf — mini printf with up to 8 fixed trailing args (stable ABI, no nightly c_variadic).
/// Windows x64 / SysV: extra args after `fmt` land in the next registers/stack slots we capture.
pub unsafe extern "C" fn BeaconPrintf(
    _typ: i32,
    fmt: *const i8,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
) {
    if fmt.is_null() {
        return;
    }
    let args = [a1, a2, a3, a4, a5, a6, a7, a8];
    let msg = mini_printf(fmt, &args);
    if let Ok(mut o) = BOF_OUTPUT.lock() {
        o.push_str(&msg);
    }
}

/// Minimal printf for BOF output. `args` consumed left-to-right for each conversion.
/// Supports flags (- + 0), numeric width, length modifiers (h/l/ll/z), and the
/// conversions d i u x X p c s % — with %ls/%lc reading UTF-16 strings.
fn mini_printf(fmt: *const i8, args: &[usize]) -> String {
    let c_str = unsafe { CStr::from_ptr(fmt) };
    let s = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return String::from_utf8_lossy(c_str.to_bytes()).into_owned(),
    };
    let mut out = String::with_capacity(s.len() + 32);
    let mut ai = 0usize;
    let b = s.as_bytes();
    let mut i = 0usize;

    // Format `body` into a field honoring width / left-align / zero-pad.
    fn pad(out: &mut String, body: &str, width: usize, zero_pad: bool, left: bool) {
        if body.len() >= width {
            out.push_str(body);
            return;
        }
        let fill = width - body.len();
        if left {
            out.push_str(body);
            for _ in 0..fill {
                out.push(' ');
            }
        } else if zero_pad {
            // keep sign ahead of zeros for negative numbers
            if body.starts_with('-') {
                out.push('-');
                for _ in 0..fill {
                    out.push('0');
                }
                out.push_str(&body[1..]);
            } else {
                for _ in 0..fill {
                    out.push('0');
                }
                out.push_str(body);
            }
        } else {
            for _ in 0..fill {
                out.push(' ');
            }
            out.push_str(body);
        }
    }

    // Decode a NUL-terminated UTF-16 string.
    unsafe fn wide_to_string(p: usize) -> String {
        if p == 0 {
            return String::from("(null)");
        }
        let mut units = Vec::new();
        let mut wp = p as *const u16;
        for _ in 0..32768 {
            let u = *wp;
            if u == 0 {
                break;
            }
            units.push(u);
            wp = wp.add(1);
        }
        String::from_utf16_lossy(&units)
    }

    while i < b.len() {
        if b[i] != b'%' {
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= b.len() {
            out.push('%');
            break;
        }
        // flags
        let mut left = false;
        let mut zero_pad = false;
        while i < b.len() && matches!(b[i], b'-' | b'+' | b'#' | b' ' | b'0') {
            if b[i] == b'-' {
                left = true;
            }
            if b[i] == b'0' {
                zero_pad = true;
            }
            i += 1;
        }
        if left {
            zero_pad = false;
        }
        // width
        let mut width = 0usize;
        while i < b.len() && b[i].is_ascii_digit() {
            width = width * 10 + (b[i] - b'0') as usize;
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        // length modifier
        let mut long = 0u8; // 0 = default, 1 = l, 2 = ll
        if b[i] == b'l' {
            long = 1;
            i += 1;
            if i < b.len() && b[i] == b'l' {
                long = 2;
                i += 1;
            }
        } else if b[i] == b'h' {
            i += 1;
            if i < b.len() && b[i] == b'h' {
                i += 1;
            }
        } else if b[i] == b'z' || b[i] == b't' {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let spec = b[i] as char;
        i += 1;
        match spec {
            '%' => out.push('%'),
            's' => {
                let p = args.get(ai).copied().unwrap_or(0);
                ai += 1;
                let body = if long >= 1 {
                    unsafe { wide_to_string(p) }
                } else if p == 0 {
                    String::from("(null)")
                } else {
                    let cs = unsafe { CStr::from_ptr(p as *const i8) };
                    cs.to_string_lossy().into_owned()
                };
                pad(&mut out, &body, width, false, left);
            }
            'c' => {
                let v = args.get(ai).copied().unwrap_or(0);
                ai += 1;
                let body = if long >= 1 {
                    String::from_utf16_lossy(&[v as u16])
                } else {
                    String::from(v as u8 as char)
                };
                pad(&mut out, &body, width, false, left);
            }
            'd' | 'i' => {
                let v = args.get(ai).copied().unwrap_or(0);
                ai += 1;
                let body = if long >= 2 {
                    (v as i64).to_string()
                } else {
                    (v as i32).to_string()
                };
                pad(&mut out, &body, width, zero_pad, left);
            }
            'u' => {
                let v = args.get(ai).copied().unwrap_or(0);
                ai += 1;
                let body = if long >= 2 {
                    (v as u64).to_string()
                } else {
                    (v as u32).to_string()
                };
                pad(&mut out, &body, width, zero_pad, left);
            }
            'x' | 'X' => {
                let v = args.get(ai).copied().unwrap_or(0);
                ai += 1;
                let body = if long >= 2 {
                    if spec == 'x' {
                        format!("{:x}", v as u64)
                    } else {
                        format!("{:X}", v as u64)
                    }
                } else if spec == 'x' {
                    format!("{:x}", v as u32)
                } else {
                    format!("{:X}", v as u32)
                };
                pad(&mut out, &body, width, zero_pad, left);
            }
            'p' => {
                let v = args.get(ai).copied().unwrap_or(0);
                ai += 1;
                let body = format!("0x{:X}", v);
                pad(&mut out, &body, width, false, left);
            }
            other => {
                // unknown: keep literal
                out.push('%');
                out.push(other);
            }
        }
    }
    out
}

/// BeaconOutput - 输出原始数据
pub extern "C" fn BeaconOutput(_typ: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }

    let slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let msg = String::from_utf8_lossy(slice).into_owned();
    if let Ok(mut o) = BOF_OUTPUT.lock() {
        o.push_str(&msg);
    }
}

/// 获取 BOF 输出
pub fn get_bof_output() -> String {
    BOF_OUTPUT.lock().map(|o| o.clone()).unwrap_or_default()
}

/// 清空 BOF 输出
pub fn clear_bof_output() {
    if let Ok(mut o) = BOF_OUTPUT.lock() {
        o.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_data_parser() {
        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x0A, // int: 10
            0x00, 0x05, // short: 5
        ];

        let mut parser = BeaconDataParser::new(data.as_ptr(), data.len() as i32);

        assert_eq!(parser.extract_int(), 10);
        assert_eq!(parser.extract_short(), 5);
        assert_eq!(parser.length(), 0);
    }

    #[test]
    fn test_beacon_data_extract_reads_length_prefix() {
        // len=4 BE + "abcd"
        let data: Vec<u8> = vec![0x00, 0x00, 0x00, 0x04, b'a', b'b', b'c', b'd'];
        let mut parser = BeaconDataParser::new(data.as_ptr(), data.len() as i32);
        let mut size = -1i32;
        let p = parser.extract_data(&mut size);
        assert_eq!(size, 4);
        assert!(!p.is_null());
        let got = unsafe { std::slice::from_raw_parts(p, 4) };
        assert_eq!(got, b"abcd");
    }

    #[test]
    fn test_mini_printf_percent_s_and_d() {
        let hello = CString::new("hello").unwrap();
        let fmt = CString::new("msg=%s n=%d").unwrap();
        let out = mini_printf(
            fmt.as_ptr(),
            &[hello.as_ptr() as usize, 42usize, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(out, "msg=hello n=42");
    }

    #[test]
    fn test_format_append_is_raw_no_length_prefix() {
        let mut fmt = BeaconFormatBuffer::new(64);
        let data = b"xy";
        fmt.append_raw(data.as_ptr(), 2);
        assert_eq!(fmt.get_length(), 2);
        let buf = unsafe { std::slice::from_raw_parts(fmt.get_buffer(), 2) };
        assert_eq!(buf, b"xy");
        fmt.free();
    }

    #[test]
    fn test_format_buffer() {
        let mut buffer = BeaconFormatBuffer::new(1024);

        buffer.append_int(42);
        buffer.append_short(10);

        assert_eq!(buffer.get_length(), 6);

        buffer.free();
    }
}
