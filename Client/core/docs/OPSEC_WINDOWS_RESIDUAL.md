# Windows API / OPSEC Residual Map

Last updated: 2026-07-22 (two-layer architecture)

This document lists **remaining Win32 / residual exposure** and the **default vs stealth-adv** split. Use it for OPSEC review and future migrations.

## Two-layer architecture

### Layer A — Default path (version-agnostic)

| Constraint | Rule |
|------------|------|
| OS version | Must not depend on a specific Windows build layout |
| Arch | Only `x86` / `x64` `cfg` differences allowed |
| Failure | Syscall → D/Invoke → Win32(PEB); never panic |

Includes: lazy SSN + gadget pool, process list/open/kill/thread, memory Nt*, base stack spoof, **CreateProcessW + dynamic attributes** spawn baseline.

### Layer B — `stealth-adv` (version-sensitive allowed)

| Constraint | Rule |
|------------|------|
| Compile gate | `feature = "stealth-adv"` (also via `full`) |
| Runtime gate | `stealth::version` (PEB / `RtlGetVersion`) |
| Failure | **Graceful fallback to Layer A**; no crash / total loss |

| Capability | Gate | Fallback |
|------------|------|----------|
| `NtCreateUserProcess` PPID | `major>=10 && build>=17763` (`NT_CREATE_USER_PROCESS_MIN_BUILD`) | `spawn_create_process_w_dyn` |
| Manual map ntdll | future | skip |
| Temporary unhook | future | skip |

Version helpers live in `stealth/version.rs` (Layer A implementation, used by Layer B gates).

## Call-chain policy (default Windows build)

| Priority | Path | When used |
|----------|------|-----------|
| 1 | Indirect syscall (x64 SSN + gadget pool) | Preferred for Nt* |
| 2 | ntdll D/Invoke (PEB + export hash) | SSN/gadget fail, or x86 default |
| 3 | Win32 via PEB hash (no IAT hard-import where possible) | Last resort for process/spawn/memory |

Caches (arch-agnostic): module base (`ntdll`/`kernel32`/`kernelbase`), export `(base, hash)→VA`.

Stack spoof: `stealth::stack::with_spoofed_stack` → **hard path on x64 Windows 10+ only** (return-address rewrite of *this image* frames via `RtlCaptureStackBackTrace` + synthetic RBP locals + ntdll gadgets). **Pre-Win10 (Win8.1 / Server 2012 R2 = 6.3) defaults to soft path** (stack noise only) — hard rewrite caused BEX64 / `StackHash` / `PCH_AB_FROM_ntdll` AVs under AppCompat. Override: `APP_STACK_POLICY=0|1`. RBP+8 rewrite requires validated frame pointer (omit-fp safe). **Not CET/shadow-stack proof.**

---

## Migrated (low residual)

| Capability | Implementation |
|------------|----------------|
| Process list | `NtQuerySystemInformation` → Toolhelp PEB fallback |
| Open / kill process | `NtOpenProcess` / `NtTerminateProcess` → OpenProcess/TerminateProcess PEB |
| Network adapters | IP Helper `GetAdaptersAddresses` (PEB) — shell `ipconfig` not used |
| Local users/groups | NetAPI `NetUserEnum` / `NetLocalGroupEnum` — shell `net user` not used |
| Hybrid shell | Built-ins = API; external = direct spawn + pipes (**no cmd/powershell**) |
| Interactive PTY stream (0x01) | **Default Mode A HybridSession** (cwd + line mode + stream pipes). Legacy cmd pipe: `APP_PTY_MODE=cmd` |
| Thread create (agent) | `NtCreateThreadEx` → CreateThread PEB |
| Wait / close | `NtWaitForSingleObject` / `NtClose` → Wait/CloseHandle PEB |
| ETW disable | `NtSetInformationProcess` syscall + spoof; fallback `EtwEventWrite` patch |
| AMSI patch | `NtProtectVirtualMemory` + spoof; only if `amsi.dll` already loaded |
| BOF section map | `NtOpenFile` / `NtCreateSection` / `NtMapViewOfSection` / `NtProtect*` |
| BOF format buffer | `NtAllocateVirtualMemory` / `NtFreeVirtualMemory` (not HeapAlloc) |
| .NET host load | PEB COM + **AppDomain.Load_3(byte[]) in-memory** (no temp file) |
| COM init (main) | Dynamic `CoInitializeEx` |

---

## Residual Win32 / high-signal points (still present)

### P0 — Process creation (dual path)

**Location:** `native/spawn.rs` → `spawn_spoofed_process`

| Step | Layer A (always) | Layer B (`stealth-adv` + build≥17763) |
|------|------------------|--------------------------------------|
| Find parent PID | Nt | same |
| Open parent | Nt | same |
| Create child | **CreateProcessW** + PEB attribute APIs | Prefer **NtCreateUserProcess** + `PS_ATTRIBUTE_PARENT_PROCESS` |
| On B failure | — | Automatic fallthrough to Layer A |
| Close handles | NtClose | NtClose |

**MVP limits (Layer B):** first command token should be an absolute image path; PATH search stays Layer A strength. Debug log: `spawn: nt_create_user_process ok` or `fallback CreateProcessW`.

**OPSEC note:** EDR still monitors process-create + parent spoof regardless of API; Layer B mainly reduces userland hook surface on CreateProcess.

### P1 — Optional / diagnostic UI

**Location:** `stealth/mod.rs` (`hide_console`, `setup_diagnostic_console`)

- `GetConsoleWindow` / `ShowWindow` / `AllocConsole` / `OutputDebugStringA` / `CreateFileA` / `WriteConsoleA`
- PEB-resolved; **production should skip** `setup_diagnostic_console` (only when `RUST_LOG` / debug).

### P1 — Heavy-op pacing (default on)

**Location:** `utils::opsec_heavy_pace*` — called before BOF (in-process mod_bof), native_exec, module load.

- Default random 300–1200 ms between heavy jobs (env `APP_PACE_MS`).
- Stage residual: INetCache `~DF*.dll` / `~DF*.tmp` (not `cpx_*` under %TEMP%).

### P1 — Sleep mask / heap walk (feature-gated)

**Location:** `stealth/mask.rs` (`sleep-mask` feature)

- May use heap walk APIs when enabled; **off by default**.

### P1 — BOF types only

**Location:** `loader/bof.rs`

- `winapi` PE headers / NT object attribute **types** (no HeapAlloc).
- Execution path is Nt* + module overload; entry call is direct function pointer into mapped `.text`.

### P2 — std / Tokio / Rust runtime

- Network, threads, allocators from the Rust std and Tokio still generate legitimate Win32/NT traffic.
- Full `#![no_std]` is **out of scope** for this agent.

### P2 — Remaining stealth-adv items

- Manual-map clean ntdll for SSN/gadget (still use lazy SSN; no hard offsets)
- Temporary per-stub unhook (fail → skip)
- Richer `NtCreateUserProcess` (env, std handles, PATH resolution)

---

## Stack spoof coverage matrix

| Path | Default `with_spoofed_stack` |
|------|------------------------------|
| `open_process` / `terminate_process` | Yes |
| `create_thread_ex` | Yes |
| `spawn_spoofed_process` | Yes |
| BOF `execute` (map/protect/go) | Yes |
| `patch_etw` / `patch_amsi` | Yes |
| Passive list alone | No (volume; uses Nt; spoof optional later) |
| Individual BOF `NtProtect` calls | Covered by outer BOF execute spoof |
| Dotnet CLR host | No (COM path residual) |

---

## Acceptance checklist

### Automated

```text
cd Client/core
cargo test --features "ws,standard" --lib
cargo test --features "ws,standard" --lib native::process::tests
```

### Manual (required — unit tests ≠ runtime OPSEC)

1. Start agent (debug): confirm log  
   `syscall layer: lazy resolved 0 on init (SSN on-demand)`
2. Exercise: heartbeat, `ps`, `kill` (safe PID), optional BOF, optional PPID spawn
3. Optional telemetry:
   - `dumpbin /imports` — expect no `CreateToolhelp32Snapshot` / hard `OpenProcess` / `CreateThread` / `HeapAlloc` from our code paths if features trimmed
   - Procmon: ntdll read volume vs pre–Phase-1 baseline
   - Sysmon: process-create parent PID vs spoof target

---

## Feature flags

| Feature | Stealth relevance |
|---------|-------------------|
| default / `standard` | Nt process path + lazy syscall **on** |
| `stealth-adv` | ETW/AMSI at startup; `NtCreateUserProcess` spawn attempt; future unhook/manual-map |
| `sleep-mask` | PE section XOR sleep; higher crash risk with async |

---

## Ownership for next work

1. **P1:** Harden NtCreateUserProcess (PATH, desktop, CREATE_NO_WINDOW parity)
2. **P1:** Dotnet CLR path stack spoof / further COM reduction
3. **P2:** Manual map ntdll / unhook under same version-gate pattern
4. **P2:** Hash seed rotation for `hash_api_name` (static signature)
