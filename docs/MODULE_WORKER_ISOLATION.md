# Module Isolation & In-Process BOF (v2)

> Module system v2 — 2026-08-08. Supersedes the `iso_host` universal-host design.

## Product modules

| Module   | Form                         | Execution model                                        |
|----------|------------------------------|--------------------------------------------------------|
| `bof`    | cdylib (`cupcake_mod_bof`)   | **In-process** classic BOF: COFF Manual-Mapped into the agent (fileless, no new process) |
| `inject` | EXE (`cupcake-inject-worker`)| **Sacrificial worker** process; shellcode runs in the child, not the agent |
| `ad`     | EXE (`cupcake-ad-worker`)    | **Sacrificial worker** process (Tier0/roast/graph; DCSync gated) |

Retired: `iso_host` (universal sacrificial host), `dotnet` / `execute_assembly`
(convert assemblies to shellcode, e.g. Donut, and use `inject`).

## Goal

Worker crash / leak / hang / output flood **must not** take down the Stage0 Agent
(C2 session, heartbeat, command queue).

Core split:

> `inject` / `ad` never run inside the agent — they execute only in
> independent, short-lived worker processes.
> `bof` is the deliberate exception: a classic Beacon-style COFF loader that
> runs **inside** the agent process, because "no file on disk, no new process"
> is the point of a BOF. Its safety comes from the loader sandbox, not process
> isolation (see "bof in-process design").

```text
Main Agent (Stage0)
  ├─ transport / heartbeat / command queue
  ├─ ModuleSupervisor (whitelist · CKMS verify · state · deadlines · circuit)
  ├─ bof module (Manual-Mapped cdylib; COFF loader + Beacon API shim)
  └─ IPC (length-prefixed job frame / JSON envelope)
       ├─ cupcake-inject-worker.exe   (short-lived per job; Job Object)
       └─ cupcake-ad-worker.exe       (short-lived per job; Job Object)
```

## Why bof is in-process

Requirements driving the design:

1. **Fileless** — the COFF image never touches disk; Manual-Map only.
2. **No new process** — sacrificial processes (and PPID spoofing) are
   high-signal for EDR; a BOF must look like ordinary agent work.
3. **Signature hygiene** — the agent must not land on disk pre-packed with
   Beacon*/BOF-engine strings. The BOF engine ships as an on-demand L2 module
   whose binary is string-erased (see Client/core/docs/OPSEC_WINDOWS_RESIDUAL.md)
   and wiped (PE header zeroed after map).

Accepted trade-off: a crashing BOF can take the agent. Mitigations:

- COFF loader validates structure before mapping (section/reloc/symbol checks);
  malformed images are rejected, not executed.
- Invocation is wrapped in `catch_unwind`; loader faults abort the job, not the agent
  (best-effort — a hard AV in mapped COFF code is unrecoverable by design of BOFs).
- `APP_MEM_MAP_STRICT` / header wipe keep the mapped image off forensic fast paths.

If isolation is acceptable for a given payload, prefer `inject` (shellcode) over bof.

## Rules

1. `inject` / `ad` are **never** Manual-Mapped or `LoadLibrary`'d in Stage0.
2. For workers, Stage0 only: stages bytes, verifies, tracks `WorkerState`,
   spawns the worker, forwards IPC, enforces timeout, kills via Job Object.
3. Server / UI `loaded_on_agent` means **worker_ready / registered** (inject, ad)
   or **mapped & ready** (bof: `bof:mem`), not "long-lived process running".
4. Thread isolation, `catch_unwind`, or `FreeLibrary` alone is **not** isolation
   for native code you do not trust — independent process is mandatory
   (which is exactly why untrusted/native payloads go to `inject`, not `bof`).

## Worker states (inject/ad — not agent state)

```text
Stopped → Starting → Ready → Busy
             ↓         ↓
           Failed ← Timeout → (restart / circuit open)
```

String surface (module status, not agent online/offline):

| State     | Surface string     |
|-----------|--------------------|
| Stopped   | `stopped`          |
| Starting  | `worker_starting`  |
| Ready     | `worker_ready`     |
| Busy      | `executing`        |
| Failed    | `failed`           |
| Timeout   | `timeout`          |

bof has no worker lifecycle: load modes reported by the agent are
`bof:mem` (mapped), plus `stub` / `absent` before/after unload.

## Worker lifecycle guarantees (inject/ad)

The `isolated-exec` path applies:

- every spawned worker is assigned to a Windows Job Object before input is sent;
- a failed Job Object assignment is a hard startup failure and the child is terminated;
- synchronous pipe I/O runs outside the Tokio executor; stdout/stderr lengths are bounded;
- deadlines are clamped to 1–300 seconds and timeout terminates the Job Object and child before cleanup;
- staged PE copies, inherited pipe handles, and process handles are cleaned on success and failure.

Main Agent retains only:

- Module whitelist (`bof` / `inject` / `ad`)
- Hash / HMAC package verify (CKMS)
- Worker status map (inject/ad) · mapped-module registry (bof)
- Request forward to child process (inject/ad)
- Deadline / timeout kill
- Crash auto-restart policy + consecutive-failure circuit breaker
- Pending request cleanup on worker exit
- Stop workers when Agent disconnects / process exits (Job Object KillOnJobClose)

**Forbidden in Stage0 for `inject` / `ad`:**

- `LoadLibrary` / Manual Map
- `mod_init` / `mod_invoke` / `mod_shutdown`
- Sharing pointers, threads, or heaps with workers

## IPC protocol bounds

Request (logical; inject uses binary job frame over stdin today):

```json
{
  "request_id": "...",
  "module_id": "inject",
  "operation": "execute",
  "payload_b64": "...",
  "deadline_ms": 30000
}
```

Response:

```json
{
  "request_id": "...",
  "status": "ok|error|timeout",
  "stdout": "...",
  "stderr": "...",
  "error_code": ""
}
```

Hard limits (Stage0 enforces):

| Limit              | Default   |
|--------------------|-----------|
| Max payload        | 8 MiB     |
| Max stdout/stderr  | 2 MiB ea  |
| Deadline           | 1s–300s   |
| Max concurrent     | 4         |
| Circuit open after | 5 fails   |

Worker no-response → timeout kill → fail pending → optional restart.

## Windows Job Object

Workers are assigned to a Job Object with:

- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — Agent exit cleans workers
- No orphan child processes after Agent restart
- Future: process / memory / handle limits

## Stage0 role per module

| Module   | Worker model                         | Stage0 role                                    |
|----------|--------------------------------------|------------------------------------------------|
| `bof`    | In-process mapped COFF runner        | CKMS verify → Manual-Map → invoke → unload     |
| `inject` | One-shot sacrificial EXE             | Stage PE bytes; spawn; IPC forward             |
| `ad`     | One-shot sacrificial EXE             | Stage PE bytes; spawn; IPC forward             |

## Anti-signature posture (bof path)

- Module engine (`cupcake_mod_bof.dll`) built with `max_level_off` logs,
  XOR-obfuscated carrier strings, no `#[no_mangle]` exports, `strip = "symbols"`.
- Build scripts (`server/scripts/build-*-module.ps1`) strip the PE debug
  directory (RSDS/PDB path) via `pe-strip-debug.py` and run `strings-gate.ps1`.
- On load: CKMS verify → Manual-Map → PE header wipe; `module_unload` unmaps.
- Runtime env surface uses generic `APP_*` names (no product brand).

## Acceptance criteria

```text
Worker crash (inject/ad) → Agent still heartbeats
Worker infinite loop     → Agent still handles new commands (deadline kill)
Worker output flood      → Agent transport not blocked (output cap + drop counter)
Worker force-killed      → Agent does not crash
Agent restart            → no residual Worker (Job Object kill-on-close)
bof: malformed COFF      → rejected before mapping, agent unaffected
bof: module_unload       → mapped image unmapped; list_loaded drops bof:mem
```

## Non-goals

- Cross-platform Job Object (Windows first)
- Shared-memory zero-copy IPC
- Policy-locked server-side module delete
- Surviving a hard AV inside mapped COFF (inherent to in-process BOF)

## Code map

| Area                           | Path                                      |
|--------------------------------|-------------------------------------------|
| Supervisor                     | `Client/core/src/module_supervisor/`      |
| COFF loader + Beacon shim      | `Client/core/src/loader/` · `modules/bof` |
| Manual-Map (pe_map)            | `Client/core/src/pe_map.rs`               |
| Product load / invoke bridge   | `Client/core/src/module_loader.rs`        |
| Inject sacrificial worker      | `Client/modules/inject/`                  |
| AD sacrificial worker          | `Client/modules/ad/`                      |
| Isolated exec spawn            | `Client/core/src/isolated_exec.rs`        |
| Module build scripts           | `server/scripts/build-{bof,inject,ad}-module.ps1` |
| Design                         | this file                                 |

## Platform split (Linux vs Windows) — 2026-08

Product L2 modules (`bof` / `inject` / `ad`) are Windows-only.

- Server `ListCatalog(agentUUID, agentOS)` filters the catalog using `modulePlatforms` + `IsModuleSupportedOnOS`.
- Push, auto-push (`MaybeAutoPushModule`), pack, and MCP confirm paths reject windows-only modules for non-windows agents.
- Client hard-gates: `is_module_supported_on_current_os`, `ensure_module_for_command`, and AD command surface in handler.rs (returns `unsupported_platform`).
- UI (ModulePanel / ModuleManager / Plugin lists) hides or disables entries for mismatched OS.
- Plugins declare `required_os` in manifest; `DeployPlugin` and UI respect it.

Agent OS comes from `SystemInfo::collect()` (register) → stored in `globals.Client.OS` and `agents.os`. All decisions must use the live reported value, not build-time or label-only.

Add new entries to `modulePlatforms` (module_service.go) when new platform-specific modules are introduced.
