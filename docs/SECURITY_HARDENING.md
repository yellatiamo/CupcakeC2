# Security Hardening — Production Boundary

## Overview

This document tracks the first batch of production security hardening applied
to Server, MCP, and Client. The goal is fail-closed boundaries: missing
credentials, missing keys, or unknown endpoints must never silently degrade to
an open or cleartext path.

## 1. Server Origin validation

CORS and WebSocket Origin checks now use strict URL parsing instead of string
prefix/contains matching.

- `server/main.go` CORS `AllowOriginFunc` parses the Origin URL and compares
  scheme, hostname, and port explicitly.
- `server/pkg/globals/globals.go` `originAllowed()` is shared by both CORS and
  WebSocket upgraders. It rejects origins with paths, queries, fragments, or
  userinfo.
- Malicious subdomains like `http://localhost.attacker.example` are rejected.
- Tests: `server/pkg/globals/origin_test.go` covers same-host, port mismatch,
  malicious subdomain, IPv6, empty, and malformed origins.

## 2. MCP Server endpoint allowlist

MCP authorization changed from "HTTP method + path blacklist" to an explicit
endpoint allowlist with read/write capability.

- `server/pkg/middleware/auth.go` defines `mcpAllowlist` — every MCP-accessible
  route is declared with its method, prefix, and write flag.
- Read-only mode (default) rejects all write endpoints, not just non-GET
  methods.
- Unknown endpoints are denied by default — there is no "any GET is fine" path.
- Management paths (`/api/settings`, `/api/maintenance`, `/api/auth`,
  `/api/generate`, `/api/stager`, `/api/agents/connect`) are never in the MCP
  allowlist, even when read-only is off.
- Denials return a structured `error_code` (`mcp_disabled`, `mcp_read_only`,
  `mcp_endpoint_denied`) instead of bare 403 text.
- Tests: `server/pkg/middleware/mcp_policy_test.go` covers read-only allowed,
  read-only denied, write-allowed, management-path denied, and unknown denied.

## 3. MCP client fail-closed

- `MCPClient/client.py` removed the hardcoded default token. `C2_API_TOKEN`
  is required; missing token causes immediate startup failure.
- `c2_request()` now checks HTTP status codes and returns structured
  `{ok, status, error_code, message, data}` for 401, 403, 404, 5xx, timeout,
  and connection errors.
- `MCPClient/command_guard.py` can no longer be disabled via config. A config
  setting `"enabled": false` is ignored. Corrupt or unreadable config falls
  back to built-in rules with an error, not silent fail-open.

## 4. MCP token migration

- `server/pkg/store/db.go` `initDefaultAdmin()` no longer reuses the legacy
  `system_api_token` as the MCP token. On upgrade, a fresh random
  `mcp_api_token` is generated and the legacy token is cleared.
- Default policy remains fail-closed: `system_mcp_enabled=false`,
  `mcp_allowed_cidrs=127.0.0.1/32,::1/128`, `mcp_read_only=true`.

## 5. Panel session invalidation on password change

- `server/controllers/admin_controller.go` `HandleChangeMyPassword()` now
  rotates the bearer token on password change. The old session token is
  invalidated immediately and a new token is returned to the caller.
- A leaked token cannot survive a password change.

## 6. Client transport fail-closed

- `Client/core/src/transport/session_crypto.rs` rejects empty keys in
  `traffic_key()`, `seal_for_wire()`, `FragReassembler::push()`, and
  `open_wire_frame()`. Production builds never send or accept cleartext.
- `Client/core/src/transport/ws.rs` refuses to establish a WebSocket session
  when the Noise PSK is missing. The old "warn and continue" path is removed.
- `Client/core/src/transport/tcp.rs` refuses to establish a TCP session when
  the Noise PSK is missing.
- `Client/core/src/transport/tcp_bind.rs` refuses to accept a bind connection
  when the Noise PSK is missing.
- Tests: 4 new `session_crypto` tests verify empty-key rejection for seal,
  traffic_key, open_wire_frame, and reassembler push.

## 7. TCP bind address preservation

- `Client/core/src/main.rs` `run_bind_mode()` no longer rewrites the bind
  address to `0.0.0.0`. The configured host is preserved; when only a port is
  given, the default is `127.0.0.1` (loopback). Explicit `0.0.0.0` must be
  chosen by the operator.

## Verification (batch 1)

```text
Server:
  go test ./pkg/middleware/... ./pkg/globals/... ./controllers/...
  → ok (3 packages)

Client:
  cargo test --features minimal session_crypto --lib
  → 9 passed (5 existing + 4 new empty-key rejection tests)
```

---

# Batch 2 — Worker limits, Desktop relay, HTTP/file quotas

## 8. Worker output and resource limits (Client Rust)

### 8a. Inject worker reader thread (deadlock fix)

- `module_supervisor/mod.rs` `run_inject_via_iso_host` spawns a stdout reader
  thread **before** `WaitForSingleObject`, matching `run_job_blocking`.
- Prevents pipe-buffer deadlock when worker output exceeds ~64 KiB.

### 8b. Native worker bounded output

- `isolated_exec.rs` `run_native_job` uses `pipe_read_to_end_bounded(..., MAX_OUTPUT_BYTES)`
  (2 MiB) instead of reading up to 32 MiB then rejecting.
- Truncation terminates the Job Object / process and returns
  `worker output too large`.
- `native/spawn.rs` `apply_output_bound` is the pure cap used by the read loop.

### 8c–8d. Job Object fail-closed + resource limits

- `job_object.rs` `create()` returns `None` if limit configuration fails
  (no more `let _ = set_kill_on_close()`).
- Limits applied together with kill-on-close:
  - `active_process_limit` = 32
  - `job_memory_limit` = 512 MiB
  - `per_process_user_time_limit` = 60s CPU

### 8e. Agent exit cleanup

- `main.rs` each `run_*_mode` session end calls
  `module_supervisor::supervisor().stop_all()`.
- `utils::self_destruct` calls `stop_all()` before `process::exit`.

## 9. Server HTTP timeouts and file/plugin quotas

### 9a. Admin HTTP Server timeouts (P0)

- `main.go` `newAdminHTTPServer`:
  - `ReadHeaderTimeout` 10s
  - `ReadTimeout` 60s
  - `WriteTimeout` 300s
  - `IdleTimeout` 120s
  - `MaxHeaderBytes` 1 MiB

### 9b. Agent upload limits (P0)

- `transfer_service.go`: max file 256 MiB; RFC-4122 UUID required
  (`ValidateAgentUpload` / `ValidAgentUUID`).

### 9c. Plugin upload size + admin auth (P0)

- `plugin_controller.go`: max plugin file 64 MiB; SHA-256 stored on upload.
- `main.go` `/plugins/upload`, `/plugins/run`, `/plugins/delete` gated with
  `RequireAdmin()` (same as module delete / generate).

### 9d. Plugin hash trust chain (P1)

- `PluginMetadata.Hash` = lowercase hex SHA-256 of file bytes.
- `DeployPlugin` calls `VerifyPluginHash` before staging to the agent;
  mismatch refuses deploy and drops cache.

### 9e. Task output retention (P1)

- `command_store.go` `PurgeExpiredTaskLogs` removes `logs/task_*.txt` and
  matching DB rows older than N days (default 7;
  env `CUPCAKE_TASK_LOG_RETENTION_DAYS`).
- `StartTaskLogRetentionWorker` runs hourly from `main`.

## Verification (batch 2)

```text
Server:
  go test ./...
  → admin HTTP timeouts, transfer gates, plugin hash, retention,
    plugin RequireAdmin routes

Client:
  cargo test --features minimal --lib
  → job_object fail-closed, stop_all, MAX_OUTPUT_BYTES, apply_output_bound
```

## Not covered (later batches)

True remaining deferrals after Batches 1–7 (this document). Items already
shipped are **not** listed here.

- **Prometheus ecosystem** — no scrape-format `/metrics`, exporters, or PromQL; admin JSON `/api/metrics` only
- **HSM / production release signing** — HMAC trust keys + CI checksum/module inventory; no hardware key custody, no signed GitHub Releases, no client reproducible-build attestation
- **External PKI / sigstore** — package trust is HMAC-SHA256 + version anti-rollback (`pkg/trustchain`), not public-key PKI
- **Multi-tenant aggregate storage budgets** — per-file ceilings, min free disk reject (507), task-log retention; no per-user global quota dashboard
- **CI secret scan + syft/trivy SBOM gate** — linux server `sha256sum` + `go list -m all` artifacts; no gitleaks/trivy/syft hard fail yet
- **Rust clippy / `cargo fmt` hard gates** and MCP pytest suite

---

# Batch 3 — Route RBAC, MCP allowlist tighten, MCP audit, module admin gates

## 11. Full route RBAC matrix (viewer / operator / admin)

Roles: `viewer`, `operator`, `admin`. Aliases treated as admin:
`administrator`, `break-glass-admin`.

Helpers in `server/pkg/middleware/auth.go`:

- `IsAdminRole`, `IsOperatorOrAbove`, `IsViewerOrAbove`
- `RequireAdmin()`, `RequireOperator()`, `RequireViewer()`, `RequireRole(...)`

Route gates in `server/main.go` (min role):

| Min role | Routes |
|----------|--------|
| **viewer** (any authenticated) | GET dashboard, clients, history, listeners, tunnel/socks list, files list/read/download, processes list, plugins list/result, modules list/pack, resp; auth logout/password |
| **operator** | POST `/cmd`; files upload/delete; processes kill; tunnel/socks start/stop/delete; shell/pty WS; modules query POST |
| **admin** | modules upload/push/DELETE; plugins run/upload/delete; listeners mutate; clients DELETE/migrate; agents/connect; settings/*; generate/stager; maintenance |

Tests: `server/controllers/rbac_routes_test.go` — viewer denied on `/cmd` and kill;
operator denied on modules upload/push and plugins; admin (and aliases) allowed.

## 12. MCP allowlist tighten

High-risk writes are **removed from `mcpAllowlist` entirely** (denied even when
`mcp_read_only=false`):

- `/api/files/delete`, `/api/files/upload`
- `/api/processes/kill`
- `/api/plugins/run`, `/api/plugins/upload`
- `/api/modules/push`, `/api/modules/upload`, `/api/modules/query`
- `/api/tunnel/*` and `/api/socks/*` write paths

Sole MCP write when read-only is off: **`POST /api/cmd`**.

All previous read GETs remain. Tests updated in
`server/pkg/middleware/mcp_policy_test.go`.

## 13. MCP audit logging

- Model: `model.AuditLog` (principal, username, role, method, path, client_ip,
  status, error_code, message, timestamp).
- Store: `store.SaveAuditLog` / `GetAuditLogs`; AutoMigrate in `db.go`.
- On MCP deny: write audit with `status=denied` and structured `error_code`.
- On MCP allow: after `c.Next()`, log HTTP status for method/path.
- Best-effort (no panic if DB nil — unit tests without InitDB still pass).

## 14. Module admin gates + plugin hash fail-closed

- `POST /api/modules/upload` and `POST /api/modules/push` use `RequireAdmin()`
  (same plane as module DELETE / plugin management).
- `VerifyPluginHash`: empty hash **fails** by default. Lab migration only:
  `CUPCAKE_ALLOW_LEGACY_PLUGIN_HASH=1`. Tests in `plugin_hash_test.go`.

## Verification (batch 3)

```text
Server (from server/):
  go test ./pkg/middleware/... ./controllers/... ./services/... ./pkg/store/...
  → RBAC matrix, MCP allowlist, role helpers, plugin hash fail-closed, store
```

---

# Batch 4 — Public stager hardening + health probes (E + J-min)

## 15. Public stager delivery hardening

Unauthenticated stager routes (agent first-stage pull):

- `GET /api/s/bin/:id`, `GET /api/s/:id`, `GET /api/s/l/:id`
- `GET /api/stage2/:id`, `GET /api/s/stage2/:id`

| Control | Behavior |
|---------|----------|
| **Rate limit** | Fixed window **30 req / minute / client IP** (`pkg/stagerguard`). Exceeded → **429** + `Retry-After: 60`. |
| **Max hits** | Each cache id allows **N downloads** (default **5**, env `CUPCAKE_STAGER_MAX_HITS`). After max → entry deleted, **404** (audit status `max_hits`). |
| **TTL** | Unchanged ~**10 minutes** for stager + stage2 cache. |
| **Audit** | Each hit via `logx` event `stager_public_access` with `ip`, `path`, `id`, `status` (`ok` / `404` / `429` / `expired` / `max_hits` / `bad_id`). |
| **Auth** | `/api/stage2/*` explicitly auth-exempt (same as `/api/s/*`). |

Implementation:

- `server/pkg/stagerguard/` — rate limiter, hit counter, audit, gin middleware
- `server/controllers/generate_controller.go` — `stagerCacheConsume` + audit on public handlers
- `server/services/fileless_service.go` — `ConsumeStage2` / `Stage2Exists` (loader peek does not burn stage2 hits)

Tests: `pkg/stagerguard/*_test.go`, `controllers/stager_cache_test.go`, `services` ConsumeStage2 max-hits.

## 16. Health endpoints (no auth)

| Path | Meaning |
|------|---------|
| `GET /healthz` or `GET /api/healthz` | Liveness: process up → **200** `{"status":"ok"}` |
| `GET /readyz` or `GET /api/readyz` | Readiness: `store.DB` ping → **200** `{"status":"ok"}`, else **503** `{"status":"not_ready","reason":"..."}` |

Registered in `main.go` **before** `AuthMiddleware`. Non-`/api` paths and `/api/healthz` `/api/readyz` are also skipped by auth.

```bash
curl -sS http://127.0.0.1:<admin_port>/healthz
curl -sS http://127.0.0.1:<admin_port>/readyz
```

## Verification (batch 4)

```text
Server (from server/):
  go test ./pkg/stagerguard/... ./controllers/... ./services/...
  → rate limiter, hit counter, stager cache max-hits/TTL, ConsumeStage2 max-hits
```

---

# Batch 5 — Light observability (J-metrics partial)

## 17. Admin metrics JSON (`GET /api/metrics`)

**Admin-only** (`RequireAdmin`). No public `/metrics` scrape (agent counts and deny totals are operationally sensitive).

Simple JSON (zero Prometheus deps):

| Field | Source |
|-------|--------|
| `agents_online` | `globals.Clients` live map size |
| `agents_total` | `store.GetAllAgents()` count (0 if DB unavailable) |
| `mcp_denies_total` | In-memory atomic counter (`pkg/metrics`) |
| `rbac_denies_total` | In-memory atomic counter on `Require*` denials |
| `db_ok` | SQLite ping (same idea as `/readyz`) |
| `uptime_sec` | Seconds since process start |

Counters increment in:

- `denyMCP` + MCP IP allowlist failure → `mcp_denies_total`
- `RequireAdmin` / `RequireOperator` / `RequireViewer` / `RequireRole` denials → `rbac_denies_total`

```bash
# Panel session or admin bearer required
curl -sS -H "Authorization: Bearer <admin_session>" \
  http://127.0.0.1:<admin_port>/api/metrics
```

Example:

```json
{
  "agents_online": 1,
  "agents_total": 3,
  "mcp_denies_total": 0,
  "rbac_denies_total": 2,
  "db_ok": true,
  "uptime_sec": 3600
}
```

## 18. Admin audit log list

| Path | Auth |
|------|------|
| `GET /api/settings/logs/audit` | `RequireAdmin` (settings group) |
| `GET /api/settings/audit` | alias of the above |

Uses existing `store.GetAuditLogs(limit)` (MCP allow/deny rows). Query `?limit=` default **100**, max **500**.

```bash
curl -sS -H "Authorization: Bearer <admin_session>" \
  "http://127.0.0.1:<admin_port>/api/settings/logs/audit?limit=50"
```

## Verification (batch 5)

```text
Server (from server/):
  go test ./controllers/... ./pkg/middleware/...
  go build .
  → metrics JSON shape, admin gate, audit empty list without DB
```

---

# Batch 6 — CI scaffold (work package L, partial)

## 19. Multi-stack GitHub Actions CI

Added `.github/workflows/ci.yml` — runs on push/PR to `main`, `master`, and `0.0.5`.

| Job | Runner | Working dir | What it does |
|-----|--------|-------------|--------------|
| **go-server** | `ubuntu-latest` | `server/` | Go from `go.mod` (1.25.x); `go vet ./...`; `go test -tags nodonut ./...` (5m timeout; skips Donut-linked PE conversion) |
| **rust-client** | `windows-latest` | `Client/` | Rust stable; `cargo test -p cupcake-core --features minimal --lib`; clippy `continue-on-error: true` |
| **frontend** | `ubuntu-latest` | `server/frontend-v2/` | Node 20; `npm ci` + `npm run build` (lockfile) |
| **mcp-python** | `ubuntu-latest` | `MCPClient/` | Python 3.11; `python -m py_compile client.py command_guard.py` |

Caching: Go modules (`setup-go`), Cargo (`Swatinem/rust-cache`), npm (`setup-node` + package-lock). No secrets in workflow.

### Known limitations (scaffold)

- Rust job is **Windows-only** — Stage0 is productized for Windows (`cfg(windows)` syscalls/Job Objects/PE map); Linux lib tests would miss most product paths.
- Go CI uses **`-tags nodonut`** so unit tests do not link go-donut (AV-noisy / heavy PE conversion). Full Donut path remains manual / `scripts/test-services.ps1 -WithDonut`.
- Clippy and `cargo fmt --check` are not hard gates yet (clippy non-blocking; fmt skipped until tree is consistently formatted).
- MCP job is syntax-only (no pytest suite, no live server).
- Release signing, secret scan, and full SBOM tooling remain deferred (see Batch 7 + “Not covered”).

---

# Batch 7 — Trust chain, sessions, quotas, CI artifacts

Consolidates hardening that lands after Batch 6 (CI scaffold) and the
checksum/module-inventory job in this batch.

## 20. Plugin / module trust chain (`pkg/trustchain`)

- Canonical HMAC-SHA256 over `module_id|version|sha256|target|abi_version|signer`.
- `Sign` / `Verify` fail-closed on empty key, empty signature, or wrong MAC.
- `RollbackGuard.CheckAndCommit` refuses lower versions than last published.
- **Plugins:** hash + signature + rollback via `VerifyPluginTrust` before deploy;
  lab escapes: `CUPCAKE_ALLOW_UNSIGNED_PLUGIN=1`, `CUPCAKE_TRUST_REQUIRE_SIG=0`,
  `CUPCAKE_ALLOW_LEGACY_PLUGIN_HASH=1`.
- **Modules:** `{id}.trust.json` sidecar; `VerifyModuleBeforePush` before stage.
- Keys: `CUPCAKE_TRUST_HMAC_KEY` or `CUPCAKE_TRUST_DEV_KEYS=1` for tests.
- Not external PKI / HSM / sigstore (deferred).

## 21. Panel sessions + short-lived WS upgrade tickets

- Sessions: **token hash only**, TTL (`CUPCAKE_SESSION_TTL_HOURS`, default 24h),
  max 10 concurrent, revoke on logout/password change.
- Interactive WS (`/api/pty/*`, `/api/shell/*`, `/api/build/logs/*`):
  - **No** durable `?token=` session query auth.
  - Mint: `POST /api/auth/ws-ticket` `{"purpose":"pty"|"shell"|"build_logs"}`.
  - Connect once with `?ticket=` (single-use, default TTL 60s, max 300s).
  - `Authorization: Bearer <session>` still accepted on those paths.
- Package: `pkg/wsticket` + middleware Redeem; frontend-v2 mints tickets.

## 22. Disk / file quotas (server)

| Control | Limit |
|---------|--------|
| Agent upload (per file) | **256 MiB** + UUID path isolation |
| Min free disk before write | **100 MiB** (`CUPCAKE_MIN_FREE_DISK_MB`); else **HTTP 507** |
| Plugin upload | **64 MiB** + hash + disk check |
| Task log retention | default **7 days** |
| Stager public hits | rate limit + max hits (Batch 4) |

`RejectIfInsufficient` / `CheckDiskForWrite` in `services/disk_quota.go`.

## 24. CI checksum + lightweight SBOM inventory

`.github/workflows/ci.yml` job **`release-artifacts`** (`needs: go-server`,
`ubuntu-latest`):

1. `go build -o cupcake-server ./` (linux binary under `server/`)
2. `sha256sum cupcake-server > cupcake-server.sha256`
3. `go list -m all > go-modules.txt` and `sha256sum go-modules.txt > go-modules.txt.sha256`
4. `actions/upload-artifact@v4` name `cupcake-server-linux` (binary + checksums + module list; 14-day retention)

Existing jobs (`go-server`, `rust-client`, `frontend`, `mcp-python`) unchanged
in behavior; release job only runs after go tests pass.

## Verification (batch 7)

```text
Server (from server/):
  go test -tags nodonut ./...
  go build -o cupcake-server ./
  sha256sum cupcake-server
  go list -m all | head

CI:
  release-artifacts job uploads cupcake-server + .sha256 + go-modules.txt
```
