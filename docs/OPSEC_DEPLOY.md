# OPSEC deploy notes (agent + control plane)

> Updated: 2026-08-08 · module system v2 (bof | inject | ad)

## Control plane defaults

| Item | Safe default |
|------|----------------|
| `admin_bind` | `127.0.0.1` |
| `admin_pass` | empty → random on first boot |
| Lab only | `CUPCAKE_FORCE_DEV_PASS=1` → admin/`cupcake123` (**never production**) |
| Config sample | `server/config.example.json` (real `config.json` is gitignored) |

## Tunnel credentials

- SOCKS/HTTP proxy passwords are **bcrypt-hashed** in DB.
- List API does not return password material (`has_auth` only).
- Legacy plaintext rows still verify until next start rewrite.

## Malleable profile (WS)

- Agent rewrites path via `uri_template` + injects profile headers.
- Listener accepts **any** WebSocket path (catch-all) so gmail/outlook URIs work.
- Optional: set listener `profile` + `profile_strict`, or env `CUPCAKE_PROFILE_STRICT=1`.

## Agent build profiles

| Profile | Use |
|---------|-----|
| `minimal` | **Default red-team** reverse/forward |
| `standard` | Monolith forward extras |
| `full` / `stealth-adv` | Loud; only if you accept ETW/AMSI hunting |

## Heavy ops

- BOF runs **in-process** via module `bof` (Manual-Map, fileless) — no sacrificial host anymore; do not burst jobs.
- .NET is **retired**: convert assemblies to shellcode (e.g. Donut) and use `inject`.
- `APP_PACE_MS` pacing (default 300–1200 ms).
- Avoid `native_exec`/fscan early.

## Process inject (L2 module only)

Stage0 **does not** include inject. On demand:

```powershell
cd server
powershell -File scripts/build-inject-module.ps1
# cargo build -p cupcake-inject-worker --release
# → target/release/cupcake-inject-worker.exe → storage/modules/inject.bin
# (also strips the PE debug directory and runs the strings gate)
```

Operator:

1. Panel Modules → upload/push `inject` to agent (or auto-push on `module_required:inject`)
2. Command type `process_inject`, content JSON:

```json
{"pid": 1234, "data": "<base64 shellcode>", "method": "auto", "wait_ms": 0}
```

3. `module_unload` id=`inject` after use

OPSEC: remote VirtualAllocEx + thread create is high-signal; use sparingly, unload after.

## Unit tests vs AV (`services.test.exe`)

Package `services` used to always link **go-donut**, so Defender often deletes the package test binary.

**Daily (safe):**

```powershell
cd server
powershell -File scripts/test-services.ps1
# go test ./services/ -tags nodonut -count=1
```

**Never:**

```powershell
go test -c ./services/    # drops services.test.exe into server/ → AV magnet
```

**Donut path (lab / may be killed):**

```powershell
powershell -File scripts/test-services.ps1 -WithDonut -Compile
```

Production `go build` is unchanged (real Donut included).

## Wire seed (production)

Client `build.rs` and server `WireIDs` **must** share the same seed.

| Priority | Source |
|----------|--------|
| 1 | Env `CUPCAKE_WIRE_SEED` |
| 2 | `server/config.json` → `wire_seed` |
| 3 | DB setting `wire_seed` |
| 4 | Generate once (`wire-gen-…`), write to config.json + DB |

- Retired public default `wire-v1-default-2026` is rejected.
- Builder always sets `CUPCAKE_WIRE_SEED` from `utils.WireSeed()` when compiling agents.

## Agent build injection (Builder)

Source placeholders in `Client/core/src/config.rs` (must remain until Builder runs):

| Token | Injected as |
|-------|-------------|
| `REPLACE_ME_URL` | Listener C2 URL (`ws://` / `wss://` / …) |
| `REPLACE_ME_AES_KEY` | 32-byte ASCII or 64 hex AES base key |
| `REPLACE_ME_SALT` | Encryption salt (padded to 32 bytes at runtime) |
| `REPLACE_ME_OBF` | Packet obfuscation (`padding` default; empty/`none` forced to `padding`) |
| `REPLACE_ME_JITTER` | Heartbeat jitter percent |

Unpatched **release** agents: empty server URL → `invalid_target` (no lab localhost fallback).

## Noise v2 + agent/server alignment (required)

| Item | Rule |
|------|------|
| Handshake | **Noise v2 only**: 49-byte frames (`0x02 \|\| pubkey32 \|\| psk_mac16`) |
| PSK | Listener AES **base** key — same bytes as agent `get_aes_key_base()` (32 ASCII or 64 hex). Short keys rejected (no zero-pad). |
| Legacy | 33-byte v1 handshake is **rejected** on WS/TCP |
| Register | Agent `reg_proof` = HMAC(session_key, seed-derived-domain\|\|uuid) (both ends from wire seed) |
| Deploy | Rebuild **both** `cupcake-server` and agent after protocol/seed changes |

```powershell
cd server
# 1) Edit config.json (admin_bind / wire_seed / pass)
# 2) go build -o cupcake-server.exe .
# 3) Start server once — note printed admin password if generated
# 4) Create listener with 32-byte AES key + obfuscation=padding
# 5) Panel generate / Builder → patches REPLACE_ME_* + CUPCAKE_WIRE_SEED
```

## L2 inject methods (panel / API)

`process_inject` JSON `method`: `nt` | `crt` | `apc` | `stomping` | `auto`  
(`auto` = stomping → apc → nt fallback chain.)

## WSS / JA3 (起步)

Default `ws` feature uses platform TLS. For **rustls + cipher order by profile ja3_hint**:

```powershell
cargo build -p cupcake-core --no-default-features --features "ws,ws-tls,minimal" --release
```

Not full browser JA3 (no GREASE / extension order). Suite order differs for chrome/edge vs firefox vs aws/github hints.

## Frontend embed

```powershell
cd server
powershell -File scripts/build-frontend.ps1
# → dist/ only (//go:embed dist/*)
```

Do not use legacy `server/ui/`.

## Yamux debug

Default silent. Enable only in lab:

```text
set CUPCAKE_YAMUX_DEBUG=1
```
