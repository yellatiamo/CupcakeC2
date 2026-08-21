# Server scripts

| Script | Purpose |
|--------|---------|
| `build-frontend.ps1` | `frontend-v2` → **`web/dist`** (`//go:embed web/dist/*`) |
| `build-bof-module.ps1` | L2 BOF engine → `storage/modules/bof.bin` (`app_rt.dll`) |
| `build-inject-module.ps1` | L2 inject PE → `storage/modules/inject.bin` |
| `build-ad-module.ps1` | L2 AD PE → `storage/modules/ad.bin` |
| `test-services.ps1` | Safe Go tests with `-tags nodonut` |
| `pe-strip-debug.py` | Wipe RSDS/PDB residual from PE |

## Repo root (recommended)

```powershell
# Everything
.\compile.ps1

# Server only (reuse existing web/dist)
.\compile.ps1 -Target server -SkipFrontend

# Lab binary name
.\compile.ps1 -Target server -OutputName tmp-server.exe

# Fast agent iterate (x64 WS only)
.\compile.ps1 -Target agent -AgentProfile core

# L2 modules only
.\compile.ps1 -Target modules -SkipModuleGate
```

Or call legacy wrappers:

```powershell
.\compile_server.ps1
.\compile_windows.ps1 -Profile product
```

## Frontend embed path

**Only** `server/web/dist` is embedded (`server/embed.go`).

```powershell
powershell -File scripts/build-frontend.ps1
```

Do **not** rely on `server/ui` (removed / obsolete).

## L2 modules

```powershell
powershell -File scripts/build-bof-module.ps1
powershell -File scripts/build-inject-module.ps1
powershell -File scripts/build-ad-module.ps1
# optional lab DCSync feature:
powershell -File scripts/build-ad-module.ps1 -WithDcsync
```

Artifacts land in `storage/modules/{bof,inject,ad}.bin` (stripped + strings-gated).

## Go tests (`test-services.ps1`)

AV often quarantines Donut-linked test binaries. Daily:

```powershell
cd server
powershell -File scripts/test-services.ps1
```

Full Donut path:

```powershell
powershell -File scripts/test-services.ps1 -WithDonut
```

Never leave `go test -c` artifacts on a scanned volume without exclusion.
