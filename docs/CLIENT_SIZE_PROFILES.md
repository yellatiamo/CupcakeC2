# Client product model — sole tier `minimal`

## Product rule

**Only one Stage0 aggregate: `minimal`.**  
Deleted product tiers: `standard`, `full`, `beacon`.

```text
Stage0 (minimal)
  transport + crypto + module-loader + isolated-exec + Layer-A stealth
  + shell / fs / process / pty / socks

L2 (on demand)
  iso_host.bin  → BOF / .NET
  inject.bin    → process inject
```

## Cargo

```toml
default = ["ws", "minimal"]
minimal = [
  "post-ex", "pty", "socks", "encoding-support",
  "module-loader", "isolated-exec",
  # no mem-map: product L2 never Manual-Maps into Stage0
]
```

Builder **always** passes `--features <transport>,minimal`.  
Legacy API values `standard` / `full` / `beacon` are ignored with a log line.

Optional non-product features (manual only): `plugin`, `stealth-adv`, `logging`, `rt-multi`, `bof`, `dotnet`, `inject`, `mem-map`, `sleep-mask`.

Workspace L2 crates: `iso_host`, `modules/inject`, `modules/ad` only  
(legacy `modules/bof` / `modules/dotnet` removed — engine lives in `iso_host` PE).

## Measured size (Windows release, panic=abort, LTO fat)

| Build | Approx. |
|-------|---------|
| `ws,minimal` (before size pass, with mem-map) | ~948 KiB (`971264` B) |
| `ws,minimal` (no mem-map, rlib-only lib) | ~941 KiB (`963072` B) |
| `cupcake-iso-host` release | ~305 KiB (BOF/.NET engine PE) |

## Release profile

```toml
[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
```
