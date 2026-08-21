# Build L2 AD worker PE → storage/modules/ad.bin
#
# Prefer cupcake_ad_worker.dll (cdylib / reflective 4.0.2 path).
# Falls back to cupcake-ad-worker.exe if only the bin target was built.
#
# Usage: powershell -File scripts/build-ad-module.ps1
#        powershell -File scripts/build-ad-module.ps1 -WithDcsync   # lab only
param(
    [switch]$WithDcsync,
    [switch]$SkipGate
)

$ErrorActionPreference = 'Stop'
$ServerRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot   = Split-Path -Parent $ServerRoot
$ClientRoot = Join-Path $RepoRoot 'Client'
$OutDir     = Join-Path $ServerRoot 'storage\modules'
$Pkg        = 'cupcake-ad-worker'
$DstName    = 'ad.bin'
$StripPy    = Join-Path $PSScriptRoot 'pe-strip-debug.py'
$Gate       = Join-Path $ClientRoot 'scripts\strings-gate.ps1'

if (-not (Test-Path $ClientRoot)) { throw "Client tree not found: $ClientRoot" }

$feat = @()
if ($WithDcsync) { $feat += 'ad-dcsync' }

Write-Host "[*] cargo build -p $Pkg --release$(if ($feat.Count) { ' --features ' + ($feat -join ',') })"
Push-Location $ClientRoot
try {
    $env:RUSTFLAGS = "--remap-path-prefix `"$ClientRoot`"=."
    if ($feat.Count) {
        cargo build -p $Pkg --release --features ($feat -join ',')
    } else {
        cargo build -p $Pkg --release
    }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$rel = Join-Path $ClientRoot 'target\release'
$src = $null
foreach ($n in @('cupcake_ad_worker.dll', 'cupcake-ad-worker.exe')) {
    $c = Join-Path $rel $n
    if (Test-Path $c) { $src = $c; break }
}
if (-not $src) { throw 'built AD PE not found (dll or exe)' }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$dst = Join-Path $OutDir $DstName
Copy-Item -Force $src $dst

if (Test-Path $StripPy) {
    Write-Host '[*] stripping PE debug directory (RSDS/PDB)'
    python $StripPy $dst
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "[+] Installed $dst ($((Get-Item $dst).Length) bytes) from $(Split-Path $src -Leaf)"
Write-Host '    AD ops gated server-side (role + high-risk confirm).'

if (-not $SkipGate -and (Test-Path $Gate)) {
    & $Gate -Path $dst
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
