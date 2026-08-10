# Build L2 AD sacrificial worker -> storage/modules/ad.bin
#
# Architecture v2: ad = standalone short-lived worker EXE (process isolation)
# for Tier0 / roast / graph ops; DCSync stays behind the ad-dcsync feature
# and the server-side high-risk gate (KD-18). Release builds keep ad-dcsync OFF.
#
# Post-processing: strips RSDS/PDB debug-directory residue (pe-strip-debug.py),
# then runs the strings gate.
#
# Usage:
#   powershell -File scripts/build-ad-module.ps1

$ErrorActionPreference = "Stop"
$ServerRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot   = Split-Path -Parent $ServerRoot
$ClientRoot = Join-Path $RepoRoot "Client"
$OutDir     = Join-Path $ServerRoot "storage\modules"
$ExeName    = "cupcake-ad-worker.exe"
$StripPy    = Join-Path $PSScriptRoot "pe-strip-debug.py"
$Gate       = Join-Path $ClientRoot "scripts\strings-gate.ps1"

if (-not (Test-Path $ClientRoot)) {
    throw "Client tree not found: $ClientRoot"
}

Write-Host "[*] cargo build -p cupcake-ad-worker --release"
Push-Location $ClientRoot
try {
    cargo build -p cupcake-ad-worker --release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$src = Join-Path $ClientRoot "target\release\$ExeName"
if (-not (Test-Path $src)) {
    throw "built EXE not found: $src"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$dst = Join-Path $OutDir "ad.bin"
Copy-Item -Force $src $dst

Write-Host "[*] stripping PE debug directory (RSDS/PDB path residue)"
python $StripPy $dst
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[+] Installed $dst ($((Get-Item $dst).Length) bytes)"
Write-Host "    Push via Modules UI; AD ops are gated (role + high-risk confirm)."

if (Test-Path $Gate) {
    & $Gate -Path $dst
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
