# Build L2 classic BOF module (in-process COFF runner) -> storage/modules/bof.bin
#
# Architecture v2: bof = cdylib mapped INTO the agent process via Manual-Map
# (fileless, no new process). The blob registered here is CKMS-packed+signed
# by the server on push.
#
# Post-processing: strips the RSDS/PDB debug-directory residue that survives
# `strip = "symbols"` on MSVC (see pe-strip-debug.py), then runs the strings gate.
#
# Usage:
#   powershell -File scripts/build-bof-module.ps1

$ErrorActionPreference = "Stop"
$ServerRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot   = Split-Path -Parent $ServerRoot
$ClientRoot = Join-Path $RepoRoot "Client"
$OutDir     = Join-Path $ServerRoot "storage\modules"
$DllName    = "app_rt.dll"
$StripPy    = Join-Path $PSScriptRoot "pe-strip-debug.py"
$Gate       = Join-Path $ClientRoot "scripts\strings-gate.ps1"

if (-not (Test-Path $ClientRoot)) {
    throw "Client tree not found: $ClientRoot"
}

Write-Host "[*] cargo build -p cupcake-mod-bof --release"
Push-Location $ClientRoot
try {
    cargo build -p cupcake-mod-bof --release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$src = Join-Path $ClientRoot "target\release\$DllName"
if (-not (Test-Path $src)) {
    throw "built DLL not found: $src"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$dst = Join-Path $OutDir "bof.bin"
Copy-Item -Force $src $dst

Write-Host "[*] stripping PE debug directory (RSDS/PDB path residue)"
python $StripPy $dst
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[+] Installed $dst ($((Get-Item $dst).Length) bytes)"
Write-Host "    Push via Modules UI; bof maps into the agent process (no file on target)."

if (Test-Path $Gate) {
    & $Gate -Path $dst
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
