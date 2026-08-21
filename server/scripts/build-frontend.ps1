# Build Vue frontend-v2 into server/web/dist (//go:embed web/dist/*).
# Usage:
#   powershell -File scripts/build-frontend.ps1
#   powershell -File scripts/build-frontend.ps1 -SkipInstall
param(
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
$ServerRoot = Split-Path -Parent $PSScriptRoot
$Fe         = Join-Path $ServerRoot 'frontend-v2'
$ViteOut    = Join-Path $ServerRoot 'dist'       # vite.config outDir: ../dist
$EmbedOut   = Join-Path $ServerRoot 'web\dist'   # go:embed web/dist/*

if (-not (Test-Path $Fe)) {
    throw "frontend-v2 not found: $Fe"
}

Set-Location $Fe
if (-not $SkipInstall -or -not (Test-Path 'node_modules')) {
    if (-not (Test-Path 'node_modules')) {
        Write-Host '[*] npm ci / install ...'
        if (Test-Path 'package-lock.json') { npm ci } else { npm install }
        if ($LASTEXITCODE -ne 0) { throw 'npm install failed' }
    }
}

Write-Host '[*] npm run build → server/dist then sync → server/web/dist'
npm run build
if ($LASTEXITCODE -ne 0) { throw 'npm run build failed' }

$srcIndex = Join-Path $ViteOut 'index.html'
if (-not (Test-Path $srcIndex)) {
    throw "build failed: $srcIndex missing"
}

if (Test-Path $EmbedOut) { Remove-Item -Recurse -Force $EmbedOut }
New-Item -ItemType Directory -Force -Path $EmbedOut | Out-Null
Copy-Item -Recurse -Force (Join-Path $ViteOut '*') $EmbedOut

if (-not (Test-Path (Join-Path $EmbedOut 'index.html'))) {
    throw "sync failed: $EmbedOut\index.html missing"
}

Write-Host "[+] Frontend ready for embed: $EmbedOut"
Write-Host '    //go:embed web/dist/*  (server/embed.go)'
Write-Host '    Legacy server/ui is obsolete — do not use.'
