#requires -Version 5.1
<#
.SYNOPSIS
  Build Vue frontend (embed path) + Go control plane.

.DESCRIPTION
  - frontend-v2 → server/web/dist  (//go:embed web/dist/* in server/embed.go)
  - go build ./cmd/server → server/cupcake-server.exe
  - Creates storage dirs; does not wipe DB.

.PARAMETER SkipFrontend
  Only rebuild Go binary (requires existing web/dist).

.PARAMETER SkipInstall
  Skip npm ci when node_modules already present.

.PARAMETER OutputName
  Default: cupcake-server.exe (also can set tmp-server.exe for lab).

.EXAMPLE
  .\compile_server.ps1
  .\compile_server.ps1 -SkipFrontend
  .\compile_server.ps1 -OutputName tmp-server.exe
#>
param(
    [switch]$SkipFrontend,
    [switch]$SkipInstall,
    [string]$OutputName = 'cupcake-server.exe'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$BaseDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerDir   = Join-Path $BaseDir 'server'
$FrontendDir = Join-Path $ServerDir 'frontend-v2'
$WebDistDir  = Join-Path $ServerDir 'web\dist'
$LegacyDist  = Join-Path $ServerDir 'dist'
$OutputFile  = Join-Path $ServerDir $OutputName

function Write-Step($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Fail($m) { Write-Host "  [!] $m" -ForegroundColor Red }

Write-Host ""
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host "     Cupcake C2 - Server + Frontend" -ForegroundColor Blue
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host ""

# ── tools ───────────────────────────────────────────────────────────────────
if (-not $SkipFrontend) {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Fail 'Node.js/npm not found'
        exit 1
    }
    Write-Ok "npm $(npm --version)"
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Fail 'Go not found'
    exit 1
}
Write-Ok "$(go version)"
Write-Host ""

# ── dirs ────────────────────────────────────────────────────────────────────
@(
    'server\storage\payloads',
    'server\storage\backups',
    'server\storage\logs',
    'server\storage\modules',
    'server\assets',
    'server\web\dist'
) | ForEach-Object {
    $p = Join-Path $BaseDir $_
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
}

# ── frontend → web/dist (embed path) ────────────────────────────────────────
if (-not $SkipFrontend) {
    if (-not (Test-Path $FrontendDir)) {
        Write-Fail "frontend missing: $FrontendDir"
        exit 1
    }
    Write-Step '[1/2] frontend-v2 → server/web/dist'
    Push-Location $FrontendDir
    try {
        if (-not $SkipInstall -or -not (Test-Path 'node_modules')) {
            if (-not (Test-Path 'node_modules')) {
                Write-Host '  [*] npm ci ...' -ForegroundColor Gray
                if (Test-Path 'package-lock.json') { npm ci } else { npm install }
                if ($LASTEXITCODE -ne 0) { throw 'npm install failed' }
            }
        }
        # Vite outDir is ../dist (server/dist). We always sync into web/dist for embed.
        Write-Host '  [*] npm run build ...' -ForegroundColor Gray
        npm run build
        if ($LASTEXITCODE -ne 0) { throw 'npm run build failed' }
    } finally {
        Pop-Location
    }

    $viteIndex = Join-Path $LegacyDist 'index.html'
    if (-not (Test-Path $viteIndex)) {
        Write-Fail "vite output missing: $viteIndex (check frontend-v2/vite.config.js outDir)"
        exit 1
    }

    # Always sync server/dist → server/web/dist for //go:embed web/dist/*
    if (Test-Path $WebDistDir) { Remove-Item -Recurse -Force $WebDistDir }
    New-Item -ItemType Directory -Force -Path $WebDistDir | Out-Null
    Copy-Item -Recurse -Force (Join-Path $LegacyDist '*') $WebDistDir
    if (-not (Test-Path (Join-Path $WebDistDir 'index.html'))) {
        Write-Fail "embed tree incomplete: $WebDistDir"
        exit 1
    }
    Write-Ok "frontend ready → $WebDistDir"
} else {
    if (-not (Test-Path (Join-Path $WebDistDir 'index.html'))) {
        Write-Fail "SkipFrontend but missing $WebDistDir\index.html — run without -SkipFrontend once"
        exit 1
    }
    Write-Step 'skip frontend (using existing web/dist)'
}
Write-Host ""

# ── Go server (cmd/server) ──────────────────────────────────────────────────
Write-Step "[2/2] go build ./cmd/server → $OutputName"
Push-Location $ServerDir
try {
    # Do not force go mod tidy every time (slow + network); only if go.mod newer than sum optional.
    Write-Host '  [*] go build (CGO=0, strip, trimpath) ...' -ForegroundColor Gray
    $env:CGO_ENABLED = '0'
    # package path: main under cmd/server; embed via cupcake-server module root
    go build -ldflags='-s -w' -buildvcs=false -trimpath -o $OutputName ./cmd/server
    if ($LASTEXITCODE -ne 0) {
        Write-Fail 'go build failed'
        exit 1
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $OutputFile)) {
    Write-Fail "missing output $OutputFile"
    exit 1
}
$mb = [math]::Round((Get-Item $OutputFile).Length / 1MB, 2)
Write-Host ""
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host "  [DONE] Server build complete" -ForegroundColor Green
Write-Host "  [+] binary : $OutputFile ($mb MB)" -ForegroundColor Green
Write-Host "  [+] embed  : $WebDistDir" -ForegroundColor Green
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host ""
