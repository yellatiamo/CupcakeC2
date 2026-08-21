#requires -Version 5.1
<#
.SYNOPSIS
  Unified Cupcake C2 build entry (Windows host).

.DESCRIPTION
  Targets:
    server   - frontend embed + Go control plane
    agent    - Windows agent templates → server/assets
    modules  - L2 bof / inject / ad → storage/modules
    frontend - Vue only → web/dist
    all      - server + agent(product) + modules

.PARAMETER Target
  One or more of: all, server, agent, modules, frontend

.PARAMETER AgentProfile
  product | core | all  (passed to compile_windows.ps1)

.PARAMETER WireSeed
  Optional; also read from env / server/config.json

.PARAMETER SkipFrontend
  When building server, skip npm and reuse web/dist

.EXAMPLE
  .\compile.ps1
  .\compile.ps1 -Target server,modules
  .\compile.ps1 -Target agent -AgentProfile core
  .\compile.ps1 -Target server -OutputName tmp-server.exe -SkipFrontend
#>
param(
    [ValidateSet('all', 'server', 'agent', 'modules', 'frontend')]
    [string[]]$Target = @('all'),

    [ValidateSet('product', 'core', 'all')]
    [string]$AgentProfile = 'product',

    [string]$WireSeed = '',

    [switch]$SkipFrontend,

    [string]$OutputName = 'cupcake-server.exe',

    [switch]$SkipModuleGate
)

$ErrorActionPreference = 'Stop'
$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $BaseDir

function Invoke-Step([string]$Name, [scriptblock]$Body) {
    Write-Host ""
    Write-Host "======== $Name ========" -ForegroundColor Magenta
    & $Body
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "step failed: $Name (exit $LASTEXITCODE)"
    }
}

$want = [System.Collections.Generic.HashSet[string]]::new([string[]]$Target)
if ($want.Contains('all')) {
    [void]$want.Add('server')
    [void]$want.Add('agent')
    [void]$want.Add('modules')
    [void]$want.Remove('all')
}

Write-Host ""
Write-Host "  Cupcake build  targets=[$($want -join ', ')]" -ForegroundColor Blue
Write-Host ""

$sw = [System.Diagnostics.Stopwatch]::StartNew()

if ($want.Contains('frontend') -and -not $want.Contains('server')) {
    Invoke-Step 'frontend' {
        $args = @('-NoProfile', '-File', (Join-Path $BaseDir 'server\scripts\build-frontend.ps1'))
        & powershell @args
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}

if ($want.Contains('server')) {
    Invoke-Step 'server' {
        $args = @(
            '-NoProfile', '-File', (Join-Path $BaseDir 'compile_server.ps1'),
            '-OutputName', $OutputName
        )
        if ($SkipFrontend) { $args += '-SkipFrontend' }
        & powershell @args
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}

if ($want.Contains('agent')) {
    Invoke-Step 'agent-templates' {
        $args = @(
            '-NoProfile', '-File', (Join-Path $BaseDir 'compile_windows.ps1'),
            '-Profile', $AgentProfile
        )
        if ($WireSeed) { $args += @('-WireSeed', $WireSeed) }
        & powershell @args
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}

if ($want.Contains('modules')) {
    $modScripts = @(
        'build-bof-module.ps1',
        'build-inject-module.ps1',
        'build-ad-module.ps1'
    )
    foreach ($s in $modScripts) {
        Invoke-Step "module $s" {
            $path = Join-Path $BaseDir "server\scripts\$s"
            $args = @('-NoProfile', '-File', $path)
            if ($SkipModuleGate) { $args += '-SkipGate' }
            & powershell @args
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
    }
}

$sw.Stop()
Write-Host ""
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host "  [DONE] all selected targets  ($([math]::Round($sw.Elapsed.TotalSeconds,1))s)" -ForegroundColor Green
Write-Host "  =========================================" -ForegroundColor Blue
Write-Host ""
