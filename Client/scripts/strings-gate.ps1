# Fail if high-signal brand / diagnostic / path strings remain in a release binary.
# Wire-protocol command tokens (bof_exec, module_stage, …) are intentionally allowed —
# they are required for server↔agent matching and are not product brand IoCs.
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Path)) {
    Write-Error "file not found: $Path"
    exit 2
}
$bytes = [IO.File]::ReadAllBytes((Resolve-Path $Path))
$text = [Text.Encoding]::ASCII.GetString($bytes)
$banned = @(
    # Brand / project path
    'cupcake-noise-v2',
    'cupcake-mod-key-v1',
    'CUPCAKE_MODULE_KEY',
    'CupcakeC2',
    '[Cupcake]',
    'CUPCAKE_TRACE',
    'C2-dev-main',
    # Legacy ASCII protocol brands (must be seed-derived now)
    'CKMS',
    'CKF1',
    'CIS1',
    # Report IoC: agent diagnostics
    '[agent]',
    'Sending Register',
    'Gadget pool',
    'TCP hardened',
    'SystemInfo collected',
    'Connection driver',
    # Report IoC: config placeholders (must not appear as contiguous plaintext)
    'REPLACE_ME_URL',
    'REPLACE_ME_AES',
    'REPLACE_ME_SLEEP',
    'REPLACE_ME_',
    'KDF_SALT',
    # Report IoC: capability / version slogans
    'no LoadLibrary fallback',
    '4.0.2',
    'reflective inject',
    'Fragment encryption',
    'AES-256 requires',
    'no usable traffic key',
    'WindowStyleHidden',
    'powershell.exe',
    'POST /api/v1/sync',
    'shellunload',
    'APP_MEM_MAP',
    'APP_DEBUG_FILE',
    # Project identity in absolute form only (relative core\src also appears in libstd)
    'C2-dev-main\Client',
    'reflective_loader.rs',
    'session_crypto.rs'
)
$hits = @()
foreach ($s in $banned) {
    if ($text.Contains($s)) { $hits += $s }
}
if ($hits.Count -gt 0) {
    Write-Host "STRINGS GATE FAIL: $Path" -ForegroundColor Red
    $hits | ForEach-Object { Write-Host "  HIT: $_" }
    exit 1
}
Write-Host "STRINGS GATE OK: $Path" -ForegroundColor Green
exit 0
