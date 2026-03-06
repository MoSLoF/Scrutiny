#Requires -Version 7.0
<#
.SYNOPSIS
    Invoke-Scrutiny.ps1 - PowerShell wrapper for the Scrutiny syscall analysis engine.

.PARAMETER Target
    WSL2 binary to trace. Valid: targetProc0, targetProc1, targetProc2. Default: targetProc2

.PARAMETER Rebuild
    Forces make clean && make before running.

.PARAMETER TailLines
    JSONL lines to display. Default: 20

.PARAMETER BaselineLog
    Windows path to a baseline .log for monitor.py comparison. Optional.

.PARAMETER ScrutinyPath
    Scrutiny repo root (Windows path). Default: auto-detected from script location.

.EXAMPLE
    .\Invoke-Scrutiny.ps1
    .\Invoke-Scrutiny.ps1 -Rebuild
    .\Invoke-Scrutiny.ps1 -Target targetProc0

.NOTES
    Requires PowerShell 7.0+, WSL2 (Ubuntu/Debian), sudo, gcc, make.
    Delegates launch+trace to scrutiny_run.sh (pure bash, no interpolation issues).
#>

[CmdletBinding()]
param(
    [ValidateSet('targetProc0','targetProc1','targetProc2')]
    [string]$Target = 'targetProc2',
    [string]$BaselineLog = '',
    [switch]$Rebuild,
    [int]$TailLines = 20,
    [string]$WazuhUrl  = '',
    [string]$WazuhUser = '',
    [System.Security.SecureString]$WazuhPass,
    [string]$ScrutinyPath = ''
)

$ErrorActionPreference = 'Stop'

function Write-Banner {
    $w = '=' * 62
    Write-Host $w -ForegroundColor Cyan
    Write-Host '  Scrutiny / HoneyBadger Vanguard - PowerShell Wrapper' -ForegroundColor Cyan
    Write-Host '  Phase 5 - Windows orchestration via WSL2'             -ForegroundColor Cyan
    Write-Host $w -ForegroundColor Cyan
}
function Write-Step([string]$m) { Write-Host "`n[*] $m" -ForegroundColor Yellow }
function Write-Ok([string]$m)   { Write-Host "[+] $m"  -ForegroundColor Green  }
function Write-Err([string]$m)  { Write-Host "[!] $m"  -ForegroundColor Red    }
function Write-Info([string]$m) { Write-Host "    $m"  -ForegroundColor Gray   }

function ConvertTo-WslPath([string]$p) {
    $p = $p.Replace('\','/')
    if ($p -match '^([A-Za-z]):(.*)$') {
        return "/mnt/$($Matches[1].ToLower())$($Matches[2])"
    }
    return $p
}

function ConvertFrom-WslPath([string]$p) {
    $p = $p.Trim()
    if ($p -match '^/mnt/([a-z])/(.+)$') {
        $drive = $Matches[1].ToUpper()
        $rest  = $Matches[2] -replace '/', '\'
        return "${drive}:\${rest}"
    }
    return $p
}

function Invoke-Wsl([string]$cmd, [switch]$PassThru) {
    if ($PassThru) {
        $out = wsl bash -c $cmd
        if ($null -eq $out) { return '' }
        return ($out -join "`n")
    }
    wsl bash -c $cmd
    if ($LASTEXITCODE -ne 0) { throw "WSL failed (exit $LASTEXITCODE): $cmd" }
}

function Get-LatestJsonl([string]$jsonDir) {
    $wslDir = ConvertTo-WslPath $jsonDir
    $r = (Invoke-Wsl "ls -t $wslDir/*.jsonl 2>/dev/null | head -1" -PassThru).Trim()
    if ($r) { return ConvertFrom-WslPath $r }
    return $null
}

function Show-JsonlTail([string]$path, [int]$n) {
    if (-not (Test-Path $path)) { Write-Info "Log not found: $path"; return }
    $sep  = '-' * 62
    $rows = Get-Content $path -Tail $n | ForEach-Object { $_ | ConvertFrom-Json }
    Write-Host "`n$sep" -ForegroundColor DarkCyan
    Write-Host ('  {0,-26} {1,-10} {2,5}  {3}' -f 'Syscall','Tier','Score','Timestamp') -ForegroundColor DarkCyan
    Write-Host $sep -ForegroundColor DarkCyan
    foreach ($r in $rows) {
        $c = switch ($r.risk_tier) {
            'CRITICAL' {'Red'} 'HIGH' {'Yellow'} 'MEDIUM' {'Cyan'} default {'Gray'}
        }
        Write-Host ('  {0,-26} {1,-10} {2,5}  {3}' -f `
            $r.syscall_name, $r.risk_tier, $r.risk_score, $r.timestamp) -ForegroundColor $c
    }
    Write-Host $sep -ForegroundColor DarkCyan
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Banner

if (-not $ScrutinyPath) { $ScrutinyPath = Split-Path -Parent $PSCommandPath }
if (-not (Test-Path $ScrutinyPath)) { Write-Err "Path not found: $ScrutinyPath"; exit 1 }

$WslRoot   = ConvertTo-WslPath $ScrutinyPath
$BinDir    = Join-Path $ScrutinyPath 'bin'
$LogsDir   = Join-Path $ScrutinyPath 'logs'
$TargetBin = Join-Path $BinDir $Target
$RunScript = "$WslRoot/scrutiny_run.sh"

Write-Info "Repo  : $ScrutinyPath"
Write-Info "WSL   : $WslRoot"
Write-Info "Target: $Target"

# ---------------------------------------------------------------------------
# Step 1: Build
# ---------------------------------------------------------------------------
Write-Step "Checking binaries..."
if ($Rebuild -or (-not (Test-Path $TargetBin))) {
    $buildCmd = if ($Rebuild) { 'make clean && make' } else { 'make' }
    Write-Step "Building ($buildCmd)..."
    Invoke-Wsl "cd $WslRoot && $buildCmd"
    Write-Ok "Build complete."
} else {
    Write-Ok "Binaries present. Use -Rebuild to force a rebuild."
}

# ---------------------------------------------------------------------------
# Step 2+3: Launch target AND attach baseliner via scrutiny_run.sh
#
# All process orchestration is delegated to scrutiny_run.sh (pure bash).
# This avoids every PS/WSL interpolation issue encountered with $!, &,
# here-strings, and background process lifetime across WSL session boundaries.
#
# scrutiny_run.sh:
#   - kills any leftover target instances
#   - launches target in background within the same bash session
#   - waits for binary startup line then pipes PID to sudo baseliner
#   - blocks until target exits (~120s for targetProc2)
# ---------------------------------------------------------------------------
Write-Step "Running scrutiny_run.sh for $Target (~120s, requires sudo)..."
Write-Info "You may be prompted for your WSL2 sudo password."

wsl bash -c "sudo bash $RunScript $Target $WslRoot"

Write-Ok "Baseliner finished."

# ---------------------------------------------------------------------------
# Step 4: Tail the JSONL output
# ---------------------------------------------------------------------------
Write-Step "Reading latest JSONL log..."

$jsonDir   = Join-Path $LogsDir $Target 'json'
$jsonlPath = Get-LatestJsonl $jsonDir
$allEvents = @()

if ($jsonlPath -and (Test-Path $jsonlPath)) {
    Write-Ok "Log: $jsonlPath"
    Show-JsonlTail $jsonlPath $TailLines

    $allEvents = Get-Content $jsonlPath | ForEach-Object { $_ | ConvertFrom-Json }
    $critCount = ($allEvents | Where-Object { $_.risk_tier -eq 'CRITICAL' }).Count
    $hiCount   = ($allEvents | Where-Object { $_.risk_tier -eq 'HIGH'     }).Count
    Write-Info "Total events : $($allEvents.Count)"
    Write-Info "CRITICAL     : $critCount"
    Write-Info "HIGH         : $hiCount"
} else {
    Write-Err "No JSONL log found in: $jsonDir"
}

# ---------------------------------------------------------------------------
# Step 5: Optional monitor.py comparison
# ---------------------------------------------------------------------------
if ($BaselineLog) {
    Write-Step "Running monitor.py comparison..."
    wsl bash -c "cd $WslRoot && python3 src/monitor.py"
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
$fin = '=' * 62
Write-Host "`n$fin"                   -ForegroundColor Cyan
Write-Host "  Scrutiny run complete." -ForegroundColor Cyan
if ($jsonlPath) { Write-Host "  JSONL : $jsonlPath" -ForegroundColor Cyan }
Write-Host "$fin`n"                   -ForegroundColor Cyan
