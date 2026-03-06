#Requires -Version 7.0
<#
.SYNOPSIS
    Invoke-Scrutiny.ps1 - Scrutiny orchestration wrapper (Phase 6 - Final)

.DESCRIPTION
    Full Windows-native orchestration for the Scrutiny syscall analysis engine.
    Supports live trace, baseline capture, behavioral diff, and real-time dashboard.

.PARAMETER Target
    Process to trace. Valid: targetProc0, targetProc1, targetProc2. Default: targetProc2

.PARAMETER Baseline
    Capture a clean run and store it as a named baseline for future comparison.

.PARAMETER Compare
    After tracing, automatically diff the result against the stored baseline.

.PARAMETER Dashboard
    Launch Scrutiny-Dashboard.ps1 in a new PowerShell window for live event streaming.

.PARAMETER Rebuild
    Force make clean && make before running.

.PARAMETER TailLines
    Number of JSONL lines to display in the post-run tail. Default: 20

.PARAMETER ScrutinyPath
    Repo root (Windows path). Defaults to the directory containing this script.

.EXAMPLE
    # Standard live trace
    .\Invoke-Scrutiny.ps1

    # Capture clean baseline for targetProc0
    .\Invoke-Scrutiny.ps1 -Target targetProc0 -Baseline

    # Trace targetProc2 and auto-diff against its stored baseline
    .\Invoke-Scrutiny.ps1 -Compare

    # Full demo mode: live trace + dashboard + auto-compare
    .\Invoke-Scrutiny.ps1 -Compare -Dashboard

    # Rebuild binaries first
    .\Invoke-Scrutiny.ps1 -Rebuild -Compare

.NOTES
    Requires: PowerShell 7+, WSL2 with gcc/make, sudo, python3
    Part of Scrutiny / HoneyBadger Vanguard - Phase 6
#>

[CmdletBinding()]
param(
    [ValidateSet('targetProc0','targetProc1','targetProc2')]
    [string]$Target       = 'targetProc2',
    [switch]$Baseline,
    [switch]$Compare,
    [switch]$Dashboard,
    [switch]$Rebuild,
    [int]$TailLines       = 20,
    [string]$ScrutinyPath = ''
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Banner {
    $w = '=' * 66
    Write-Host "`n$w" -ForegroundColor Cyan
    Write-Host '  SCRUTINY  //  HoneyBadger Vanguard  //  Phase 6' -ForegroundColor Cyan
    Write-Host "  $w" -ForegroundColor DarkCyan
    if ($Baseline) {
        Write-Host '  Mode    : BASELINE CAPTURE' -ForegroundColor Green
    } elseif ($Compare) {
        Write-Host '  Mode    : LIVE TRACE + BEHAVIORAL DIFF' -ForegroundColor Yellow
    } else {
        Write-Host '  Mode    : LIVE TRACE' -ForegroundColor White
    }
    Write-Host "  Target  : $Target" -ForegroundColor White
    Write-Host "  Repo    : $ScrutinyPath" -ForegroundColor DarkGray
    Write-Host $w -ForegroundColor Cyan
}

function Write-Step([string]$m)  { Write-Host "`n[*] $m" -ForegroundColor Yellow  }
function Write-Ok([string]$m)    { Write-Host "[+] $m"  -ForegroundColor Green   }
function Write-Err([string]$m)   { Write-Host "[!] $m"  -ForegroundColor Red     }
function Write-Info([string]$m)  { Write-Host "    $m"  -ForegroundColor DarkGray }
function Write-Warn([string]$m)  { Write-Host "[~] $m"  -ForegroundColor Yellow  }

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
        $out = wsl bash -c $cmd 2>&1
        if ($null -eq $out) { return '' }
        return ($out -join "`n")
    }
    wsl bash -c $cmd
    if ($LASTEXITCODE -ne 0) { throw "WSL command failed (exit $LASTEXITCODE)" }
}

function Get-LatestJsonl([string]$dir) {
    $wslDir = ConvertTo-WslPath $dir
    $r = (Invoke-Wsl "ls -t `"$wslDir`"/*.jsonl 2>/dev/null | head -1" -PassThru).Trim()
    if ($r) { return ConvertFrom-WslPath $r }
    return $null
}

function Get-LatestBaselineJsonl([string]$target) {
    $dir    = Join-Path $ScrutinyPath 'logs' 'baselines' $target
    $wslDir = ConvertTo-WslPath $dir
    $r = (Invoke-Wsl "ls -t `"$wslDir`"/*.jsonl 2>/dev/null | head -1" -PassThru).Trim()
    if ($r) { return ConvertFrom-WslPath $r }
    return $null
}

# ---------------------------------------------------------------------------
# JSONL tail with color-coding
# ---------------------------------------------------------------------------
function Show-JsonlTail([string]$path, [int]$n) {
    if (-not (Test-Path $path)) { Write-Info "Log not found: $path"; return }
    $sep  = '-' * 66
    $rows = @()
    try {
        $rows = Get-Content $path -Tail $n |
                ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } |
                Where-Object { $_ }
    } catch { Write-Warn "Could not parse JSONL: $path"; return }

    Write-Host "`n$sep" -ForegroundColor DarkCyan
    Write-Host ('  {0,-26} {1,-10} {2,5}  {3}' -f 'Syscall','Tier','Score','Timestamp') -ForegroundColor DarkCyan
    Write-Host $sep     -ForegroundColor DarkCyan

    foreach ($r in $rows) {
        $c = switch ($r.risk_tier) {
            'CRITICAL' { 'Red'      }
            'HIGH'     { 'Yellow'   }
            'MEDIUM'   { 'Cyan'     }
            default    { 'DarkGray' }
        }
        Write-Host ('  {0,-26} {1,-10} {2,5}  {3}' -f `
            $r.syscall_name, $r.risk_tier, $r.risk_score, $r.timestamp) -ForegroundColor $c
    }
    Write-Host $sep -ForegroundColor DarkCyan
}

# ---------------------------------------------------------------------------
# Event stats
# ---------------------------------------------------------------------------
function Show-EventStats([string]$path) {
    if (-not (Test-Path $path)) { return }
    $events    = Get-Content $path | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } | Where-Object { $_ }
    $total     = $events.Count
    $critical  = ($events | Where-Object { $_.risk_tier -eq 'CRITICAL' }).Count
    $high      = ($events | Where-Object { $_.risk_tier -eq 'HIGH'     }).Count
    $medium    = ($events | Where-Object { $_.risk_tier -eq 'MEDIUM'   }).Count
    $low       = ($events | Where-Object { $_.risk_tier -eq 'LOW'      }).Count
    $SCORES    = @{ CRITICAL=10; HIGH=7; MEDIUM=3; LOW=1 }
    $score     = ($critical * 10) + ($high * 7) + ($medium * 3) + ($low * 1)

    Write-Host ''
    Write-Host '  EVENT SUMMARY' -ForegroundColor DarkCyan
    Write-Host ('  {0,-16} {1,6}' -f 'Total events', $total)    -ForegroundColor White
    Write-Host ('  {0,-16} {1,6}' -f 'Threat score', $score)    -ForegroundColor White
    Write-Host ('  {0,-16} {1,6}' -f 'CRITICAL', $critical)     -ForegroundColor Red
    Write-Host ('  {0,-16} {1,6}' -f 'HIGH',     $high)         -ForegroundColor Yellow
    Write-Host ('  {0,-16} {1,6}' -f 'MEDIUM',   $medium)       -ForegroundColor Cyan
    Write-Host ('  {0,-16} {1,6}' -f 'LOW',      $low)          -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
if (-not $ScrutinyPath) { $ScrutinyPath = Split-Path -Parent $PSCommandPath }
if (-not (Test-Path $ScrutinyPath)) { Write-Err "Repo not found: $ScrutinyPath"; exit 1 }

$WslRoot    = ConvertTo-WslPath $ScrutinyPath
$BinDir     = Join-Path $ScrutinyPath 'bin'
$LogsDir    = Join-Path $ScrutinyPath 'logs'
$TargetBin  = Join-Path $BinDir $Target
$RunScript  = "$WslRoot/scrutiny_run.sh"
$MonitorPy  = "$WslRoot/src/monitor.py"
$DashScript = Join-Path $ScrutinyPath 'Scrutiny-Dashboard.ps1'

$RunMode = if ($Baseline) { 'baseline' } else { 'run' }

Write-Banner

# ---------------------------------------------------------------------------
# Step 1 — Build
# ---------------------------------------------------------------------------
Write-Step "Checking binaries..."
if ($Rebuild -or (-not (Test-Path $TargetBin))) {
    $buildCmd = if ($Rebuild) { 'make clean && make' } else { 'make' }
    Write-Step "Building ($buildCmd)..."
    wsl bash -c "cd $WslRoot && $buildCmd"
    Write-Ok "Build complete."
} else {
    Write-Ok "Binaries present. Use -Rebuild to force a rebuild."
}

# ---------------------------------------------------------------------------
# Step 2 — Optional: launch dashboard in new window
# ---------------------------------------------------------------------------
if ($Dashboard -and (Test-Path $DashScript)) {
    Write-Step "Launching live dashboard in new window..."
    Write-Info "The dashboard will auto-find the latest log once tracing starts."
    $dashArgs = "-NoExit -File `"$DashScript`" -ScrutinyPath `"$ScrutinyPath`""
    Start-Process pwsh -ArgumentList $dashArgs -WindowStyle Normal
    Write-Ok "Dashboard window launched."
    Start-Sleep -Seconds 2   # give it time to init before trace starts
}

# ---------------------------------------------------------------------------
# Step 3 — Run trace / baseline capture
# ---------------------------------------------------------------------------
$modeLabel = if ($Baseline) { 'BASELINE CAPTURE' } else { 'LIVE TRACE' }
Write-Step "$modeLabel for $Target (~120s, requires sudo)..."
Write-Info "You may be prompted for your WSL2 sudo password."

wsl bash -c "sudo bash $RunScript $Target $WslRoot $RunMode"

Write-Ok "Baseliner finished."

# ---------------------------------------------------------------------------
# Step 4 — Find the log that was just written
# ---------------------------------------------------------------------------
Write-Step "Locating output log..."

$jsonlPath = $null

if ($Baseline) {
    $jsonlPath = Get-LatestBaselineJsonl $Target
    if ($jsonlPath) {
        Write-Ok "Baseline log: $jsonlPath"
    }
} else {
    $jsonDir   = Join-Path $LogsDir $Target 'json'
    $jsonlPath = Get-LatestJsonl $jsonDir
    if ($jsonlPath) {
        Write-Ok "Run log: $jsonlPath"
    }
}

if (-not $jsonlPath -or -not (Test-Path $jsonlPath)) {
    Write-Err "Could not locate output log. Check WSL output above."
    exit 1
}

# ---------------------------------------------------------------------------
# Step 5 — If baseline mode: store it in the baseline library
# ---------------------------------------------------------------------------
if ($Baseline) {
    Write-Step "Storing baseline in library..."
    $wslJsonl = ConvertTo-WslPath $jsonlPath
    wsl bash -c "cd $WslRoot && python3 $MonitorPy --save-baseline `"$wslJsonl`" --target $Target"
    Write-Ok "Baseline '$Target' stored."
}

# ---------------------------------------------------------------------------
# Step 6 — Tail the JSONL
# ---------------------------------------------------------------------------
Write-Step "Recent events (last $TailLines)..."
Show-JsonlTail $jsonlPath $TailLines
Show-EventStats $jsonlPath

# ---------------------------------------------------------------------------
# Step 7 — Behavioral diff (if -Compare and not -Baseline)
# ---------------------------------------------------------------------------
if ($Compare -and -not $Baseline) {
    Write-Step "Running behavioral diff against stored baseline '$Target'..."

    $wslJsonl = ConvertTo-WslPath $jsonlPath
    $diffOut  = wsl bash -c "cd $WslRoot && python3 src/monitor.py --compare `"$wslJsonl`" --baseline-name $Target" 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Diff failed or no baseline stored yet."
        Write-Info "To capture a baseline first: .\Invoke-Scrutiny.ps1 -Target $Target -Baseline"
        $diffOut | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    } else {
        # Print diff output with tier-based coloring
        $diffOut | ForEach-Object {
            $line = $_
            if     ($line -match '\[!!!\]|CRITICAL|SUSPICIOUS')  { Write-Host $line -ForegroundColor Red    }
            elseif ($line -match '\[ ! \]|HIGH|ELEVATED')        { Write-Host $line -ForegroundColor Yellow }
            elseif ($line -match '\[ ~ \]|MEDIUM|FREQUENCY')     { Write-Host $line -ForegroundColor Cyan   }
            elseif ($line -match '\[CLEAN\]|No significant')     { Write-Host $line -ForegroundColor Green  }
            elseif ($line -match '^=+$|^-+$')                    { Write-Host $line -ForegroundColor DarkCyan }
            else                                                  { Write-Host $line -ForegroundColor White  }
        }
    }
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
$w = '=' * 66
Write-Host "`n$w"                    -ForegroundColor Cyan
Write-Host '  Scrutiny run complete.' -ForegroundColor Cyan
if ($Baseline) {
    Write-Host "  Baseline '$Target' captured and stored." -ForegroundColor Green
}
if ($jsonlPath) {
    Write-Host "  Log     : $jsonlPath" -ForegroundColor DarkGray
}
Write-Host "$w`n"                    -ForegroundColor Cyan
