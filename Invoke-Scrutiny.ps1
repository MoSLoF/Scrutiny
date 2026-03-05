#Requires -Version 7.0
<#
.SYNOPSIS
    Invoke-Scrutiny.ps1 - PowerShell wrapper for the Scrutiny syscall analysis engine.

.DESCRIPTION
    Orchestrates the full Scrutiny pipeline from Windows via WSL2:
      1. Optionally rebuilds the C binaries (make clean && make)
      2. Launches a target process in WSL2
      3. Pipes the PID to sudo bin/baseliner for syscall capture
      4. Tails the JSON Lines log in real time to the PowerShell console
      5. Runs monitor.py comparison when a baseline log is supplied
      6. Optionally forwards CRITICAL events to a Wazuh REST API endpoint

    Part of the Scrutiny project - HoneyBadger Vanguard fork.
    https://github.com/MoSLoF/Scrutiny

.PARAMETER Target
    WSL2 binary to trace. Relative to the Scrutiny bin/ directory.
    Valid values: targetProc0, targetProc1, targetProc2
    Default: targetProc2

.PARAMETER BaselineLog
    Path (Windows or WSL2) to a baseline .log file for monitor.py comparison.
    If omitted, the comparison step is skipped.

.PARAMETER Rebuild
    Forces a full 'make clean && make' before running.
    Without this flag, existing binaries are used if present.

.PARAMETER TailLines
    Number of recent JSONL lines to display during live tail.
    Default: 20

.PARAMETER WazuhUrl
    Optional. Wazuh REST API base URL for forwarding CRITICAL events.
    Example: https://wazuh-manager:55000
    Requires -WazuhUser and -WazuhPass.

.PARAMETER WazuhUser
    Wazuh API username. Required with -WazuhUrl.

.PARAMETER WazuhPass
    Wazuh API password as SecureString. Required with -WazuhUrl.

.PARAMETER ScrutinyPath
    Full Windows path to the Scrutiny repo root.
    Default: auto-detected from script location.

.EXAMPLE
    # Basic run - trace targetProc2, tail output live
    .\Invoke-Scrutiny.ps1

.EXAMPLE
    # Rebuild first, then trace
    .\Invoke-Scrutiny.ps1 -Rebuild

.EXAMPLE
    # Full pipeline: rebuild, trace, compare against baseline
    .\Invoke-Scrutiny.ps1 -Rebuild -BaselineLog "logs\targetProc0\2026-03-05_12-38.log"

.EXAMPLE
    # Forward CRITICAL events to Wazuh
    $pass = Read-Host -AsSecureString "Wazuh password"
    .\Invoke-Scrutiny.ps1 -WazuhUrl "https://192.168.1.100:55000" -WazuhUser "wazuh" -WazuhPass $pass

.NOTES
    Requirements:
      - PowerShell 7.0+
      - WSL2 with a Debian/Ubuntu distribution
      - sudo configured for the WSL2 user (for ptrace)
      - gcc / make available in WSL2
#>

[CmdletBinding()]
param(
    [ValidateSet('targetProc0', 'targetProc1', 'targetProc2')]
    [string]$Target = 'targetProc2',

    [string]$BaselineLog = '',

    [switch]$Rebuild,

    [int]$TailLines = 20,

    [string]$WazuhUrl = '',

    [string]$WazuhUser = '',

    [System.Security.SecureString]$WazuhPass,

    [string]$ScrutinyPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Banner {
    $width = 62
    $line  = '=' * $width
    Write-Host $line                                    -ForegroundColor Cyan
    Write-Host '  Scrutiny / HoneyBadger Vanguard - PowerShell Wrapper'   -ForegroundColor Cyan
    Write-Host '  Phase 5 - Windows orchestration via WSL2'                -ForegroundColor Cyan
    Write-Host $line                                    -ForegroundColor Cyan
}

function Write-Step([string]$msg) {
    Write-Host "`n[*] $msg" -ForegroundColor Yellow
}

function Write-Ok([string]$msg) {
    Write-Host "[+] $msg" -ForegroundColor Green
}

function Write-Err([string]$msg) {
    Write-Host "[!] $msg" -ForegroundColor Red
}

function Write-Info([string]$msg) {
    Write-Host "    $msg" -ForegroundColor Gray
}

function ConvertTo-WslPath([string]$winPath) {
    # D:\06-WORKSPACE\... -> /mnt/d/06-WORKSPACE/...
    $winPath = $winPath.Replace('\', '/')
    if ($winPath -match '^([A-Za-z]):(.*)$') {
        $drive = $Matches[1].ToLower()
        $rest  = $Matches[2]
        return "/mnt/$drive$rest"
    }
    return $winPath
}

function Invoke-Wsl([string]$cmd, [switch]$PassThru) {
    if ($PassThru) {
        return wsl bash -c $cmd
    }
    wsl bash -c $cmd
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed (exit $LASTEXITCODE): $cmd"
    }
}

function Get-LatestJsonl([string]$jsonDir) {
    $wslJsonDir = ConvertTo-WslPath $jsonDir
    $result = Invoke-Wsl "ls -t '$wslJsonDir'/*.jsonl 2>/dev/null | head -1" -PassThru
    if ($result) {
        # Convert back to Windows path for Get-Content
        $wslPath = $result.Trim()
        # /mnt/d/... -> D:\...
        if ($wslPath -match '^/mnt/([a-z])/(.*)$') {
            return "$($Matches[1].ToUpper()):\$($Matches[2].Replace('/', '\'))"
        }
    }
    return $null
}

function Show-JsonlTail([string]$jsonlPath, [int]$lines) {
    if (-not (Test-Path $jsonlPath)) {
        Write-Info "No JSONL log found at: $jsonlPath"
        return
    }

    $SEP  = '-' * 62
    $rows = Get-Content $jsonlPath -Tail $lines |
            ForEach-Object { $_ | ConvertFrom-Json }

    Write-Host "`n$SEP" -ForegroundColor DarkCyan
    Write-Host ('  {0,-26} {1,-10} {2,5}  {3}' -f 'Syscall', 'Tier', 'Score', 'Timestamp') -ForegroundColor DarkCyan
    Write-Host $SEP -ForegroundColor DarkCyan

    foreach ($row in $rows) {
        $color = switch ($row.risk_tier) {
            'CRITICAL' { 'Red'     }
            'HIGH'     { 'Yellow'  }
            'MEDIUM'   { 'Cyan'    }
            default    { 'Gray'    }
        }
        $line = '  {0,-26} {1,-10} {2,5}  {3}' -f `
            $row.syscall_name, $row.risk_tier, $row.risk_score, $row.timestamp
        Write-Host $line -ForegroundColor $color
    }
    Write-Host $SEP -ForegroundColor DarkCyan
}

function Send-ToWazuh {
    param(
        [object[]]$Events,
        [string]$BaseUrl,
        [string]$User,
        [System.Security.SecureString]$Pass
    )

    # Build basic auth header
    $plainPass = [System.Net.NetworkCredential]::new('', $Pass).Password
    $pair      = "${User}:${plainPass}"
    $b64       = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $headers   = @{ Authorization = "Basic $b64" }

    # POST each CRITICAL event as a JSON alert to Wazuh active-response endpoint
    $endpoint = "$BaseUrl/active-response"
    $sent     = 0

    foreach ($evt in $Events) {
        if ($evt.risk_tier -ne 'CRITICAL') { continue }
        $body = $evt | ConvertTo-Json -Compress
        try {
            $null = Invoke-RestMethod -Uri $endpoint -Method Post `
                        -Headers $headers -Body $body `
                        -ContentType 'application/json' `
                        -SkipCertificateCheck
            $sent++
        }
        catch {
            Write-Err "Wazuh POST failed for $($evt.syscall_name): $_"
        }
    }
    Write-Ok "Forwarded $sent CRITICAL event(s) to Wazuh at $BaseUrl"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Banner

# Resolve Scrutiny repo root
if (-not $ScrutinyPath) {
    $ScrutinyPath = Split-Path -Parent $PSCommandPath
}
if (-not (Test-Path $ScrutinyPath)) {
    Write-Err "Scrutiny path not found: $ScrutinyPath"
    exit 1
}

$WslRoot  = ConvertTo-WslPath $ScrutinyPath
$BinDir   = Join-Path $ScrutinyPath 'bin'
$LogsDir  = Join-Path $ScrutinyPath 'logs'
$TargetBin = Join-Path $BinDir $Target

Write-Info "Repo  : $ScrutinyPath"
Write-Info "WSL   : $WslRoot"
Write-Info "Target: $Target"

# ---------------------------------------------------------------------------
# Step 1: Build
# ---------------------------------------------------------------------------
Write-Step "Checking binaries..."

$needBuild = $Rebuild -or (-not (Test-Path $TargetBin))

if ($needBuild) {
    $buildCmd = if ($Rebuild) { 'make clean && make' } else { 'make' }
    Write-Step "Building ($buildCmd)..."
    Invoke-Wsl "cd '$WslRoot' && $buildCmd"
    Write-Ok "Build complete."
}
else {
    Write-Ok "Binaries present. Skipping build. (Use -Rebuild to force.)"
}

# ---------------------------------------------------------------------------
# Step 2: Launch target process in WSL2
# ---------------------------------------------------------------------------
Write-Step "Launching $Target in WSL2..."

# Run target in background, capture PID
$pidScript = "cd '$WslRoot' && bin/$Target & echo `$!"
$targetPid = (Invoke-Wsl $pidScript -PassThru).Trim()

if ($targetPid -notmatch '^\d+$') {
    Write-Err "Failed to get PID for $Target. Got: '$targetPid'"
    exit 1
}
Write-Ok "$Target launched with PID $targetPid"

# ---------------------------------------------------------------------------
# Step 3: Attach baseliner via sudo
# ---------------------------------------------------------------------------
Write-Step "Attaching baseliner to PID $targetPid (requires sudo)..."
Write-Info "You may be prompted for your WSL2 sudo password."

# Pipe PID to baseliner's stdin; inherit console so sudo prompt is visible
$baselinerCmd = "cd '$WslRoot' && echo $targetPid | sudo bin/baseliner"
wsl bash -c $baselinerCmd

Write-Ok "Baseliner finished."

# ---------------------------------------------------------------------------
# Step 4: Tail the JSONL output
# ---------------------------------------------------------------------------
Write-Step "Reading latest JSONL log..."

$jsonDir   = Join-Path $LogsDir $Target 'json'
$jsonlPath = Get-LatestJsonl $jsonDir

if ($jsonlPath -and (Test-Path $jsonlPath)) {
    Write-Ok "Log: $jsonlPath"
    Show-JsonlTail $jsonlPath $TailLines

    # Collect all events for optional Wazuh forwarding
    $allEvents = Get-Content $jsonlPath | ForEach-Object { $_ | ConvertFrom-Json }
    $critCount = ($allEvents | Where-Object { $_.risk_tier -eq 'CRITICAL' }).Count
    $hiCount   = ($allEvents | Where-Object { $_.risk_tier -eq 'HIGH'     }).Count
    Write-Info "Total events : $($allEvents.Count)"
    Write-Info "CRITICAL     : $critCount"
    Write-Info "HIGH         : $hiCount"
}
else {
    Write-Err "Could not find JSONL log in $jsonDir"
}

# ---------------------------------------------------------------------------
# Step 5: Optional monitor.py comparison
# ---------------------------------------------------------------------------
if ($BaselineLog) {
    Write-Step "Running monitor.py comparison..."

    # Resolve baseline path to WSL2
    $wslBaseline = if ($BaselineLog -match '^[A-Za-z]:') {
        ConvertTo-WslPath $BaselineLog
    } else {
        "$WslRoot/$BaselineLog"
    }

    $wslTarget = ConvertTo-WslPath $jsonlPath.Replace('.jsonl', '.log')
    # Fall back to latest .log if path math fails
    $latestLog = (Invoke-Wsl "ls -t '$WslRoot/logs/$Target'/*.log 2>/dev/null | head -1" -PassThru).Trim()
    if ($latestLog) { $wslTarget = $latestLog }

    $monitorCmd = "cd '$WslRoot' && python3 src/monitor.py --baseline '$wslBaseline' --target '$wslTarget' 2>&1 || python3 src/monitor.py"
    Write-Info "This will open the file picker if monitor.py runs interactively."
    wsl bash -c "cd '$WslRoot' && python3 src/monitor.py"
}

# ---------------------------------------------------------------------------
# Step 6: Optional Wazuh forwarding
# ---------------------------------------------------------------------------
if ($WazuhUrl -and $WazuhUser -and $WazuhPass -and $allEvents) {
    Write-Step "Forwarding CRITICAL events to Wazuh..."
    Send-ToWazuh -Events $allEvents -BaseUrl $WazuhUrl `
                 -User $WazuhUser -Pass $WazuhPass
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host "`n$('=' * 62)" -ForegroundColor Cyan
Write-Host "  Scrutiny run complete." -ForegroundColor Cyan
if ($jsonlPath) {
    Write-Host "  JSONL : $jsonlPath" -ForegroundColor Cyan
}
Write-Host "$('=' * 62)`n" -ForegroundColor Cyan
