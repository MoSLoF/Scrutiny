#Requires -Version 7.0
<#
.SYNOPSIS
    Scrutiny-Dashboard.ps1 - Real-time syscall event dashboard

.DESCRIPTION
    Streams a live JSONL log as it is written by baseliner. Displays a
    color-coded event feed, running tier counters, threat score meter,
    and top-N syscall frequency table. Polls the file for new lines.

.PARAMETER JsonlPath
    Full Windows path to the .jsonl file to tail. If omitted, waits for
    a new file to appear under logs\ (auto-discovery mode).

.PARAMETER RefreshMs
    Poll interval in milliseconds. Default: 500

.PARAMETER TopN
    Rows in the top-syscall frequency table. Default: 10

.PARAMETER ScrutinyPath
    Repo root. Defaults to the directory containing this script.

.EXAMPLE
    # Auto-discovery (launched by Invoke-Scrutiny.ps1 -Dashboard)
    .\Scrutiny-Dashboard.ps1

    # Explicit path
    .\Scrutiny-Dashboard.ps1 -JsonlPath "D:\...\logs\targetProc2\json\2026-03-06_10-49.jsonl"
#>

[CmdletBinding()]
param(
    [string]$JsonlPath    = '',
    [int]$RefreshMs       = 500,
    [int]$TopN            = 10,
    [string]$ScrutinyPath = ''
)

$ErrorActionPreference = 'Stop'

if (-not $ScrutinyPath) { $ScrutinyPath = Split-Path -Parent $PSCommandPath }
$LogsDir = Join-Path $ScrutinyPath 'logs'

# ---------------------------------------------------------------------------
# Auto-discovery: wait for a NEW .jsonl to appear (not in baselines\)
# We record what exists now, then wait until something new shows up.
# ---------------------------------------------------------------------------
function Wait-ForNewJsonl([string]$logsDir, [int]$timeoutSec = 180) {
    $before = Get-ChildItem -Path $logsDir -Recurse -Filter '*.jsonl' -File -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -notmatch '\\baselines\\' } |
              Select-Object -ExpandProperty FullName

    Write-Host "`n  Waiting for a new JSONL log to appear..." -ForegroundColor Yellow
    Write-Host "  (Run Invoke-Scrutiny.ps1 now if you haven't already)" -ForegroundColor DarkGray

    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $after = Get-ChildItem -Path $logsDir -Recurse -Filter '*.jsonl' -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -notmatch '\\baselines\\' } |
                 Select-Object -ExpandProperty FullName

        $newFiles = $after | Where-Object { $_ -notin $before }
        if ($newFiles) {
            # Return the newest one
            return ($newFiles | Sort-Object { (Get-Item $_).LastWriteTime } -Descending | Select-Object -First 1)
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Resolve the target JSONL
# ---------------------------------------------------------------------------
if ($JsonlPath -and (Test-Path $JsonlPath)) {
    Write-Host "`n  Attaching to specified log: $JsonlPath" -ForegroundColor Cyan
} else {
    if ($JsonlPath) {
        Write-Host "  Specified path not found: $JsonlPath" -ForegroundColor Yellow
        Write-Host "  Switching to auto-discovery mode." -ForegroundColor Yellow
    }
    $JsonlPath = Wait-ForNewJsonl $LogsDir
    if (-not $JsonlPath) {
        Write-Host "[!] Timed out waiting for a new JSONL. Exiting." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Discovered: $JsonlPath" -ForegroundColor Green
    Start-Sleep -Milliseconds 300   # let baseliner write a few lines first
}

# ---------------------------------------------------------------------------
# Risk tier helpers
# ---------------------------------------------------------------------------
$CRITICAL_SYSCALLS = [System.Collections.Generic.HashSet[string]]@(
    'execve','execveat','connect','sendto','sendmsg','sendmmsg',
    'ptrace','init_module','finit_module','delete_module',
    'kexec_load','kexec_file_load','bpf','process_vm_writev')
$HIGH_SYSCALLS = [System.Collections.Generic.HashSet[string]]@(
    'socket','access','faccessat','chmod','fchmod','fchmodat',
    'chown','fchown','lchown','fchownat','kill','tkill','tgkill',
    'setuid','setgid','setreuid','setregid','setresuid','setresgid',
    'setfsuid','setfsgid','capset','mount','umount2','chroot',
    'pivot_root','prctl','seccomp')
$MEDIUM_SYSCALLS = [System.Collections.Generic.HashSet[string]]@(
    'open','openat','openat2','read','write','unlink','unlinkat',
    'rename','renameat','renameat2','fork','vfork','clone',
    'bind','listen','accept','accept4')

function Get-EventTier([string]$name) {
    if ($CRITICAL_SYSCALLS.Contains($name)) { return 'CRITICAL' }
    if ($HIGH_SYSCALLS.Contains($name))     { return 'HIGH'     }
    if ($MEDIUM_SYSCALLS.Contains($name))   { return 'MEDIUM'   }
    return 'LOW'
}

function Get-TierColor([string]$tier) {
    switch ($tier) {
        'CRITICAL' { return 'Red'      }
        'HIGH'     { return 'Yellow'   }
        'MEDIUM'   { return 'Cyan'     }
        default    { return 'DarkGray' }
    }
}

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------
function Draw-ThreatMeter([int]$score) {
    $max    = 2000
    $width  = 40
    $ratio  = [Math]::Min($score / $max, 1.0)
    $filled = [int]($ratio * $width)
    $empty  = $width - $filled
    $bar    = ('#' * $filled) + ('-' * $empty)
    $pct    = [int]($ratio * 100)
    $col    = if ($pct -ge 75) { 'Red' } elseif ($pct -ge 35) { 'Yellow' } else { 'Green' }
    Write-Host '  Threat Score  [' -NoNewline -ForegroundColor DarkCyan
    Write-Host $bar                -NoNewline -ForegroundColor $col
    Write-Host ']  '               -NoNewline -ForegroundColor DarkCyan
    Write-Host "$score"                       -ForegroundColor $col
}

function Draw-Screen {
    param(
        [string]$logName,
        [string]$target,
        [hashtable]$tiers,
        [int]$total,
        [int]$score,
        [hashtable]$freq,
        [System.Collections.Generic.List[object]]$feed
    )

    $w = '=' * 70
    Clear-Host

    # Header
    Write-Host $w -ForegroundColor Cyan
    Write-Host '  SCRUTINY  //  HoneyBadger Vanguard  //  LIVE DASHBOARD' -ForegroundColor Cyan
    Write-Host $w -ForegroundColor Cyan
    Write-Host "  Target : $target" -ForegroundColor White
    Write-Host "  Log    : $logName" -ForegroundColor DarkGray
    Write-Host "  Press Ctrl+C to stop" -ForegroundColor DarkGray
    Write-Host $w -ForegroundColor Cyan

    # Tier counters
    Write-Host ''
    Write-Host ('  {0,-12} {1,-12} {2,-12} {3,-12}  Total: {4,6}' -f `
        'CRITICAL','HIGH','MEDIUM','LOW', $total) -ForegroundColor DarkCyan
    Write-Host -NoNewline '  '
    Write-Host ('{0,-12}' -f $tiers['CRITICAL']) -ForegroundColor Red      -NoNewline
    Write-Host ('{0,-12}' -f $tiers['HIGH'])     -ForegroundColor Yellow   -NoNewline
    Write-Host ('{0,-12}' -f $tiers['MEDIUM'])   -ForegroundColor Cyan     -NoNewline
    Write-Host ('{0,-12}' -f $tiers['LOW'])       -ForegroundColor DarkGray
    Write-Host ''
    Draw-ThreatMeter $score

    # Top syscalls table
    Write-Host ''
    Write-Host '  TOP SYSCALLS' -ForegroundColor DarkCyan
    Write-Host ('  {0,-26} {1,-10} {2,6}' -f 'Syscall','Tier','Count') -ForegroundColor DarkCyan
    Write-Host ('  ' + '-' * 46) -ForegroundColor DarkCyan
    $freq.GetEnumerator() |
        Sort-Object Value -Descending |
        Select-Object -First $TopN |
        ForEach-Object {
            $tier = Get-EventTier $_.Key
            $col  = Get-TierColor $tier
            Write-Host ('  {0,-26} {1,-10} {2,6}' -f $_.Key, $tier, $_.Value) -ForegroundColor $col
        }

    # Live event feed
    Write-Host ''
    Write-Host '  LIVE EVENT FEED' -ForegroundColor DarkCyan
    Write-Host ('  {0,-8} {1,-26} {2,-10} {3,5}  {4}' -f `
        'PID','Syscall','Tier','Score','Timestamp') -ForegroundColor DarkCyan
    Write-Host ('  ' + '-' * 62) -ForegroundColor DarkCyan
    $display = if ($feed.Count -gt 15) { $feed.GetRange($feed.Count - 15, 15) } else { $feed }
    foreach ($ev in $display) {
        $col = Get-TierColor $ev.risk_tier
        Write-Host -NoNewline ('  {0,-8} ' -f $ev.pid)           -ForegroundColor DarkGray
        Write-Host -NoNewline ('{0,-26} '  -f $ev.syscall_name)  -ForegroundColor $col
        Write-Host -NoNewline ('{0,-10} '  -f $ev.risk_tier)     -ForegroundColor $col
        Write-Host -NoNewline ('{0,5}  '   -f $ev.risk_score)    -ForegroundColor $col
        Write-Host ($ev.timestamp)                                -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
$logName   = Split-Path $JsonlPath -Leaf
$targetDir = Split-Path (Split-Path $JsonlPath -Parent) -Parent
$target    = Split-Path $targetDir -Leaf

$tiers     = @{ CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0 }
$freq      = @{}
$totalEvt  = 0
$threatScr = 0
$feed      = [System.Collections.Generic.List[object]]::new()
$SCORE_MAP = @{ CRITICAL=10; HIGH=7; MEDIUM=3; LOW=1 }

# Use a StreamReader for true tail-follow behavior (tracks file position)
$stream = $null
$reader = $null

try {
    # Open with FileShare.ReadWrite so baseliner can still write
    $stream = [System.IO.File]::Open($JsonlPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite)
    $reader = [System.IO.StreamReader]::new($stream)

    while ($true) {
        # Drain all new lines since last poll
        $gotNew = $false
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if (-not $line) { continue }
            try { $ev = $line | ConvertFrom-Json } catch { continue }

            $tier = if ($ev.risk_tier) { $ev.risk_tier } else { 'LOW' }
            if (-not $tiers.ContainsKey($tier)) { $tier = 'LOW' }
            $tiers[$tier]++
            $totalEvt++
            $threatScr += $SCORE_MAP[$tier]

            $sname = $ev.syscall_name
            if ($freq.ContainsKey($sname)) { $freq[$sname]++ } else { $freq[$sname] = 1 }
            $feed.Add($ev)
            $gotNew = $true
        }

        Draw-Screen $logName $target $tiers $totalEvt $threatScr $freq $feed
        Start-Sleep -Milliseconds $RefreshMs
    }
}
catch [System.Management.Automation.PipelineStoppedException] {
    # Ctrl+C — clean exit
}
finally {
    if ($reader) { $reader.Close() }
    if ($stream) { $stream.Close() }

    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host '  Dashboard stopped.' -ForegroundColor Cyan
    Write-Host "  Final  —  Events: $totalEvt  |  Threat Score: $threatScr" -ForegroundColor White
    Write-Host "  CRITICAL: $($tiers['CRITICAL'])  HIGH: $($tiers['HIGH'])  MEDIUM: $($tiers['MEDIUM'])  LOW: $($tiers['LOW'])" -ForegroundColor White
    Write-Host "$('=' * 70)`n" -ForegroundColor Cyan
}
