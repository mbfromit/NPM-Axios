#Requires -Version 5.1
<#
.SYNOPSIS
    Scans for evidence of the March 31, 2026 Axios NPM supply chain attack.
.DESCRIPTION
    Runs ten checks covering the full compromise kill chain:
    lockfile evidence, deployed package artifacts, npm cache, dropped RAT payloads,
    persistence mechanisms, XOR-obfuscated indicators, and network evidence.
    Generates a forensic report and optionally emails it.
.PARAMETER Path
    Root directories to scan for Node.js projects. Defaults to common dev locations.
.PARAMETER OutputPath
    Directory for report and log files.
.PARAMETER SendEmail
    Send the report by email. Requires -SMTPServer, -FromAddress, -ToAddress.
.EXAMPLE
    .\Invoke-AxiosCompromiseScanner.ps1
.EXAMPLE
    .\Invoke-AxiosCompromiseScanner.ps1 -Path C:\Dev -SendEmail -SMTPServer smtp.co.com -FromAddress sec@co.com -ToAddress ir@co.com
#>
[CmdletBinding()]
param(
    [string[]]$Path         = $(if ($IsWindows -or $env:OS -eq 'Windows_NT') { @('C:\Users','C:\Dev','C:\Projects') } else { @($env:HOME,'/opt','/srv') }),
    [string]$OutputPath     = $(if ($IsWindows -or $env:OS -eq 'Windows_NT') { 'C:\Logs' } else { '/tmp' }),
    [switch]$SendEmail,
    [string]$SMTPServer,
    [int]$SMTPPort          = 587,
    [string]$FromAddress,
    [string[]]$ToAddress,
    [PSCredential]$Credential,
    [bool]$UseTLS           = $true,
    [int]$Threads           = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$pvt = Join-Path $PSScriptRoot 'Private'
. (Join-Path $pvt 'Get-NodeProjects.ps1')
. (Join-Path $pvt 'Invoke-LockfileAnalysis.ps1')
. (Join-Path $pvt 'Find-ForensicArtifacts.ps1')
. (Join-Path $pvt 'Invoke-NpmCacheScan.ps1')
. (Join-Path $pvt 'Search-DroppedPayloads.ps1')
. (Join-Path $pvt 'Find-PersistenceArtifacts.ps1')
. (Join-Path $pvt 'Search-XorEncodedC2.ps1')
. (Join-Path $pvt 'Get-NetworkEvidence.ps1')
. (Join-Path $pvt 'New-ScanReport.ps1')
. (Join-Path $pvt 'New-ExecBriefing.ps1')
. (Join-Path $pvt 'Send-ScanReport.ps1')

if ($SendEmail) {
    if (-not $SMTPServer)  { throw '-SMTPServer is required when -SendEmail is specified' }
    if (-not $FromAddress) { throw '-FromAddress is required when -SendEmail is specified' }
    if (-not $ToAddress)   { throw '-ToAddress is required when -SendEmail is specified' }
}

$null = New-Item -ItemType Directory -Path $OutputPath -Force
$hn   = $env:COMPUTERNAME ?? $env:HOSTNAME ?? 'unknown'
$ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
$log  = Join-Path $OutputPath "Axios-Scan-${hn}-${ts}.log"

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = "[$(Get-Date -Format 'HH:mm:ss')] [$Level] $Msg"
    Write-Host $line
    Add-Content -Path $log -Value $line -ErrorAction SilentlyContinue
}

$attackWindow = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
$startTime    = Get-Date

Write-Log "Axios Compromise Scanner — 10-check suite"
Write-Log "Attack window start: $attackWindow"
Write-Log "Scanning paths: $($Path -join ', ')"

# ── Check 1: Discover Node.js projects ────────────────────────────────────────
Write-Log "[1/10] Discovering Node.js projects..."
$projects = Get-NodeProjects -Path $Path
Write-Log "Found $($projects.Count) project(s)"

# ── Checks 2 & 3: Lockfile analysis + artifact detection (parallel on PS7) ───
if ($PSVersionTable.PSVersion.Major -ge 7 -and $projects.Count -gt 0) {
    Write-Log "[2/10] Analysing lockfiles (parallel, $Threads threads)..."
    $lockfileResults = $projects | ForEach-Object -Parallel {
        . (Join-Path $using:pvt 'Invoke-LockfileAnalysis.ps1')
        Invoke-LockfileAnalysis -ProjectPath $_.ProjectPath
    } -ThrottleLimit $Threads

    Write-Log "[3/10] Detecting project-level forensic artifacts (parallel)..."
    $rawArtifacts = $projects | ForEach-Object -Parallel {
        . (Join-Path $using:pvt 'Find-ForensicArtifacts.ps1')
        Find-ForensicArtifacts -ProjectPath $_.ProjectPath
    } -ThrottleLimit $Threads
} else {
    Write-Log "[2/10] Analysing lockfiles (sequential)..."
    $lockfileResults = $projects | ForEach-Object { Invoke-LockfileAnalysis -ProjectPath $_.ProjectPath }
    Write-Log "[3/10] Detecting project-level forensic artifacts..."
    $rawArtifacts    = $projects | ForEach-Object { Find-ForensicArtifacts -ProjectPath $_.ProjectPath }
}
$artifacts = @($rawArtifacts | Where-Object { $_ })

# ── Check 4: npm cache ────────────────────────────────────────────────────────
Write-Log "[4/10] Scanning npm cache and global npm..."
$cacheFindings = Invoke-NpmCacheScan

# ── Check 5: Dropped payloads ─────────────────────────────────────────────────
Write-Log "[5/10] Searching for dropped RAT payloads in temp/appdata..."
$droppedPayloads = Search-DroppedPayloads -AttackWindowStart $attackWindow

# ── Check 6: Persistence ──────────────────────────────────────────────────────
Write-Log "[6/10] Checking persistence mechanisms (tasks, registry, startup)..."
$persistenceArtifacts = Find-PersistenceArtifacts -AttackWindowStart $attackWindow

# ── Check 7: XOR-encoded indicators ──────────────────────────────────────────
Write-Log "[7/10] Scanning for XOR-encoded C2 indicators..."
$xorFindings = Search-XorEncodedC2

# ── Check 8: Network evidence ─────────────────────────────────────────────────
Write-Log "[8/10] Checking network evidence (DNS cache, active connections, firewall log)..."
$networkEvidence = Get-NetworkEvidence

# ── Check 9: Generate report ──────────────────────────────────────────────────
$duration = (Get-Date) - $startTime
$metadata = @{
    Timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
    Hostname  = $hn
    Username  = $env:USERNAME ?? $env:USER ?? 'unknown'
    Duration  = "$([Math]::Round($duration.TotalSeconds,1))s"
    Paths     = $Path
}

Write-Log "[9/10] Generating forensic report..."
$reportPath = New-ScanReport `
    -Projects             $projects `
    -LockfileResults      @($lockfileResults) `
    -Artifacts            $artifacts `
    -CacheFindings        $cacheFindings `
    -DroppedPayloads      $droppedPayloads `
    -PersistenceArtifacts $persistenceArtifacts `
    -XorFindings          $xorFindings `
    -NetworkEvidence      $networkEvidence `
    -OutputPath           $OutputPath `
    -ScanMetadata         $metadata

Write-Log "Technical report: $reportPath"

# ── Check 9b: Executive Briefing ──────────────────────────────────────────────
Write-Log "[9b/10] Generating executive briefing..."
$briefingPath = New-ExecBriefing `
    -ProjectCount         $projects.Count `
    -LockfileResults      @($lockfileResults) `
    -Artifacts            $artifacts `
    -CacheFindings        $cacheFindings `
    -DroppedPayloads      $droppedPayloads `
    -PersistenceArtifacts $persistenceArtifacts `
    -XorFindings          $xorFindings `
    -NetworkEvidence      $networkEvidence `
    -TechnicalReportPath  $reportPath `
    -OutputPath           $OutputPath `
    -ScanMetadata         $metadata

Write-Log "Executive briefing: $briefingPath"

# ── Check 10: Email ───────────────────────────────────────────────────────────
if ($SendEmail) {
    Write-Log "[10/10] Emailing report to $($ToAddress -join ', ')..."
    $sent = Send-ScanReport -ReportPaths @($briefingPath, $reportPath) -SMTPServer $SMTPServer -SMTPPort $SMTPPort `
        -FromAddress $FromAddress -ToAddress $ToAddress -Credential $Credential -UseTLS $UseTLS
    if ($sent) { Write-Log 'Email sent.' } else { Write-Log 'Email failed — report available locally.' 'WARN' }
} else {
    Write-Log "[10/10] Email skipped (no -SendEmail flag)"
}

# ── Summary ───────────────────────────────────────────────────────────────────
$vulnCount      = @($lockfileResults | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto }).Count
$criticalCount  = @($artifacts + $cacheFindings + $droppedPayloads + $persistenceArtifacts + $xorFindings + $networkEvidence | Where-Object { $_.Severity -eq 'Critical' }).Count

Write-Log ''
Write-Log "═══════════════════════════════════════"
Write-Log " SCAN COMPLETE — $(Get-Date -Format 'HH:mm:ss')"
Write-Log " Projects scanned    : $($projects.Count)"
Write-Log " Vulnerable (lockfile): $vulnCount"
Write-Log " Critical findings   : $criticalCount"
Write-Log " Technical report    : $reportPath"
Write-Log " Executive briefing  : $briefingPath"

if ($vulnCount -gt 0 -or $criticalCount -gt 0) {
    Write-Log ' STATUS: COMPROMISED — isolate machine and review reports' 'WARN'
    exit 1
} else {
    Write-Log ' STATUS: CLEAN — no compromise evidence found across all 10 checks'
    exit 0
}
