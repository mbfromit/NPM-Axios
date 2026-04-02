function Submit-ScanToApi {
    param(
        [string]$ApiUrl,
        [string]$Password,
        [string]$Hostname,
        [string]$Username,
        [string]$ScanTimestamp,
        [string]$Duration,
        [string]$Verdict,
        [int]$ProjectsScanned,
        [int]$VulnerableCount,
        [int]$CriticalCount,
        [string]$PathsScanned,
        [string]$BriefPath,
        [string]$ReportPath
    )

    if ([string]::IsNullOrEmpty($Password)) {
        return @{ Status = 'skipped' }
    }

    try {
        $response = Invoke-RestMethod -Uri $ApiUrl -Method POST -Form @{
            password         = $Password
            hostname         = $Hostname
            username         = $Username
            scan_timestamp   = $ScanTimestamp
            duration         = $Duration
            verdict          = $Verdict
            projects_scanned = [string]$ProjectsScanned
            vulnerable_count = [string]$VulnerableCount
            critical_count   = [string]$CriticalCount
            paths_scanned    = $PathsScanned
            brief            = Get-Item -LiteralPath $BriefPath
            report           = Get-Item -LiteralPath $ReportPath
        }
        return @{ Status = 'success'; Id = $response.id }
    }
    catch {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { }
        if ($statusCode -eq 401) {
            return @{ Status = 'wrong-password' }
        }
        return @{ Status = 'error'; Message = $_.ToString() }
    }
}
