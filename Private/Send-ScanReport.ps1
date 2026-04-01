function Send-ScanReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ReportPaths,
        [Parameter(Mandatory)][string]$SMTPServer,
        [int]$SMTPPort = 587,
        [Parameter(Mandatory)][string]$FromAddress,
        [Parameter(Mandatory)][string[]]$ToAddress,
        [PSCredential]$Credential,
        [bool]$UseTLS = $true
    )
    try {
        $hn     = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } elseif ($env:HOSTNAME) { $env:HOSTNAME } else { 'unknown' }
        $params = @{
            SmtpServer  = $SMTPServer; Port = $SMTPPort; From = $FromAddress; To = $ToAddress
            Subject     = "Axios Compromise Scan - ${hn} - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            Body        = 'Axios NPM compromise scan report and executive briefing attached. Review immediately.'
            Attachments = $ReportPaths; UseSsl = $UseTLS; ErrorAction = 'Stop'
        }
        if ($Credential) { $params.Credential = $Credential }
        Send-MailMessage @params
        return $true
    } catch {
        Write-Warning "Email failed: $_"
        return $false
    }
}
