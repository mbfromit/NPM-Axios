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
        [string]$ReportPath,
        [string]$AiVerdict = ''
    )

    if ([string]::IsNullOrEmpty($Password)) {
        return @{ Status = 'skipped' }
    }

    try {
        # Build multipart/form-data manually. Invoke-RestMethod -Form relies on
        # .NET's MultipartFormDataContent which always quotes the boundary value
        # (boundary="xxx"). Cloudflare Workers' formData() cannot parse quoted
        # boundaries, so we construct the body ourselves with an unquoted boundary.
        $boundary = [System.Guid]::NewGuid().ToString('N')
        $CRLF     = "`r`n"
        $enc      = [System.Text.Encoding]::UTF8
        $parts    = [System.Collections.Generic.List[byte[]]]::new()

        $fields = [ordered]@{
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
        }
        if ($AiVerdict) { $fields['ai_verdict'] = $AiVerdict }

        foreach ($key in $fields.Keys) {
            $parts.Add($enc.GetBytes(
                "--$boundary$CRLF" +
                "Content-Disposition: form-data; name=`"$key`"$CRLF$CRLF" +
                $fields[$key] + $CRLF
            ))
        }

        foreach ($file in @(
            @{ Name = 'brief';  Path = $BriefPath  },
            @{ Name = 'report'; Path = $ReportPath }
        )) {
            $fileName  = [System.IO.Path]::GetFileName($file.Path)
            $fileBytes = [System.IO.File]::ReadAllBytes($file.Path)
            $parts.Add($enc.GetBytes(
                "--$boundary$CRLF" +
                "Content-Disposition: form-data; name=`"$($file.Name)`"; filename=`"$fileName`"$CRLF" +
                "Content-Type: text/html$CRLF$CRLF"
            ))
            $parts.Add($fileBytes)
            $parts.Add($enc.GetBytes($CRLF))
        }

        $parts.Add($enc.GetBytes("--$boundary--$CRLF"))

        $totalSize = 0; foreach ($p in $parts) { $totalSize += $p.Length }
        $body = [byte[]]::new($totalSize)
        $offset = 0
        foreach ($p in $parts) {
            [System.Buffer]::BlockCopy($p, 0, $body, $offset, $p.Length)
            $offset += $p.Length
        }

        $response = Invoke-RestMethod -Uri $ApiUrl -Method POST `
            -Body $body `
            -ContentType "multipart/form-data; boundary=$boundary"

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
