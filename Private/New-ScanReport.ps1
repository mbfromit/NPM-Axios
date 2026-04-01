function New-ScanReport {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Projects             = @(),
        [PSCustomObject[]]$LockfileResults      = @(),
        [PSCustomObject[]]$Artifacts            = @(),
        [PSCustomObject[]]$CacheFindings        = @(),
        [PSCustomObject[]]$DroppedPayloads      = @(),
        [PSCustomObject[]]$PersistenceArtifacts = @(),
        [PSCustomObject[]]$XorFindings          = @(),
        [PSCustomObject[]]$NetworkEvidence      = @(),
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$ScanMetadata
    )

    $vulnProjects   = @($LockfileResults     | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto })
    $allFindings    = @($Artifacts) + @($CacheFindings) + @($DroppedPayloads) + @($PersistenceArtifacts) + @($XorFindings) + @($NetworkEvidence)
    $criticalCount  = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $overallStatus  = if ($vulnProjects.Count -gt 0 -or $allFindings.Count -gt 0) { 'COMPROMISED' } else { 'CLEAN' }

    $sb = [System.Text.StringBuilder]::new()

    function Add-Section { param([string]$Title) [void]$sb.AppendLine(); [void]$sb.AppendLine($Title); [void]$sb.AppendLine('-' * 60) }
    function Add-Line    { param([string]$Line)  [void]$sb.AppendLine($Line) }

    [void]$sb.AppendLine('=' * 80)
    [void]$sb.AppendLine('AXIOS NPM SUPPLY CHAIN COMPROMISE SCANNER — FORENSIC REPORT')
    [void]$sb.AppendLine('=' * 80)

    Add-Section 'EXECUTIVE SUMMARY'
    Add-Line "Total projects scanned    : $($Projects.Count)"
    Add-Line "Vulnerable (lockfile)     : $($vulnProjects.Count)"
    Add-Line "Critical findings (total) : $criticalCount"
    Add-Line "Overall status            : $overallStatus"
    if ($overallStatus -eq 'COMPROMISED') {
        Add-Line ''
        Add-Line '*** ACTION REQUIRED: Evidence of compromise detected. Isolate this machine.'
        Add-Line '*** Do NOT use for further development until remediation is complete.'
    }

    Add-Section 'SCAN METADATA'
    Add-Line "Timestamp     : $($ScanMetadata.Timestamp)"
    Add-Line "Hostname      : $($ScanMetadata.Hostname)"
    Add-Line "Username      : $($ScanMetadata.Username)"
    Add-Line "Scan Duration : $($ScanMetadata.Duration)"
    Add-Line "Paths Scanned : $($ScanMetadata.Paths -join ', ')"

    Add-Section 'VULNERABLE PROJECTS (Lockfile Evidence)'
    if ($vulnProjects.Count -eq 0) { Add-Line 'None.' } else {
        foreach ($vp in $vulnProjects) {
            Add-Line "Project  : $($vp.ProjectPath)"
            Add-Line "Lockfile : $($vp.LockfileType) — $($vp.LockfilePath)"
            if ($vp.HasVulnerableAxios)      { Add-Line "FINDING  : axios@$($vp.VulnerableAxiosVersion) — malicious version" }
            if ($vp.HasMaliciousPlainCrypto) { Add-Line "FINDING  : plain-crypto-js@4.2.1 — postinstall dropper" }
            Add-Line "FIX      : npm install axios@1.14.0 && npm cache clean --force && rm -rf node_modules && npm install"
            Add-Line ''
        }
    }

    Add-Section 'FORENSIC ARTIFACTS (node_modules / setup.js / plaintext C2)'
    if ($Artifacts.Count -eq 0) { Add-Line 'None.' } else {
        foreach ($a in $Artifacts) {
            Add-Line "Type     : $($a.Type)  Severity: $($a.Severity)"
            Add-Line "Path     : $($a.Path)"
            if ($a.Hash) { Add-Line "SHA256   : $($a.Hash)" }
            Add-Line "Detail   : $($a.Description)"
            Add-Line ''
        }
    }

    Add-Section 'NPM CACHE FINDINGS'
    if ($CacheFindings.Count -eq 0) { Add-Line 'None.' } else {
        foreach ($c in $CacheFindings) {
            Add-Line "Type     : $($c.Type)  Severity: $($c.Severity)"
            Add-Line "Package  : $($c.PackageName)@$($c.Version)"
            Add-Line "Path     : $($c.Path)"
            Add-Line "Detail   : $($c.Description)"
            Add-Line ''
        }
    }

    Add-Section 'DROPPED PAYLOADS (RAT binaries/scripts in temp/appdata)'
    if ($DroppedPayloads.Count -eq 0) { Add-Line 'None detected.' } else {
        foreach ($dp in $DroppedPayloads) {
            Add-Line "Type     : $($dp.Type)  Severity: $($dp.Severity)"
            Add-Line "Path     : $($dp.Path)"
            Add-Line "Created  : $($dp.CreationTime)"
            if ($dp.Hash) { Add-Line "SHA256   : $($dp.Hash)" }
            Add-Line "Detail   : $($dp.Description)"
            Add-Line ''
        }
    }

    Add-Section 'PERSISTENCE MECHANISMS (scheduled tasks / registry / startup)'
    if ($PersistenceArtifacts.Count -eq 0) { Add-Line 'None detected.' } else {
        foreach ($pa in $PersistenceArtifacts) {
            Add-Line "Type     : $($pa.Type)  Severity: $($pa.Severity)"
            Add-Line "Location : $($pa.Location)"
            Add-Line "Name     : $($pa.Name)"
            Add-Line "Value    : $($pa.Value)"
            Add-Line "Detail   : $($pa.Description)"
            Add-Line ''
        }
    }

    Add-Section 'XOR-ENCODED INDICATORS (ObfuscatedC2 via OrDeR_7077 key)'
    if ($XorFindings.Count -eq 0) { Add-Line 'None detected.' } else {
        foreach ($xf in $XorFindings) {
            Add-Line "Type      : $($xf.Type)  Severity: $($xf.Severity)"
            Add-Line "Path      : $($xf.Path)"
            Add-Line "Indicator : $($xf.DecodedIndicator)"
            Add-Line "Detail    : $($xf.Description)"
            Add-Line ''
        }
    }

    Add-Section 'NETWORK EVIDENCE (DNS cache / active connections / firewall log)'
    if ($NetworkEvidence.Count -eq 0) { Add-Line 'None detected.' } else {
        foreach ($ne in $NetworkEvidence) {
            Add-Line "Type     : $($ne.Type)  Severity: $($ne.Severity)"
            Add-Line "Detail   : $($ne.Detail)"
            Add-Line "Summary  : $($ne.Description)"
            Add-Line ''
        }
    }

    Add-Section 'CREDENTIALS AT RISK'
    Add-Line 'If COMPROMISED status — rotate ALL of the following immediately:'
    $credPaths = @(
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.ssh'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.gitconfig'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.npmrc'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.aws/credentials'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.kube/config'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.docker/config.json')
    )
    foreach ($cp in $credPaths) {
        $label = if (Test-Path $cp) { '  PRESENT — ROTATE:' } else { '  (not found):' }
        Add-Line "$label $cp"
    }
    Add-Line 'Also rotate: GitHub tokens, NPM tokens, AWS/GCP/Azure keys, container registry secrets, K8s service accounts'

    Add-Section 'APPENDIX: IOC REFERENCE'
    Add-Line 'Malicious packages : axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1'
    Add-Line 'setup.js SHA256    : e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09'
    Add-Line 'C2 domain/IP/port  : sfrclak.com, 142.11.206.73:8000'
    Add-Line 'XOR key/constant   : OrDeR_7077 / 333 (0x4D mask)'
    Add-Line 'Attack window      : 2026-03-31 00:21 UTC — 2026-03-31 03:15 UTC'

    Add-Section 'REMEDIATION GUIDANCE'
    Add-Line 'STEP 1 — Lockfile cleanup:'
    Add-Line '  npm install axios@1.14.0   (or axios@0.30.3 for v0.x)'
    Add-Line '  npm cache clean --force'
    Add-Line '  Remove-Item node_modules -Recurse -Force && npm install'
    Add-Line ''
    Add-Line 'STEP 2 — If dropped payloads or persistence found:'
    Add-Line '  1. Isolate machine from network immediately'
    Add-Line '  2. Capture forensic disk image before any changes'
    Add-Line '  3. Remove scheduled tasks, registry run keys, startup entries found above'
    Add-Line '  4. Delete dropped payload files found above'
    Add-Line '  5. Check Windows Event Log (EID 4688 / Sysmon 1) for node.exe child processes around 2026-03-31'
    Add-Line '  6. Review network logs for traffic to sfrclak.com or 142.11.206.73:8000'
    Add-Line '  7. Consider full OS re-image if active connection was found'
    Add-Line ''
    Add-Line 'STEP 3 — Credential rotation (mandatory if COMPROMISED):'
    Add-Line '  SSH keys, GitHub tokens, NPM tokens, AWS/GCP/Azure credentials,'
    Add-Line '  Kubernetes configs, container registry secrets, any secrets in .env files'

    # ── Write file ─────────────────────────────────────────────────────────────
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    $ts       = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hn       = $env:COMPUTERNAME ?? $env:HOSTNAME ?? 'unknown'
    $filePath = Join-Path $OutputPath "Axios-Scan-${hn}-${ts}.txt"

    $sb.ToString() | Set-Content -Path $filePath -Encoding UTF8

    if ($IsWindows -or $env:OS -eq 'Windows_NT') {
        try {
            $acl = Get-Acl $filePath
            $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','Allow')))
            Set-Acl $filePath $acl
        } catch { Write-Warning "Could not restrict report permissions: $_" }
    } else {
        & chmod 600 $filePath 2>$null
    }

    return $filePath
}
