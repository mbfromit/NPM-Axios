function New-ExecBriefing {
    [CmdletBinding()]
    param(
        [int]$ProjectCount                              = 0,
        [PSCustomObject[]]$LockfileResults              = @(),
        [PSCustomObject[]]$Artifacts                    = @(),
        [PSCustomObject[]]$CacheFindings                = @(),
        [PSCustomObject[]]$DroppedPayloads              = @(),
        [PSCustomObject[]]$PersistenceArtifacts         = @(),
        [PSCustomObject[]]$XorFindings                  = @(),
        [PSCustomObject[]]$NetworkEvidence              = @(),
        [Parameter(Mandatory)][string]$TechnicalReportPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$ScanMetadata
    )

    # ── Derive per-check pass/fail ─────────────────────────────────────────────
    $vulnLockfiles = @($LockfileResults | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto })

    $checks = [ordered]@{
        '1' = @{
            Name     = 'Project Discovery'
            What     = 'Node.js projects on disk'
            Examined = "$ProjectCount found"
            Findings = $null      # informational only - never fails
            Pass     = $true
        }
        '2' = @{
            Name     = 'Dependency Lockfiles'
            What     = 'Known-malicious axios versions in npm/yarn/pnpm'
            Examined = "$($LockfileResults.Count) lockfiles"
            Findings = $vulnLockfiles.Count
            Pass     = $vulnLockfiles.Count -eq 0
        }
        '3' = @{
            Name     = 'Malicious Package Files'
            What     = 'Backdoor package directory and dropper script hash'
            Examined = "$ProjectCount project dirs"
            Findings = $Artifacts.Count
            Pass     = $Artifacts.Count -eq 0
        }
        '4' = @{
            Name     = 'npm Package Cache'
            What     = 'Poisoned packages still cached in npm content store'
            Examined = '1 cache'
            Findings = $CacheFindings.Count
            Pass     = $CacheFindings.Count -eq 0
        }
        '5' = @{
            Name     = 'Dropped Malware Payloads'
            What     = 'Executables/scripts written to temp or appdata after attack'
            Examined = 'Temp and appdata locations'
            Findings = $DroppedPayloads.Count
            Pass     = $DroppedPayloads.Count -eq 0
        }
        '6' = @{
            Name     = 'Persistence Mechanisms'
            What     = 'Scheduled tasks, registry Run keys, startup folder'
            Examined = '3 persistence sources'
            Findings = $PersistenceArtifacts.Count
            Pass     = $PersistenceArtifacts.Count -eq 0
        }
        '7' = @{
            Name     = 'Obfuscated Attack Signals'
            What     = "XOR-encoded C2 callbacks (key: OrDeR_7077)"
            Examined = 'Temp and appdata files'
            Findings = $XorFindings.Count
            Pass     = $XorFindings.Count -eq 0
        }
        '8' = @{
            Name     = 'Network Contact Evidence'
            What     = 'DNS cache, active TCP connections, Windows Firewall log'
            Examined = '3 network sources'
            Findings = $NetworkEvidence.Count
            Pass     = $NetworkEvidence.Count -eq 0
        }
    }

    $failedChecks   = @($checks.GetEnumerator() | Where-Object { -not $_.Value.Pass })
    $overallClean   = $failedChecks.Count -eq 0
    $verdictLabel   = if ($overallClean) { 'CLEAN' } else { 'COMPROMISED' }
    $verdictSymbol  = if ($overallClean) { [char]0x2713 } else { [char]0x2717 }   # ✓ / ✗

    # ── Hash the technical report for integrity footer ─────────────────────────
    $reportHash = 'unavailable'
    try { $reportHash = (Get-FileHash -Path $TechnicalReportPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
    $reportFilename = [IO.Path]::GetFileName($TechnicalReportPath)

    # ── Build document ─────────────────────────────────────────────────────────
    $w  = 68  # document width
    $sb = [System.Text.StringBuilder]::new()

    function HR  { [void]$sb.AppendLine('=' * $w) }
    function HR2 { [void]$sb.AppendLine('-' * $w) }
    function Ln  { param([string]$s = '') [void]$sb.AppendLine($s) }

    HR
    Ln 'AXIOS SUPPLY CHAIN ATTACK - EXECUTIVE SECURITY BRIEFING'
    Ln "Prepared : $($ScanMetadata.Timestamp)"
    Ln "Machine  : $($ScanMetadata.Hostname)   |   Analyst: $($ScanMetadata.Username)"
    HR
    Ln
    Ln "  OVERALL VERDICT:  $verdictSymbol $verdictLabel"
    Ln
    if (-not $overallClean) {
        Ln '  *** ACTION REQUIRED - See REQUIRED ACTIONS section below ***'
        Ln
    }

    HR2
    Ln "SECURITY CHECK RESULTS   (8 checks performed)"
    HR2
    Ln
    Ln (' #{0,-3} {1,-30} {2,-35} {3,-10} {4,-8} {5}' -f '', 'CHECK', 'WHAT WE LOOKED FOR', 'EXAMINED', 'FINDINGS', 'STATUS')
    Ln (' {0,-4} {1,-30} {2,-35} {3,-10} {4,-8} {5}' -f '─', ('─' * 29), ('─' * 34), ('─' * 9), ('─' * 7), '──────')

    foreach ($entry in $checks.GetEnumerator()) {
        $c         = $entry.Value
        $status    = if ($c.Pass) { 'PASS' } else { 'FAIL' }
        $findStr   = if ($null -eq $c.Findings) { '-' } elseif ($c.Findings -eq 0) { '0 hits' } else { "$($c.Findings) found" }
        Ln (' {0,-4} {1,-30} {2,-35} {3,-10} {4,-8} {5}' -f $entry.Key, $c.Name, $c.What, $c.Examined, $findStr, $status)
    }

    Ln
    HR2
    Ln 'WHAT THIS MEANS'
    HR2
    Ln
    if ($overallClean) {
        Ln '  No evidence of compromise was detected across all 8 checks.'
        Ln '  The malicious software either was never installed on this machine'
        Ln '  or was fully removed before execution.'
        Ln
        Ln '  This developer may resume work after completing standard lockfile'
        Ln '  cleanup (detailed in the technical report).'
    } else {
        Ln "  Evidence of attack found in $($failedChecks.Count) of 8 checks."
        Ln
        Ln '  The Axios supply chain attack is designed to steal credentials'
        Ln '  (SSH keys, cloud provider tokens, git credentials, API keys) and'
        Ln '  install a persistent backdoor. Any secrets accessible from this'
        Ln '  machine must be treated as compromised.'
        Ln
        Ln '  Failed checks:'
        foreach ($f in $failedChecks) {
            Ln "    Check $($f.Key) - $($f.Value.Name)"
        }
    }

    Ln
    HR2
    Ln 'REQUIRED ACTIONS'
    HR2
    Ln
    if ($overallClean) {
        Ln '  1. Run: npm install axios@1.14.0  (or 0.30.3 for v0.x branches)'
        Ln '  2. Run: npm cache clean --force'
        Ln '  3. Delete node_modules/ and re-run npm install'
        Ln '  4. No credential rotation required beyond standard hygiene.'
    } else {
        Ln '  IMMEDIATE (within the hour):'
        Ln '  1. Disconnect this machine from the corporate network'
        Ln '  2. Do not use this machine for any further work'
        Ln '  3. Notify the Security Incident Response team'
        Ln
        Ln '  WITHIN 24 HOURS - rotate ALL credentials that exist on this machine:'
        Ln '  - SSH private keys'
        Ln '  - GitHub / GitLab / Bitbucket personal access tokens'
        Ln '  - NPM publish tokens'
        Ln '  - AWS / GCP / Azure access keys'
        Ln '  - Kubernetes kubeconfig service account tokens'
        Ln '  - Docker registry credentials'
        Ln '  - Any secrets stored in .env files or IDE keychains'
        Ln
        Ln '  INVESTIGATION:'
        Ln '  - Preserve a forensic disk image before remediation'
        Ln '  - Review Windows Event Logs for suspicious process execution'
        Ln "  - Check all systems this developer accessed since 2026-03-31"
        if ($NetworkEvidence.Count -gt 0) {
            Ln '  - ACTIVE C2 CONNECTION DETECTED: assume data exfiltration occurred'
        }
        Ln
        Ln '  See the technical report for full artifact locations and details.'
    }

    Ln
    HR2
    Ln 'SCAN INTEGRITY'
    HR2
    Ln "  Scanner version  : 1.0"
    Ln "  Checks completed : 8 of 8"
    Ln "  Scan duration    : $($ScanMetadata.Duration)"
    Ln "  Scanned paths    : $($ScanMetadata.Paths -join ', ')"
    Ln "  Technical report : $reportFilename"
    Ln "  Report SHA256    : $reportHash"
    Ln

    # ── Write file ─────────────────────────────────────────────────────────────
    $null = New-Item -ItemType Directory -Path $OutputPath -Force

    $ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hn   = $ScanMetadata.Hostname
    $file = Join-Path $OutputPath "ExecBriefing-${hn}-${ts}.txt"

    $sb.ToString() | Set-Content -Path $file -Encoding UTF8

    return $file
}
