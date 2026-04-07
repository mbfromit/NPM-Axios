function Get-NetworkEvidence {
    [CmdletBinding()]
    param(
        [string]$FirewallLogPath
    )

    $c2IP      = '142.11.206.73'
    $c2Domain  = 'sfrclak.com'
    $c2Domain2 = 'callnrwise.com'
    $c2Port    = 8000
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($IsWindows) {
        if (-not $FirewallLogPath) { $FirewallLogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" }

        # ── Windows: Active TCP connections ───────────────────────────────────
        try {
            $c2Conns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                       Where-Object { $_.RemoteAddress -eq $c2IP -or $_.RemotePort -eq $c2Port }
            foreach ($conn in $c2Conns) {
                $procName = $null
                try { $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name } catch { }
                $findings.Add([PSCustomObject]@{
                    Type        = 'ActiveC2Connection'
                    Detail      = "$($conn.RemoteAddress):$($conn.RemotePort) State=$($conn.State) PID=$($conn.OwningProcess) Process=$procName"
                    Severity    = 'Critical'
                    Description = "ACTIVE connection to C2 endpoint $($conn.RemoteAddress):$($conn.RemotePort) - RAT likely running (process: $procName)"
                })
            }
        } catch { Write-Warning "TCP connection check failed: $_" }

        # ── Windows: DNS cache ────────────────────────────────────────────────
        try {
            $dnsOutput = Invoke-Expression 'ipconfig /displaydns' 2>$null
            foreach ($domain in @($c2Domain, $c2Domain2)) {
                if ($dnsOutput -match [regex]::Escape($domain)) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'DnsCacheHit'
                        Detail      = "DNS cache contains entry for $domain"
                        Severity    = 'High'
                        Description = "$domain found in DNS cache - machine resolved attacker domain"
                    })
                }
            }
        } catch { Write-Warning "DNS cache check failed: $_" }

        # ── Windows: Firewall log ─────────────────────────────────────────────
        if (Test-Path $FirewallLogPath) {
            try {
                $fwContent = Get-Content $FirewallLogPath -Raw -ErrorAction Stop
                if ($fwContent -match [regex]::Escape($c2IP)) {
                    $fwMatches = [regex]::Matches($fwContent, "^[^\r\n]*$([regex]::Escape($c2IP))[^\r\n]*", 'Multiline')
                    $sample = ($fwMatches | Select-Object -First 3 | ForEach-Object { $_.Value }) -join '; '
                    $findings.Add([PSCustomObject]@{
                        Type        = 'FirewallLogHit'
                        Detail      = "Firewall log contains connection records to $c2IP - sample: $sample"
                        Severity    = 'High'
                        Description = "Windows Firewall log shows traffic to C2 IP $c2IP"
                    })
                }
            } catch { Write-Warning "Firewall log scan failed: $_" }
        }

    } else {
        # ── macOS / Linux: Active connections via lsof ────────────────────────
        try {
            $lsofOutput = if (Get-Command lsof -ErrorAction SilentlyContinue) {
                & lsof -i -n -P 2>/dev/null
            } elseif (Get-Command ss -ErrorAction SilentlyContinue) {
                & ss -tnp 2>/dev/null
            } else { '' }

            if ($lsofOutput) {
                $lsofText = if ($lsofOutput -is [array]) { $lsofOutput -join "`n" } else { $lsofOutput }
                if ($lsofText -match [regex]::Escape($c2IP)) {
                    $matchLines = ($lsofText -split "`n" | Where-Object { $_ -match [regex]::Escape($c2IP) }) -join '; '
                    $findings.Add([PSCustomObject]@{
                        Type        = 'ActiveC2Connection'
                        Detail      = "Active connection to $c2IP detected: $matchLines"
                        Severity    = 'Critical'
                        Description = "ACTIVE connection to C2 IP $c2IP - RAT likely running"
                    })
                }
                if ($lsofText -match ":$c2Port\b") {
                    $portLines = ($lsofText -split "`n" | Where-Object { $_ -match ":$c2Port\b" -and $_ -notmatch [regex]::Escape($c2IP) }) -join '; '
                    if ($portLines) {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'SuspiciousPortConnection'
                            Detail      = "Connection on C2 beacon port $c2Port detected: $portLines"
                            Severity    = 'High'
                            Description = "Connection on known RAT beacon port $c2Port"
                        })
                    }
                }
            }
        } catch { Write-Warning "Network connection check failed: $_" }

        # ── macOS / Linux: DNS evidence ───────────────────────────────────────
        try {
            if ($IsMacOS) {
                # Check unified log for DNS resolutions
                # Include sample log lines so the manager/AI can determine if the resolution
                # was from actual malware or from the scanner's own log search
                foreach ($domain in @($c2Domain, $c2Domain2)) {
                    $logOutput = & log show --predicate "eventMessage contains '$domain'" --style compact --last 1d 2>/dev/null |
                        Select-Object -First 10
                    # Filter out entries that are clearly from this scanner running log show
                    $realEntries = @($logOutput | Where-Object { $_ -and $_ -notmatch 'log\s+show.*predicate' })
                    if ($realEntries.Count -gt 0) {
                        $sample = ($realEntries | Select-Object -First 3) -join '; '
                        $findings.Add([PSCustomObject]@{
                            Type        = 'DnsCacheHit'
                            Detail      = "System log contains DNS resolution for $domain - sample: $sample"
                            Severity    = 'High'
                            Description = "$domain found in macOS unified log - machine may have resolved attacker domain. Review sample log entries to confirm."
                        })
                    }
                }
            } else {
                # Linux: check systemd journal or /var/log/syslog
                $journalOutput = $null
                if (Get-Command journalctl -ErrorAction SilentlyContinue) {
                    $journalOutput = & journalctl --since "2026-03-30" --no-pager --grep "$c2Domain" 2>/dev/null | Select-Object -First 5
                }
                if (-not $journalOutput -and (Test-Path '/var/log/syslog')) {
                    $journalOutput = & grep -i $c2Domain /var/log/syslog 2>/dev/null | Select-Object -First 5
                }
                if ($journalOutput) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'DnsCacheHit'
                        Detail      = "System log contains reference to $c2Domain"
                        Severity    = 'High'
                        Description = "$c2Domain found in system logs - machine may have resolved attacker domain"
                    })
                }
            }
        } catch { Write-Warning "DNS/log check failed: $_" }

        # ── macOS / Linux: Firewall logs ──────────────────────────────────────
        try {
            $fwLogPaths = if ($IsMacOS) {
                @('/var/log/appfirewall.log')
            } else {
                @('/var/log/ufw.log', '/var/log/firewall', '/var/log/syslog', '/var/log/messages')
            }
            foreach ($fwLog in ($fwLogPaths | Where-Object { Test-Path $_ })) {
                $fwContent = Get-Content $fwLog -Raw -ErrorAction SilentlyContinue
                if ($fwContent -match [regex]::Escape($c2IP)) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'FirewallLogHit'
                        Detail      = "Firewall/system log $fwLog contains connection records to $c2IP"
                        Severity    = 'High'
                        Description = "Log file shows traffic to C2 IP $c2IP"
                    })
                    break
                }
            }
        } catch { Write-Warning "Firewall log scan failed: $_" }
    }

    return @($findings)
}
