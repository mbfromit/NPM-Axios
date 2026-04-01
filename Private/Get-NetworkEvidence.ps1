function Get-NetworkEvidence {
    [CmdletBinding()]
    param(
        [string]$FirewallLogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    )

    $c2IP      = '142.11.206.73'
    $c2Domain  = 'sfrclak.com'
    $c2Port    = 8000
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ── Active TCP connections ─────────────────────────────────────────────────
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
                Description = "ACTIVE connection to C2 endpoint $($conn.RemoteAddress):$($conn.RemotePort) — RAT likely running (process: $procName)"
            })
        }
    } catch { Write-Warning "TCP connection check failed: $_" }

    # ── DNS cache ──────────────────────────────────────────────────────────────
    try {
        $dnsOutput = Invoke-Expression 'ipconfig /displaydns' 2>$null
        if ($dnsOutput -match [regex]::Escape($c2Domain)) {
            $findings.Add([PSCustomObject]@{
                Type        = 'DnsCacheHit'
                Detail      = "DNS cache contains entry for $c2Domain"
                Severity    = 'High'
                Description = "$c2Domain found in DNS cache — machine resolved attacker domain (connection likely occurred)"
            })
        }
    } catch { Write-Warning "DNS cache check failed: $_" }

    # ── Windows Firewall log ───────────────────────────────────────────────────
    if (Test-Path $FirewallLogPath) {
        try {
            $fwContent = Get-Content $FirewallLogPath -Raw -ErrorAction Stop
            if ($fwContent -match [regex]::Escape($c2IP)) {
                $matches = [regex]::Matches($fwContent, "^[^\r\n]*$([regex]::Escape($c2IP))[^\r\n]*", 'Multiline')
                $sample  = ($matches | Select-Object -First 3 | ForEach-Object { $_.Value }) -join '; '
                $findings.Add([PSCustomObject]@{
                    Type        = 'FirewallLogHit'
                    Detail      = "Firewall log contains connection records to $c2IP — sample: $sample"
                    Severity    = 'High'
                    Description = "Windows Firewall log shows traffic to C2 IP $c2IP — machine communicated with attacker"
                })
            }
        } catch { Write-Warning "Firewall log scan failed: $_" }
    }

    return @($findings)
}
