function Search-DroppedPayloads {
    [CmdletBinding()]
    param(
        [string[]]$ScanPaths,
        [datetime]$AttackWindowStart = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
    )

    # Default to the filesystem locations a dropper would target
    if (-not $ScanPaths) {
        $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:HOME }
        $appData      = if ($env:APPDATA)      { $env:APPDATA }      else { Join-Path $env:HOME '.config' }
        $ScanPaths = @(
            $env:TEMP,
            $env:TMP,
            (Join-Path $localAppData 'Temp'),
            $localAppData,
            $appData
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    }

    $suspiciousExtensions = @('.exe', '.dll', '.ps1', '.vbs', '.bat', '.cmd', '.js', '.msi')
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($scanPath in $ScanPaths) {
        try {
            Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -ge $AttackWindowStart } |
            Select-Object -First 2000 |   # safety cap
            ForEach-Object {
                $file = $_
                $type = $null
                $sev  = 'Medium'

                # Check for PE magic bytes (MZ header = 0x4D 0x5A)
                if ($file.Extension -in @('.exe', '.dll') -or $file.Length -gt 0) {
                    try {
                        $bytes = [IO.File]::ReadAllBytes($file.FullName) | Select-Object -First 2
                        if ($bytes.Count -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                            $type = 'DroppedExecutable'
                            $sev  = 'Critical'
                        }
                    } catch { }
                }

                # Check suspicious script extensions in temp-like locations
                if (-not $type -and $file.Extension -in @('.ps1', '.vbs', '.bat', '.cmd')) {
                    $type = 'SuspiciousScript'
                    $sev  = 'High'
                }

                if ($type) {
                    $hash = $null
                    try { $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower() } catch { }
                    $findings.Add([PSCustomObject]@{
                        Type         = $type
                        Path         = $file.FullName
                        Hash         = $hash
                        CreationTime = $file.CreationTime
                        Severity     = $sev
                        Description  = "${type} created after attack window in temp/appdata location: $($file.FullName)"
                    })
                }
            }
        } catch { Write-Warning "Error scanning ${scanPath}: $_" }
    }

    return @($findings)
}
