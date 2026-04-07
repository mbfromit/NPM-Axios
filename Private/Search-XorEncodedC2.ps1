function Invoke-XorDecode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [string]$Key      = 'OrDeR_7077',
        [int]$Constant    = 333
    )
    $keyBytes = [Text.Encoding]::UTF8.GetBytes($Key)
    $mask     = $Constant -band 0xFF
    $result   = New-Object byte[] $Data.Length
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $result[$i] = [byte](($Data[$i] -bxor $keyBytes[$i % $keyBytes.Length]) -bxor $mask)
    }
    return $result
}

function Search-XorEncodedC2 {
    [CmdletBinding()]
    param(
        [string[]]$SearchPaths
    )

    if (-not $SearchPaths) {
        if ($IsWindows) {
            $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:HOME }
            $appData      = if ($env:APPDATA)      { $env:APPDATA }      else { Join-Path $env:HOME '.config' }
            $SearchPaths = @($env:TEMP, $env:TMP, $localAppData, $appData)
        } elseif ($IsMacOS) {
            $SearchPaths = @('/tmp', (Join-Path $env:HOME 'Library/Caches'), (Join-Path $env:HOME '.config'))
        } else {
            $SearchPaths = @('/tmp', '/var/tmp', (Join-Path $env:HOME '.cache'), (Join-Path $env:HOME '.config'))
        }
        $SearchPaths = @($SearchPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)
    }

    $c2Indicators = @('sfrclak.com', 'callnrwise.com', '142.11.206.73')
    $findings     = [System.Collections.Generic.List[PSCustomObject]]::new()
    # Only scan file types that could plausibly carry an obfuscated payload
    if ($IsWindows) {
        $scanExts = @('.exe', '.dll', '.bin', '.dat', '.ps1', '.js', '.vbs', '.bat', '.tmp', '.log')
    } elseif ($IsMacOS) {
        $scanExts = @('.dylib', '.bin', '.dat', '.sh', '.py', '.js', '.tmp', '.log', '.command')
    } else {
        $scanExts = @('.so', '.elf', '.bin', '.dat', '.sh', '.py', '.js', '.tmp', '.log')
    }

    foreach ($scanPath in $SearchPaths) {
        try {
            Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { ($_.Extension -in $scanExts -or $_.Extension -eq '') -and $_.Length -le 5MB -and $_.Length -gt 0 } |
            Where-Object { try { [IO.File]::OpenRead($_.FullName).Dispose(); $true } catch { $false } } |
            Select-Object -First 1000 |
            ForEach-Object {
                try {
                    $bytes   = [IO.File]::ReadAllBytes($_.FullName)
                    $decoded = Invoke-XorDecode -Data $bytes
                    $text    = [Text.Encoding]::UTF8.GetString($decoded)

                    foreach ($indicator in $c2Indicators) {
                        if ($text -match [regex]::Escape($indicator)) {
                            $findings.Add([PSCustomObject]@{
                                Type             = 'XorEncodedC2'
                                Path             = $_.FullName
                                DecodedIndicator = $indicator
                                Severity         = 'Critical'
                                Description      = "XOR-encoded C2 indicator '$indicator' found after decoding file: $($_.FullName)"
                            })
                            break
                        }
                    }
                } catch { }
            }
        } catch { Write-Warning "XOR scan error in ${scanPath}: $_" }
    }

    return @($findings)
}
