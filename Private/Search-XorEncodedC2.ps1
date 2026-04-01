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
        $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:HOME }
        $appData      = if ($env:APPDATA)      { $env:APPDATA }      else { Join-Path $env:HOME '.config' }
        $SearchPaths = @(
            $env:TEMP, $env:TMP,
            $localAppData,
            $appData
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    }

    $c2Indicators = @('sfrclak.com', '142.11.206.73')
    $findings     = [System.Collections.Generic.List[PSCustomObject]]::new()
    # Only scan file types that could plausibly carry an obfuscated payload
    $scanExts     = @('.exe', '.dll', '.bin', '.dat', '.ps1', '.js', '.vbs', '.bat', '.tmp', '.log')

    foreach ($scanPath in $SearchPaths) {
        try {
            Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in $scanExts -or $_.Extension -eq '' } |
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
