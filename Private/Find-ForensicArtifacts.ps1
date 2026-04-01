function Find-ForensicArtifacts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectPath)

    $knownHash  = 'e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09'
    $c2Patterns = @('sfrclak.com', '142.11.206.73')
    $artifacts  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $sep        = [IO.Path]::DirectorySeparatorChar

    $cryptoDir = @("${ProjectPath}${sep}node_modules${sep}plain-crypto-js", "$ProjectPath/node_modules/plain-crypto-js") |
                 Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($cryptoDir) {
        $artifacts.Add([PSCustomObject]@{ Type='MaliciousPackage'; Path=$cryptoDir; Hash=$null; Severity='Critical'; Description='Malicious plain-crypto-js package in node_modules' })

        $setupJs = Join-Path $cryptoDir 'setup.js'
        if (Test-Path $setupJs) {
            try {
                $hash    = (Get-FileHash -Path $setupJs -Algorithm SHA256).Hash.ToLower()
                $isKnown = $hash -eq $knownHash
                $artifacts.Add([PSCustomObject]@{
                    Type        = 'MaliciousScript'
                    Path        = $setupJs
                    Hash        = $hash
                    Severity    = if ($isKnown) { 'Critical' } else { 'High' }
                    Description = if ($isKnown) { 'Known malicious setup.js (hash match)' } else { 'Suspicious setup.js in plain-crypto-js (hash mismatch - possible variant)' }
                })
            } catch { Write-Warning "Cannot hash ${setupJs}: $_" }
        }
    }

    try {
        Get-ChildItem -Path $ProjectPath -Filter '*.js' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch 'node_modules' -or $_.FullName -match "node_modules[/\\]plain-crypto-js[/\\]" } |
        Select-Object -First 1000 |
        ForEach-Object {
            try {
                $content = Get-Content $_.FullName -Raw -ErrorAction Stop
                foreach ($pat in $c2Patterns) {
                    if ($content -match [regex]::Escape($pat)) {
                        $artifacts.Add([PSCustomObject]@{ Type='C2Indicator'; Path=$_.FullName; Hash=$null; Severity='Critical'; Description="C2 indicator '$pat' found in file" })
                        break
                    }
                }
            } catch { }
        }
    } catch { Write-Warning "C2 scan error in ${ProjectPath}: $_" }

    return @($artifacts)
}
