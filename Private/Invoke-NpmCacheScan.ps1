function Invoke-NpmCacheScan {
    [CmdletBinding()]
    param(
        [string]$CacheDirOverride   # When set, skips 'npm config get cache' — used for test artifacts
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Verbose 'npm not found - skipping cache scan'
        return @($findings)
    }

    $maliciousPkgs = @('plain-crypto-js', 'axios')
    $vulnVersions  = @('4.2.1', '1.14.1', '0.30.4')

    # ── npm content-addressable cache ──────────────────────────────────────────
    try {
        $cacheDir = if ($CacheDirOverride) { $CacheDirOverride } else { (Invoke-Expression 'npm config get cache' 2>$null).Trim() }
        $indexDir = Join-Path $cacheDir '_cacache/index-v5'

        if (Test-Path $indexDir) {
            Get-ChildItem -Path $indexDir -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object -First 5000 |
            ForEach-Object {
                try {
                    $raw = Get-Content $_.FullName -Raw -ErrorAction Stop
                    foreach ($pkg in $maliciousPkgs) {
                        foreach ($ver in $vulnVersions) {
                            if ($raw -match "$pkg/-/$pkg-$ver\.tgz") {
                                $findings.Add([PSCustomObject]@{
                                    Type        = 'NpmCacheHit'
                                    Path        = $_.FullName
                                    PackageName = $pkg
                                    Version     = $ver
                                    Severity    = 'High'
                                    Description = "Malicious ${pkg}@${ver} found in npm cache index - run: npm cache clean --force"
                                })
                            }
                        }
                    }
                } catch { }
            }
        }
    } catch { Write-Warning "npm cache scan failed: $_" }

    # ── Global npm node_modules ────────────────────────────────────────────────
    try {
        $globalRoot = (Invoke-Expression 'npm root -g' 2>$null).Trim()
        if ($globalRoot -and (Test-Path $globalRoot)) {
            foreach ($pkg in $maliciousPkgs) {
                $globalPkgDir = Join-Path $globalRoot $pkg
                if (Test-Path $globalPkgDir) {
                    # Read version from package.json if present
                    $pkgJson = Join-Path $globalPkgDir 'package.json'
                    $ver = $null
                    if (Test-Path $pkgJson) {
                        try { $ver = (Get-Content $pkgJson -Raw | ConvertFrom-Json).version } catch { }
                    }
                    $isMalicious = (-not $ver) -or ($ver -in $vulnVersions)
                    if ($isMalicious) {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'GlobalNpmHit'
                            Path        = $globalPkgDir
                            PackageName = $pkg
                            Version     = if ($ver) { $ver } else { 'unknown' }
                            Severity    = 'Critical'
                            Description = "Malicious ${pkg} found in global npm - run: npm uninstall -g $pkg"
                        })
                    }
                }
            }
        }
    } catch { Write-Warning "Global npm scan failed: $_" }

    return @($findings)
}
