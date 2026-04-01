BeforeAll {
    . "$PSScriptRoot/../Private/New-ScanReport.ps1"

    $outDir   = Join-Path $TestDrive 'reports'
    $metadata = @{ Timestamp='2026-04-01 12:00:00 UTC'; Hostname='TESTHOST'; Username='testuser'; Duration='45.2s'; Paths=@('C:\Dev') }

    $projects = @([PSCustomObject]@{ ProjectPath='C:\Dev\app'; PackageJsonPath='C:\Dev\app\package.json' })

    $lockfileResults = @([PSCustomObject]@{
        ProjectPath='C:\Dev\app'; HasVulnerableAxios=$true; VulnerableAxiosVersion='1.14.1'
        HasMaliciousPlainCrypto=$true; LockfileType='npm'; LockfilePath='C:\Dev\app\package-lock.json'; Error=$null
    })

    $artifacts = @([PSCustomObject]@{ Type='MaliciousPackage'; Path='C:\Dev\app\node_modules\plain-crypto-js'; Hash=$null; Severity='Critical'; Description='plain-crypto-js found' })
    $cache     = @([PSCustomObject]@{ Type='NpmCacheHit'; Path='C:\npm-cache\entry'; PackageName='plain-crypto-js'; Version='4.2.1'; Severity='High'; Description='Found in cache' })
    $payloads  = @([PSCustomObject]@{ Type='DroppedExecutable'; Path='C:\Temp\svc.exe'; Hash='abc123'; CreationTime=[datetime]'2026-03-31 02:00'; Severity='Critical'; Description='PE in temp' })
    $persist   = @([PSCustomObject]@{ Type='SuspiciousScheduledTask'; Location='Task Scheduler'; Name='WinHelper'; Value='powershell.exe -File C:\Temp\x.ps1'; Severity='Critical'; Description='Suspicious task' })
    $xor       = @([PSCustomObject]@{ Type='XorEncodedC2'; Path='C:\Temp\payload.bin'; DecodedIndicator='sfrclak.com'; Severity='Critical'; Description='XOR encoded C2' })
    $network   = @([PSCustomObject]@{ Type='ActiveC2Connection'; Detail='142.11.206.73:8000 State=Established'; Severity='Critical'; Description='Active C2 connection' })

    $reportPath = New-ScanReport -Projects $projects -LockfileResults $lockfileResults -Artifacts $artifacts `
        -CacheFindings $cache -DroppedPayloads $payloads -PersistenceArtifacts $persist `
        -XorFindings $xor -NetworkEvidence $network -OutputPath $outDir -ScanMetadata $metadata
}

Describe 'New-ScanReport' {
    It 'creates report file'                          { Test-Path $reportPath | Should -BeTrue }
    It 'filename contains RatCatcher-Report-'         { [IO.Path]::GetFileName($reportPath) | Should -Match 'RatCatcher-Report-' }
    It 'contains EXECUTIVE SUMMARY'                   { Get-Content $reportPath -Raw | Should -Match 'EXECUTIVE SUMMARY' }
    It 'shows COMPROMISED status'                     { Get-Content $reportPath -Raw | Should -Match 'COMPROMISED' }
    It 'shows correct project count'                  { Get-Content $reportPath -Raw | Should -Match 'Total projects scanned\s*:\s*1' }
    It 'contains SCAN METADATA with hostname'         { Get-Content $reportPath -Raw | Should -Match 'TESTHOST' }
    It 'contains VULNERABLE PROJECTS section'         { Get-Content $reportPath -Raw | Should -Match 'VULNERABLE PROJECTS' }
    It 'lists vulnerable axios version'               { Get-Content $reportPath -Raw | Should -Match 'axios@1\.14\.1' }
    It 'contains FORENSIC ARTIFACTS section'          { Get-Content $reportPath -Raw | Should -Match 'FORENSIC ARTIFACTS' }
    It 'contains NPM CACHE FINDINGS section'          { Get-Content $reportPath -Raw | Should -Match 'NPM CACHE' }
    It 'contains DROPPED PAYLOADS section'            { Get-Content $reportPath -Raw | Should -Match 'DROPPED PAYLOADS' }
    It 'contains PERSISTENCE MECHANISMS section'      { Get-Content $reportPath -Raw | Should -Match 'PERSISTENCE MECHANISMS' }
    It 'contains XOR-ENCODED INDICATORS section'      { Get-Content $reportPath -Raw | Should -Match 'XOR-ENCODED' }
    It 'contains NETWORK EVIDENCE section'            { Get-Content $reportPath -Raw | Should -Match 'NETWORK EVIDENCE' }
    It 'contains CREDENTIALS AT RISK section'         { Get-Content $reportPath -Raw | Should -Match 'CREDENTIALS AT RISK' }
    It 'contains IOC REFERENCE appendix'              { Get-Content $reportPath -Raw | Should -Match 'sfrclak\.com' }
    It 'contains REMEDIATION GUIDANCE'                { Get-Content $reportPath -Raw | Should -Match 'npm cache clean' }

    Context 'null collection inputs do not throw' {
        It 'generates report when optional collections are null' {
            {
                New-ScanReport `
                    -Projects            @([PSCustomObject]@{ ProjectPath='C:\ok'; PackageJsonPath='C:\ok\package.json' }) `
                    -LockfileResults     @([PSCustomObject]@{ ProjectPath='C:\ok'; HasVulnerableAxios=$false; HasMaliciousPlainCrypto=$false; LockfileType='npm'; LockfilePath=''; VulnerableAxiosVersion=$null; Error=$null }) `
                    -Artifacts           $null -CacheFindings $null -DroppedPayloads $null `
                    -PersistenceArtifacts $null -XorFindings $null -NetworkEvidence $null `
                    -OutputPath          $outDir -ScanMetadata $metadata
            } | Should -Not -Throw
        }
        It 'shows CLEAN when null collections passed' {
            $p = New-ScanReport `
                -Projects            @([PSCustomObject]@{ ProjectPath='C:\ok'; PackageJsonPath='C:\ok\package.json' }) `
                -LockfileResults     @([PSCustomObject]@{ ProjectPath='C:\ok'; HasVulnerableAxios=$false; HasMaliciousPlainCrypto=$false; LockfileType='npm'; LockfilePath=''; VulnerableAxiosVersion=$null; Error=$null }) `
                -Artifacts           $null -CacheFindings $null -DroppedPayloads $null `
                -PersistenceArtifacts $null -XorFindings $null -NetworkEvidence $null `
                -OutputPath          $outDir -ScanMetadata $metadata
            Get-Content $p -Raw | Should -Match 'CLEAN'
        }
    }

    Context 'clean scan' {
        It 'shows CLEAN status' {
            $cleanPath = New-ScanReport `
                -Projects            @([PSCustomObject]@{ ProjectPath='C:\ok'; PackageJsonPath='C:\ok\package.json' }) `
                -LockfileResults     @([PSCustomObject]@{ ProjectPath='C:\ok'; HasVulnerableAxios=$false; HasMaliciousPlainCrypto=$false; LockfileType='npm'; LockfilePath=''; VulnerableAxiosVersion=$null; Error=$null }) `
                -Artifacts           @() -CacheFindings @() -DroppedPayloads @() `
                -PersistenceArtifacts @() -XorFindings @() -NetworkEvidence @() `
                -OutputPath          $outDir -ScanMetadata $metadata
            Get-Content $cleanPath -Raw | Should -Match 'CLEAN'
        }
    }
}
