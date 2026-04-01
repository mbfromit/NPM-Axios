BeforeAll {
    . "$PSScriptRoot/../Private/New-ExecBriefing.ps1"

    $outDir   = Join-Path $TestDrive 'briefings'
    $metadata = @{ Timestamp='2026-04-01 14:32:00 UTC'; Hostname='DEVBOX-01'; Username='jsmith'; Duration='45.2s'; Paths=@('C:\Dev') }

    # Create a fake technical report to hash
    $fakeReport = Join-Path $TestDrive 'fake-report.txt'
    'Technical report content' | Set-Content $fakeReport

    $vulnLockfile = [PSCustomObject]@{
        ProjectPath='C:\Dev\app'; HasVulnerableAxios=$true; VulnerableAxiosVersion='1.14.1'
        HasMaliciousPlainCrypto=$true; LockfileType='npm'; LockfilePath='C:\Dev\app\package-lock.json'; Error=$null
    }
    $cleanLockfile = [PSCustomObject]@{
        ProjectPath='C:\Dev\ok'; HasVulnerableAxios=$false; HasMaliciousPlainCrypto=$false
        LockfileType='npm'; LockfilePath='C:\Dev\ok\package-lock.json'; VulnerableAxiosVersion=$null; Error=$null
    }
    $criticalArtifact = [PSCustomObject]@{ Type='MaliciousPackage'; Path='C:\Dev\app\node_modules\plain-crypto-js'; Hash=$null; Severity='Critical'; Description='plain-crypto-js found' }
}

Describe 'New-ExecBriefing' {
    Context 'null collection inputs do not throw' {
        It 'generates briefing when optional collections are null' {
            {
                New-ExecBriefing -ProjectCount 0 -LockfileResults $null `
                    -Artifacts $null -CacheFindings $null -DroppedPayloads $null `
                    -PersistenceArtifacts $null -XorFindings $null -NetworkEvidence $null `
                    -TechnicalReportPath $fakeReport -OutputPath $outDir -ScanMetadata $metadata
            } | Should -Not -Throw
        }
        It 'verdict is CLEAN when null inputs and no findings' {
            $p = New-ExecBriefing -ProjectCount 0 -LockfileResults $null `
                -Artifacts $null -CacheFindings $null -DroppedPayloads $null `
                -PersistenceArtifacts $null -XorFindings $null -NetworkEvidence $null `
                -TechnicalReportPath $fakeReport -OutputPath $outDir -ScanMetadata $metadata
            Get-Content $p -Raw | Should -Match 'CLEAN'
        }
    }

    Context 'generates briefing file' {
        BeforeAll {
            $path = New-ExecBriefing -ProjectCount 2 -LockfileResults @($cleanLockfile) `
                -Artifacts @() -CacheFindings @() -DroppedPayloads @() `
                -PersistenceArtifacts @() -XorFindings @() -NetworkEvidence @() `
                -TechnicalReportPath $fakeReport -OutputPath $outDir -ScanMetadata $metadata
        }
        It 'creates the briefing file' { Test-Path $path | Should -BeTrue }
        It 'filename contains ExecBriefing' { [IO.Path]::GetFileName($path) | Should -Match 'ExecBriefing' }
    }

    Context 'clean scan' {
        BeforeAll {
            $path = New-ExecBriefing -ProjectCount 47 -LockfileResults @($cleanLockfile) `
                -Artifacts @() -CacheFindings @() -DroppedPayloads @() `
                -PersistenceArtifacts @() -XorFindings @() -NetworkEvidence @() `
                -TechnicalReportPath $fakeReport -OutputPath $outDir -ScanMetadata $metadata
            $content = Get-Content $path -Raw
        }
        It 'verdict is CLEAN'                          { $content | Should -Match 'CLEAN' }
        It 'shows 8 checks performed'                  { $content | Should -Match '8 checks performed' }
        It 'shows project count in check 1 row'        { $content | Should -Match '47' }
        It 'all check rows show PASS'                  { ($content | Select-String 'PASS').Matches.Count | Should -Be 8 }
        It 'no FAIL rows'                              { $content | Should -Not -Match '\bFAIL\b' }
        It 'contains WHAT THIS MEANS section'          { $content | Should -Match 'WHAT THIS MEANS' }
        It 'contains SCAN INTEGRITY section'           { $content | Should -Match 'SCAN INTEGRITY' }
        It 'contains report SHA256 hash'               { $content | Should -Match 'Report SHA256' }
        It 'shows 8 of 8 checks completed'             { $content | Should -Match '8 of 8' }
        It 'contains technical report filename'        { $content | Should -Match 'fake-report\.txt' }
    }

    Context 'compromised scan — lockfile hit' {
        BeforeAll {
            $path = New-ExecBriefing -ProjectCount 10 -LockfileResults @($vulnLockfile) `
                -Artifacts @($criticalArtifact) -CacheFindings @() -DroppedPayloads @() `
                -PersistenceArtifacts @() -XorFindings @() -NetworkEvidence @() `
                -TechnicalReportPath $fakeReport -OutputPath $outDir -ScanMetadata $metadata
            $content = Get-Content $path -Raw
        }
        It 'verdict is COMPROMISED'                    { $content | Should -Match 'COMPROMISED' }
        It 'check 2 row shows FAIL'                    { $content | Should -Match 'FAIL' }
        It 'contains REQUIRED ACTIONS section'         { $content | Should -Match 'REQUIRED ACTIONS' }
        It 'REQUIRED ACTIONS mentions credential rotation' { $content | Should -Match 'credential' }
    }

    Context 'compromised scan — active C2 connection' {
        BeforeAll {
            $c2 = [PSCustomObject]@{ Type='ActiveC2Connection'; Detail='142.11.206.73:8000'; Severity='Critical'; Description='Active connection' }
            $path = New-ExecBriefing -ProjectCount 5 -LockfileResults @($cleanLockfile) `
                -Artifacts @() -CacheFindings @() -DroppedPayloads @() `
                -PersistenceArtifacts @() -XorFindings @() -NetworkEvidence @($c2) `
                -TechnicalReportPath $fakeReport -OutputPath $outDir -ScanMetadata $metadata
            $content = Get-Content $path -Raw
        }
        It 'verdict is COMPROMISED'                    { $content | Should -Match 'COMPROMISED' }
        It 'check 8 row shows FAIL'                    { $content | Should -Match 'FAIL' }
        It 'REQUIRED ACTIONS mentions isolate machine'  { $content | Should -Match '[Ii]solat' }
    }
}
