BeforeAll {
    . "$PSScriptRoot/../Private/Find-ForensicArtifacts.ps1"
    $fix = "$PSScriptRoot/Fixtures"
}

Describe 'Find-ForensicArtifacts' {
    Context 'clean project' {
        It 'returns empty' { Find-ForensicArtifacts -ProjectPath "$fix/CleanProject" | Should -BeNullOrEmpty }
    }
    Context 'vulnerable npm project' {
        BeforeAll { $results = Find-ForensicArtifacts -ProjectPath "$fix/VulnerableNpmProject" }
        It 'detects plain-crypto-js dir as MaliciousPackage Critical' {
            $r = $results | Where-Object Type -eq 'MaliciousPackage'
            $r          | Should -Not -BeNullOrEmpty
            $r.Severity | Should -Be 'Critical'
        }
        It 'detects setup.js as MaliciousScript with a hash' {
            $r = $results | Where-Object Type -eq 'MaliciousScript'
            $r      | Should -Not -BeNullOrEmpty
            $r.Hash | Should -Not -BeNullOrEmpty
        }
        It 'detects sfrclak.com as C2Indicator Critical' {
            $r = $results | Where-Object Type -eq 'C2Indicator'
            $r                | Should -Not -BeNullOrEmpty
            $r.Severity       | Should -Be 'Critical'
            $r.Description    | Should -Match 'sfrclak\.com'
        }
    }
    Context 'setup.js matching known malicious hash' {
        It 'sets severity Critical and description contains hash match' {
            . "$PSScriptRoot/../Private/Find-ForensicArtifacts.ps1"
            Mock Get-FileHash { [PSCustomObject]@{ Hash = 'E10B1FA84F1D6481625F741B69892780140D4E0E7769E7491E5F4D894C2E0E09' } }
            $r = (Find-ForensicArtifacts -ProjectPath "$fix/VulnerableNpmProject") | Where-Object Type -eq 'MaliciousScript'
            $r.Severity    | Should -Be 'Critical'
            $r.Description | Should -Match 'hash match'
        }
    }
}
