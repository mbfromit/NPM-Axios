BeforeAll {
    . "$PSScriptRoot/../Private/Invoke-NpmCacheScan.ps1"
}

Describe 'Invoke-NpmCacheScan' {
    Context 'npm not installed' {
        BeforeAll { Mock Get-Command { $null } -ParameterFilter { $Name -eq 'npm' } }
        It 'returns empty without throwing' {
            { Invoke-NpmCacheScan } | Should -Not -Throw
            Invoke-NpmCacheScan    | Should -BeNullOrEmpty
        }
    }

    Context 'malicious package in npm cache index' {
        BeforeAll {
            # Simulate a cache index directory with a file referencing plain-crypto-js@4.2.1
            $fakeCacheDir = Join-Path $TestDrive 'npm-cache'
            $indexDir     = Join-Path $fakeCacheDir '_cacache/index-v5/ab/cd'
            $null = New-Item -ItemType Directory -Path $indexDir -Force
            # npm cache index entries are newline-delimited JSON; write a fake one
            $entry = '{"key":"make-fetch-happen:request-cache:https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz","integrity":"sha512-FAKE","time":1743379261000}'
            $entry | Set-Content (Join-Path $indexDir 'fakeentry')

            Mock Invoke-Expression { return $fakeCacheDir } -ParameterFilter { $Command -match 'npm config get cache' }
            Mock Get-Command { [PSCustomObject]@{ Name = 'npm' } } -ParameterFilter { $Name -eq 'npm' }
        }
        It 'returns a finding of type NpmCacheHit' {
            $results = Invoke-NpmCacheScan
            ($results | Where-Object Type -eq 'NpmCacheHit') | Should -Not -BeNullOrEmpty
        }
        It 'finding severity is High' {
            ($results | Where-Object Type -eq 'NpmCacheHit').Severity | Should -Be 'High'
        }
    }

    Context 'CacheDirOverride bypasses npm config command' {
        BeforeAll {
            $overrideDir = Join-Path $TestDrive 'override-cache'
            $indexDir    = Join-Path $overrideDir '_cacache/index-v5/ab/cd'
            $null = New-Item -ItemType Directory -Path $indexDir -Force
            '{"key":"https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz"}' |
                Set-Content (Join-Path $indexDir 'entry')
            Mock Get-Command { [PSCustomObject]@{ Name = 'npm' } } -ParameterFilter { $Name -eq 'npm' }
        }
        It 'finds NpmCacheHit using the override directory' {
            $results = Invoke-NpmCacheScan -CacheDirOverride $overrideDir
            ($results | Where-Object Type -eq 'NpmCacheHit') | Should -Not -BeNullOrEmpty
        }
        It 'does not invoke npm config get cache when override is provided' {
            Mock Invoke-Expression { throw 'should not call npm config' } -ParameterFilter { $Command -match 'npm config get cache' }
            { Invoke-NpmCacheScan -CacheDirOverride $overrideDir } | Should -Not -Throw
        }
    }

    Context 'malicious package installed globally' {
        BeforeAll {
            $fakeGlobal = Join-Path $TestDrive 'global-npm'
            $null = New-Item -ItemType Directory -Path (Join-Path $fakeGlobal 'plain-crypto-js') -Force

            Mock Invoke-Expression { return $fakeGlobal } -ParameterFilter { $Command -match 'npm root -g' }
            Mock Get-Command { [PSCustomObject]@{ Name = 'npm' } } -ParameterFilter { $Name -eq 'npm' }
            Mock Invoke-Expression { return '' } -ParameterFilter { $Command -match 'npm config get cache' }
        }
        It 'returns a finding of type GlobalNpmHit' {
            $results = Invoke-NpmCacheScan
            ($results | Where-Object Type -eq 'GlobalNpmHit') | Should -Not -BeNullOrEmpty
        }
        It 'finding severity is Critical' {
            ($results | Where-Object Type -eq 'GlobalNpmHit').Severity | Should -Be 'Critical'
        }
    }
}
