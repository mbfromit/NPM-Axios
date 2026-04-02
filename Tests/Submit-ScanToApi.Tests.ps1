BeforeAll {
    . "$PSScriptRoot/../Private/Submit-ScanToApi.ps1"
    $briefFile  = Join-Path $TestDrive 'brief.html'
    $reportFile = Join-Path $TestDrive 'report.html'
    '<html>brief</html>'  | Set-Content $briefFile
    '<html>report</html>' | Set-Content $reportFile

    $baseParams = @{
        ApiUrl          = 'https://mbfromit.com/ratcatcher/submit'
        Password        = 'correct-pass'
        Hostname        = 'DESKTOP-TEST'
        Username        = 'testuser'
        ScanTimestamp   = '2026-04-01 14:32:00 UTC'
        Duration        = '47.3s'
        Verdict         = 'CLEAN'
        ProjectsScanned = 5
        VulnerableCount = 0
        CriticalCount   = 0
        PathsScanned    = '["C:\\Dev"]'
        BriefPath       = $briefFile
        ReportPath      = $reportFile
    }
}

Describe 'Submit-ScanToApi' {
    Context 'empty password' {
        It 'returns status skipped without calling Invoke-RestMethod' {
            Mock Invoke-RestMethod {}
            $result = Submit-ScanToApi @baseParams -Password ''
            $result.Status | Should -Be 'skipped'
            Should -Invoke Invoke-RestMethod -Times 0
        }
    }

    Context 'successful submission' {
        BeforeAll {
            Mock Invoke-RestMethod { return [PSCustomObject]@{ id = 'test-uuid-1234' } }
        }

        It 'returns status success with the submission ID' {
            $result = Submit-ScanToApi @baseParams
            $result.Status | Should -Be 'success'
            $result.Id     | Should -Be 'test-uuid-1234'
        }

        It 'calls Invoke-RestMethod with the correct URI' {
            Submit-ScanToApi @baseParams
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -eq 'https://mbfromit.com/ratcatcher/submit'
            }
        }

        It 'calls Invoke-RestMethod with POST method' {
            Submit-ScanToApi @baseParams
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Method -eq 'POST'
            }
        }
    }

    Context 'wrong password (401 response)' {
        BeforeAll {
            Mock Invoke-RestMethod {
                $ex = [System.Net.WebException]::new('401')
                $response = [PSCustomObject]@{ StatusCode = [System.Net.HttpStatusCode]::Unauthorized }
                Add-Member -InputObject $ex -MemberType NoteProperty -Name Response -Value $response -Force
                throw $ex
            }
        }

        It 'returns status wrong-password' {
            $result = Submit-ScanToApi @baseParams
            $result.Status | Should -Be 'wrong-password'
        }

        It 'does not throw' {
            { Submit-ScanToApi @baseParams } | Should -Not -Throw
        }
    }

    Context 'network error' {
        BeforeAll {
            Mock Invoke-RestMethod { throw [System.Net.WebException]::new('Connection refused') }
        }

        It 'returns status error with a message' {
            $result = Submit-ScanToApi @baseParams
            $result.Status  | Should -Be 'error'
            $result.Message | Should -Not -BeNullOrEmpty
        }

        It 'does not throw' {
            { Submit-ScanToApi @baseParams } | Should -Not -Throw
        }
    }
}
