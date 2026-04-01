BeforeAll {
    $script    = "$PSScriptRoot/../Invoke-AxiosCompromiseScanner.ps1"
    $fixRoot   = "$PSScriptRoot/Fixtures"
    $outDir    = Join-Path $TestDrive 'output'
}

Describe 'Invoke-AxiosCompromiseScanner integration' {
    It 'runs without throwing' {
        { & $script -Path $fixRoot -OutputPath $outDir } | Should -Not -Throw
    }
    It 'creates a report file' {
        & $script -Path $fixRoot -OutputPath $outDir
        (Get-ChildItem $outDir -Filter 'Axios-Scan-*.txt' -ErrorAction SilentlyContinue).Count | Should -BeGreaterOrEqual 1
    }
    It 'exits 1 when vulnerable projects found' {
        $proc = Start-Process pwsh -ArgumentList @('-NonInteractive','-NoProfile','-File',$script,'-Path',"$fixRoot/VulnerableNpmProject",'-OutputPath',$outDir) -Wait -PassThru -NoNewWindow
        $proc.ExitCode | Should -Be 1
    }
    It 'exits 0 when only clean projects found' {
        $proc = Start-Process pwsh -ArgumentList @('-NonInteractive','-NoProfile','-File',$script,'-Path',"$fixRoot/CleanProject",'-OutputPath',$outDir) -Wait -PassThru -NoNewWindow
        $proc.ExitCode | Should -Be 0
    }
    It 'throws when -SendEmail used without -SMTPServer' {
        { & $script -Path $fixRoot -OutputPath $outDir -SendEmail } | Should -Throw '*SMTPServer*'
    }
}
