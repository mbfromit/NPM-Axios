BeforeAll {
    . "$PSScriptRoot/../Private/Send-ScanReport.ps1"
    $testReport = Join-Path $TestDrive 'report.txt'
    'Report content' | Set-Content $testReport
}

Describe 'Send-ScanReport' {
    Context 'successful send' {
        BeforeAll { Mock Send-MailMessage { } }
        It 'returns true' {
            Send-ScanReport -ReportPaths @($testReport) -SMTPServer 'smtp.co.com' -SMTPPort 587 `
                -FromAddress 'a@co.com' -ToAddress @('b@co.com') -UseTLS $true | Should -BeTrue
        }
        It 'calls Send-MailMessage with correct server' {
            Send-ScanReport -ReportPaths @($testReport) -SMTPServer 'smtp.co.com' -SMTPPort 587 `
                -FromAddress 'a@co.com' -ToAddress @('b@co.com') -UseTLS $true
            Should -Invoke Send-MailMessage -Times 1 -ParameterFilter { $SmtpServer -eq 'smtp.co.com' -and $Port -eq 587 }
        }
        It 'attaches the report file' {
            Send-ScanReport -ReportPaths @($testReport) -SMTPServer 'smtp.co.com' -SMTPPort 587 `
                -FromAddress 'a@co.com' -ToAddress @('b@co.com') -UseTLS $true
            Should -Invoke Send-MailMessage -Times 1 -ParameterFilter { $Attachments -contains $testReport }
        }
    }
    Context 'SMTP failure' {
        BeforeAll { Mock Send-MailMessage { throw 'Connection refused' } }
        It 'returns false without throwing' {
            { Send-ScanReport -ReportPaths @($testReport) -SMTPServer 'smtp.co.com' -SMTPPort 587 `
                -FromAddress 'a@co.com' -ToAddress @('b@co.com') -UseTLS $true } | Should -Not -Throw
            Send-ScanReport -ReportPaths @($testReport) -SMTPServer 'smtp.co.com' -SMTPPort 587 `
                -FromAddress 'a@co.com' -ToAddress @('b@co.com') -UseTLS $true | Should -BeFalse
        }
    }
}
