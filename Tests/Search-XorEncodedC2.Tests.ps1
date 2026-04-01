BeforeAll {
    . "$PSScriptRoot/../Private/Search-XorEncodedC2.ps1"
}

Describe 'Search-XorEncodedC2' {
    Context 'XOR encoding/decoding' {
        It 'decodes a string encoded with OrDeR_7077 key and 333 constant back to original' {
            $original  = 'sfrclak.com'
            $key       = 'OrDeR_7077'
            $constant  = 333 -band 0xFF   # = 77

            $keyBytes   = [Text.Encoding]::UTF8.GetBytes($key)
            $srcBytes   = [Text.Encoding]::UTF8.GetBytes($original)
            $encoded    = New-Object byte[] $srcBytes.Length
            for ($i = 0; $i -lt $srcBytes.Length; $i++) {
                $encoded[$i] = [byte](($srcBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]) -bxor $constant)
            }

            $decoded = Invoke-XorDecode -Data $encoded
            [Text.Encoding]::UTF8.GetString($decoded) | Should -Be $original
        }
    }

    Context 'file containing XOR-encoded C2 domain' {
        BeforeAll {
            $key      = 'OrDeR_7077'
            $constant = 333 -band 0xFF
            $keyBytes = [Text.Encoding]::UTF8.GetBytes($key)
            $srcBytes = [Text.Encoding]::UTF8.GetBytes('sfrclak.com')
            $encoded  = New-Object byte[] $srcBytes.Length
            for ($i = 0; $i -lt $srcBytes.Length; $i++) {
                $encoded[$i] = [byte](($srcBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]) -bxor $constant)
            }

            $tmpDir  = Join-Path $TestDrive 'xor-test'
            $null    = New-Item -ItemType Directory $tmpDir -Force
            $xorFile = Join-Path $tmpDir 'payload.bin'
            # Pad with some junk before and after
            $junk    = [byte[]](1..10 | ForEach-Object { Get-Random -Maximum 255 })
            [IO.File]::WriteAllBytes($xorFile, ($junk + $encoded + $junk))
        }
        It 'detects XOR-encoded sfrclak.com as XorEncodedC2' {
            $results = Search-XorEncodedC2 -SearchPaths @($tmpDir)
            ($results | Where-Object Type -eq 'XorEncodedC2') | Should -Not -BeNullOrEmpty
        }
        It 'severity is Critical' {
            $results = Search-XorEncodedC2 -SearchPaths @($tmpDir)
            ($results | Where-Object Type -eq 'XorEncodedC2').Severity | Should -Be 'Critical'
        }
        It 'includes decoded indicator in finding' {
            $results = Search-XorEncodedC2 -SearchPaths @($tmpDir)
            ($results | Where-Object Type -eq 'XorEncodedC2').DecodedIndicator | Should -Match 'sfrclak\.com'
        }
    }

    Context 'files larger than 5 MB are skipped' {
        BeforeAll {
            $largeDir = Join-Path $TestDrive 'large-xor'
            $null = New-Item -ItemType Directory $largeDir -Force

            # Build a file that is >5 MB and contains a valid XOR-encoded C2 indicator
            $key      = 'OrDeR_7077'
            $constant = 333 -band 0xFF
            $keyBytes = [Text.Encoding]::UTF8.GetBytes($key)
            $srcBytes = [Text.Encoding]::UTF8.GetBytes('sfrclak.com')
            $encoded  = New-Object byte[] $srcBytes.Length
            for ($i = 0; $i -lt $srcBytes.Length; $i++) {
                $encoded[$i] = [byte](($srcBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]) -bxor $constant)
            }
            $padding = New-Object byte[] (6 * 1024 * 1024)   # 6 MB of zeros
            [IO.File]::WriteAllBytes((Join-Path $largeDir 'huge.bin'), ($padding + $encoded))
        }
        It 'returns no findings for a file over 5 MB' {
            Search-XorEncodedC2 -SearchPaths @($largeDir) | Should -BeNullOrEmpty
        }
    }

    Context 'clean file' {
        BeforeAll {
            $cleanDir  = Join-Path $TestDrive 'clean-xor'
            $null      = New-Item -ItemType Directory $cleanDir -Force
            'hello world this is a normal file' | Set-Content (Join-Path $cleanDir 'readme.txt')
        }
        It 'returns empty for files with no encoded C2' {
            Search-XorEncodedC2 -SearchPaths @($cleanDir) | Should -BeNullOrEmpty
        }
    }
}
