function Find-PersistenceArtifacts {
    [CmdletBinding()]
    param(
        [datetime]$AttackWindowStart = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $suspiciousPaths = @('temp', 'tmp', 'appdata', 'localappdata', 'programdata', 'public')

    # ── Scheduled Tasks ────────────────────────────────────────────────────────
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } |
        ForEach-Object {
            $task = $_
            # Was this task registered after the attack?
            $taskDate = $null
            try { $taskDate = [datetime]::Parse($task.Date) } catch { }
            $isNew = $taskDate -and $taskDate -ge $AttackWindowStart

            foreach ($action in $task.Actions) {
                $exe  = if ($action.Execute)   { $action.Execute }   else { '' }
                $args = if ($action.Arguments) { $action.Arguments } else { '' }
                $full = "$exe $args".ToLower()

                $isSuspiciousPath   = $suspiciousPaths | Where-Object { $full -match $_ }
                $isSuspiciousExe    = $exe -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|cmd\.exe'
                $hasHiddenWindow    = $args -match '-windowstyle\s+hidden|-w\s+hidden|-nop|-noni'

                if ($isNew -or ($isSuspiciousPath -and $isSuspiciousExe) -or $hasHiddenWindow) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'SuspiciousScheduledTask'
                        Location    = "Task Scheduler: $($task.TaskPath)$($task.TaskName)"
                        Name        = $task.TaskName
                        Value       = "$exe $args"
                        Severity    = 'Critical'
                        Description = "Scheduled task '$($task.TaskName)' runs suspicious command: $exe $args"
                    })
                }
            }
        }
    } catch { Write-Warning "Scheduled task scan failed: $_" }

    # ── Registry Run Keys ──────────────────────────────────────────────────────
    $runKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($keyPath in $runKeys) {
        try {
            $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }

            $props.PSObject.Properties |
            Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
            ForEach-Object {
                $val  = $_.Value.ToLower()
                $isSuspiciousPath = $suspiciousPaths | Where-Object { $val -match $_ }
                $hasNodeOrScript  = $val -match 'node|npm|\.ps1|\.vbs|\.bat|\.cmd|\.js'

                if ($isSuspiciousPath -or $hasNodeOrScript) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'SuspiciousRunKey'
                        Location    = $keyPath
                        Name        = $_.Name
                        Value       = $_.Value
                        Severity    = 'Critical'
                        Description = "Registry Run key '$($_.Name)' points to suspicious path: $($_.Value)"
                    })
                }
            }
        } catch { Write-Warning "Registry key scan failed for ${keyPath}: $_" }
    }

    # ── Startup Folder ─────────────────────────────────────────────────────────
    $startupFolders = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($folder in $startupFolders) {
        try {
            Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -ge $AttackWindowStart } |
            ForEach-Object {
                $findings.Add([PSCustomObject]@{
                    Type        = 'SuspiciousStartupEntry'
                    Location    = $folder
                    Name        = $_.Name
                    Value       = $_.FullName
                    Severity    = 'Critical'
                    Description = "File added to startup folder after attack window: $($_.FullName)"
                })
            }
        } catch { Write-Warning "Startup folder scan failed for ${folder}: $_" }
    }

    return @($findings)
}
