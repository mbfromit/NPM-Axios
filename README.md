# RatCatcher 2.0

![RatCatcher 2.0](RatCatcher2.png)

An **AI-powered** PowerShell forensic scanner for detecting evidence of the **March 31, 2026 Axios NPM supply chain attack**, which distributed a malicious `plain-crypto-js` dependency via compromised versions of the `axios` package (v1.14.1 and v0.30.4). RatCatcher runs ten checks covering the full compromise kill chain, produces detailed reports, and **automatically evaluates every finding using Gemma 4 AI** to distinguish real threats from false positives.

You can read more about the attack here: https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html

---

## What's New in v2.0

- **Automatic AI Evaluation** - Every scan is automatically analysed by Gemma 4 AI. No manual steps needed - by the time you open the dashboard, the AI has already determined what is a real threat and what is a false positive.
- **Manager Certification** - When AI confirms a compromise, a manager must review the findings and certify with their name before the case is closed. Creates an audit trail.
- **AI Verdicts in Reports** - Technical Reports show AI assessments inline on each finding with colour-coded verdicts and reasoning.
- **Updated Threat Intelligence** - AI uses the latest IOCs from Elastic Security Labs, Unit42, Microsoft, and Google Threat Intelligence, including the confirmed North Korean state actor attribution.
- **Remediation Tracking** - Machines that were previously compromised but scanned clean are flagged as Remediated. Click any hostname to see full scan history.
- **Simplified Dashboard** - Six filter cards: Total, Clean, Reviewed, Positive Findings, Unreviewed, and Remediated. Every submission is accounted for.
- **Faster Scans** - Scanner skips non-development directories (media, drivers, VMs) to reduce scan time and false positives.
- **Status Legend** - Built-in legend explaining every dashboard status badge and manager certification flow.

> **Note:** The original Copilot Agent workflow still works exactly as before. AI is an addition, not a replacement. You can use AI only, Copilot only, or both.

---
NOTE: It is recommended that you stop and save all work before running. This scan can take a very long time.
## Download and Install

### Prerequisites

- **Windows** (PowerShell 5.1 minimum; **PowerShell 7+ strongly recommended** for parallel processing — see [Performance](#performance) below)
- No additional modules required

### Option 1 — Clone with Git

```powershell
git clone https://github.com/mbfromit/RatCatcher.git
cd RatCatcher
```

### Option 2 — Download ZIP

1. Go to the repository on GitHub
2. Click **Code → Download ZIP**
3. Extract the ZIP to a folder of your choice (e.g. `C:\Tools\RatCatcher`)
4. Open PowerShell and `cd` into that folder

### Allow the Script to Run

If you haven't run unsigned PowerShell scripts before, you may need to adjust the execution policy for your session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

> **Important:** This only changes the policy for the current PowerShell window. After the scan completes, close the PowerShell window or restore the default policy by running:
>
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Restricted
> ```
>
> Leaving the execution policy on Bypass allows any script to run without warning, which is a security risk.

---

## Running the Scanner

### Basic scan (defaults to all of C:\, skips OS folders)

```powershell
.\Invoke-RatCatcher.ps1
```

The script will display the exact folders it intends to scan and ask for confirmation before starting.

### Scan a specific folder

```powershell
.\Invoke-RatCatcher.ps1 -Path C:\Dev
```

### Scan multiple folders

```powershell
.\Invoke-RatCatcher.ps1 -Path C:\Dev, C:\Projects, C:\Users\you\source
```

### Save reports to a custom location

```powershell
.\Invoke-RatCatcher.ps1 -OutputPath C:\IR\Reports
```

### Submission password

Before the scan begins, you will be prompted to enter a **submission password**. This password is required — the scan will not run without it. Contact your **manager** or the **DevOps team** to obtain the password.

Reports are always saved locally to `C:\Logs` (or `-OutputPath`).

---

## Performance

| PowerShell Version | Check 2 (lockfile analysis) |
|---|---|
| 5.1 | Sequential — can take 30–60 min on large machines |
| 7+ | Parallel (4 threads by default) — typically under 2 min |

To install PowerShell 7 side-by-side with your existing PS5.1:

```powershell
winget install Microsoft.PowerShell
```

Then run the scanner with `pwsh` instead of `powershell`:

```powershell
pwsh .\Invoke-RatCatcher.ps1
```

You can also adjust the thread count:

```powershell
pwsh .\Invoke-RatCatcher.ps1 -Threads 8
```

---

## What the Scanner Checks

### Check 1 — Discover Node.js Projects

Recursively walks every folder in the scan path looking for `package.json` files, skipping `node_modules` subdirectories to avoid false positives. This builds the complete list of Node.js projects on the machine that will be examined in checks 2 and 3.

### Check 2 — Lockfile Analysis

For every project found in check 1, the scanner examines whichever lockfile is present (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`) and looks for two specific indicators:

- **Vulnerable axios versions** — `1.14.1` or `0.30.4` (the two compromised releases published by the attacker)
- **Malicious plain-crypto-js** — version `4.2.1` (the RAT-dropping dependency injected via the compromised axios releases)

A hit here means the project _referenced_ a malicious package at install time. It does not confirm the package was actually installed — check 3 verifies physical presence.

### Check 3 — Forensic Artifact Detection (Project Level)

Examines the `node_modules` directory of each project for physical evidence of compromise:

- **Malicious package presence** — checks whether `node_modules/plain-crypto-js` actually exists on disk
- **Known-bad file hash** — if `plain-crypto-js/setup.js` is present, computes its SHA-256 and compares it against the known malicious hash (`e10b1fa8...`). A hash mismatch is flagged as High severity (possible variant), a match is Critical
- **C2 indicators in source files** — scans `.js` files across the project (including inside `plain-crypto-js`) for hardcoded references to the attacker's C2 domain `sfrclak.com` or IP `142.11.206.73`

### Check 4 — npm Cache and Global npm

Inspects two locations that persist evidence even after `npm uninstall`:

- **npm content-addressable cache** (`~/.npm/_cacache/index-v5`) — searches cache index entries for references to `plain-crypto-js-4.2.1.tgz`, `axios-1.14.1.tgz`, or `axios-0.30.4.tgz`. A hit means the malicious tarball was downloaded and cached, even if the project has since been cleaned up. Remediation: `npm cache clean --force`
- **Global npm install** — checks whether `axios` or `plain-crypto-js` is installed globally (`npm root -g`) and flags any installation at a vulnerable version as Critical

### Check 5 — Dropped Payload Search

The malicious `plain-crypto-js` setup script drops a Remote Access Trojan (RAT) to disk during `npm install`. This check scans `%TEMP%`, `%TMP%`, `%LOCALAPPDATA%`, and `%APPDATA%` for files created **after the attack window start (2026-03-31 00:21 UTC)** that match dropper behavior:

- **Executables and DLLs** — reads the first two bytes of every file and flags any with a PE/MZ header (`0x4D 0x5A`), regardless of file extension (severity: Critical)
- **Suspicious scripts** — flags `.ps1`, `.vbs`, `.bat`, and `.cmd` files created in temp locations after the attack window (severity: High)

### Check 6 — Persistence Mechanisms

If the RAT was executed, it will have attempted to establish persistence. This check examines three Windows persistence locations for artifacts created after the attack window or bearing suspicious characteristics:

- **Scheduled Tasks** — enumerates all non-Microsoft, non-disabled tasks. Flags tasks that were registered after the attack window, or that invoke living-off-the-land binaries (`powershell`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`) from temp/appdata paths, or that use hidden window arguments (`-WindowStyle Hidden`, `-NonInteractive`)
- **Registry Run Keys** — inspects `HKCU\...\Run`, `HKLM\...\Run`, `HKCU\...\RunOnce`, and `HKLM\...\RunOnce` for entries that reference node, npm, or script files (`.ps1`, `.vbs`, `.bat`, `.cmd`, `.js`)
- **Startup Folders** — checks the user and all-users startup folders for any files added after the attack window

### Check 7 — XOR-Encoded C2 Indicators

The RAT is known to store its C2 configuration XOR-encoded to evade simple string searches. This check reads files from temp and appdata locations, decodes them using the attacker's known XOR scheme (key: `OrDeR_7077`, constant: `333`), and searches the decoded output for the C2 domain `sfrclak.com` and IP `142.11.206.73`. Scanned file types include `.exe`, `.dll`, `.bin`, `.dat`, `.ps1`, `.js`, `.vbs`, `.bat`, `.tmp`, and `.log`.

### Check 8 — Network Evidence

Looks for signs that the RAT has already communicated with the attacker's infrastructure:

- **Active TCP connections** — queries live network connections for any session currently open to `142.11.206.73` or port `8000` (the known C2 beacon port). If found, identifies the owning process by PID. An active connection means the RAT is running right now
- **DNS cache** — runs `ipconfig /displaydns` and searches the output for `sfrclak.com`. A cache hit means the machine resolved the attacker's domain at some point since the last DNS flush, indicating a connection attempt was made
- **Windows Firewall log** — if the firewall log is enabled (`C:\Windows\System32\LogFiles\Firewall\pfirewall.log`), searches it for any historical traffic to `142.11.206.73` and includes sample log lines as evidence

### Check 9 — Report Generation

Produces two output files in the report directory:

- **Technical forensic report** — full detail on every finding across all ten checks, including file paths, hashes, timestamps, severity ratings, and remediation commands
- **Executive briefing** — a concise summary suitable for management or incident response teams, covering scope, confirmed findings, and recommended actions

Both files are named with the hostname and timestamp for easy identification.

### Check 10 — Dashboard Submission

Submits the scan results (verdict, finding counts, and report files) to the RatCatcher dashboard using the submission password entered at the start of the scan. Reports are always saved locally regardless of whether submission succeeds.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No compromise evidence found across all 10 checks |
| `1` | One or more Critical or lockfile findings detected — review reports immediately |

---

## Indicators of Compromise (IOC) Reference

| Indicator | Type | Description |
|---|---|---|
| `axios` v1.14.1 | npm package | Compromised release |
| `axios` v0.30.4 | npm package | Compromised release |
| `plain-crypto-js` v4.2.0 | npm package | Staging package (precursor) |
| `plain-crypto-js` v4.2.1 | npm package | Malicious RAT-dropping dependency |
| `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` | SHA-256 | Known malicious `setup.js` |
| `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` | SHA-256 | Windows PowerShell RAT payload |
| `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` | SHA-256 | macOS C++ binary payload |
| `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` | SHA-256 | Linux Python RAT payload |
| `sfrclak.com` | Domain | Primary C2 domain |
| `callnrwise.com` | Domain | Secondary C2 domain |
| `142.11.206.73` | IP address | C2 server |
| `142.11.206.73:8000` | IP:Port | RAT beacon endpoint |
| `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` | User-Agent | Spoofed UA used by all RAT variants |
| `%TEMP%\6202033.ps1` | File path | Windows RAT payload temp location |
| `%PROGRAMDATA%\wt.exe` | File path | Renamed PowerShell binary |
| `%PROGRAMDATA%\system.bat` | File path | Windows persistence batch file |

**Attribution:** UNC1069 / Sapphire Sleet (North Korean state actor) - confirmed by Google Threat Intelligence and Microsoft.
