# Linux Python Port — Axios Compromise Scanner
**Date:** 2026-04-01
**Status:** Approved

## Overview

A Linux-native port of `Invoke-AxiosCompromiseScanner.ps1`, written in Python 3.9 using stdlib only. Placed in `linux-port/` subfolder of the existing `NPM-Axios` project. Scans for evidence of the March 31, 2026 Axios NPM supply chain attack, with Windows-specific checks replaced by Linux equivalents. Email sending is dropped from this version.

---

## Structure

```
linux-port/
  axios_scanner.py         # entry point — argparse, orchestration, confirmation prompt
  checks/
    __init__.py
    node_projects.py       # find package.json files (os.walk, excludes node_modules)
    lockfile_analysis.py   # parse npm/yarn/pnpm lockfiles for vulnerable versions
    forensic_artifacts.py  # scan node_modules/plain-crypto-js, hash setup.js, scan .js for C2 indicators
    npm_cache.py           # scan ~/.npm/_cacache/index-v5 for plain-crypto-js entries
    dropped_payloads.py    # find ELF/suspicious files in /tmp, /var/tmp, ~/.cache, ~/.local/share
    persistence.py         # cron jobs, systemd user timers, shell RC file injections
    xor_c2.py              # XOR decode (key=OrDeR_7077, constant=333) and scan files
    network_evidence.py    # ss / /proc/net/tcp for active connections, /etc/hosts, syslog
    report.py              # write technical report + exec briefing text files
  tests/
    __init__.py
    fixtures/              # copied from existing Tests/Fixtures (CleanProject, VulnerableNpmProject, etc.)
    test_node_projects.py
    test_lockfile_analysis.py
    test_forensic_artifacts.py
    test_npm_cache.py
    test_dropped_payloads.py
    test_persistence.py
    test_network_evidence.py
    test_xor_c2.py
    test_report.py
    test_scanner.py        # integration test
```

---

## Check Mapping

| # | Check | PS Module | Python Module | Notes |
|---|---|---|---|---|
| 1 | Node project discovery | `Get-NodeProjects` | `node_projects.py` | `os.walk`, excludes `node_modules` |
| 2 | Lockfile analysis | `Invoke-LockfileAnalysis` | `lockfile_analysis.py` | npm/yarn/pnpm; flags `axios@1.14.1`, `plain-crypto-js` |
| 3 | Forensic artifacts | `Find-ForensicArtifacts` | `forensic_artifacts.py` | `plain-crypto-js` dir, `setup.js` SHA-256, C2 patterns in .js files |
| 4 | npm cache | `Invoke-NpmCacheScan` | `npm_cache.py` | Scans `~/.npm/_cacache/index-v5` JSON entries |
| 5 | Dropped payloads | `Search-DroppedPayloads` | `dropped_payloads.py` | ELF header (`\x7fELF`) replaces PE (`MZ`); Linux temp paths |
| 6 | Persistence | `Find-PersistenceArtifacts` | `persistence.py` | **Replaced**: cron, systemd timers, shell RC injection |
| 7 | XOR-encoded C2 | `Search-XorEncodedC2` | `xor_c2.py` | Identical logic |
| 8 | Network evidence | `Get-NetworkEvidence` | `network_evidence.py` | **Replaced**: `ss -tnp`, `/proc/net/tcp`, `/etc/hosts`, syslog |
| 9 | Report generation | `New-ScanReport` + `New-ExecBriefing` | `report.py` | Both reports in one module |
| 10 | Email | `Send-ScanReport` | **Dropped** | Not included in Linux port |

---

## Finding Schema

All checks return a list of `Finding` namedtuples:

```python
Finding = namedtuple('Finding', ['type', 'path', 'detail', 'severity', 'description', 'hash'])
```

Severity values: `Critical`, `High`, `Medium`, `Info`

---

## Linux Persistence Check Detail

Replaces Windows registry Run keys, scheduled tasks, and startup folder checks.

**Cron jobs** — flags entries referencing `/tmp`, `/var/tmp`, `~/.cache`, `node`, `npm`, or `.js`:
- `crontab -l` (current user)
- `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/crontab`
- Files modified after attack window → finding type `SuspiciousCronEntry` (Critical)

**Systemd user timers** — scans `~/.config/systemd/user/*.timer` and `*.service` created/modified after attack window for suspicious `ExecStart` values:
- Finding type: `SuspiciousSystemdUnit` (Critical)

**Shell RC injection** — scans `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc` for lines matching suspicious patterns (node/npm/tmp paths), file `mtime` after attack window:
- Finding type: `SuspiciousRcInjection` (Critical)

---

## Linux Network Evidence Detail

Replaces Windows `Get-NetTCPConnection` and firewall log.

- **Active connections**: `ss -tnp` output parsed for C2 IP `142.11.206.73` or port `8000`; falls back to `/proc/net/tcp` if `ss` unavailable → `ActiveC2Connection` (Critical)
- **Hosts file**: `/etc/hosts` scanned for C2 domain `sfrclak.com` → `HostsFileHit` (Critical)
- **Syslog**: `/var/log/syslog` and `/var/log/auth.log` scanned for C2 IP/domain → `SyslogHit` (High)

---

## Data Flow

```
axios_scanner.py
  │
  ├─ [1] node_projects.py        → project list
  │         │
  ├─ [2] lockfile_analysis.py   ← project list (threaded)
  ├─ [3] forensic_artifacts.py  ← project list (threaded)
  │
  ├─ [4] npm_cache.py           (system-wide)
  ├─ [5] dropped_payloads.py    (system-wide)
  ├─ [6] persistence.py         (system-wide)
  ├─ [7] xor_c2.py              (system-wide)
  ├─ [8] network_evidence.py    (system-wide)
  │
  └─ [9] report.py              ← all findings → technical report + exec briefing
```

Checks 2 & 3 run via `concurrent.futures.ThreadPoolExecutor` when `--threads > 1` (default: 4).

---

## Error Handling

- Each check catches all exceptions internally and returns an empty list on failure
- Errors logged to run log as `[WARN]` — a failed check never halts the scan
- Missing tools (`npm`, `ss`) handled gracefully with a warning log entry
- Mirrors PowerShell `$ErrorActionPreference = 'Continue'` behaviour

---

## CLI Interface

```
python3 axios_scanner.py [--path PATH [PATH ...]] [--output DIR] [--threads N]
```

Defaults:
- `--path /` (expanded to immediate subdirectories, excluding `/proc`, `/sys`, `/dev`)
- `--output /tmp`
- `--threads 4`

Shows confirmation prompt listing scan paths before starting. Accepts Enter to proceed, `q` to quit.

**Exit codes:** `1` if any vulnerable lockfiles or critical findings; `0` if clean.

---

## Testing

Run: `python3 -m unittest discover linux-port/tests/`

| Test file | Approach |
|---|---|
| `test_node_projects.py` | Fixture-based |
| `test_lockfile_analysis.py` | Fixture-based (npm/yarn/pnpm fixtures) |
| `test_forensic_artifacts.py` | Fixture-based |
| `test_npm_cache.py` | `tempfile` + mock `subprocess.run` for npm path |
| `test_dropped_payloads.py` | `tempfile` with ELF header bytes (`\x7fELF`) |
| `test_persistence.py` | `tempfile` for crontab, RC, and systemd unit files |
| `test_network_evidence.py` | `unittest.mock.patch` for `subprocess.run` and file reads |
| `test_xor_c2.py` | Direct logic test + `tempfile` with encoded bytes |
| `test_report.py` | Verifies output file creation and key string content |
| `test_scanner.py` | Integration: runs scanner against fixtures, checks exit codes |

---

## Constraints

- Python 3.9, stdlib only — no `pip install` required
- No email functionality
- No Windows-specific checks
- Fixtures copied from existing `Tests/Fixtures/` into `linux-port/tests/fixtures/` so the port is self-contained and can be deployed independently
