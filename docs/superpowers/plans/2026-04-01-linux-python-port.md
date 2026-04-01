# Linux Python Port — Axios Compromise Scanner — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the PowerShell Axios compromise scanner to a self-contained Python 3.9 (stdlib-only) package in `linux-port/`, replacing Windows-specific checks with Linux equivalents and dropping email.

**Architecture:** Nine check modules under `linux-port/checks/` orchestrated by `linux-port/axios_scanner.py`. All checks return `Finding` namedtuples (or `LockfileResult` namedtuples for check 2). Checks 2 & 3 run in parallel via `concurrent.futures.ThreadPoolExecutor`. Each check catches all exceptions internally and never halts the scan. Exit code 1 = compromised, 0 = clean.

**Tech Stack:** Python 3.9, stdlib only — `os`, `re`, `json`, `subprocess`, `hashlib`, `datetime`, `concurrent.futures`, `argparse`, `collections`, `unittest`, `tempfile`, `unittest.mock`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `linux-port/axios_scanner.py` | Entry point: argparse, path resolution, confirmation prompt, orchestration |
| `linux-port/checks/__init__.py` | Exports `Finding` namedtuple |
| `linux-port/checks/node_projects.py` | `find_node_projects(paths)` — walk for package.json, exclude node_modules |
| `linux-port/checks/lockfile_analysis.py` | `analyze_lockfile(project_path)` — npm/yarn/pnpm; exports `LockfileResult` |
| `linux-port/checks/forensic_artifacts.py` | `find_forensic_artifacts(project_path)` — plain-crypto-js dir, setup.js hash, C2 patterns in .js |
| `linux-port/checks/npm_cache.py` | `scan_npm_cache()` — `~/.npm/_cacache/index-v5` + global npm |
| `linux-port/checks/dropped_payloads.py` | `scan_dropped_payloads(scan_paths)` — ELF header + scripts in temp dirs post attack window |
| `linux-port/checks/persistence.py` | `find_persistence_artifacts(rc_files, cron_paths, systemd_user_dir)` |
| `linux-port/checks/xor_c2.py` | `xor_decode(data)` + `scan_xor_encoded_c2(scan_paths)` |
| `linux-port/checks/network_evidence.py` | `get_network_evidence(hosts_path, syslog_paths)` — ss/proc, hosts, syslog |
| `linux-port/checks/report.py` | `write_reports(...)` — technical report + exec briefing, chmod 600 |
| `linux-port/tests/__init__.py` | Empty |
| `linux-port/tests/fixtures/` | Copied from `Tests/Fixtures/` |
| `linux-port/tests/test_node_projects.py` | Fixture-based |
| `linux-port/tests/test_lockfile_analysis.py` | Fixture-based (npm/yarn/pnpm/malformed) |
| `linux-port/tests/test_forensic_artifacts.py` | Fixture-based |
| `linux-port/tests/test_npm_cache.py` | tempfile + mock subprocess |
| `linux-port/tests/test_dropped_payloads.py` | tempfile with ELF magic bytes |
| `linux-port/tests/test_persistence.py` | tempfile + mock subprocess for crontab |
| `linux-port/tests/test_xor_c2.py` | Direct decode logic + tempfile |
| `linux-port/tests/test_network_evidence.py` | mock subprocess + tempfile |
| `linux-port/tests/test_report.py` | Verify file creation and content |
| `linux-port/tests/test_scanner.py` | Integration: scan fixtures, check exit codes |

**Run all tests from project root:**
```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -v
```

**Run single test file:**
```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_node_projects.py" -v
```

---

## Task 1: Scaffold directory structure and copy fixtures

**Files:**
- Create: `linux-port/` tree (dirs + empty `__init__.py` files)
- Create: `linux-port/tests/fixtures/` (copy from `Tests/Fixtures/`)

- [ ] **Step 1: Create directories and empty init files**

```bash
mkdir -p "linux-port/checks" "linux-port/tests/fixtures"
touch "linux-port/checks/__init__.py" "linux-port/tests/__init__.py"
```

- [ ] **Step 2: Copy fixtures**

```bash
cp -r "Tests/Fixtures/CleanProject" "linux-port/tests/fixtures/"
cp -r "Tests/Fixtures/VulnerableNpmProject" "linux-port/tests/fixtures/"
cp -r "Tests/Fixtures/VulnerableYarnProject" "linux-port/tests/fixtures/"
cp -r "Tests/Fixtures/VulnerablePnpmProject" "linux-port/tests/fixtures/"
cp -r "Tests/Fixtures/MalformedProject" "linux-port/tests/fixtures/"
```

- [ ] **Step 3: Verify structure**

```bash
find linux-port -type f | sort
```

Expected output includes:
```
linux-port/checks/__init__.py
linux-port/tests/__init__.py
linux-port/tests/fixtures/CleanProject/package-lock.json
linux-port/tests/fixtures/CleanProject/package.json
linux-port/tests/fixtures/MalformedProject/package-lock.json
linux-port/tests/fixtures/VulnerableNpmProject/malware-loader.js
linux-port/tests/fixtures/VulnerableNpmProject/node_modules/plain-crypto-js/setup.js
linux-port/tests/fixtures/VulnerableNpmProject/package-lock.json
linux-port/tests/fixtures/VulnerablePnpmProject/pnpm-lock.yaml
linux-port/tests/fixtures/VulnerableYarnProject/yarn.lock
```

- [ ] **Step 4: Commit**

```bash
git add linux-port/
git commit -m "feat: scaffold linux-port directory structure and copy test fixtures"
```

---

## Task 2: `checks/__init__.py` — Finding namedtuple

**Files:**
- Modify: `linux-port/checks/__init__.py`

- [ ] **Step 1: Write the test**

Create `linux-port/tests/test_finding.py`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks import Finding

class TestFinding(unittest.TestCase):
    def test_fields(self):
        f = Finding(
            type='MaliciousPackage', path='/tmp/foo', detail='bar',
            severity='Critical', description='desc', hash='abc123'
        )
        self.assertEqual(f.type, 'MaliciousPackage')
        self.assertEqual(f.severity, 'Critical')
        self.assertIsNone(Finding(
            type='x', path='y', detail=None,
            severity='High', description='d', hash=None
        ).hash)

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_finding.py" -v
```

Expected: `ImportError` or `AttributeError` — `Finding` not yet defined.

- [ ] **Step 3: Implement**

Write `linux-port/checks/__init__.py`:

```python
from collections import namedtuple

Finding = namedtuple('Finding', ['type', 'path', 'detail', 'severity', 'description', 'hash'])
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_finding.py" -v
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/__init__.py linux-port/tests/test_finding.py
git commit -m "feat: add Finding namedtuple to checks/__init__.py"
```

---

## Task 3: `checks/node_projects.py`

**Files:**
- Create: `linux-port/checks/node_projects.py`
- Create: `linux-port/tests/test_node_projects.py`

- [ ] **Step 1: Write the failing test**

Create `linux-port/tests/test_node_projects.py`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks.node_projects import find_node_projects

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')

class TestFindNodeProjects(unittest.TestCase):
    def test_finds_all_fixture_projects(self):
        projects = find_node_projects([FIXTURES])
        names = [os.path.basename(p) for p in projects]
        self.assertIn('CleanProject', names)
        self.assertIn('VulnerableNpmProject', names)
        self.assertIn('VulnerableYarnProject', names)
        self.assertIn('VulnerablePnpmProject', names)

    def test_excludes_node_modules_paths(self):
        projects = find_node_projects([FIXTURES])
        for p in projects:
            parts = p.replace('\\', '/').split('/')
            self.assertNotIn('node_modules', parts)

    def test_nonexistent_path_returns_empty(self):
        self.assertEqual(find_node_projects(['/nonexistent/xyz123']), [])

    def test_empty_list_returns_empty(self):
        self.assertEqual(find_node_projects([]), [])

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_node_projects.py" -v
```

Expected: `ModuleNotFoundError: No module named 'checks.node_projects'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/checks/node_projects.py`:

```python
import os


def find_node_projects(paths):
    """Return list of directory paths containing package.json, excluding node_modules."""
    projects = []
    for root_path in paths:
        if not os.path.isdir(root_path):
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root_path):
                dirnames[:] = [d for d in dirnames if d != 'node_modules']
                if 'package.json' in filenames:
                    projects.append(dirpath)
        except Exception:
            pass
    return projects
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_node_projects.py" -v
```

Expected: `Ran 4 tests in ...s  OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/node_projects.py linux-port/tests/test_node_projects.py
git commit -m "feat: add node_projects check — find package.json excluding node_modules"
```

---

## Task 4: `checks/lockfile_analysis.py`

**Files:**
- Create: `linux-port/checks/lockfile_analysis.py`
- Create: `linux-port/tests/test_lockfile_analysis.py`

- [ ] **Step 1: Write the failing test**

Create `linux-port/tests/test_lockfile_analysis.py`:

```python
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks.lockfile_analysis import analyze_lockfile

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')

class TestAnalyzeLockfile(unittest.TestCase):
    def test_npm_clean(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'CleanProject'))
        self.assertEqual(r.lockfile_type, 'npm')
        self.assertFalse(r.has_vulnerable_axios)
        self.assertFalse(r.has_malicious_plain_crypto)
        self.assertIsNone(r.error)

    def test_npm_vulnerable(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'VulnerableNpmProject'))
        self.assertEqual(r.lockfile_type, 'npm')
        self.assertTrue(r.has_vulnerable_axios)
        self.assertEqual(r.vulnerable_axios_version, '1.14.1')
        self.assertTrue(r.has_malicious_plain_crypto)
        self.assertIsNone(r.error)

    def test_yarn_vulnerable(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'VulnerableYarnProject'))
        self.assertEqual(r.lockfile_type, 'yarn')
        self.assertTrue(r.has_vulnerable_axios)
        self.assertEqual(r.vulnerable_axios_version, '0.30.4')
        self.assertTrue(r.has_malicious_plain_crypto)

    def test_pnpm_vulnerable(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'VulnerablePnpmProject'))
        self.assertEqual(r.lockfile_type, 'pnpm')
        self.assertTrue(r.has_vulnerable_axios)
        self.assertEqual(r.vulnerable_axios_version, '1.14.1')
        self.assertTrue(r.has_malicious_plain_crypto)

    def test_malformed_sets_error(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'MalformedProject'))
        self.assertIsNotNone(r.error)
        self.assertFalse(r.has_vulnerable_axios)

    def test_no_lockfile(self):
        with tempfile.TemporaryDirectory() as d:
            r = analyze_lockfile(d)
        self.assertIsNone(r.lockfile_type)
        self.assertFalse(r.has_vulnerable_axios)
        self.assertFalse(r.has_malicious_plain_crypto)

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_lockfile_analysis.py" -v
```

Expected: `ModuleNotFoundError: No module named 'checks.lockfile_analysis'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/checks/lockfile_analysis.py`:

```python
import json
import os
import re
from collections import namedtuple

VULNERABLE_AXIOS = {'1.14.1', '0.30.4'}
VULNERABLE_PLAIN_CRYPTO = '4.2.1'

LockfileResult = namedtuple('LockfileResult', [
    'project_path', 'has_vulnerable_axios', 'vulnerable_axios_version',
    'has_malicious_plain_crypto', 'lockfile_type', 'lockfile_path', 'error',
])


def analyze_lockfile(project_path):
    state = dict(
        project_path=project_path,
        has_vulnerable_axios=False,
        vulnerable_axios_version=None,
        has_malicious_plain_crypto=False,
        lockfile_type=None,
        lockfile_path=None,
        error=None,
    )

    pkg_lock = os.path.join(project_path, 'package-lock.json')
    yarn_lock = os.path.join(project_path, 'yarn.lock')
    pnpm_lock = os.path.join(project_path, 'pnpm-lock.yaml')

    if os.path.isfile(pkg_lock):
        state['lockfile_type'] = 'npm'
        state['lockfile_path'] = pkg_lock
        try:
            with open(pkg_lock, encoding='utf-8') as f:
                lock = json.load(f)
            packages = lock.get('packages') or lock.get('dependencies') or {}
            for name, info in packages.items():
                clean = name.removeprefix('node_modules/')
                ver = info.get('version', '')
                if clean == 'axios' and ver in VULNERABLE_AXIOS:
                    state['has_vulnerable_axios'] = True
                    state['vulnerable_axios_version'] = ver
                if clean == 'plain-crypto-js' and ver == VULNERABLE_PLAIN_CRYPTO:
                    state['has_malicious_plain_crypto'] = True
        except Exception as e:
            state['error'] = f'Failed to parse package-lock.json: {e}'

    elif os.path.isfile(yarn_lock):
        state['lockfile_type'] = 'yarn'
        state['lockfile_path'] = yarn_lock
        try:
            content = open(yarn_lock, encoding='utf-8').read()
            for m in re.finditer(r'^axios@[^\n]+\n\s+version\s+"([^"]+)"', content, re.M):
                if m.group(1) in VULNERABLE_AXIOS:
                    state['has_vulnerable_axios'] = True
                    state['vulnerable_axios_version'] = m.group(1)
            for m in re.finditer(r'^plain-crypto-js@[^\n]+\n\s+version\s+"([^"]+)"', content, re.M):
                if m.group(1) == VULNERABLE_PLAIN_CRYPTO:
                    state['has_malicious_plain_crypto'] = True
        except Exception as e:
            state['error'] = f'Failed to parse yarn.lock: {e}'

    elif os.path.isfile(pnpm_lock):
        state['lockfile_type'] = 'pnpm'
        state['lockfile_path'] = pnpm_lock
        try:
            content = open(pnpm_lock, encoding='utf-8').read()
            for m in re.finditer(r'^\s+(?:/?)axios[/@]([^\s:]+):', content, re.M):
                if m.group(1) in VULNERABLE_AXIOS:
                    state['has_vulnerable_axios'] = True
                    state['vulnerable_axios_version'] = m.group(1)
            for m in re.finditer(r'^\s+(?:/?)plain-crypto-js[/@]([^\s:]+):', content, re.M):
                if m.group(1) == VULNERABLE_PLAIN_CRYPTO:
                    state['has_malicious_plain_crypto'] = True
        except Exception as e:
            state['error'] = f'Failed to parse pnpm-lock.yaml: {e}'

    return LockfileResult(**state)
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_lockfile_analysis.py" -v
```

Expected: `Ran 6 tests in ...s  OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/lockfile_analysis.py linux-port/tests/test_lockfile_analysis.py
git commit -m "feat: add lockfile_analysis check — npm/yarn/pnpm vulnerable version detection"
```

---

## Task 5: `checks/forensic_artifacts.py`

**Files:**
- Create: `linux-port/checks/forensic_artifacts.py`
- Create: `linux-port/tests/test_forensic_artifacts.py`

The fixture `VulnerableNpmProject/node_modules/plain-crypto-js/setup.js` contains `// TEST FIXTURE - simulates malicious postinstall script\nmodule.exports = {};\n` — its SHA-256 does NOT match the known malicious hash (`e10b1fa...`), so it triggers the `High` severity "hash mismatch" path.

- [ ] **Step 1: Write the failing test**

Create `linux-port/tests/test_forensic_artifacts.py`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks.forensic_artifacts import find_forensic_artifacts

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')
VULN = os.path.join(FIXTURES, 'VulnerableNpmProject')
CLEAN = os.path.join(FIXTURES, 'CleanProject')

class TestFindForensicArtifacts(unittest.TestCase):
    def test_finds_malicious_package_dir(self):
        findings = find_forensic_artifacts(VULN)
        self.assertIn('MaliciousPackage', [f.type for f in findings])

    def test_finds_setup_js_high_severity(self):
        findings = find_forensic_artifacts(VULN)
        s = next((f for f in findings if f.type == 'MaliciousScript'), None)
        self.assertIsNotNone(s)
        self.assertEqual(s.severity, 'High')   # fixture hash != known malicious hash
        self.assertIsNotNone(s.hash)

    def test_finds_c2_indicator_in_js(self):
        findings = find_forensic_artifacts(VULN)
        c2 = [f for f in findings if f.type == 'C2Indicator']
        self.assertTrue(len(c2) > 0)
        self.assertEqual(c2[0].severity, 'Critical')

    def test_clean_project_no_findings(self):
        self.assertEqual(find_forensic_artifacts(CLEAN), [])

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_forensic_artifacts.py" -v
```

Expected: `ModuleNotFoundError: No module named 'checks.forensic_artifacts'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/checks/forensic_artifacts.py`:

```python
import hashlib
import os

from checks import Finding

KNOWN_SETUP_JS_HASH = 'e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09'
C2_PATTERNS = ['sfrclak.com', '142.11.206.73']


def find_forensic_artifacts(project_path):
    findings = []

    crypto_dir = os.path.join(project_path, 'node_modules', 'plain-crypto-js')
    if os.path.isdir(crypto_dir):
        findings.append(Finding(
            type='MaliciousPackage', path=crypto_dir, detail=None,
            severity='Critical',
            description='Malicious plain-crypto-js package in node_modules',
            hash=None,
        ))
        setup_js = os.path.join(crypto_dir, 'setup.js')
        if os.path.isfile(setup_js):
            try:
                h = hashlib.sha256(open(setup_js, 'rb').read()).hexdigest()
                is_known = h == KNOWN_SETUP_JS_HASH
                findings.append(Finding(
                    type='MaliciousScript', path=setup_js, detail=None,
                    severity='Critical' if is_known else 'High',
                    description='Known malicious setup.js (hash match)' if is_known
                                else 'Suspicious setup.js in plain-crypto-js (hash mismatch - possible variant)',
                    hash=h,
                ))
            except Exception:
                pass

    try:
        count = 0
        for dirpath, dirnames, filenames in os.walk(project_path):
            for fname in filenames:
                if not fname.endswith('.js'):
                    continue
                if count >= 1000:
                    break
                count += 1
                fpath = os.path.join(dirpath, fname)
                # Include plain-crypto-js files; skip other node_modules
                norm = fpath.replace('\\', '/')
                if '/node_modules/' in norm and '/node_modules/plain-crypto-js/' not in norm:
                    continue
                try:
                    content = open(fpath, encoding='utf-8', errors='ignore').read()
                    for pat in C2_PATTERNS:
                        if pat in content:
                            findings.append(Finding(
                                type='C2Indicator', path=fpath, detail=None,
                                severity='Critical',
                                description=f"C2 indicator '{pat}' found in file",
                                hash=None,
                            ))
                            break
                except Exception:
                    pass
    except Exception:
        pass

    return findings
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_forensic_artifacts.py" -v
```

Expected: `Ran 4 tests in ...s  OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/forensic_artifacts.py linux-port/tests/test_forensic_artifacts.py
git commit -m "feat: add forensic_artifacts check — plain-crypto-js dir, setup.js hash, C2 indicators"
```

---

## Task 6: `checks/npm_cache.py`

**Files:**
- Create: `linux-port/checks/npm_cache.py`
- Create: `linux-port/tests/test_npm_cache.py`

- [ ] **Step 1: Write the failing test**

Create `linux-port/tests/test_npm_cache.py`:

```python
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from unittest.mock import MagicMock, patch
from checks.npm_cache import scan_npm_cache


def _mock_run(stdout, returncode=0):
    m = MagicMock()
    m.stdout = stdout
    m.returncode = returncode
    return m


class TestScanNpmCache(unittest.TestCase):
    def test_finds_malicious_entry_in_cache_index(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            index_dir = os.path.join(cache_dir, '_cacache', 'index-v5', 'ab')
            os.makedirs(index_dir)
            index_file = os.path.join(index_dir, 'abc123')
            with open(index_file, 'w') as f:
                f.write('plain-crypto-js/-/plain-crypto-js-4.2.1.tgz\n')

            with patch('subprocess.run') as mock_run:
                mock_run.side_effect = [
                    _mock_run(cache_dir + '\n'),      # npm config get cache
                    _mock_run('/nonexistent\n'),       # npm root -g
                ]
                findings = scan_npm_cache()

        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].type, 'NpmCacheHit')
        self.assertIn('4.2.1', findings[0].detail)
        self.assertEqual(findings[0].severity, 'High')

    def test_npm_unavailable_returns_empty(self):
        with patch('subprocess.run', side_effect=FileNotFoundError):
            findings = scan_npm_cache()
        self.assertEqual(findings, [])

    def test_empty_cache_returns_empty(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch('subprocess.run') as mock_run:
                mock_run.side_effect = [
                    _mock_run(cache_dir + '\n'),
                    _mock_run('/nonexistent\n'),
                ]
                findings = scan_npm_cache()
        self.assertEqual(findings, [])

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_npm_cache.py" -v
```

Expected: `ModuleNotFoundError: No module named 'checks.npm_cache'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/checks/npm_cache.py`:

```python
import json
import os
import subprocess

from checks import Finding

MALICIOUS_PKGS = ['plain-crypto-js', 'axios']
VULN_VERSIONS = ['4.2.1', '1.14.1', '0.30.4']


def scan_npm_cache():
    findings = []

    try:
        r = subprocess.run(['npm', 'config', 'get', 'cache'],
                           capture_output=True, text=True, timeout=10)
        cache_dir = r.stdout.strip()
    except Exception:
        return findings

    index_dir = os.path.join(cache_dir, '_cacache', 'index-v5')
    if os.path.isdir(index_dir):
        count = 0
        for dirpath, _, filenames in os.walk(index_dir):
            for fname in filenames:
                if count >= 5000:
                    break
                count += 1
                fpath = os.path.join(dirpath, fname)
                try:
                    raw = open(fpath, encoding='utf-8', errors='ignore').read()
                    for pkg in MALICIOUS_PKGS:
                        for ver in VULN_VERSIONS:
                            if f'{pkg}/-/{pkg}-{ver}.tgz' in raw:
                                findings.append(Finding(
                                    type='NpmCacheHit', path=fpath,
                                    detail=f'{pkg}@{ver}', severity='High',
                                    description=f'Malicious {pkg}@{ver} in npm cache — run: npm cache clean --force',
                                    hash=None,
                                ))
                except Exception:
                    pass

    try:
        r = subprocess.run(['npm', 'root', '-g'],
                           capture_output=True, text=True, timeout=10)
        global_root = r.stdout.strip()
        if global_root and os.path.isdir(global_root):
            for pkg in MALICIOUS_PKGS:
                pkg_dir = os.path.join(global_root, pkg)
                if os.path.isdir(pkg_dir):
                    ver = None
                    pkg_json = os.path.join(pkg_dir, 'package.json')
                    if os.path.isfile(pkg_json):
                        try:
                            ver = json.load(open(pkg_json)).get('version')
                        except Exception:
                            pass
                    if ver is None or ver in VULN_VERSIONS:
                        findings.append(Finding(
                            type='GlobalNpmHit', path=pkg_dir,
                            detail=f'{pkg}@{ver or "unknown"}', severity='Critical',
                            description=f'Malicious {pkg} in global npm — run: npm uninstall -g {pkg}',
                            hash=None,
                        ))
    except Exception:
        pass

    return findings
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_npm_cache.py" -v
```

Expected: `Ran 3 tests in ...s  OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/npm_cache.py linux-port/tests/test_npm_cache.py
git commit -m "feat: add npm_cache check — scan cache index and global npm for malicious packages"
```

---

## Task 7: `checks/dropped_payloads.py`

**Files:**
- Create: `linux-port/checks/dropped_payloads.py`
- Create: `linux-port/tests/test_dropped_payloads.py`

- [ ] **Step 1: Write the failing test**

Create `linux-port/tests/test_dropped_payloads.py`:

```python
import sys, os, datetime, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks.dropped_payloads import scan_dropped_payloads

ELF_MAGIC = b'\x7fELF'
BEFORE_ATTACK = datetime.datetime(2026, 3, 30, 0, 0, 0,
                                  tzinfo=datetime.timezone.utc).timestamp()


class TestScanDroppedPayloads(unittest.TestCase):
    def test_finds_elf_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, 'backdoor')
            open(f, 'wb').write(ELF_MAGIC + b'\x00' * 60)
            findings = scan_dropped_payloads(scan_paths=[tmp])
        self.assertTrue(any(x.type == 'DroppedExecutable' for x in findings))
        elf = next(x for x in findings if x.type == 'DroppedExecutable')
        self.assertEqual(elf.severity, 'Critical')
        self.assertIsNotNone(elf.hash)

    def test_finds_suspicious_shell_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, 'setup.sh')
            open(f, 'w').write('#!/bin/bash\ncurl http://sfrclak.com/\n')
            findings = scan_dropped_payloads(scan_paths=[tmp])
        self.assertTrue(any(x.type == 'SuspiciousScript' for x in findings))
        sh = next(x for x in findings if x.type == 'SuspiciousScript')
        self.assertEqual(sh.severity, 'High')

    def test_old_file_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, 'old')
            open(f, 'wb').write(ELF_MAGIC + b'\x00' * 60)
            os.utime(f, (BEFORE_ATTACK, BEFORE_ATTACK))
            findings = scan_dropped_payloads(scan_paths=[tmp])
        self.assertEqual(findings, [])

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scan_dropped_payloads(scan_paths=[tmp]), [])

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_dropped_payloads.py" -v
```

Expected: `ModuleNotFoundError: No module named 'checks.dropped_payloads'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/checks/dropped_payloads.py`:

```python
import datetime
import hashlib
import os

from checks import Finding

ATTACK_WINDOW_START = datetime.datetime(2026, 3, 31, 0, 21, 0, tzinfo=datetime.timezone.utc)
ELF_MAGIC = b'\x7fELF'
SUSPICIOUS_EXTS = {'.sh', '.py', '.js', '.pl'}

DEFAULT_SCAN_PATHS = [
    '/tmp', '/var/tmp',
    os.path.expanduser('~/.cache'),
    os.path.expanduser('~/.local/share'),
]


def scan_dropped_payloads(scan_paths=None):
    if scan_paths is None:
        scan_paths = [p for p in DEFAULT_SCAN_PATHS if os.path.isdir(p)]

    findings = []
    count = 0

    for scan_path in scan_paths:
        try:
            for dirpath, _, filenames in os.walk(scan_path):
                for fname in filenames:
                    if count >= 2000:
                        break
                    fpath = os.path.join(dirpath, fname)
                    try:
                        stat = os.stat(fpath)
                        mtime = datetime.datetime.fromtimestamp(
                            stat.st_mtime, tz=datetime.timezone.utc)
                        if mtime < ATTACK_WINDOW_START:
                            continue
                        count += 1

                        ftype = sev = None

                        try:
                            with open(fpath, 'rb') as fh:
                                header = fh.read(4)
                            if header == ELF_MAGIC:
                                ftype, sev = 'DroppedExecutable', 'Critical'
                        except Exception:
                            pass

                        if ftype is None:
                            ext = os.path.splitext(fname)[1].lower()
                            if ext in SUSPICIOUS_EXTS:
                                ftype, sev = 'SuspiciousScript', 'High'

                        if ftype:
                            sha = None
                            try:
                                sha = hashlib.sha256(open(fpath, 'rb').read()).hexdigest()
                            except Exception:
                                pass
                            findings.append(Finding(
                                type=ftype, path=fpath,
                                detail=mtime.isoformat(), severity=sev,
                                description=f'{ftype} created after attack window: {fpath}',
                                hash=sha,
                            ))
                    except Exception:
                        pass
        except Exception:
            pass

    return findings
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_dropped_payloads.py" -v
```

Expected: `Ran 4 tests in ...s  OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/dropped_payloads.py linux-port/tests/test_dropped_payloads.py
git commit -m "feat: add dropped_payloads check — ELF binaries and scripts in temp dirs post attack window"
```

---

## Task 8: `checks/persistence.py`

**Files:**
- Create: `linux-port/checks/persistence.py`
- Create: `linux-port/tests/test_persistence.py`

`find_persistence_artifacts()` accepts optional `rc_files`, `cron_paths`, and `systemd_user_dir` parameters so tests can inject temp paths instead of reading real system files. Passing `[]` skips that source. Passing `None` uses real system defaults.

- [ ] **Step 1: Write the failing test**

Create `linux-port/tests/test_persistence.py`:

```python
import sys, os, datetime, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from unittest.mock import MagicMock, patch
from checks.persistence import find_persistence_artifacts

AFTER = datetime.datetime(2026, 4, 1, tzinfo=datetime.timezone.utc).timestamp()


class TestFindPersistenceArtifacts(unittest.TestCase):
    def test_suspicious_crontab_entry(self):
        crontab = '*/5 * * * * /tmp/.node_helper\n'
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=crontab)
            findings = find_persistence_artifacts(cron_paths=[], rc_files=[], systemd_user_dir='')
        self.assertTrue(any(f.type == 'SuspiciousCronEntry' for f in findings))

    def test_suspicious_cron_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cron_file = os.path.join(tmp, 'evil')
            open(cron_file, 'w').write('*/5 * * * * node /tmp/payload.js\n')
            os.utime(cron_file, (AFTER, AFTER))
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = find_persistence_artifacts(
                    cron_paths=[cron_file], rc_files=[], systemd_user_dir='')
        self.assertTrue(any(f.type == 'SuspiciousCronEntry' for f in findings))

    def test_rc_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = os.path.join(tmp, '.bashrc')
            open(rc, 'w').write('export PATH=/tmp/node/bin:$PATH\n')
            os.utime(rc, (AFTER, AFTER))
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = find_persistence_artifacts(
                    rc_files=[rc], cron_paths=[], systemd_user_dir='')
        self.assertTrue(any(f.type == 'SuspiciousRcInjection' for f in findings))

    def test_systemd_unit_after_attack(self):
        with tempfile.TemporaryDirectory() as sdir:
            svc = os.path.join(sdir, 'evil.service')
            open(svc, 'w').write('[Service]\nExecStart=node /tmp/payload.js\n')
            os.utime(svc, (AFTER, AFTER))
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = find_persistence_artifacts(
                    rc_files=[], cron_paths=[], systemd_user_dir=sdir)
        self.assertTrue(any(f.type == 'SuspiciousSystemdUnit' for f in findings))

    def test_clean_system_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = find_persistence_artifacts(
                    rc_files=[], cron_paths=[], systemd_user_dir=tmp)
        self.assertEqual(findings, [])

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_persistence.py" -v
```

Expected: `ModuleNotFoundError: No module named 'checks.persistence'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/checks/persistence.py`:

```python
import datetime
import os
import re
import subprocess

from checks import Finding

ATTACK_WINDOW_START = datetime.datetime(2026, 3, 31, 0, 21, 0, tzinfo=datetime.timezone.utc)
SUSPICIOUS_PAT = re.compile(r'/tmp|/var/tmp|\.cache|node|npm|\.js', re.IGNORECASE)

_DEFAULT_RC_FILES = [
    os.path.expanduser('~/.bashrc'),
    os.path.expanduser('~/.bash_profile'),
    os.path.expanduser('~/.profile'),
    os.path.expanduser('~/.zshrc'),
]
_DEFAULT_CRON_PATHS = [
    '/etc/crontab',
    *([os.path.join(d, f)
       for d in ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly']
       if os.path.isdir(d)
       for f in os.listdir(d)])
]
_DEFAULT_SYSTEMD_USER_DIR = os.path.expanduser('~/.config/systemd/user')


def _after_attack(path):
    try:
        mtime = datetime.datetime.fromtimestamp(os.stat(path).st_mtime, tz=datetime.timezone.utc)
        return mtime >= ATTACK_WINDOW_START
    except Exception:
        return False


def find_persistence_artifacts(rc_files=None, cron_paths=None, systemd_user_dir=None):
    if rc_files is None:
        rc_files = _DEFAULT_RC_FILES
    if cron_paths is None:
        cron_paths = _DEFAULT_CRON_PATHS
    if systemd_user_dir is None:
        systemd_user_dir = _DEFAULT_SYSTEMD_USER_DIR

    findings = []

    # crontab -l
    try:
        r = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if line.startswith('#') or not line.strip():
                    continue
                if SUSPICIOUS_PAT.search(line):
                    findings.append(Finding(
                        type='SuspiciousCronEntry', path='crontab -l',
                        detail=line, severity='Critical',
                        description=f'Suspicious crontab entry: {line}',
                        hash=None,
                    ))
    except Exception:
        pass

    # cron files
    for fpath in cron_paths:
        if not os.path.isfile(fpath) or not _after_attack(fpath):
            continue
        try:
            for line in open(fpath, encoding='utf-8', errors='ignore'):
                stripped = line.rstrip()
                if stripped.startswith('#') or not stripped:
                    continue
                if SUSPICIOUS_PAT.search(stripped):
                    findings.append(Finding(
                        type='SuspiciousCronEntry', path=fpath,
                        detail=stripped, severity='Critical',
                        description=f'Suspicious cron entry in {fpath}: {stripped}',
                        hash=None,
                    ))
        except Exception:
            pass

    # systemd user timers/services
    if systemd_user_dir and os.path.isdir(systemd_user_dir):
        for fname in os.listdir(systemd_user_dir):
            if not (fname.endswith('.timer') or fname.endswith('.service')):
                continue
            fpath = os.path.join(systemd_user_dir, fname)
            if not _after_attack(fpath):
                continue
            try:
                for line in open(fpath, encoding='utf-8', errors='ignore'):
                    stripped = line.rstrip()
                    if stripped.startswith('ExecStart=') and SUSPICIOUS_PAT.search(stripped):
                        findings.append(Finding(
                            type='SuspiciousSystemdUnit', path=fpath,
                            detail=stripped, severity='Critical',
                            description=f'Suspicious ExecStart in {fpath}: {stripped}',
                            hash=None,
                        ))
            except Exception:
                pass

    # RC files
    for fpath in rc_files:
        if not os.path.isfile(fpath) or not _after_attack(fpath):
            continue
        try:
            for line in open(fpath, encoding='utf-8', errors='ignore'):
                stripped = line.strip()
                if stripped.startswith('#') or not stripped:
                    continue
                if SUSPICIOUS_PAT.search(stripped):
                    findings.append(Finding(
                        type='SuspiciousRcInjection', path=fpath,
                        detail=stripped, severity='Critical',
                        description=f'Suspicious RC injection in {fpath}: {stripped}',
                        hash=None,
                    ))
        except Exception:
            pass

    return findings
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_persistence.py" -v
```

Expected: `Ran 5 tests in ...s  OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/persistence.py linux-port/tests/test_persistence.py
git commit -m "feat: add persistence check — cron, systemd user timers, shell RC injection"
```

---

## Task 9: `checks/xor_c2.py`

**Files:**
- Create: `linux-port/checks/xor_c2.py`
- Create: `linux-port/tests/test_xor_c2.py`

- [ ] **Step 1: Write the failing test**

Create `linux-port/tests/test_xor_c2.py`:

```python
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks.xor_c2 import xor_decode, scan_xor_encoded_c2


def xor_encode(data: bytes) -> bytes:
    """Mirror of xor_decode — XOR is symmetric, same algorithm encodes and decodes."""
    key = b'OrDeR_7077'
    mask = 333 & 0xFF
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = (b ^ key[i % len(key)]) ^ mask
    return bytes(result)


class TestXorDecode(unittest.TestCase):
    def test_decode_reverses_encode(self):
        plaintext = b'connecting to sfrclak.com port 8000'
        self.assertEqual(xor_decode(xor_encode(plaintext)), plaintext)

    def test_empty_input(self):
        self.assertEqual(xor_decode(b''), b'')


class TestScanXorEncodedC2(unittest.TestCase):
    def test_finds_encoded_ip_in_bin_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = os.path.join(tmp, 'data.bin')
            open(payload, 'wb').write(xor_encode(b'connecting to 142.11.206.73:8000'))
            findings = scan_xor_encoded_c2(scan_paths=[tmp])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, 'XorEncodedC2')
        self.assertEqual(findings[0].severity, 'Critical')
        self.assertEqual(findings[0].detail, '142.11.206.73')

    def test_finds_encoded_domain_in_js_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = os.path.join(tmp, 'loader.js')
            open(payload, 'wb').write(xor_encode(b'beacon sfrclak.com'))
            findings = scan_xor_encoded_c2(scan_paths=[tmp])
        self.assertTrue(any(f.detail == 'sfrclak.com' for f in findings))

    def test_benign_binary_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, 'benign.bin'), 'wb').write(b'\x00' * 100)
            findings = scan_xor_encoded_c2(scan_paths=[tmp])
        self.assertEqual(findings, [])

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scan_xor_encoded_c2(scan_paths=[tmp]), [])

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_xor_c2.py" -v
```

Expected: `ModuleNotFoundError: No module named 'checks.xor_c2'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/checks/xor_c2.py`:

```python
import os

from checks import Finding

_XOR_KEY = b'OrDeR_7077'
_XOR_MASK = 333 & 0xFF   # = 77 = 0x4D
C2_INDICATORS = ['sfrclak.com', '142.11.206.73']
SCAN_EXTENSIONS = {'.bin', '.dat', '.js', '.log', '.sh', '.py', '.tmp', ''}

DEFAULT_SCAN_PATHS = [
    '/tmp', '/var/tmp',
    os.path.expanduser('~/.cache'),
    os.path.expanduser('~/.config'),
]


def xor_decode(data: bytes) -> bytes:
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = (b ^ _XOR_KEY[i % len(_XOR_KEY)]) ^ _XOR_MASK
    return bytes(result)


def scan_xor_encoded_c2(scan_paths=None):
    if scan_paths is None:
        scan_paths = [p for p in DEFAULT_SCAN_PATHS if os.path.isdir(p)]

    findings = []
    count = 0

    for scan_path in scan_paths:
        try:
            for dirpath, _, filenames in os.walk(scan_path):
                for fname in filenames:
                    if count >= 1000:
                        break
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in SCAN_EXTENSIONS:
                        continue
                    count += 1
                    fpath = os.path.join(dirpath, fname)
                    try:
                        data = open(fpath, 'rb').read()
                        text = xor_decode(data).decode('utf-8', errors='ignore')
                        for indicator in C2_INDICATORS:
                            if indicator in text:
                                findings.append(Finding(
                                    type='XorEncodedC2', path=fpath,
                                    detail=indicator, severity='Critical',
                                    description=f"XOR-encoded C2 indicator '{indicator}' found after decoding: {fpath}",
                                    hash=None,
                                ))
                                break
                    except Exception:
                        pass
        except Exception:
            pass

    return findings
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_xor_c2.py" -v
```

Expected: `Ran 4 tests in ...s  OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/xor_c2.py linux-port/tests/test_xor_c2.py
git commit -m "feat: add xor_c2 check — XOR decode (key=OrDeR_7077, mask=0x4D) and scan for C2 indicators"
```

---

## Task 10: `checks/network_evidence.py`

**Files:**
- Create: `linux-port/checks/network_evidence.py`
- Create: `linux-port/tests/test_network_evidence.py`

`get_network_evidence()` accepts `hosts_path` and `syslog_paths` for test injection.

- [ ] **Step 1: Write the failing test**

Create `linux-port/tests/test_network_evidence.py`:

```python
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from unittest.mock import MagicMock, patch
from checks.network_evidence import get_network_evidence


class TestGetNetworkEvidence(unittest.TestCase):
    def test_finds_c2_ip_in_ss_output(self):
        ss_out = 'ESTAB 0 0 10.0.0.5:43210 142.11.206.73:8000 users:(("node",pid=1234,fd=5))\n'
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ss_out)
            findings = get_network_evidence(hosts_path='/nonexistent', syslog_paths=[])
        c2 = [f for f in findings if f.type == 'ActiveC2Connection']
        self.assertTrue(len(c2) > 0)
        self.assertEqual(c2[0].severity, 'Critical')

    def test_finds_c2_in_hosts_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hosts', delete=False) as f:
            f.write('# hosts\n142.11.206.73 sfrclak.com\n')
            hosts_path = f.name
        try:
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = get_network_evidence(hosts_path=hosts_path, syslog_paths=[])
        finally:
            os.unlink(hosts_path)
        hits = [f for f in findings if f.type == 'HostsFileHit']
        self.assertTrue(len(hits) > 0)
        self.assertEqual(hits[0].severity, 'Critical')

    def test_finds_c2_in_syslog(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write('Apr 1 10:00:00 host node[123]: connected to 142.11.206.73:8000\n')
            log_path = f.name
        try:
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = get_network_evidence(hosts_path='/nonexistent', syslog_paths=[log_path])
        finally:
            os.unlink(log_path)
        hits = [f for f in findings if f.type == 'SyslogHit']
        self.assertTrue(len(hits) > 0)
        self.assertEqual(hits[0].severity, 'High')

    def test_clean_system_no_findings(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout='')
            findings = get_network_evidence(hosts_path='/nonexistent', syslog_paths=[])
        self.assertEqual(findings, [])

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_network_evidence.py" -v
```

Expected: `ModuleNotFoundError: No module named 'checks.network_evidence'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/checks/network_evidence.py`:

```python
import os
import subprocess

from checks import Finding

C2_IP = '142.11.206.73'
C2_DOMAIN = 'sfrclak.com'
C2_PORT = 8000


def _ip_to_proc_hex(ip):
    """Convert dotted-decimal IP to little-endian hex used in /proc/net/tcp."""
    octets = list(map(int, ip.split('.')))
    return ''.join(f'{o:02X}' for o in reversed(octets))


def get_network_evidence(
    hosts_path='/etc/hosts',
    syslog_paths=('/var/log/syslog', '/var/log/auth.log'),
):
    findings = []

    # Active connections via ss
    ss_ok = False
    try:
        r = subprocess.run(['ss', '-tnp'], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            ss_ok = True
            for line in r.stdout.splitlines():
                if C2_IP in line or f':{C2_PORT}' in line:
                    findings.append(Finding(
                        type='ActiveC2Connection', path='ss -tnp',
                        detail=line.strip(), severity='Critical',
                        description=f'ACTIVE connection to C2 endpoint: {line.strip()}',
                        hash=None,
                    ))
    except Exception:
        pass

    # Fallback: /proc/net/tcp
    if not ss_ok and os.path.isfile('/proc/net/tcp'):
        try:
            c2_hex = _ip_to_proc_hex(C2_IP)
            port_hex = f'{C2_PORT:04X}'
            for line in open('/proc/net/tcp'):
                upper = line.upper()
                if c2_hex in upper or port_hex in upper:
                    findings.append(Finding(
                        type='ActiveC2Connection', path='/proc/net/tcp',
                        detail=line.strip(), severity='Critical',
                        description=f'Active C2 connection in /proc/net/tcp: {line.strip()}',
                        hash=None,
                    ))
        except Exception:
            pass

    # /etc/hosts
    if os.path.isfile(hosts_path):
        try:
            for line in open(hosts_path, encoding='utf-8', errors='ignore'):
                stripped = line.strip()
                if stripped.startswith('#') or not stripped:
                    continue
                if C2_DOMAIN in stripped or C2_IP in stripped:
                    findings.append(Finding(
                        type='HostsFileHit', path=hosts_path,
                        detail=stripped, severity='Critical',
                        description=f'C2 indicator found in {hosts_path}: {stripped}',
                        hash=None,
                    ))
        except Exception:
            pass

    # Syslog
    for log_path in syslog_paths:
        if not os.path.isfile(log_path):
            continue
        try:
            for line in open(log_path, encoding='utf-8', errors='ignore'):
                if C2_IP in line or C2_DOMAIN in line:
                    findings.append(Finding(
                        type='SyslogHit', path=log_path,
                        detail=line.strip(), severity='High',
                        description=f'C2 indicator found in {log_path}',
                        hash=None,
                    ))
        except Exception:
            pass

    return findings
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_network_evidence.py" -v
```

Expected: `Ran 4 tests in ...s  OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/network_evidence.py linux-port/tests/test_network_evidence.py
git commit -m "feat: add network_evidence check — ss/proc active connections, hosts file, syslog"
```

---

## Task 11: `checks/report.py`

**Files:**
- Create: `linux-port/checks/report.py`
- Create: `linux-port/tests/test_report.py`

- [ ] **Step 1: Write the failing test**

Create `linux-port/tests/test_report.py`:

```python
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks import Finding
from checks.lockfile_analysis import LockfileResult
from checks.report import write_reports


def _meta():
    return {
        'timestamp': '20260401-120000',
        'hostname': 'testhost',
        'username': 'testuser',
        'duration': '5.0s',
        'paths': ['/home/test'],
    }


class TestWriteReports(unittest.TestCase):
    def test_creates_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tech, brief = write_reports([], [], [], [], [], [], [], [], tmp, _meta())
            self.assertTrue(os.path.isfile(tech))
            self.assertTrue(os.path.isfile(brief))

    def test_clean_shows_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            tech, _ = write_reports([], [], [], [], [], [], [], [], tmp, _meta())
            content = open(tech).read()
        self.assertIn('CLEAN', content)
        self.assertNotIn('COMPROMISED', content)

    def test_compromised_with_vulnerable_lockfile(self):
        lr = LockfileResult(
            project_path='/home/test/app',
            has_vulnerable_axios=True, vulnerable_axios_version='1.14.1',
            has_malicious_plain_crypto=True, lockfile_type='npm',
            lockfile_path='/home/test/app/package-lock.json', error=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            tech, brief = write_reports(
                ['/home/test/app'], [lr], [], [], [], [], [], [], tmp, _meta())
            tech_content = open(tech).read()
            brief_content = open(brief).read()
        self.assertIn('COMPROMISED', tech_content)
        self.assertIn('1.14.1', tech_content)
        self.assertIn('EXECUTIVE SECURITY BRIEFING', brief_content)
        self.assertIn('COMPROMISED', brief_content)

    def test_report_permissions_600(self):
        with tempfile.TemporaryDirectory() as tmp:
            tech, brief = write_reports([], [], [], [], [], [], [], [], tmp, _meta())
            self.assertEqual(oct(os.stat(tech).st_mode)[-3:], '600')
            self.assertEqual(oct(os.stat(brief).st_mode)[-3:], '600')

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_report.py" -v
```

Expected: `ModuleNotFoundError: No module named 'checks.report'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/checks/report.py`:

```python
import hashlib
import os


def write_reports(
    projects, lockfile_results, artifacts, cache_findings,
    dropped_payloads, persistence_artifacts, xor_findings,
    network_evidence, output_dir, scan_metadata,
):
    os.makedirs(output_dir, exist_ok=True)

    vuln_projects = [lr for lr in lockfile_results
                     if lr.has_vulnerable_axios or lr.has_malicious_plain_crypto]
    all_findings = (artifacts + cache_findings + dropped_payloads +
                    persistence_artifacts + xor_findings + network_evidence)
    critical_count = sum(1 for f in all_findings if f.severity == 'Critical')
    overall = 'COMPROMISED' if (vuln_projects or all_findings) else 'CLEAN'

    ts = scan_metadata['timestamp']
    hn = scan_metadata['hostname']

    tech_path = os.path.join(output_dir, f'Axios-Scan-{hn}-{ts}.txt')
    _write_technical(tech_path, projects, lockfile_results, artifacts, cache_findings,
                     dropped_payloads, persistence_artifacts, xor_findings,
                     network_evidence, vuln_projects, all_findings, critical_count,
                     overall, scan_metadata)
    os.chmod(tech_path, 0o600)

    brief_path = os.path.join(output_dir, f'ExecBriefing-{hn}-{ts}.txt')
    _write_briefing(brief_path, projects, lockfile_results, artifacts, cache_findings,
                    dropped_payloads, persistence_artifacts, xor_findings,
                    network_evidence, tech_path, scan_metadata)
    os.chmod(brief_path, 0o600)

    return tech_path, brief_path


def _write_technical(path, projects, lockfile_results, artifacts, cache_findings,
                     dropped_payloads, persistence_artifacts, xor_findings,
                     network_evidence, vuln_projects, all_findings, critical_count,
                     overall, meta):
    lines = []
    W = '=' * 80

    def h(title): lines.extend(['', title, '-' * 60])
    def ln(s=''): lines.append(s)

    ln(W); ln('AXIOS NPM SUPPLY CHAIN COMPROMISE SCANNER - FORENSIC REPORT'); ln(W)

    h('EXECUTIVE SUMMARY')
    ln(f'Total projects scanned    : {len(projects)}')
    ln(f'Vulnerable (lockfile)     : {len(vuln_projects)}')
    ln(f'Critical findings (total) : {critical_count}')
    ln(f'Overall status            : {overall}')
    if overall == 'COMPROMISED':
        ln(); ln('*** ACTION REQUIRED: Evidence of compromise detected. Isolate this machine.')

    h('SCAN METADATA')
    ln(f'Timestamp     : {meta["timestamp"]}')
    ln(f'Hostname      : {meta["hostname"]}')
    ln(f'Username      : {meta["username"]}')
    ln(f'Scan Duration : {meta["duration"]}')
    ln(f'Paths Scanned : {", ".join(str(p) for p in meta["paths"])}')

    h('VULNERABLE PROJECTS (Lockfile Evidence)')
    if not vuln_projects:
        ln('None.')
    else:
        for vp in vuln_projects:
            ln(f'Project  : {vp.project_path}')
            ln(f'Lockfile : {vp.lockfile_type} - {vp.lockfile_path}')
            if vp.has_vulnerable_axios:
                ln(f'FINDING  : axios@{vp.vulnerable_axios_version} - malicious version')
            if vp.has_malicious_plain_crypto:
                ln('FINDING  : plain-crypto-js@4.2.1 - postinstall dropper')
            ln('FIX      : npm install axios@1.14.0 && npm cache clean --force && rm -rf node_modules && npm install')
            ln()

    def _section(title, items, label):
        h(title)
        if not items:
            ln('None.')
        else:
            for f in items:
                ln(f'Type     : {f.type}  Severity: {f.severity}')
                ln(f'Path     : {f.path}')
                if f.detail is not None:
                    ln(f'Detail   : {f.detail}')
                if f.hash:
                    ln(f'SHA256   : {f.hash}')
                ln(f'Desc     : {f.description}')
                ln()

    _section('FORENSIC ARTIFACTS', artifacts, 'artifacts')
    _section('NPM CACHE FINDINGS', cache_findings, 'cache')
    _section('DROPPED PAYLOADS', dropped_payloads, 'payloads')
    _section('PERSISTENCE MECHANISMS', persistence_artifacts, 'persistence')
    _section('XOR-ENCODED INDICATORS', xor_findings, 'xor')
    _section('NETWORK EVIDENCE', network_evidence, 'network')

    h('CREDENTIALS AT RISK')
    ln('If COMPROMISED — rotate ALL of the following immediately:')
    home = os.path.expanduser('~')
    for cp in ['.ssh', '.gitconfig', '.npmrc', '.aws/credentials', '.kube/config', '.docker/config.json']:
        full = os.path.join(home, cp)
        label = 'PRESENT - ROTATE:' if os.path.exists(full) else '(not found):'
        ln(f'  {label} {full}')
    ln('Also rotate: GitHub tokens, NPM tokens, AWS/GCP/Azure keys, container registry secrets')

    h('APPENDIX: IOC REFERENCE')
    ln('Malicious packages : axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1')
    ln('setup.js SHA256    : e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09')
    ln('C2 domain/IP/port  : sfrclak.com, 142.11.206.73:8000')
    ln('XOR key/constant   : OrDeR_7077 / 333 (0x4D mask)')
    ln('Attack window      : 2026-03-31 00:21 UTC')

    h('REMEDIATION GUIDANCE')
    ln('STEP 1 - Lockfile cleanup:')
    ln('  pip install axios@1.14.0   (or 0.30.3 for v0.x)')
    ln('  npm cache clean --force')
    ln('  rm -rf node_modules && npm install')
    ln()
    ln('STEP 2 - If dropped payloads or persistence found:')
    ln('  1. Isolate machine from network immediately')
    ln('  2. Capture forensic disk image before any changes')
    ln('  3. Remove cron entries, systemd units, RC injections found above')
    ln('  4. Delete dropped payload files found above')
    ln('  5. Check /var/log/auth.log for suspicious process execution around 2026-03-31')
    ln('  6. Review network logs for traffic to sfrclak.com or 142.11.206.73:8000')
    ln('  7. Consider full OS re-image if active C2 connection was found')
    ln()
    ln('STEP 3 - Credential rotation (mandatory if COMPROMISED):')
    ln('  SSH keys, GitHub tokens, NPM tokens, AWS/GCP/Azure credentials,')
    ln('  Kubernetes configs, container registry secrets, any secrets in .env files')

    open(path, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')


def _write_briefing(path, projects, lockfile_results, artifacts, cache_findings,
                    dropped_payloads, persistence_artifacts, xor_findings,
                    network_evidence, tech_path, meta):
    vuln = [lr for lr in lockfile_results if lr.has_vulnerable_axios or lr.has_malicious_plain_crypto]

    checks = [
        ('1', 'Project Discovery',         'Node.js projects on disk',
         f'{len(projects)} found', None, True),
        ('2', 'Dependency Lockfiles',      'Known-malicious axios versions',
         f'{len(lockfile_results)} lockfiles', len(vuln), len(vuln) == 0),
        ('3', 'Malicious Package Files',   'plain-crypto-js dir / dropper hash',
         f'{len(projects)} project dirs', len(artifacts), len(artifacts) == 0),
        ('4', 'npm Package Cache',         'Poisoned packages in npm cache',
         '1 cache', len(cache_findings), len(cache_findings) == 0),
        ('5', 'Dropped Malware Payloads',  'ELF/scripts in temp dirs after attack',
         'Temp locations', len(dropped_payloads), len(dropped_payloads) == 0),
        ('6', 'Persistence Mechanisms',    'Cron, systemd timers, shell RC',
         '3 sources', len(persistence_artifacts), len(persistence_artifacts) == 0),
        ('7', 'Obfuscated Attack Signals', f'XOR C2 callbacks (key: OrDeR_7077)',
         'Temp/config files', len(xor_findings), len(xor_findings) == 0),
        ('8', 'Network Contact Evidence',  'Active TCP, /etc/hosts, syslog',
         '3 network sources', len(network_evidence), len(network_evidence) == 0),
    ]

    failed = [c for c in checks if not c[5]]
    clean = len(failed) == 0
    verdict = 'CLEAN' if clean else 'COMPROMISED'

    report_hash = 'unavailable'
    try:
        report_hash = hashlib.sha256(open(tech_path, 'rb').read()).hexdigest()
    except Exception:
        pass

    lines = []
    W = '=' * 68

    def ln(s=''): lines.append(s)
    def hr(): ln(W)
    def hr2(): ln('-' * 68)

    hr(); ln('AXIOS SUPPLY CHAIN ATTACK - EXECUTIVE SECURITY BRIEFING')
    ln(f'Prepared : {meta["timestamp"]}')
    ln(f'Machine  : {meta["hostname"]}   |   Analyst: {meta["username"]}')
    hr(); ln()
    ln(f'  OVERALL VERDICT:  {"✓" if clean else "✗"} {verdict}'); ln()
    if not clean:
        ln('  *** ACTION REQUIRED - See REQUIRED ACTIONS section below ***'); ln()

    hr2(); ln('SECURITY CHECK RESULTS   (8 checks performed)'); hr2(); ln()
    ln(f'  {"#":<4} {"CHECK":<28} {"WHAT WE LOOKED FOR":<33} {"EXAMINED":<12} {"FINDINGS":<10} STATUS')
    ln(f'  {"─":<4} {"─"*27:<28} {"─"*32:<33} {"─"*11:<12} {"─"*9:<10} ──────')
    for num, name, what, examined, findings, passing in checks:
        status = 'PASS' if passing else 'FAIL'
        fstr = '-' if findings is None else ('0 hits' if findings == 0 else f'{findings} found')
        ln(f'  {num:<4} {name:<28} {what:<33} {examined:<12} {fstr:<10} {status}')

    ln(); hr2(); ln('WHAT THIS MEANS'); hr2(); ln()
    if clean:
        ln('  No evidence of compromise was detected across all 8 checks.')
        ln('  This developer may resume work after standard lockfile cleanup.')
    else:
        ln(f'  Evidence of attack found in {len(failed)} of 8 checks.')
        ln()
        ln('  The Axios supply chain attack steals credentials (SSH keys, cloud')
        ln('  tokens, git credentials, API keys) and installs a persistent backdoor.')
        ln('  Any secrets accessible from this machine must be treated as compromised.')
        ln(); ln('  Failed checks:')
        for num, name, *_ in failed:
            ln(f'    Check {num} - {name}')

    ln(); hr2(); ln('REQUIRED ACTIONS'); hr2(); ln()
    if clean:
        ln('  1. Run: npm install axios@1.14.0  (or 0.30.3 for v0.x branches)')
        ln('  2. Run: npm cache clean --force')
        ln('  3. Delete node_modules/ and re-run npm install')
    else:
        ln('  IMMEDIATE (within the hour):')
        ln('  1. Disconnect this machine from the corporate network')
        ln('  2. Do not use this machine for any further work')
        ln('  3. Notify the Security Incident Response team')
        ln()
        ln('  WITHIN 24 HOURS - rotate ALL credentials that exist on this machine:')
        for cred in ['SSH private keys', 'GitHub / GitLab / Bitbucket personal access tokens',
                     'NPM publish tokens', 'AWS / GCP / Azure access keys',
                     'Kubernetes kubeconfig service account tokens',
                     'Docker registry credentials', 'Any secrets stored in .env files']:
            ln(f'  - {cred}')
        ln()
        ln('  INVESTIGATION:')
        ln('  - Preserve a forensic disk image before remediation')
        ln('  - Review /var/log/auth.log for suspicious process execution')
        ln(f'  - Check all systems this developer accessed since 2026-03-31')
        if network_evidence:
            ln('  - ACTIVE C2 CONNECTION DETECTED: assume data exfiltration occurred')

    ln(); hr2(); ln('SCAN INTEGRITY'); hr2()
    ln(f'  Scanner version  : 1.0')
    ln(f'  Checks completed : 8 of 8')
    ln(f'  Scan duration    : {meta["duration"]}')
    ln(f'  Scanned paths    : {", ".join(str(p) for p in meta["paths"])}')
    ln(f'  Technical report : {os.path.basename(tech_path)}')
    ln(f'  Report SHA256    : {report_hash}')
    ln()

    open(path, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
```

- [ ] **Step 4: Run to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_report.py" -v
```

Expected: `Ran 4 tests in ...s  OK`

- [ ] **Step 5: Commit**

```bash
git add linux-port/checks/report.py linux-port/tests/test_report.py
git commit -m "feat: add report.py — technical forensic report + executive briefing, chmod 600"
```

---

## Task 12: `axios_scanner.py` + integration test

**Files:**
- Create: `linux-port/axios_scanner.py`
- Create: `linux-port/tests/test_scanner.py`

- [ ] **Step 1: Write the failing integration test**

Create `linux-port/tests/test_scanner.py`:

```python
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from unittest.mock import patch

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestScannerIntegration(unittest.TestCase):
    def test_vulnerable_fixtures_exit_code_1(self):
        from axios_scanner import scan
        with tempfile.TemporaryDirectory() as out_dir:
            exit_code, tech_path, brief_path = scan(
                paths=[FIXTURES], output_dir=out_dir, threads=1)
        self.assertEqual(exit_code, 1)
        self.assertTrue(os.path.isfile(tech_path))
        self.assertTrue(os.path.isfile(brief_path))
        content = open(tech_path).read()
        self.assertIn('1.14.1', content)

    def test_clean_project_exit_code_0_when_system_checks_clean(self):
        from axios_scanner import scan
        # Mock system-wide checks so we only test lockfile analysis against CleanProject
        with tempfile.TemporaryDirectory() as out_dir:
            with patch('axios_scanner.scan_npm_cache', return_value=[]), \
                 patch('axios_scanner.scan_dropped_payloads', return_value=[]), \
                 patch('axios_scanner.find_persistence_artifacts', return_value=[]), \
                 patch('axios_scanner.scan_xor_encoded_c2', return_value=[]), \
                 patch('axios_scanner.get_network_evidence', return_value=[]):
                exit_code, _, _ = scan(
                    paths=[os.path.join(FIXTURES, 'CleanProject')],
                    output_dir=out_dir, threads=1)
        self.assertEqual(exit_code, 0)

    def test_nonexistent_path_doesnt_crash(self):
        from axios_scanner import scan
        with tempfile.TemporaryDirectory() as out_dir:
            with patch('axios_scanner.scan_npm_cache', return_value=[]), \
                 patch('axios_scanner.scan_dropped_payloads', return_value=[]), \
                 patch('axios_scanner.find_persistence_artifacts', return_value=[]), \
                 patch('axios_scanner.scan_xor_encoded_c2', return_value=[]), \
                 patch('axios_scanner.get_network_evidence', return_value=[]):
                exit_code, tech, brief = scan(
                    paths=['/nonexistent/path/xyz'], output_dir=out_dir, threads=1)
        self.assertIn(exit_code, [0, 1])
        self.assertTrue(os.path.isfile(tech))

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_scanner.py" -v
```

Expected: `ModuleNotFoundError: No module named 'axios_scanner'`

- [ ] **Step 3: Write minimal implementation**

Create `linux-port/axios_scanner.py`:

```python
#!/usr/bin/env python3
"""Axios NPM supply chain compromise scanner — Linux/Python port."""

import argparse
import concurrent.futures
import datetime
import getpass
import os
import socket
import sys

from checks.node_projects import find_node_projects
from checks.lockfile_analysis import analyze_lockfile
from checks.forensic_artifacts import find_forensic_artifacts
from checks.npm_cache import scan_npm_cache
from checks.dropped_payloads import scan_dropped_payloads
from checks.persistence import find_persistence_artifacts
from checks.xor_c2 import scan_xor_encoded_c2
from checks.network_evidence import get_network_evidence
from checks.report import write_reports

_EXCLUDED_TOP = {'/proc', '/sys', '/dev', '/run', '/snap'}


def scan(paths, output_dir='/tmp', threads=4):
    """Run all 9 checks and write reports. Returns (exit_code, tech_path, brief_path)."""
    start = datetime.datetime.now()
    hostname = socket.gethostname()
    username = getpass.getuser()
    log_lines = []

    def log(msg, level='INFO'):
        line = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [{level}] {msg}"
        print(line)
        log_lines.append(line)

    log('Axios Compromise Scanner - 9-check suite')
    log(f'Scanning paths: {", ".join(str(p) for p in paths)}')

    # Check 1: Project discovery
    log('[1/9] Discovering Node.js projects...')
    projects = find_node_projects(paths)
    log(f'Found {len(projects)} project(s)')

    # Checks 2 & 3: lockfile + forensic (parallel if threads > 1)
    lockfile_results = []
    artifacts = []
    if projects:
        if threads > 1:
            log(f'[2-3/9] Lockfile analysis + forensic artifacts (parallel, {threads} threads)...')
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                lf_futures = [ex.submit(analyze_lockfile, p) for p in projects]
                fa_futures = [ex.submit(find_forensic_artifacts, p) for p in projects]
                lockfile_results = [f.result() for f in lf_futures]
                for f in fa_futures:
                    artifacts.extend(f.result())
        else:
            log('[2/9] Analysing lockfiles...')
            lockfile_results = [analyze_lockfile(p) for p in projects]
            log('[3/9] Detecting forensic artifacts...')
            for p in projects:
                artifacts.extend(find_forensic_artifacts(p))
    else:
        log('[2/9] No projects — skipping lockfile analysis')
        log('[3/9] No projects — skipping forensic artifacts')

    log('[4/9] Scanning npm cache...')
    cache_findings = scan_npm_cache()

    log('[5/9] Searching for dropped payloads...')
    dropped_payloads = scan_dropped_payloads()

    log('[6/9] Checking persistence mechanisms...')
    persistence_artifacts = find_persistence_artifacts()

    log('[7/9] Scanning for XOR-encoded C2 indicators...')
    xor_findings = scan_xor_encoded_c2()

    log('[8/9] Checking network evidence...')
    network_evidence = get_network_evidence()

    duration = (datetime.datetime.now() - start).total_seconds()
    meta = {
        'timestamp': start.strftime('%Y%m%d-%H%M%S'),
        'hostname': hostname,
        'username': username,
        'duration': f'{duration:.1f}s',
        'paths': paths,
    }

    log('[9/9] Generating reports...')
    tech_path, brief_path = write_reports(
        projects=projects,
        lockfile_results=lockfile_results,
        artifacts=artifacts,
        cache_findings=cache_findings,
        dropped_payloads=dropped_payloads,
        persistence_artifacts=persistence_artifacts,
        xor_findings=xor_findings,
        network_evidence=network_evidence,
        output_dir=output_dir,
        scan_metadata=meta,
    )

    vuln_count = sum(
        1 for lr in lockfile_results if lr.has_vulnerable_axios or lr.has_malicious_plain_crypto)
    critical_count = sum(
        1 for f in (artifacts + cache_findings + dropped_payloads +
                    persistence_artifacts + xor_findings + network_evidence)
        if f.severity == 'Critical')

    log('')
    log('═══════════════════════════════════════')
    log(f' SCAN COMPLETE - {datetime.datetime.now().strftime("%H:%M:%S")}')
    log(f' Projects scanned    : {len(projects)}')
    log(f' Vulnerable (lockfile): {vuln_count}')
    log(f' Critical findings   : {critical_count}')
    log(f' Technical report    : {tech_path}')
    log(f' Executive briefing  : {brief_path}')

    if vuln_count > 0 or critical_count > 0:
        log(' STATUS: COMPROMISED - isolate machine and review reports', 'WARN')
        exit_code = 1
    else:
        log(' STATUS: CLEAN - no compromise evidence found')
        exit_code = 0

    return exit_code, tech_path, brief_path


def _resolve_paths(raw_paths):
    resolved = []
    for p in raw_paths:
        if p == '/':
            try:
                for entry in sorted(os.scandir('/'), key=lambda e: e.name):
                    if entry.is_dir(follow_symlinks=False) and entry.path not in _EXCLUDED_TOP:
                        resolved.append(entry.path)
            except Exception:
                resolved.append('/')
        else:
            resolved.append(p)
    return resolved


def main():
    parser = argparse.ArgumentParser(
        description='Axios NPM supply chain compromise scanner (Linux/Python port)')
    parser.add_argument('--path', nargs='+', default=['/'], metavar='PATH',
                        help='Paths to scan (default: /)')
    parser.add_argument('--output', default='/tmp', metavar='DIR',
                        help='Output directory for reports (default: /tmp)')
    parser.add_argument('--threads', type=int, default=4, metavar='N',
                        help='Parallel threads for checks 2 & 3 (default: 4)')
    args = parser.parse_args()

    resolved = _resolve_paths(args.path)

    print()
    print('================================================================')
    print('  AXIOS NPM SUPPLY CHAIN COMPROMISE SCANNER')
    print('================================================================')
    print()
    print('  The following folders will be scanned:')
    print()
    for p in resolved:
        print(f'    {p}')
    print()
    confirm = input('  Press ENTER to start, or type Q to quit: ')
    if confirm.strip().lower() == 'q':
        print('Scan cancelled.')
        return 0
    print()

    exit_code, _, _ = scan(resolved, output_dir=args.output, threads=args.threads)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
```

- [ ] **Step 4: Run integration test to verify it passes**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -p "test_scanner.py" -v
```

Expected: `Ran 3 tests in ...s  OK`

- [ ] **Step 5: Run the full test suite**

```bash
python3 -m unittest discover -s linux-port/tests -t linux-port -v
```

Expected: All tests pass. Count should be 28+ tests, 0 failures, 0 errors.

- [ ] **Step 6: Commit**

```bash
git add linux-port/axios_scanner.py linux-port/tests/test_scanner.py
git commit -m "feat: add axios_scanner.py orchestrator with argparse CLI, confirmation prompt, and integration tests"
```

---

## Self-Review Against Spec

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| Python 3.9, stdlib only | All tasks — no pip imports |
| `linux-port/` subfolder | Task 1 |
| `Finding` namedtuple schema | Task 2 |
| Check 1: node_projects.py | Task 3 |
| Check 2: lockfile_analysis.py — axios@1.14.1, 0.30.4, plain-crypto-js@4.2.1 | Task 4 |
| Check 3: forensic_artifacts.py — crypto dir, setup.js SHA-256, C2 patterns | Task 5 |
| Check 4: npm_cache.py — index-v5 + global npm | Task 6 |
| Check 5: dropped_payloads.py — ELF header, Linux temp paths | Task 7 |
| Check 6: persistence.py — cron, systemd user timers, shell RC injection | Task 8 |
| Check 7: xor_c2.py — key=OrDeR_7077, constant=333 | Task 9 |
| Check 8: network_evidence.py — ss/proc, /etc/hosts, syslog | Task 10 |
| Check 9: report.py — technical + exec briefing, chmod 600 | Task 11 |
| Email dropped | No task — intentionally omitted |
| ThreadPoolExecutor for checks 2 & 3 | Task 12 |
| CLI: --path, --output, --threads | Task 12 |
| Confirmation prompt | Task 12 |
| `--path /` expands to subdirs, skips /proc /sys /dev | Task 12 |
| Exit code 0=clean, 1=compromised | Task 12 |
| Fixtures copied into tests/fixtures/ | Task 1 |
| `python3 -m unittest discover linux-port/tests/` | All tasks |

**No gaps found.**
