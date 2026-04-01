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
                with open(setup_js, 'rb') as fh:
                    h = hashlib.sha256(fh.read()).hexdigest()
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
            if count >= 1000:
                break
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
                    with open(fpath, encoding='utf-8', errors='ignore') as fh:
                        content = fh.read()
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
