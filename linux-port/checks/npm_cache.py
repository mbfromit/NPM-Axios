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
                    with open(fpath, encoding='utf-8', errors='ignore') as f:
                        raw = f.read()
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
                            with open(pkg_json) as f:
                                ver = json.load(f).get('version')
                        except Exception:
                            pass
                    if ver in VULN_VERSIONS:
                        findings.append(Finding(
                            type='GlobalNpmHit', path=pkg_dir,
                            detail=f'{pkg}@{ver or "unknown"}', severity='Critical',
                            description=f'Malicious {pkg} in global npm — run: npm uninstall -g {pkg}',
                            hash=None,
                        ))
    except Exception:
        pass

    return findings
