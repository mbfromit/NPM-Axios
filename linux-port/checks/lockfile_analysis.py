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
    try:
        return _analyze_lockfile_inner(project_path)
    except Exception as e:
        return LockfileResult(
            project_path=project_path,
            has_vulnerable_axios=False,
            vulnerable_axios_version=None,
            has_malicious_plain_crypto=False,
            lockfile_type=None,
            lockfile_path=None,
            error=f'Unexpected error: {e}',
        )


def _analyze_lockfile_inner(project_path):
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
            with open(yarn_lock, encoding='utf-8') as f:
                content = f.read()
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
            with open(pnpm_lock, encoding='utf-8') as f:
                content = f.read()
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
