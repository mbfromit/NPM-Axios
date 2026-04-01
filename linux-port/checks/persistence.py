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
            with open(fpath, encoding='utf-8', errors='ignore') as fh:
                for line in fh:
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
                with open(fpath, encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
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
            with open(fpath, encoding='utf-8', errors='ignore') as fh:
                for line in fh:
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
