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
                if count >= 2000:
                    break
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
                                with open(fpath, 'rb') as fh:
                                    sha = hashlib.sha256(fh.read()).hexdigest()
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
