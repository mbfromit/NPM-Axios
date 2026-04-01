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
            with open('/proc/net/tcp') as fh:
                for line in fh:
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
            with open(hosts_path, encoding='utf-8', errors='ignore') as fh:
                for line in fh:
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
            with open(log_path, encoding='utf-8', errors='ignore') as fh:
                for line in fh:
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
