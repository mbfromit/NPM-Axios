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
    if overall == 'COMPROMISED':
        ln('Rotate ALL of the following immediately:')
    else:
        ln('No compromise detected. Standard precaution — verify these are not exposed:')
    home = os.path.expanduser('~')
    for cp in ['.ssh', '.gitconfig', '.npmrc', '.aws/credentials', '.kube/config', '.docker/config.json']:
        full = os.path.join(home, cp)
        label = 'PRESENT:' if os.path.exists(full) else '(not found):'
        ln(f'  {label} {full}')
    ln('Also check: GitHub tokens, NPM tokens, AWS/GCP/Azure keys, container registry secrets')

    h('APPENDIX: IOC REFERENCE')
    ln('Malicious packages : axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1')
    ln('setup.js SHA256    : e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09')
    ln('C2 domain/IP/port  : sfrclak.com, 142.11.206.73:8000')
    ln('XOR key/constant   : OrDeR_7077 / 333 (0x4D mask)')
    ln('Attack window      : 2026-03-31 00:21 UTC')

    h('REMEDIATION GUIDANCE')
    ln('STEP 1 - Lockfile cleanup:')
    ln('  npm install axios@1.14.0   (or 0.30.3 for v0.x)')
    ln('  npm cache clean --force')
    ln('  rm -rf node_modules && npm install')
    ln()
    if overall == 'COMPROMISED':
        ln('STEP 2 - Dropped payloads or persistence found:')
        ln('  1. Isolate machine from network immediately')
        ln('  2. Capture forensic disk image before any changes')
        ln('  3. Remove cron entries, systemd units, RC injections found above')
        ln('  4. Delete dropped payload files found above')
        ln('  5. Check /var/log/auth.log for suspicious process execution around 2026-03-31')
        ln('  6. Review network logs for traffic to sfrclak.com or 142.11.206.73:8000')
        ln('  7. Consider full OS re-image if active C2 connection was found')
        ln()
        ln('STEP 3 - Credential rotation (mandatory):')
        ln('  SSH keys, GitHub tokens, NPM tokens, AWS/GCP/Azure credentials,')
        ln('  Kubernetes configs, container registry secrets, any secrets in .env files')
    else:
        ln('STEP 2 - No further action required beyond lockfile cleanup.')
        ln('  Monitor logs as a precaution.')

    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')


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
        with open(tech_path, 'rb') as fh:
            report_hash = hashlib.sha256(fh.read()).hexdigest()
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
    ln(f'  OVERALL VERDICT:  {"OK" if clean else "!!"} {verdict}'); ln()
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

    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')
