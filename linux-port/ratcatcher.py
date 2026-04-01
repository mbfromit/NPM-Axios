#!/usr/bin/env python3
"""RatCatcher — Axios NPM supply chain compromise scanner (Linux/Python port)."""

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

    def log(msg, level='INFO'):
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [{level}] {msg}")

    log('RatCatcher - 9-check suite')
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
    any_finding = bool(
        artifacts + cache_findings + dropped_payloads +
        persistence_artifacts + xor_findings + network_evidence)

    compromised = bool(vuln_count or any_finding)
    if compromised:
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
        description='RatCatcher — Axios NPM supply chain compromise scanner (Linux/Python port)')
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
    print('  RATCATCHER')
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
