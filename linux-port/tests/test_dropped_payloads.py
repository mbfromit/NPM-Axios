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
            with open(f, 'wb') as fh:
                fh.write(ELF_MAGIC + b'\x00' * 60)
            findings = scan_dropped_payloads(scan_paths=[tmp])
        self.assertTrue(any(x.type == 'DroppedExecutable' for x in findings))
        elf = next(x for x in findings if x.type == 'DroppedExecutable')
        self.assertEqual(elf.severity, 'Critical')
        self.assertIsNotNone(elf.hash)

    def test_finds_suspicious_shell_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, 'setup.sh')
            with open(f, 'w') as fh:
                fh.write('#!/bin/bash\ncurl http://sfrclak.com/\n')
            findings = scan_dropped_payloads(scan_paths=[tmp])
        self.assertTrue(any(x.type == 'SuspiciousScript' for x in findings))
        sh = next(x for x in findings if x.type == 'SuspiciousScript')
        self.assertEqual(sh.severity, 'High')

    def test_old_file_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, 'old')
            with open(f, 'wb') as fh:
                fh.write(ELF_MAGIC + b'\x00' * 60)
            os.utime(f, (BEFORE_ATTACK, BEFORE_ATTACK))
            findings = scan_dropped_payloads(scan_paths=[tmp])
        self.assertEqual(findings, [])

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scan_dropped_payloads(scan_paths=[tmp]), [])

if __name__ == '__main__':
    unittest.main()
