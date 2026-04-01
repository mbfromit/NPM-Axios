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
            with open(cron_file, 'w') as fh:
                fh.write('*/5 * * * * node /tmp/payload.js\n')
            os.utime(cron_file, (AFTER, AFTER))
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = find_persistence_artifacts(
                    cron_paths=[cron_file], rc_files=[], systemd_user_dir='')
        self.assertTrue(any(f.type == 'SuspiciousCronEntry' for f in findings))

    def test_rc_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = os.path.join(tmp, '.bashrc')
            with open(rc, 'w') as fh:
                fh.write('export PATH=/tmp/node/bin:$PATH\n')
            os.utime(rc, (AFTER, AFTER))
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = find_persistence_artifacts(
                    rc_files=[rc], cron_paths=[], systemd_user_dir='')
        self.assertTrue(any(f.type == 'SuspiciousRcInjection' for f in findings))

    def test_systemd_unit_after_attack(self):
        with tempfile.TemporaryDirectory() as sdir:
            svc = os.path.join(sdir, 'evil.service')
            with open(svc, 'w') as fh:
                fh.write('[Service]\nExecStart=node /tmp/payload.js\n')
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
