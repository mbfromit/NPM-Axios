import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks import Finding
from checks.lockfile_analysis import LockfileResult
from checks.report import write_reports


def _meta():
    return {
        'timestamp': '20260401-120000',
        'hostname': 'testhost',
        'username': 'testuser',
        'duration': '5.0s',
        'paths': ['/home/test'],
    }


class TestWriteReports(unittest.TestCase):
    def test_creates_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tech, brief = write_reports([], [], [], [], [], [], [], [], tmp, _meta())
            self.assertTrue(os.path.isfile(tech))
            self.assertTrue(os.path.isfile(brief))

    def test_clean_shows_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            tech, _ = write_reports([], [], [], [], [], [], [], [], tmp, _meta())
            with open(tech) as fh:
                content = fh.read()
        self.assertIn('CLEAN', content)
        self.assertNotIn('COMPROMISED', content)

    def test_compromised_with_vulnerable_lockfile(self):
        lr = LockfileResult(
            project_path='/home/test/app',
            has_vulnerable_axios=True, vulnerable_axios_version='1.14.1',
            has_malicious_plain_crypto=True, lockfile_type='npm',
            lockfile_path='/home/test/app/package-lock.json', error=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            tech, brief = write_reports(
                ['/home/test/app'], [lr], [], [], [], [], [], [], tmp, _meta())
            with open(tech) as fh:
                tech_content = fh.read()
            with open(brief) as fh:
                brief_content = fh.read()
        self.assertIn('COMPROMISED', tech_content)
        self.assertIn('1.14.1', tech_content)
        self.assertIn('EXECUTIVE SECURITY BRIEFING', brief_content)
        self.assertIn('COMPROMISED', brief_content)

    def test_report_permissions_600(self):
        with tempfile.TemporaryDirectory() as tmp:
            tech, brief = write_reports([], [], [], [], [], [], [], [], tmp, _meta())
            self.assertEqual(oct(os.stat(tech).st_mode)[-3:], '600')
            self.assertEqual(oct(os.stat(brief).st_mode)[-3:], '600')

if __name__ == '__main__':
    unittest.main()
