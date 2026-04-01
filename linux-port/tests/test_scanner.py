import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from unittest.mock import patch

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestScannerIntegration(unittest.TestCase):
    def test_vulnerable_fixtures_exit_code_1(self):
        from ratcatcher import scan
        with tempfile.TemporaryDirectory() as out_dir:
            exit_code, tech_path, brief_path = scan(
                paths=[FIXTURES], output_dir=out_dir, threads=1)
            self.assertEqual(exit_code, 1)
            self.assertTrue(os.path.isfile(tech_path))
            self.assertTrue(os.path.isfile(brief_path))
            with open(tech_path) as fh:
                content = fh.read()
            self.assertIn('1.14.1', content)

    def test_clean_project_exit_code_0_when_system_checks_clean(self):
        from ratcatcher import scan
        # Mock system-wide checks so we only test lockfile analysis against CleanProject
        with tempfile.TemporaryDirectory() as out_dir:
            with patch('ratcatcher.scan_npm_cache', return_value=[]), \
                 patch('ratcatcher.scan_dropped_payloads', return_value=[]), \
                 patch('ratcatcher.find_persistence_artifacts', return_value=[]), \
                 patch('ratcatcher.scan_xor_encoded_c2', return_value=[]), \
                 patch('ratcatcher.get_network_evidence', return_value=[]):
                exit_code, _, _ = scan(
                    paths=[os.path.join(FIXTURES, 'CleanProject')],
                    output_dir=out_dir, threads=1)
        self.assertEqual(exit_code, 0)

    def test_nonexistent_path_doesnt_crash(self):
        from ratcatcher import scan
        with tempfile.TemporaryDirectory() as out_dir:
            with patch('ratcatcher.scan_npm_cache', return_value=[]), \
                 patch('ratcatcher.scan_dropped_payloads', return_value=[]), \
                 patch('ratcatcher.find_persistence_artifacts', return_value=[]), \
                 patch('ratcatcher.scan_xor_encoded_c2', return_value=[]), \
                 patch('ratcatcher.get_network_evidence', return_value=[]):
                exit_code, tech, brief = scan(
                    paths=['/nonexistent/path/xyz'], output_dir=out_dir, threads=1)
            self.assertIn(exit_code, [0, 1])
            self.assertTrue(os.path.isfile(tech))

if __name__ == '__main__':
    unittest.main()
