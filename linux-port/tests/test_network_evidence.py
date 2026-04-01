import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from unittest.mock import MagicMock, patch
from checks.network_evidence import get_network_evidence


class TestGetNetworkEvidence(unittest.TestCase):
    def test_finds_c2_ip_in_ss_output(self):
        ss_out = 'ESTAB 0 0 10.0.0.5:43210 142.11.206.73:8000 users:(("node",pid=1234,fd=5))\n'
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ss_out)
            findings = get_network_evidence(hosts_path='/nonexistent', syslog_paths=[])
        c2 = [f for f in findings if f.type == 'ActiveC2Connection']
        self.assertTrue(len(c2) > 0)
        self.assertEqual(c2[0].severity, 'Critical')

    def test_finds_c2_in_hosts_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hosts', delete=False) as f:
            f.write('# hosts\n142.11.206.73 sfrclak.com\n')
            hosts_path = f.name
        try:
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = get_network_evidence(hosts_path=hosts_path, syslog_paths=[])
        finally:
            os.unlink(hosts_path)
        hits = [f for f in findings if f.type == 'HostsFileHit']
        self.assertTrue(len(hits) > 0)
        self.assertEqual(hits[0].severity, 'Critical')

    def test_finds_c2_in_syslog(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write('Apr 1 10:00:00 host node[123]: connected to 142.11.206.73:8000\n')
            log_path = f.name
        try:
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout='')
                findings = get_network_evidence(hosts_path='/nonexistent', syslog_paths=[log_path])
        finally:
            os.unlink(log_path)
        hits = [f for f in findings if f.type == 'SyslogHit']
        self.assertTrue(len(hits) > 0)
        self.assertEqual(hits[0].severity, 'High')

    def test_clean_system_no_findings(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout='')
            findings = get_network_evidence(hosts_path='/nonexistent', syslog_paths=[])
        self.assertEqual(findings, [])

if __name__ == '__main__':
    unittest.main()
