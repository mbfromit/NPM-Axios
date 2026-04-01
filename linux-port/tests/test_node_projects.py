import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks.node_projects import find_node_projects

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')

class TestFindNodeProjects(unittest.TestCase):
    def test_finds_all_fixture_projects(self):
        projects = find_node_projects([FIXTURES])
        names = [os.path.basename(p) for p in projects]
        self.assertIn('CleanProject', names)
        self.assertIn('VulnerableNpmProject', names)
        self.assertIn('VulnerableYarnProject', names)
        self.assertIn('VulnerablePnpmProject', names)

    def test_excludes_node_modules_paths(self):
        projects = find_node_projects([FIXTURES])
        for p in projects:
            parts = p.replace('\\', '/').split('/')
            self.assertNotIn('node_modules', parts)

    def test_nonexistent_path_returns_empty(self):
        self.assertEqual(find_node_projects(['/nonexistent/xyz123']), [])

    def test_empty_list_returns_empty(self):
        self.assertEqual(find_node_projects([]), [])

if __name__ == '__main__':
    unittest.main()
