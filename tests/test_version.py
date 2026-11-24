import os
import re
import unittest

import rpl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class VersionTest(unittest.TestCase):
    def test_package_and_pyproject_agree(self):
        with open(os.path.join(ROOT, "pyproject.toml")) as f:
            m = re.search(r'^version\s*=\s*"([^"]+)"', f.read(), re.M)
        self.assertIsNotNone(m)
        self.assertEqual(rpl.__version__, m.group(1))

    def test_changelog_has_a_section_for_the_version(self):
        with open(os.path.join(ROOT, "CHANGELOG.md")) as f:
            heads = re.findall(r"^## (\S+)", f.read(), re.M)
        self.assertIn(rpl.__version__, heads)


if __name__ == "__main__":
    unittest.main()
