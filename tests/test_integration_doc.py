"""docs/integration.md: the contract for whoever drives rpl from another program. It must stay in step with the code it describes."""
import glob
import os
import re
import unittest

from rpl import __main__ as cli
from rpl import config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "integration.md")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def table_first_column(text, heading):
    """The backticked first cells of the table under `## heading`."""
    section = text.split(f"## {heading}", 1)[1].split("\n## ", 1)[0]
    return [m.group(1) for m in re.finditer(r"^\| `([^`]+)` \|", section, re.M)]


class IntegrationDoc(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.exists(DOC), "docs/integration.md is missing")
        self.text = read(DOC)
        self.code = "\n".join(read(p) for p in glob.glob(os.path.join(ROOT, "rpl", "*.py")))

    def test_every_configuration_key_of_the_code_is_in_the_table_and_nothing_else(self):
        keys = table_first_column(self.text, "Configuration keys")
        self.assertEqual(sorted(keys), sorted(config.DEFAULTS))

    def test_every_state_file_of_the_table_is_written_by_the_code(self):
        files = table_first_column(self.text, "State files")
        self.assertTrue(files)
        for name in files:
            literal = name.split("<")[0].rstrip("-")                                # notifs.json.unreadable-<stamp>
            self.assertIn(literal, self.code, name)

    def test_every_state_file_the_code_writes_by_name_is_in_the_table(self):
        written = set(re.findall(r'config\.state\(cfg, "([A-Za-z0-9._-]+)"\)', self.code))
        written |= set(re.findall(r'^(?:JOURNAL|NIGHTLY|KNOWN|LOCK_FILE|PAUSE_FILE) = "([A-Za-z0-9._-]+)"', self.code, re.M))
        listed = set(table_first_column(self.text, "State files"))
        self.assertEqual(sorted(written - listed), [])

    def test_every_command_of_the_table_exists(self):
        commands = table_first_column(self.text, "Commands")
        self.assertTrue(commands)
        for cmd in commands:
            self.assertIn(cmd.split()[0], cli.COMMANDS, cmd)

    def test_every_command_is_in_the_table(self):
        listed = {c.split()[0] for c in table_first_column(self.text, "Commands")}
        self.assertEqual(sorted(set(cli.COMMANDS) - listed), [])

    def test_it_says_where_it_comes_from_and_what_it_does_not_cover(self):
        self.assertIn("Derived from the code", self.text)
        self.assertIn("never tested against", self.text)
        self.assertIn("## What it does not cover", self.text)

    def test_the_readmes_link_to_it(self):
        self.assertIn("docs/integration.md", read(os.path.join(ROOT, "README.md")))
        self.assertIn("docs/integration.md", read(os.path.join(ROOT, "README.fr.md")))


if __name__ == "__main__":
    unittest.main()
