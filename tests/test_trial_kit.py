"""docs/trial/: the kit for a supervised trial of `rpl group` must stay runnable and in step with the command it describes."""
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.path.join(ROOT, "docs", "trial")
SCRIPT, PROCEDURE = os.path.join(KIT, "setup-trial-group.sh"), os.path.join(KIT, "README.md")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class TrialKit(unittest.TestCase):
    def test_the_setup_script_is_executable_and_parses(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        if shutil.which("bash") is None:
            self.skipTest("no bash on this machine")
        r = subprocess.run(["bash", "-n", SCRIPT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_every_rpl_group_flag_of_the_procedure_exists(self):
        known = set(re.findall(r'add_argument\("(--[a-z-]+)"', read(os.path.join(ROOT, "rpl", "group.py"))))
        used = set()
        for line in read(PROCEDURE).splitlines():
            if "rpl group" in line:
                used |= set(re.findall(r"(--[a-z][a-z-]+)", line.split("rpl group", 1)[1]))
        self.assertTrue(used, "the procedure shows no rpl group command")
        self.assertEqual(sorted(used - known), [])

    def test_the_interruption_uses_sigterm_and_covers_both_moments(self):
        text = read(PROCEDURE)
        self.assertEqual(text.count("kill -TERM"), 2, "one kill after the backup, one after the parent was recreated")
        self.assertNotIn("kill -INT", text, "a background job of a non-interactive shell ignores SIGINT: that kill does nothing")
        for marker in ('"^backup:"', '"^parent: recreated"'):
            self.assertIn(marker, text)

    def test_the_kit_carries_no_bypass_of_the_proof(self):
        script = read(SCRIPT)
        for forbidden in ("proven_fixes", "registry_digest", "candidate_digest", "fixcheck"):
            self.assertNotIn(forbidden, script, "the kit may narrow the scan, it must not supply a proof")

    def test_names_are_the_reserved_test_ones(self):
        hosts = set(re.findall(r"Host\(`([^`]+)`\)", read(SCRIPT)))
        self.assertEqual(hosts, {"rpl-trial.example.test"})


if __name__ == "__main__":
    unittest.main()
