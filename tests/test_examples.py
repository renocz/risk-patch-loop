"""The files the README tells you to copy must exist and be usable."""
import json
import os
import re
import unittest

from rpl import config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Examples(unittest.TestCase):
    def test_every_example_file_named_in_the_readmes_exists(self):
        """Defect 6: the quick start says `cp examples/rpl.json rpl.json`, but the file was never committed (.gitignore matched it)."""
        for readme in ("README.md", "README.fr.md"):
            text = open(os.path.join(ROOT, readme), encoding="utf-8").read()
            for name in re.findall(r"examples/([\w.-]+\.json)", text):
                with self.subTest(readme=readme, file=name):
                    self.assertTrue(os.path.exists(os.path.join(ROOT, "examples", name)), name)

    def test_example_config_only_uses_known_keys_and_loads(self):
        with open(os.path.join(ROOT, "examples", "rpl.json"), encoding="utf-8") as f:
            ex = json.load(f)
        self.assertEqual([k for k in ex if not k.startswith("_") and k not in config.DEFAULTS], [])
        old = os.environ.get("RPL_CONFIG")
        os.environ["RPL_CONFIG"] = os.path.join(ROOT, "examples", "rpl.json")
        try:
            cfg = config.load()
        finally:
            os.environ.pop("RPL_CONFIG") if old is None else os.environ.__setitem__("RPL_CONFIG", old)
        self.assertIn("state_dir", cfg)

    def test_example_config_does_not_ship_a_snapshot_command_that_pretends_to_work(self):
        with open(os.path.join(ROOT, "examples", "rpl.json"), encoding="utf-8") as f:
            self.assertIsNone(json.load(f).get("snapshot_command"))

    def test_other_examples_are_valid_json(self):
        for name in os.listdir(os.path.join(ROOT, "examples")):
            with self.subTest(name=name), open(os.path.join(ROOT, "examples", name), encoding="utf-8") as f:
                json.load(f)

    def test_gitignore_does_not_hide_the_example_config(self):
        text = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read().splitlines()
        self.assertIn("!examples/rpl.json", text)


if __name__ == "__main__":
    unittest.main()
