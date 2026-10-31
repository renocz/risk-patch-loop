import unittest

from rpl import proposals as pp

ROW = lambda img, kev=True, score=85.0: {"image": img, "score": score, "kev": kev, "level": "internet-no-auth", "decision": "ACT"}
APPS = {"paperless": {"route": "paperless.example.org", "codes": "200 302", "db": {"container": "paperless_db", "user": "u", "name": "n"}},
        "radarr": {"route": "radarr.example.org", "codes": "401", "db": None}}


class NewReference(unittest.TestCase):
    def test_newer_version(self):
        self.assertEqual(pp.new_reference("ghcr.io/a/b:3.3.4", "3.4.1", None)[0], "ghcr.io/a/b:3.4.1")

    def test_moving_tag_is_pinned_to_the_digest(self):
        r, _ = pp.new_reference("lscr.io/linuxserver/radarr:latest", "latest", "sha256:new")
        self.assertEqual(r, "lscr.io/linuxserver/radarr:latest@sha256:new")

    def test_already_at_the_digest(self):
        self.assertIsNone(pp.new_reference("x/y:latest@sha256:same", "latest", "sha256:same")[0])

    def test_changed_digest_is_proposed_again(self):
        self.assertEqual(pp.new_reference("x/y:latest@sha256:old", "latest", "sha256:new")[0], "x/y:latest@sha256:new")


class Prepare(unittest.TestCase):
    INFOS = {"ghcr.io/a/paperless:3.3.4": {"service": "paperless", "compose": "/c/f.yaml", "current_image": "ghcr.io/a/paperless:3.3.4", "vpn": False},
             "x/radarr:latest": {"service": "radarr", "compose": "/c/d.yaml", "current_image": "x/radarr:latest", "vpn": False},
             "x/prowlarr:latest": {"service": "prowlarr", "compose": "/c/d.yaml", "current_image": "x/prowlarr:latest", "vpn": True}}
    FC = {"ghcr.io/a/paperless:3.3.4": {"verdict": "COMPLETE", "candidate": "3.4.1"}, "x/radarr:latest": {"verdict": "COMPLETE", "candidate": "latest"},
          "x/prowlarr:latest": {"verdict": "COMPLETE", "candidate": "latest"}, "n8n:1": {"verdict": "NONE", "candidate": "2"}}

    def test_complete_proposal_with_database(self):
        props, _ = pp.prepare([ROW("ghcr.io/a/paperless:3.3.4")], self.FC, APPS, self.INFOS, {})
        self.assertEqual(props[0]["to"], "ghcr.io/a/paperless:3.4.1")
        self.assertEqual(props[0]["db"]["container"], "paperless_db")

    def test_vpn_dependent_is_never_proposed(self):
        props, skipped = pp.prepare([ROW("x/prowlarr:latest")], self.FC, {"prowlarr": {"route": "r", "codes": "401"}}, self.INFOS, {"x/prowlarr:latest": "sha256:n"})
        self.assertEqual(props, [])
        self.assertIn("VPN", skipped[0]["reason"])

    def test_no_proven_fix_no_proposal(self):
        props, skipped = pp.prepare([ROW("n8n:1")], self.FC, APPS, self.INFOS, {})
        self.assertEqual(props, [])
        self.assertIn("no proven fix", skipped[0]["reason"])

    def test_undescribed_service_is_not_proposed(self):
        props, skipped = pp.prepare([ROW("x/radarr:latest")], self.FC, {}, self.INFOS, {"x/radarr:latest": "sha256:n"})
        self.assertEqual(props, [])
        self.assertIn("patch-apps.json", skipped[0]["reason"])

    def test_digest_pinned_image_is_still_the_same_image(self):
        props, _ = pp.prepare([ROW("x/radarr:latest@sha256:old")], self.FC, APPS, self.INFOS, {"x/radarr:latest": "sha256:new"})
        self.assertEqual(props[0]["to"], "x/radarr:latest@sha256:new")

    def test_sorted_by_score(self):
        props, _ = pp.prepare([ROW("x/radarr:latest", score=60.0), ROW("ghcr.io/a/paperless:3.3.4", score=85.0)], self.FC, APPS, self.INFOS, {"x/radarr:latest": "sha256:n"})
        self.assertEqual([p["service"] for p in props], ["paperless", "radarr"])


class Command(unittest.TestCase):
    P = {"service": "paperless", "compose": "/c/f.yaml", "from": "a:1", "to": "a:2", "route": "p.example.org", "codes": "200 302",
         "db": {"container": "paperless_db", "user": "u", "name": "n"}}

    def test_command_uses_exactly_the_proposal(self):
        c = pp.build_command(self.P)
        self.assertEqual(c[c.index("--old") + 1], "a:1")
        self.assertEqual(c[c.index("--new") + 1], "a:2")
        self.assertEqual(c[c.index("--db-container") + 1], "paperless_db")
        self.assertNotIn("--dry", c)

    def test_no_db_option_without_a_database(self):
        self.assertNotIn("--db-container", pp.build_command(dict(self.P, db=None)))

    def test_dry(self):
        self.assertIn("--dry", pp.build_command(self.P, True))


if __name__ == "__main__":
    unittest.main()
