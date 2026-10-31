import unittest

from rpl import fixcheck as fc


class SplitRef(unittest.TestCase):
    def test_ghcr(self):
        self.assertEqual(fc.split_ref("ghcr.io/immich-app/immich-server:v3.3.5"), ("ghcr.io", "immich-app/immich-server", "v3.3.5"))

    def test_lscr_is_ghcr(self):
        self.assertEqual(fc.split_ref("lscr.io/linuxserver/bazarr:latest"), ("ghcr.io", "linuxserver/bazarr", "latest"))

    def test_docker_hub_and_official(self):
        self.assertEqual(fc.split_ref("n8nio/n8n:2.45.7"), ("docker.io", "n8nio/n8n", "2.45.7"))
        self.assertEqual(fc.split_ref("redis:7"), ("docker.io", "library/redis", "7"))

    def test_digest_ignored(self):
        self.assertEqual(fc.split_ref("ghcr.io/a/b:latest@sha256:abc")[2], "latest")


class Candidate(unittest.TestCase):
    TAGS = ["v3.3.4", "v3.3.5", "v3.4.0", "v4.0.0", "latest", "v3.3.5-rc1", "3.9.0"]

    def test_same_major_first(self):
        self.assertEqual(fc.choose_candidate("v3.3.5", self.TAGS)[0], "v3.4.0")

    def test_other_major_when_nothing_in_the_same_one(self):
        c, why = fc.choose_candidate("v3.4.0", ["v3.4.0", "v4.0.0"])
        self.assertEqual(c, "v4.0.0")
        self.assertIn("breaking", why)

    def test_v_prefix_respected(self):
        self.assertEqual(fc.choose_candidate("3.3.5", self.TAGS)[0], "3.9.0")

    def test_nothing_newer(self):
        self.assertIsNone(fc.choose_candidate("v4.0.0", self.TAGS)[0])

    def test_moving_tag_is_read_again(self):
        self.assertEqual(fc.choose_candidate("latest", self.TAGS)[0], "latest")

    def test_pre_release_ignored(self):
        self.assertIsNone(fc.choose_candidate("v3.3.5", ["v3.3.5", "v3.3.6-rc1"])[0])


class Outcome(unittest.TestCase):
    ROWS = [{"cve": "C1", "pkg": "p"}, {"cve": "C2", "pkg": "q"}]

    def test_complete(self):
        self.assertEqual(fc.outcome(self.ROWS, set())["verdict"], "COMPLETE")

    def test_partial(self):
        r = fc.outcome(self.ROWS, {("C2", "q")})
        self.assertEqual((r["verdict"], r["removed"], r["remaining"]), ("PARTIAL", 1, 1))

    def test_none(self):
        self.assertEqual(fc.outcome(self.ROWS, {("C1", "p"), ("C2", "q")})["verdict"], "NONE")

    def test_duplicates_counted_once(self):
        self.assertEqual(fc.outcome(self.ROWS + self.ROWS, set())["act"], 2)


if __name__ == "__main__":
    unittest.main()
