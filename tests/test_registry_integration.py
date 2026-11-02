"""fixcheck's registry reading, against a fake registry served on a free local port (no real registry, no Docker, no Trivy)."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from rpl import config, fixcheck, proposals

from .fakes import FakeRegistry, rpl_config

IMAGE = "ghcr.io/example-org/app"
VERDICTS_THAT_CLAIM_KNOWLEDGE = ("COMPLETE", "PARTIAL", "NONE", "NO NEWER VERSION")


def write_state(state_dir, image):
    """An ACT row: a KEV finding on an image exposed to the Internet without a login (score 60 >= 45)."""
    os.makedirs(state_dir, exist_ok=True)
    with open(os.path.join(state_dir, "inventory.json"), "w") as f:
        json.dump({"app-1": {"image": image, "level": "internet-no-auth"}}, f)
    with open(os.path.join(state_dir, "findings.json"), "w") as f:
        json.dump({"A": [], "C": [], "B": [{"image": image, "cve": "CVE-2026-0001", "pkg": "libx", "severity": "HIGH", "fixed": "2"}]}, f)


class RegistryCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg_path = rpl_config(self.tmp.name)
        env = mock.patch.dict(os.environ, {"RPL_CONFIG": self.cfg_path})
        env.start()
        self.addCleanup(env.stop)
        self.state = config.load()["state_dir"]

    def fixcheck(self, image, *flags, scan_result=None):
        """Run `rpl fixcheck`; returns (exit code, [JSON line per image], scan_remote mock)."""
        write_state(self.state, image)
        out = io.StringIO()
        with mock.patch("rpl.fixcheck.scan_remote", return_value=set() if scan_result is None else scan_result) as scan, contextlib.redirect_stdout(out):
            rc = fixcheck.main(list(flags))
        return rc, [json.loads(l) for l in out.getvalue().splitlines()], scan


class NoNetwork(unittest.TestCase):
    def test_the_guard_in_tests_init_blocks_anything_but_loopback(self):
        import socket
        with self.assertRaises(AssertionError):
            socket.getaddrinfo("ghcr.io", 443)
        with self.assertRaises(AssertionError):
            socket.create_connection(("192.0.2.1", 80), timeout=1)


class ReadingTheRegistry(RegistryCase):
    def test_tag_list_is_read_with_the_token_the_registry_issued(self):
        with FakeRegistry(tags={"example-org/app": ["1.0.0", "1.1.0"]}) as reg:
            self.assertEqual(fixcheck.list_tags("ghcr.io", "example-org/app"), ["1.0.0", "1.1.0"])
        self.assertEqual([r[1].split("?")[0] for r in reg.requests], ["/token", "/v2/example-org/app/tags/list"])
        self.assertEqual(reg.requests[1][2], "Bearer tok-example-org/app")

    def test_unsupported_registry_is_not_guessed(self):
        self.assertIsNone(fixcheck.list_tags("quay.io", "x/y"))

    def test_manifest_digest_comes_from_the_registry(self):
        with FakeRegistry(digests={("example-org/app", "latest"): "sha256:abc"}) as reg:
            self.assertEqual(proposals.registry_digest(f"{IMAGE}:latest"), "sha256:abc")
        self.assertEqual(reg.requests[-1][0], "HEAD")
        self.assertEqual(reg.requests[-1][2], "Bearer tok-example-org/app")


class FixcheckVerdicts(RegistryCase):
    def test_newer_tag_is_found_and_scanned_from_the_registry(self):
        with FakeRegistry(tags={"example-org/app": ["1.0.0", "1.0.1", "1.1.0", "2.0.0", "1.2.0-rc1"]}):
            rc, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0")
        self.assertEqual(rc, 0)
        e = entries[0]
        self.assertEqual((e["candidate"], e["verdict"], e["removed"]), ("1.1.0", "COMPLETE", 1))
        scan.assert_called_once()
        self.assertEqual(scan.call_args[0][1], f"{IMAGE}:1.1.0")
        with open(os.path.join(self.state, "fixcheck.json")) as f:
            saved = json.load(f)
        self.assertEqual(saved["images"][0]["candidate"], "1.1.0")

    def test_candidate_that_still_has_the_finding_is_not_complete(self):
        with FakeRegistry(tags={"example-org/app": ["1.0.0", "1.1.0"]}):
            _, entries, _ = self.fixcheck(f"{IMAGE}:1.0.0", scan_result={("CVE-2026-0001", "libx")})
        self.assertEqual(entries[0]["verdict"], "NONE")

    def test_no_newer_tag_says_so(self):
        with FakeRegistry(tags={"example-org/app": ["0.9.0", "1.0.0"]}):
            _, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0")
        self.assertEqual(entries[0]["verdict"], "NO NEWER VERSION")
        scan.assert_not_called()

    def test_dry_run_reads_the_registry_but_scans_nothing_and_saves_nothing(self):
        with FakeRegistry(tags={"example-org/app": ["1.0.0", "1.1.0"]}):
            _, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0", "--dry")
        self.assertEqual((entries[0]["candidate"], entries[0]["verdict"]), ("1.1.0", "(dry: not scanned)"))
        scan.assert_not_called()
        self.assertFalse(os.path.exists(os.path.join(self.state, "fixcheck.json")))

    def test_moving_tag_is_read_again(self):
        with FakeRegistry(tags={"example-org/app": ["latest", "1.0.0"]}):
            _, entries, scan = self.fixcheck(f"{IMAGE}:latest")
        self.assertEqual(entries[0]["candidate"], "latest")
        self.assertEqual(scan.call_args[0][1], f"{IMAGE}:latest")

    def test_failed_remote_scan_is_reported_as_failed(self):
        with FakeRegistry(tags={"example-org/app": ["1.0.0", "1.1.0"]}):
            write_state(self.state, f"{IMAGE}:1.0.0")
            out = io.StringIO()
            with mock.patch("rpl.fixcheck.scan_remote", return_value=None), contextlib.redirect_stdout(out):
                fixcheck.main([])
        self.assertEqual(json.loads(out.getvalue())["verdict"], "SCAN FAILED")


class UnreadableRegistry(RegistryCase):
    """An unreadable registry must produce an explicit UNKNOWN with the error named, never a verdict that claims knowledge."""

    def check_unknown(self, entries, scan):
        e = entries[0]
        self.assertTrue(e["verdict"].startswith("UNKNOWN"), e)
        self.assertIn("registry_error", e)
        self.assertNotIn(e["verdict"], VERDICTS_THAT_CLAIM_KNOWLEDGE)
        self.assertNotIn("candidate", e)
        scan.assert_not_called()

    def test_server_error(self):
        with FakeRegistry(tags={"example-org/app": ["1.1.0"]}, broken={"example-org/app": "500"}):
            _, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0")
        self.check_unknown(entries, scan)
        self.assertEqual(entries[0]["registry_error"], "HTTPError")

    def test_access_denied(self):
        with FakeRegistry(tags={"example-org/app": ["1.1.0"]}, broken={"example-org/app": "401"}):
            _, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0")
        self.check_unknown(entries, scan)

    def test_repository_unknown_to_the_registry(self):
        with FakeRegistry(tags={}):
            _, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0")
        self.check_unknown(entries, scan)

    def test_answer_that_is_not_json(self):
        with FakeRegistry(broken={"example-org/app": "not-json"}):
            _, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0")
        self.check_unknown(entries, scan)

    def test_token_missing_from_the_token_answer(self):
        with FakeRegistry(broken={"example-org/app": "no-token"}):
            _, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0")
        self.check_unknown(entries, scan)

    def test_registry_unreachable(self):
        with FakeRegistry() as reg:
            pass                                    # server stopped; endpoints are restored on exit, so re-point them at the dead port
        dead = {"token": reg.url + "/token?scope=repository:{repo}:pull", "api": reg.url}
        with mock.patch.dict("rpl.fixcheck.ENDPOINTS", {"ghcr.io": dead}):
            _, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0")
        self.check_unknown(entries, scan)

    def test_registry_not_supported(self):
        _, entries, scan = self.fixcheck("quay.io/example-org/app:1.0.0")
        self.assertTrue(entries[0]["verdict"].startswith("UNKNOWN"))
        scan.assert_not_called()

    def test_unknown_is_never_proposed(self):
        entry = {"image": f"{IMAGE}:1.0.0", "verdict": "UNKNOWN (registry not supported or unreachable)"}
        row = {"image": f"{IMAGE}:1.0.0", "score": 60.0, "kev": True, "level": "internet-no-auth", "decision": "ACT"}
        props, skipped = proposals.prepare([row], {entry["image"]: entry}, {}, {}, {})
        self.assertEqual(props, [])
        self.assertIn("no proven fix", skipped[0]["reason"])


class DefectRegressions(RegistryCase):
    PAGED = ["0.8.0", "0.9.0", "1.0.0", "1.0.1", "1.1.0"]

    def test_tag_list_split_over_several_pages_is_read_in_full(self):
        """Defect 5: the Link header of a paginated tag list was ignored. With the newest tags on a later page the tool answered
        'NO NEWER VERSION' (updating changes nothing), which is a statement about data it never read."""
        with FakeRegistry(tags={"example-org/app": self.PAGED}, page_size=2) as reg:
            self.assertEqual(fixcheck.list_tags("ghcr.io", "example-org/app"), self.PAGED)
        self.assertEqual(len([r for r in reg.requests if "/tags/list" in r[1]]), 3)
        self.assertTrue(all(r[2] == "Bearer tok-example-org/app" for r in reg.requests if "/tags/list" in r[1]))

    def test_newest_tag_on_a_later_page_is_found(self):
        with FakeRegistry(tags={"example-org/app": self.PAGED}, page_size=2):
            _, entries, _ = self.fixcheck(f"{IMAGE}:1.0.0")
        self.assertEqual((entries[0]["candidate"], entries[0]["verdict"]), ("1.1.0", "COMPLETE"))

    def test_next_link_to_another_host_is_not_followed_and_the_token_is_not_sent_there(self):
        with FakeRegistry(tags={"example-org/app": ["1.1.0"]}) as other:
            with FakeRegistry(tags={"example-org/app": self.PAGED}, page_size=2, link_base=other.url):
                with self.assertRaises(ValueError):
                    fixcheck.list_tags("ghcr.io", "example-org/app")
        self.assertEqual([r for r in other.requests if "/tags/list" in r[1]], [])

    def test_endless_pagination_stops(self):
        with FakeRegistry(tags={"example-org/app": self.PAGED}, page_size=2, loop=True):
            with self.assertRaises(ValueError):
                fixcheck.list_tags("ghcr.io", "example-org/app")

    def test_registry_that_returns_no_tag_at_all_is_unknown_not_no_newer_version(self):
        """Defect 5b: `"tags": null` or [] became an empty list, and an empty list means 'nothing newer'. A repository that holds
        the image we are running cannot have zero tags: the answer is unreadable, not reassuring."""
        for tags, broken in (([], {}), (["x"], {"example-org/app": "null-tags"})):
            with self.subTest(tags=tags, broken=broken), FakeRegistry(tags={"example-org/app": tags}, broken=broken):
                _, entries, scan = self.fixcheck(f"{IMAGE}:1.0.0")
                self.assertTrue(entries[0]["verdict"].startswith("UNKNOWN"), entries[0])
                scan.assert_not_called()

    def test_the_error_names_what_went_wrong(self):
        """Defect 5c: registry_error was only the exception class ('HTTPError'): no status, nothing to act on."""
        with FakeRegistry(tags={"example-org/app": ["1.1.0"]}, broken={"example-org/app": "500"}):
            _, entries, _ = self.fixcheck(f"{IMAGE}:1.0.0")
        self.assertIn("500", entries[0]["registry_detail"])


if __name__ == "__main__":
    unittest.main()
