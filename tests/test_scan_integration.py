"""`rpl scan` must never answer "all good" when the scanner could not do its job. Docker and Trivy are replaced by fakes."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from rpl import config, scan

from .fakes import done, rpl_config

VULN = {"VulnerabilityID": "CVE-2026-0001", "PkgName": "libx", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"}


class ScanCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg_path = rpl_config(self.tmp.name)
        env = mock.patch.dict(os.environ, {"RPL_CONFIG": self.cfg_path})
        env.start()
        self.addCleanup(env.stop)
        self.findings = os.path.join(config.load()["state_dir"], "findings.json")
        guard = mock.patch("subprocess.run", side_effect=AssertionError("a real subprocess was started"))
        guard.start()
        self.addCleanup(guard.stop)

    def run_scan(self, *flags, images=None, kev=(set(), True), scan_image=None, db_age=1.0):
        """Run `rpl scan` with fakes. scan_image: callable(cfg, ref) -> list of vulns or None."""
        images = {"app:1": "sha256:aaa", "db:1": "sha256:bbb"} if images is None else images
        scan_image = scan_image or (lambda cfg, ref: [VULN])
        out = io.StringIO()
        with mock.patch.object(scan, "images_running", return_value=images), mock.patch.object(scan, "load_kev", return_value=kev), \
                mock.patch.object(scan, "scan_image", side_effect=scan_image), mock.patch.object(scan, "db_age_hours", return_value=db_age), \
                contextlib.redirect_stdout(out):
            rc = scan.main(list(flags))
        return rc, out.getvalue()

    def assert_unreliable(self, rc, out, reason):
        self.assertNotEqual(rc, 0, out)
        self.assertIn("UNRELIABLE", out)
        self.assertIn(reason, out)
        self.assertFalse(os.path.exists(self.findings), "findings.json must not be (re)written by an unreliable scan")


class ReliableScan(ScanCase):
    def test_reliable_scan_succeeds_and_writes_findings(self):
        rc, out = self.run_scan()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("UNRELIABLE", out)
        data = json.load(open(self.findings))
        self.assertEqual((len(data["A"]), data["images"]), (2, ["app:1", "db:1"]))

    def test_scan_by_image_id_not_by_name(self):
        seen = []
        self.run_scan(scan_image=lambda cfg, ref: seen.append(ref) or [])
        self.assertEqual(sorted(seen), ["sha256:aaa", "sha256:bbb"])

    def test_image_with_no_finding_is_a_clean_result_not_a_failure(self):
        rc, out = self.run_scan(scan_image=lambda cfg, ref: [])
        self.assertEqual(rc, 0, out)

    def test_dry_run_prints_but_writes_nothing(self):
        rc, _ = self.run_scan("--dry")
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.findings))


class ScannerCouldNotDoItsJob(ScanCase):
    def test_one_image_not_analysed(self):
        rc, out = self.run_scan(scan_image=lambda cfg, ref: None if ref == "sha256:bbb" else [VULN])
        self.assert_unreliable(rc, out, "1 image(s) not analysed: db:1")

    def test_no_image_analysed_at_all(self):
        rc, out = self.run_scan(scan_image=lambda cfg, ref: None)
        self.assert_unreliable(rc, out, "2 image(s) not analysed")

    def test_no_running_image_found(self):
        rc, out = self.run_scan(images={})
        self.assert_unreliable(rc, out, "no running image found")

    def test_vulnerability_database_too_old(self):
        rc, out = self.run_scan(db_age=500.0)
        self.assert_unreliable(rc, out, "vulnerability database too old")

    def test_vulnerability_database_age_unknown(self):
        rc, out = self.run_scan(db_age=None)
        self.assert_unreliable(rc, out, "age of the vulnerability database unknown")

    def test_kev_list_unavailable(self):
        rc, out = self.run_scan(kev=(set(), False))
        self.assert_unreliable(rc, out, "CISA KEV list unavailable")

    def test_unreliable_dry_run_also_fails(self):
        rc, out = self.run_scan("--dry", db_age=500.0)
        self.assertNotEqual(rc, 0)
        self.assertIn("UNRELIABLE", out)

    def test_a_previous_good_findings_file_is_left_alone(self):
        os.makedirs(os.path.dirname(self.findings))
        open(self.findings, "w").write('{"ts": 1, "A": [], "B": [], "C": [], "images": ["old"]}')
        rc, _ = self.run_scan(db_age=500.0)
        self.assertNotEqual(rc, 0)
        self.assertEqual(json.load(open(self.findings))["images"], ["old"])

    def test_every_reason_is_listed_not_only_the_first(self):
        rc, out = self.run_scan(db_age=500.0, kev=(set(), False), scan_image=lambda cfg, ref: None)
        for reason in ("too old", "KEV list unavailable", "not analysed"):
            self.assertIn(reason, out)


class LowLevelFailuresBecomeUnreliable(ScanCase):
    """The same property one layer down: what the real scan_image / images_running / load_kev do when Docker or Trivy fail."""

    def test_trivy_exits_non_zero(self):
        with mock.patch.object(scan, "run", return_value=done(1, "", "FATAL db error")):
            self.assertIsNone(scan.scan_image(config.load(), "sha256:aaa"))

    def test_trivy_exits_zero_with_garbage_output(self):
        with mock.patch.object(scan, "run", return_value=done(0, "not json at all")):
            self.assertIsNone(scan.scan_image(config.load(), "sha256:aaa"))

    def test_trivy_exits_zero_with_empty_output(self):
        with mock.patch.object(scan, "run", return_value=done(0, "")):
            self.assertIsNone(scan.scan_image(config.load(), "sha256:aaa"))

    def test_trivy_clean_image(self):
        with mock.patch.object(scan, "run", return_value=done(0, json.dumps({"Results": None}))):
            self.assertEqual(scan.scan_image(config.load(), "sha256:aaa"), [])

    def test_trivy_findings_are_flattened(self):
        d = {"Results": [{"Vulnerabilities": [VULN]}, {"Vulnerabilities": None}, {}]}
        with mock.patch.object(scan, "run", return_value=done(0, json.dumps(d))):
            self.assertEqual(scan.scan_image(config.load(), "sha256:aaa"), [VULN])

    def test_docker_ps_fails_gives_no_images(self):
        with mock.patch.object(scan, "run", return_value=done(1, "", "Cannot connect to the Docker daemon")):
            self.assertEqual(scan.images_running(), {})

    def test_whole_pipeline_with_docker_down_is_unreliable(self):
        out = io.StringIO()
        with mock.patch.object(scan, "run", return_value=done(1, "", "Cannot connect to the Docker daemon")), \
                mock.patch.object(scan, "db_age_hours", return_value=1.0), contextlib.redirect_stdout(out):
            rc = scan.main([])
        self.assertNotEqual(rc, 0)
        self.assertIn("UNRELIABLE", out.getvalue())
        self.assertFalse(os.path.exists(self.findings))

    def test_whole_pipeline_with_trivy_failing_on_every_image_is_unreliable(self):
        def fake_run(cmd, timeout=600):
            if cmd[:2] == ["docker", "ps"]:
                return done(0, "app:1|c1\ndb:1|c2\n")
            if cmd[:2] == ["docker", "inspect"]:
                return done(0, "sha256:" + cmd[-1] + "\n")
            return done(1, "", "trivy failed")                   # docker run ... trivy
        with open(os.path.join(self.tmp.name, "kev.json"), "w") as f:
            json.dump({"vulnerabilities": []}, f)
        out = io.StringIO()
        with mock.patch.object(scan, "run", side_effect=fake_run), mock.patch.object(scan, "db_age_hours", return_value=1.0), \
                contextlib.redirect_stdout(out):
            rc = scan.main([])
        self.assertNotEqual(rc, 0)
        self.assertIn("2 image(s) not analysed", out.getvalue())

    def test_kev_unreachable_without_cache_is_not_ok(self):
        cfg = dict(config.load(), kev_url="file://" + os.path.join(self.tmp.name, "missing.json"))
        self.assertEqual(scan.load_kev(cfg), (set(), False))

    def test_kev_unreachable_falls_back_to_the_cache_but_says_so(self):
        good = os.path.join(self.tmp.name, "kev-good.json")
        json.dump({"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}, open(good, "w"))
        cfg = dict(config.load(), kev_url="file://" + good)
        self.assertEqual(scan.load_kev(cfg), ({"CVE-2026-0001"}, True))
        cfg["kev_url"] = "file://" + os.path.join(self.tmp.name, "gone.json")
        self.assertEqual(scan.load_kev(cfg), ({"CVE-2026-0001"}, False))

    def test_kev_answer_that_is_not_json_is_not_ok(self):
        bad = os.path.join(self.tmp.name, "kev-bad.json")
        open(bad, "w").write("<html>")
        self.assertFalse(scan.load_kev(dict(config.load(), kev_url="file://" + bad))[1])


if __name__ == "__main__":
    unittest.main()
