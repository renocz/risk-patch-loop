"""`rpl patch` end to end against a fake Docker host (tests/fakes.FakeHost): the happy sequence and the rollback path."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from rpl import config, patch

from .fakes import FakeHost, rpl_config, write_compose

OLD, NEW = "registry.example.test/app:1", "registry.example.test/app:2"


class PatchCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.compose = write_compose(self.dir, OLD)
        self.original = open(self.compose, encoding="utf-8").read()
        self.use_config()
        # Safety net: any code path that bypasses the injected host and spawns a real process fails the test.
        guard = mock.patch("subprocess.run", side_effect=AssertionError("a real subprocess was started"))
        guard.start()
        self.addCleanup(guard.stop)

    def use_config(self, **overrides):
        env = mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.dir, **overrides)})
        env.start()
        self.addCleanup(env.stop)

    def host(self, **kw):
        return FakeHost(self.compose, **kw)

    def run_patch(self, host, *extra, db=True, service="app", new=NEW):
        argv = ["--compose", self.compose, "--service", service, "--old", OLD, "--new", new, "--route", "app.example.test", "--codes", "200 302"]
        if db:
            argv += ["--db-container", "app-db-1", "--db-user", "app", "--db-name", "app"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = patch.main(argv + list(extra), host)
        return rc, out.getvalue()

    def compose_text(self):
        with open(self.compose, encoding="utf-8") as f:
            return f.read()

    def journal(self):
        with open(os.path.join(config.load()["state_dir"], "patches.json")) as f:
            return json.load(f)


class SuccessfulUpdate(PatchCase):
    def test_sequence_snapshot_dump_pin_dry_run_recreate_check(self):
        host = self.host()
        rc, out = self.run_patch(host)
        self.assertEqual((rc, out.strip().splitlines()[-1]), (0, "OK"), out)
        self.assertEqual(host.kinds(), ["inspect-config", "snapshot", "dump", "dump-copy", "dump-verify", "validate", "dry-run", "up", "ps", "inspect", "route"])

    def test_new_image_is_pinned_and_running_and_the_old_file_is_kept(self):
        host = self.host()
        self.run_patch(host)
        self.assertIn(f"image: {NEW}", self.compose_text())
        self.assertEqual((host.running, host.up_images), (NEW, [NEW]))
        backups = [f for f in os.listdir(self.dir) if ".bak-" in f]
        self.assertEqual(len(backups), 1)
        self.assertEqual(open(os.path.join(self.dir, backups[0]), encoding="utf-8").read(), self.original)

    def test_the_other_lines_of_the_compose_file_are_untouched(self):
        self.run_patch(self.host())
        self.assertEqual(self.compose_text(), self.original.replace(OLD, NEW))

    def test_database_dump_lands_in_the_backup_dir(self):
        self.run_patch(self.host())
        dumps = [os.path.join(r, f) for r, _, fs in os.walk(os.path.join(self.dir, "backups")) for f in fs]
        self.assertEqual(len(dumps), 1)
        self.assertTrue(dumps[0].endswith(".dump"))

    def test_without_a_database_there_is_no_dump_step(self):
        host = self.host()
        rc, _ = self.run_patch(host, db=False)
        self.assertEqual(rc, 0)
        self.assertNotIn("dump", host.kinds())

    def test_the_update_is_journaled(self):
        self.run_patch(self.host())
        j = self.journal()
        self.assertEqual([(e["service"], e["from"], e["to"], e["result"]) for e in j], [("app", OLD, NEW, "ok")])

    def test_dry_flag_changes_nothing_and_runs_no_docker_command_but_the_vpn_check(self):
        host = self.host()
        rc, out = self.run_patch(host, "--dry")
        self.assertEqual(rc, 0)
        self.assertEqual(host.kinds(), ["inspect-config"])
        self.assertEqual(self.compose_text(), self.original)

    def test_no_snapshot_command_is_refused_unless_said_out_loud(self):
        self.use_config(snapshot_command=None)
        host = self.host()
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1)
        self.assertIn("REFUSED", out)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(host.up_images, [])
        rc, _ = self.run_patch(self.host(), "--no-snapshot")
        self.assertEqual(rc, 0)


class StoppedBeforeAnyChange(PatchCase):
    def assert_untouched(self, host):
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(host.up_images, [])
        self.assertNotIn("up", host.kinds())

    def test_failed_snapshot(self):
        host = self.host(snapshot_rc=1)
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1)
        self.assertIn("snapshot FAILED", out)
        self.assert_untouched(host)
        self.assertNotIn("validate", host.kinds())

    def test_failed_database_dump(self):
        host = self.host(dump_ok=False)
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1)
        self.assertIn("database dump FAILED", out)
        self.assert_untouched(host)

    def test_unknown_image_reference(self):
        host = self.host()
        argv_old = ["--compose", self.compose, "--service", "app", "--old", "registry.example.test/other:1", "--new", NEW,
                    "--route", "r.example.test", "--codes", "200"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(patch.main(argv_old, host), 1)
        self.assert_untouched(host)

    def test_compose_rejects_the_pinned_file_and_the_old_file_comes_back(self):
        host = self.host(config_rejects={NEW})
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1)
        self.assertIn("old file restored", out)
        self.assert_untouched(host)

    def test_dry_run_that_would_recreate_two_containers_is_refused(self):
        host = self.host(dry_recreates=["app", "app-db-1"])
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1)
        self.assertIn("more than one container", out)
        self.assert_untouched(host)


class AutomaticRollback(PatchCase):
    """The path that has never fired in production: proved here by deterministic failures of the fake host."""

    def assert_rolled_back(self, host, rc, out):
        self.assertEqual(rc, 2, out)
        self.assertIn("ROLLBACK", out)
        self.assertEqual(self.compose_text(), self.original, "compose file must be byte-identical to the original")
        self.assertIn(f"image: {OLD}", self.compose_text())
        self.assertEqual(host.running, OLD, "the old image must be the one running")
        self.assertEqual(host.up_images, [NEW, OLD], "recreate with the new image, then again with the old one")

    def test_container_never_becomes_healthy(self):
        host = self.host(unhealthy_images={NEW})
        rc, out = self.run_patch(host)
        self.assert_rolled_back(host, rc, out)
        self.assertIn("after rollback: container healthy; route HTTP 200", out)
        self.assertEqual(self.journal()[-1]["result"], "rollback ok")

    def test_route_answers_with_an_unexpected_status(self):
        host = self.host(route_codes={NEW: "502"})
        rc, out = self.run_patch(host)
        self.assert_rolled_back(host, rc, out)
        self.assertIn("HTTP 502", out)
        self.assertEqual(self.journal()[-1]["result"], "rollback ok")

    def test_the_wait_is_bounded_by_the_configured_timeout(self):
        host = self.host(unhealthy_images={NEW})
        start = host.now()
        self.run_patch(host)
        self.assertLessEqual(host.now() - start, 30 + 5, "one health wait of at most health_timeout_s (30 s here), then an instant rollback check")

    def test_snapshot_and_dump_happen_before_the_failed_update(self):
        host = self.host(unhealthy_images={NEW})
        self.run_patch(host)
        self.assertEqual(host.kinds()[:6], ["inspect-config", "snapshot", "dump", "dump-copy", "dump-verify", "validate"])

    def test_rollback_that_itself_fails_is_flagged_for_a_human(self):
        host = self.host(unhealthy_images={NEW, OLD})
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 2)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(self.journal()[-1]["result"], "rollback CHECK BY HAND")
        self.assertNotIn("rollback ok", json.dumps(self.journal()))


class DefectRegressions(PatchCase):
    def test_compose_up_failing_is_not_reported_as_success(self):
        """Defect 1: `docker compose up` exits non-zero (e.g. the new image cannot be pulled) and leaves the OLD container running.
        The old container is healthy and its route answers, so the check used to pass: 'OK' while the update never happened
        and the compose file pinned an image that is not running."""
        host = self.host(up_fails_for={NEW})
        rc, out = self.run_patch(host)
        self.assertNotEqual(rc, 0, out)
        self.assertNotEqual(out.strip().splitlines()[-1], "OK")
        self.assertIn("docker compose up failed", out)
        self.assertEqual(self.compose_text(), self.original, "the compose file must not stay pinned to an image that is not running")
        self.assertEqual(host.running, OLD)
        self.assertNotIn("ok", [e["result"] for e in self.journal()], "a failed update must not be journaled as ok")


if __name__ == "__main__":
    unittest.main()
