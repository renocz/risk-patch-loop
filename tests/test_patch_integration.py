"""`rpl patch` end to end against a fake Docker host (tests/fakes.FakeHost): the happy sequence and the rollback path."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from rpl import config, patch

from .fakes import FakeHost, rpl_config, write_compose, write_compose_text

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
        self.assertEqual(host.kinds(), ["inspect-config", "ps", "inspect", "snapshot", "dump", "dump-copy", "dump-verify", "inspect-config", "validate", "inspect-config",
                                        "dry-run", "ps", "inspect", "up", "ps", "inspect", "ps", "inspect", "route"])

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
        self.assertIn("exactly one", out)
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
        self.assertEqual(host.kinds()[:9], ["inspect-config", "ps", "inspect", "snapshot", "dump", "dump-copy", "dump-verify", "inspect-config", "validate"])

    def test_rollback_that_itself_fails_is_flagged_for_a_human(self):
        host = self.host(unhealthy_images={NEW, OLD})
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 4)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(self.journal()[-1]["result"], "rollback FAILED: CHECK BY HAND")
        self.assertNotIn("rollback ok", json.dumps(self.journal()))


class SecondRoundOfTheFinalCouncilReview(PatchCase):
    """Four real findings of the council's review of the merged code, each with a test that failed first."""

    def test_an_exception_after_the_pin_restores_the_compose_file_and_says_check_by_hand(self):
        host = self.host(raise_on_up=RuntimeError("the host went away"))
        with self.assertRaises(RuntimeError):
            self.run_patch(host)
        self.assertEqual(self.compose_text(), self.original, "the compose file must not stay pinned to an image nobody checked")
        self.assertEqual(self.journal()[-1]["result"], "aborted: CHECK BY HAND")

    def test_an_interruption_after_the_pin_is_handled_the_same_way(self):
        host = self.host(raise_on_up=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.run_patch(host)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(self.journal()[-1]["result"], "aborted: CHECK BY HAND")

    def test_a_service_with_no_running_container_is_refused_before_anything_changes(self):
        host = self.host(stopped=True)
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1, out)
        self.assertIn("REFUSED", out)
        self.assertIn("no running container", out)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(host.up_images, [], "nothing was recreated")
        self.assertNotIn("snapshot", host.kinds(), "refused before the snapshot too")

    def test_a_pin_that_also_changes_another_services_image_is_undone(self):
        """A shared YAML anchor: the line that was edited belongs to the service, but another service resolves to it too."""
        self.compose = write_compose_text(self.dir, f"services:\n  app:\n    image: {OLD}\n  worker:\n    image: {OLD}\n")
        self.original = self.compose_text()
        host = self.host(shared_image_with={"worker"})
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1, out)
        self.assertIn("worker", out)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(host.up_images, [], "never recreated")

    def test_a_status_code_printed_by_a_failed_curl_is_not_an_answer(self):
        host = self.host(curl_rc={NEW: 18})            # curl says 200 but exits "partial transfer"
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 2, out)
        self.assertIn("ROLLBACK", out)
        self.assertEqual(self.journal()[-1]["result"], "rollback ok")


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

    def test_failing_dry_run_stops_the_update(self):
        """Defect 2: the dry run's exit code was ignored, so a dry run that failed (compose error, flag unsupported by an old
        Compose) silently disabled the 'only this service is recreated' safety check and the update went on."""
        host = self.host(dry_rc=1)
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1, out)
        self.assertIn("dry run FAILED", out)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(host.up_images, [])

    def test_two_containers_are_detected_whatever_prefix_compose_prints(self):
        """Defect 2b: container names were taken as the 2nd word of the line, which is 'MODE' when Compose prefixes the line with
        'DRY-RUN MODE -': the set then always had one element and the two-container refusal could never fire."""
        host = self.host(dry_recreates=["app", "app-db-1"], dry_prefix="DRY-RUN MODE -  ")
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1, out)
        self.assertIn("exactly one", out)
        self.assertEqual(host.up_images, [])

    def test_the_planned_container_is_reported_by_name_with_a_prefix(self):
        host = self.host(dry_prefix="DRY-RUN MODE -  ")
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 0, out)
        self.assertIn("dry run would recreate ['app']", out)


# Real output of `docker compose up -d --no-deps --dry-run web` (Docker 29.9.2, Compose v5.6.1), captured on a throwaway
# container; it goes to STDERR, has no "DRY-RUN MODE" prefix, and ends with lines about a temporary container.
REAL_DRY_RUN = (" Container rpltest-web-1 Recreate \n Container rpltest-web-1 Recreated \n"
                " Container 0f8101710b94_rpltest-web-1 Starting \n Container 0f8101710b94_rpltest-web-1 Started \n")


class DryRunMustShowExactlyOneRecreation(PatchCase):
    """Council point 1: only 'more than one' was refused; zero recognised recreations (unreadable output, other Compose format,
    nothing to recreate) passed, and the name was never compared with the service's own container."""

    def assert_refused(self, host, rc, out):
        self.assertEqual(rc, 1, out)
        self.assertIn("exactly one", out)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(host.up_images, [])

    def test_zero_recreations_is_refused(self):
        host = self.host(dry_recreates=[])
        self.assert_refused(host, *self.run_patch(host))

    def test_unintelligible_output_is_refused(self):
        host = self.host(dry_raw="something Compose never printed before")
        self.assert_refused(host, *self.run_patch(host))

    def test_empty_output_is_refused(self):
        host = self.host(dry_raw="")
        self.assert_refused(host, *self.run_patch(host))

    def test_two_containers_are_refused(self):
        host = self.host(dry_recreates=["app", "app-db-1"])
        self.assert_refused(host, *self.run_patch(host))

    def test_one_recreation_of_another_services_container_is_refused(self):
        host = self.host(dry_recreates=["app-db-1"])
        self.assert_refused(host, *self.run_patch(host))

    def test_two_replicas_of_the_service_are_refused(self):
        host = self.host(dry_recreates=["app", "app"], dry_raw=" Container app Recreate\n Container app-2 Recreate\n")
        self.assert_refused(host, *self.run_patch(host))

    def test_the_one_expected_container_passes_with_or_without_prefix(self):
        for prefix in ("", "DRY-RUN MODE -  "):
            with self.subTest(prefix=prefix):
                host = self.host(dry_prefix=prefix)
                rc, out = self.run_patch(host)
                self.assertEqual(rc, 0, out)
                self.setUp()                                   # fresh compose file for the next round

    def test_container_name_that_differs_from_the_service_name_is_matched_by_lookup(self):
        host = self.host(container="proj-app-1")
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 0, out)
        self.assertIn("['proj-app-1']", out)

    def test_name_that_is_only_the_service_name_is_refused_when_the_container_is_called_otherwise(self):
        host = self.host(container="proj-app-1", dry_recreates=["app"])
        self.assert_refused(host, *self.run_patch(host))

    def test_real_compose_output_passes(self):
        host = self.host(container="rpltest-web-1", dry_raw=REAL_DRY_RUN)
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 0, out)
        self.assertIn("['rpltest-web-1']", out)

    def test_no_container_exists_for_the_service_is_refused(self):
        host = self.host(dry_recreates=["app"])
        host.running = None                                    # `ps -a -q` finds nothing
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 1, out)
        self.assertIn("no running container", out, "refused before any change, since the rollback could not be verified")
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(host.up_images, [])


class RollbackAndSuccessAreVerifiedByImage(PatchCase):
    """Council point 3: the rollback's own `compose up` exit code was ignored and the check was only health + route, so a failed
    rollback that left the NEW image running, healthy and answering was journaled 'rollback ok'; likewise a 'successful' update
    was never checked to be running the new image."""

    def flapping_route(self):
        return {NEW: ["502"] * 8 + ["200"]}                     # fails during the update's check window, answers 200 afterwards

    def test_failed_rollback_up_with_the_new_image_still_healthy_and_answering_is_not_rollback_ok(self):
        host = self.host(route_codes=self.flapping_route(), up_fails_for={OLD})
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 4, out)
        self.assertIn("CHECK BY HAND", out)
        self.assertEqual(self.journal()[-1]["result"], "rollback FAILED: CHECK BY HAND")
        self.assertEqual(host.running, NEW, "the scenario: the new image really is still the one running")

    def test_rollback_that_restores_the_old_image_is_ok_and_says_which_image_runs(self):
        host = self.host(unhealthy_images={NEW})
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 2, out)
        self.assertEqual(self.journal()[-1]["result"], "rollback ok")
        self.assertIn(OLD, out.splitlines()[-1])

    def test_rollback_to_the_same_ref_but_a_different_image_id_is_not_ok(self):
        host = self.host(unhealthy_images={NEW}, rebuilt_on_up={OLD: "sha256:somethingelse"})
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 4, out)
        self.assertEqual(self.journal()[-1]["result"], "rollback FAILED: CHECK BY HAND")

    def test_update_that_leaves_the_old_image_running_is_not_ok(self):
        host = self.host(up_noop_for={NEW})
        rc, out = self.run_patch(host)
        self.assertNotEqual(out.strip().splitlines()[-1], "OK")
        self.assertEqual(rc, 2, out)
        self.assertIn(f"runs {OLD}, not {NEW}", out)
        self.assertNotIn("ok", [e["result"] for e in self.journal()])
        self.assertEqual(self.compose_text(), self.original)

    def test_successful_update_is_checked_against_the_new_image_only(self):
        host = self.host()
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"image {NEW}", out)


class PinIsBoundToTheService(PatchCase):
    """Council point 2: the pin replaced the one `image:` line equal to --old anywhere in the file, never checking it belonged to
    --service, and service_defined only checked that the service exists."""

    X, Y = "registry.example.test/app:1", "registry.example.test/other:1"

    def go(self, text, service="app", old=None, **host_kw):
        self.compose = write_compose_text(self.dir, text)
        self.original = self.compose_text()
        host = self.host(service=service, **host_kw)
        rc, out = self.run_patch(host, db=False, service=service, old=old or self.X)
        return host, rc, out

    def run_patch(self, host, *extra, db=True, service="app", new=NEW, old=OLD):
        argv = ["--compose", self.compose, "--service", service, "--old", old, "--new", new, "--route", "app.example.test", "--codes", "200 302"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = patch.main(argv + list(extra), host)
        return rc, out.getvalue()

    def test_two_services_with_the_same_image_only_the_requested_one_changes(self):
        host, rc, out = self.go(f"services:\n  app:\n    image: {self.X}\n  worker:\n    image: {self.X}\n")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.compose_text(), f"services:\n  app:\n    image: {NEW}\n  worker:\n    image: {self.X}\n")

    def test_old_image_that_belongs_to_another_service_is_refused(self):
        host, rc, out = self.go(f"services:\n  app:\n    image: {self.X}\n  worker:\n    image: {self.Y}\n", old=self.Y)
        self.assertEqual(rc, 1, out)
        self.assertIn("uses image", out)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(host.up_images, [])

    def test_resolved_image_equal_but_literal_line_in_another_service_is_refused(self):
        text = f"services:\n  app:\n    image: ${{APP_IMAGE:-{self.X}}}\n  worker:\n    image: {self.X}\n"
        host, rc, out = self.go(text)
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.compose_text(), self.original, "the other service's line must not be edited")
        self.assertEqual(host.up_images, [])

    def test_image_given_through_a_variable_is_refused_not_guessed(self):
        host, rc, out = self.go(f"services:\n  app:\n    image: ${{APP_IMAGE:-{self.X}}}\n")
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.compose_text(), self.original)

    def test_service_built_locally_has_no_image_to_pin(self):
        host, rc, out = self.go("services:\n  app:\n    build: .\n")
        self.assertEqual(rc, 1, out)
        self.assertIn("build", out)
        self.assertEqual(self.compose_text(), self.original)

    def test_service_with_both_build_and_image_is_refused(self):
        host, rc, out = self.go(f"services:\n  app:\n    build: .\n    image: {self.X}\n")
        self.assertEqual(rc, 1, out)
        self.assertIn("build", out)

    def test_an_image_line_outside_services_is_not_a_candidate(self):
        text = f"x-defaults:\n  image: {self.X}\nservices:\n  app:\n    image: {self.X}\n"
        host, rc, out = self.go(text)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.compose_text(), text.replace(f"  app:\n    image: {self.X}", f"  app:\n    image: {NEW}"))

    def test_comments_blank_lines_and_quoted_keys_inside_blocks(self):
        text = f'services:\n  # first\n  "app":\n\n    # the image\n    image: {self.X}  # pinned\n  worker:\n    image: {self.Y}\n'
        host, rc, out = self.go(text)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"image: {NEW}  # pinned", self.compose_text())
        self.assertIn(f"image: {self.Y}", self.compose_text())

    def test_pin_function_alone_refuses_a_line_outside_the_service_block(self):
        f = write_compose_text(self.dir, f"services:\n  app:\n    restart: always\n  worker:\n    image: {self.X}\n")
        ok, msg, _ = patch.pin(f, self.X, NEW, apply=True, host=self.host(), service="app")
        self.assertFalse(ok)
        self.assertNotIn(NEW, open(f).read())


class InputValidation(PatchCase):
    """Defect 3: nothing checked the names handed to `docker` / `compose`. They come from files the owner maintains, so the risk is
    low, but a value with a space or a newline was passed through, a name could be given as '--service=--privileged' (argparse only
    blocks the two-word form), and a value with a newline became extra lines of the compose file."""

    BASE = ["--route", "r.example.test", "--codes", "200"]

    def go(self, host, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = patch.main(argv, host)
            except SystemExit as e:                      # argparse's own refusal
                rc = e.code
        return rc, out.getvalue()

    def argv(self, **over):
        v = {"--compose": self.compose, "--service": "app", "--old": OLD, "--new": NEW, "--db-container": "app-db-1", "--db-user": "app", "--db-name": "app"}
        v.update(over)
        return [x for k, val in v.items() if val is not None for x in (k, val)] + self.BASE

    def assert_refused(self, host, rc, out):
        self.assertNotEqual(rc, 0, out)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual(host.up_images, [])
        self.assertNotIn("snapshot", host.kinds())

    def test_invalid_service_names_are_refused(self):
        for bad in ("--privileged", "-d", "app; reboot", "app name", "../app", "", "app\n"):
            with self.subTest(service=bad):
                host = self.host()
                self.assert_refused(host, *self.go(host, self.argv(**{"--service": bad})))

    def test_invalid_database_names_are_refused(self):
        for flag in ("--db-container", "--db-user", "--db-name"):
            for bad in ("--help", "x y", "a;b", "n\nm"):
                with self.subTest(flag=flag, value=bad):
                    host = self.host()
                    self.assert_refused(host, *self.go(host, self.argv(**{flag: bad})))

    def test_equals_form_cannot_smuggle_an_option(self):
        host = self.host()
        argv = ["--compose", self.compose, "--service=--privileged", "--old", OLD, "--new", NEW] + self.BASE
        rc, out = self.go(host, argv)
        self.assert_refused(host, rc, out)
        self.assertIn("REFUSED", out)

    def test_database_options_go_together(self):
        host = self.host()
        rc, out = self.go(host, self.argv(**{"--db-user": None, "--db-name": None}))
        self.assert_refused(host, rc, out)
        self.assertIn("REFUSED", out)

    def test_image_reference_with_a_newline_cannot_inject_compose_lines(self):
        host = self.host()
        rc, out = self.go(host, self.argv(**{"--new": NEW + "\n    privileged: true"}))
        self.assert_refused(host, rc, out)
        self.assertIn("REFUSED", out)

    def test_service_missing_from_the_compose_file_is_refused(self):
        host = self.host()
        rc, out = self.go(host, self.argv(**{"--service": "typo"}))
        self.assertEqual(rc, 1, out)
        self.assertIn("not defined", out)
        self.assertEqual(host.kinds(), ["inspect-config"])
        self.assertEqual(self.compose_text(), self.original)

    def test_valid_names_with_dots_dashes_and_underscores_still_work(self):
        self.compose = write_compose(self.dir, OLD, service="my_app-2.web")
        host = self.host(service="my_app-2.web")
        rc, out = self.go(host, self.argv(**{"--service": "my_app-2.web", "--compose": self.compose, "--db-container": None, "--db-user": None, "--db-name": None}))
        self.assertEqual(rc, 0, out)


class RouteAndCodesAreValidated(PatchCase):
    """Council point 4: --route goes into a curl 'Host:' header and --codes is compared with curl's answer; neither was validated.
    (Found on the way: the earlier name checks used re.match with '$', which accepts a trailing newline.)"""

    BASE, go, argv, assert_refused = InputValidation.BASE, InputValidation.go, InputValidation.argv, InputValidation.assert_refused

    def test_invalid_routes_are_refused(self):
        for bad in ("app.example.test\nX-Evil: 1", "app example.test", "a;b", "", "-bad.example.test", "app.example.test:abc",
                    "app..example.test", "app.example.test\n", "app.example.test:", "http://app.example.test", "app.example.test/path", "a" * 64 + ".example.test"):
            with self.subTest(route=repr(bad)):
                host = self.host()
                argv = self.argv()
                argv[argv.index("--route") + 1] = bad
                rc, out = self.go(host, argv)
                self.assert_refused(host, rc, out)
                if rc != 2:
                    self.assertIn("--route", out)

    def test_invalid_codes_are_refused(self):
        for bad in ("", " ", "200\n302", "2000", "20", "abc", "200;302", "200,302", "200 \n", "99 200", "600", "200\t302"):
            with self.subTest(codes=repr(bad)):
                host = self.host()
                argv = self.argv()
                argv[argv.index("--codes") + 1] = bad
                rc, out = self.go(host, argv)
                self.assert_refused(host, rc, out)
                if rc != 2:
                    self.assertIn("--codes", out)

    def test_valid_routes_and_codes_pass(self):
        for route in ("app.example.test", "app.example.test:8443", "localhost", "app-1.example.test", "A.Example.test"):
            for codes in ("200", "200 302", "401", "200  302"):
                with self.subTest(route=route, codes=codes):
                    host = self.host()
                    argv = self.argv(**{"--db-container": None, "--db-user": None, "--db-name": None})
                    argv[argv.index("--route") + 1] = route
                    argv[argv.index("--codes") + 1] = codes
                    self.assertEqual(self.go(host, argv + ["--dry"])[0], 0)

    def test_trailing_newline_is_refused_in_names_and_references(self):
        for flag in ("--service", "--db-container", "--db-user", "--db-name", "--new"):
            with self.subTest(flag=flag):
                host = self.host()
                value = (NEW if flag == "--new" else "app") + "\n"
                rc, out = self.go(host, self.argv(**{flag: value}))
                self.assert_refused(host, rc, out)
                self.assertIn("REFUSED: " + flag, out, "refused for the right reason, not as a side effect")


if __name__ == "__main__":
    unittest.main()
