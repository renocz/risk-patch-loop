"""The pause switch and the shared lock (rpl/gate.py), and their use by every command that applies something.

The lock tests use a real lock file in a temporary directory and, for two of them, a real second Python process: a lock that is only
exercised inside one process proves little. No Docker, no network.
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from rpl import __main__ as cli
from rpl import config, gate, patch, proposals

from .fakes import FakeHost, done, rpl_config, write_compose
from .test_patch_integration import NEW, OLD, PatchCase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROPOSAL = {"id": "app", "service": "app", "compose": "/srv/app/compose.yaml", "from": OLD, "to": NEW, "why": "newer version", "score": 60.0,
            "act_rows": 1, "kev": True, "level": "internet-no-auth", "route": "app.example.test", "codes": "200 302", "db": None}
# a second runner: takes the lock, says so, then holds it until it is killed
HOLDER = ("import sys, time\nfrom rpl import gate\n"
          "with gate.applying({'state_dir': sys.argv[1]}, 'other runner'):\n"
          "    print('held', flush=True)\n    time.sleep(60)\n")


def captured(fn, *a, **kw):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = fn(*a, **kw)
    return rc, out.getvalue()


class GateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = {"state_dir": os.path.join(self.tmp.name, "state")}
        self.pause_file = os.path.join(self.cfg["state_dir"], gate.PAUSE_FILE)
        self.lock_file = os.path.join(self.cfg["state_dir"], gate.LOCK_FILE)

    def touch_pause(self):
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        open(self.pause_file, "w").close()

    def assert_free(self):
        with gate.applying(self.cfg, "check"):
            pass


class PauseSwitch(GateCase):
    def test_not_paused_by_default(self):
        self.assertIsNone(gate.paused(self.cfg))

    def test_pause_on_is_seen_with_its_reason_and_off_clears_it(self):
        gate.pause_on(self.cfg, "kernel upgrade tonight", now=1_800_000_000)
        self.assertIn("kernel upgrade tonight", gate.paused(self.cfg))
        self.assertTrue(gate.pause_off(self.cfg))
        self.assertIsNone(gate.paused(self.cfg))

    def test_an_empty_file_created_by_hand_pauses(self):
        self.touch_pause()
        self.assertIsNotNone(gate.paused(self.cfg))

    def test_anything_at_that_path_pauses_whatever_it_contains(self):
        os.makedirs(self.cfg["state_dir"])
        for make in (lambda: os.mkdir(self.pause_file), lambda: os.symlink("/nonexistent/target", self.pause_file),
                     lambda: open(self.pause_file, "wb").write(b"\xff\x00 not json")):
            with self.subTest(make=make):
                make()
                self.assertIsNotNone(gate.paused(self.cfg))
                os.rmdir(self.pause_file) if os.path.isdir(self.pause_file) and not os.path.islink(self.pause_file) else os.unlink(self.pause_file)

    def test_when_the_switch_cannot_be_read_the_answer_is_paused(self):
        with mock.patch("os.lstat", side_effect=PermissionError(13, "Permission denied")):
            reason = gate.paused(self.cfg)
        self.assertIn("cannot tell", reason)

    def test_when_the_state_directory_cannot_be_created_the_answer_is_paused(self):
        blocker = os.path.join(self.tmp.name, "a-file")
        open(blocker, "w").close()
        self.assertIn("cannot tell", gate.paused({"state_dir": os.path.join(blocker, "state")}))

    def test_pause_off_when_not_paused_is_not_an_error(self):
        self.assertFalse(gate.pause_off(self.cfg))

    def test_control_characters_of_a_reason_are_not_shown(self):
        gate.pause_on(self.cfg, "stop\x1b[2J\nnow")
        shown = gate.paused(self.cfg)
        self.assertNotIn("\x1b", shown)
        self.assertNotIn("\n", shown)

    def test_a_paused_runner_is_refused_and_the_lock_is_not_even_taken(self):
        gate.pause_on(self.cfg, "maintenance")
        with self.assertRaises(gate.NotNow) as e:
            with gate.applying(self.cfg, "patch app-1"):
                self.fail("the body must not run while paused")
        self.assertIn("maintenance", str(e.exception))
        self.assertFalse(os.path.exists(self.lock_file))

    def test_a_pause_set_while_waiting_for_the_lock_is_seen_under_the_lock(self):
        real = gate.fcntl.flock

        def pause_then_lock(fd, op):
            if op & gate.fcntl.LOCK_EX:
                self.touch_pause()
            return real(fd, op)

        with mock.patch.object(gate.fcntl, "flock", side_effect=pause_then_lock):
            with self.assertRaises(gate.NotNow):
                with gate.applying(self.cfg, "patch app-1"):
                    self.fail("paused: the body must not run")
        os.unlink(self.pause_file)
        self.assert_free()                               # and the lock was given back


class SharedLock(GateCase):
    def test_a_second_runner_is_refused_while_the_first_holds_the_lock(self):
        with gate.applying(self.cfg, "patch app-1"):
            with self.assertRaises(gate.NotNow) as e:
                with gate.applying(self.cfg, "patch app-2"):
                    self.fail("two runners inside the lock")
        self.assertIn("patch app-1", str(e.exception))
        self.assertIn(f"pid {os.getpid()}", str(e.exception))

    def test_the_lock_is_free_again_after_the_block(self):
        with gate.applying(self.cfg, "one"):
            pass
        self.assert_free()

    def test_the_lock_is_free_again_after_an_exception_or_an_interruption(self):
        for error in (RuntimeError("boom"), KeyboardInterrupt()):
            with self.subTest(error=error):
                with self.assertRaises(type(error)):
                    with gate.applying(self.cfg, "one"):
                        raise error
                self.assert_free()

    def test_the_lock_file_stays_and_only_its_owner_can_read_it(self):
        with gate.applying(self.cfg, "one"):
            pass
        self.assertEqual(os.stat(self.lock_file).st_mode & 0o777, 0o600)

    def test_the_holder_is_written_in_the_lock_file(self):
        with gate.applying(self.cfg, "patch app-1"):
            with open(self.lock_file, encoding="utf-8") as f:
                holder = json.load(f)
        self.assertEqual((holder["pid"], holder["what"]), (os.getpid(), "patch app-1"))

    def test_an_unreadable_holder_does_not_turn_a_refusal_into_a_crash(self):
        with gate.applying(self.cfg, "one"):
            with open(self.lock_file, "w") as f:
                f.write("{ torn")
            with self.assertRaises(gate.NotNow) as e:
                with gate.applying(self.cfg, "two"):
                    pass
        self.assertIn("holder unknown", str(e.exception))

    def holder_process(self):
        p = subprocess.Popen([sys.executable, "-c", HOLDER, self.cfg["state_dir"]], cwd=ROOT, stdout=subprocess.PIPE, text=True)
        self.addCleanup(p.wait)
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.kill)
        self.assertEqual(p.stdout.readline().strip(), "held")
        return p

    def test_another_process_holding_the_lock_refuses_this_one(self):
        p = self.holder_process()
        with self.assertRaises(gate.NotNow) as e:
            with gate.applying(self.cfg, "patch app-1"):
                self.fail("two processes inside the lock")
        self.assertIn(f"pid {p.pid}", str(e.exception))
        self.assertIn("other runner", str(e.exception))

    def test_a_killed_holder_leaves_no_stale_lock(self):
        p = self.holder_process()
        p.kill()                                         # SIGKILL: no cleanup code runs in the holder
        p.wait()
        self.assert_free()

    def test_a_child_process_started_under_the_lock_does_not_keep_it(self):
        with gate.applying(self.cfg, "one"):
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        self.assertIsNone(child.poll(), "the child must still be alive for this test to mean something")
        self.assert_free()

    def test_without_file_locking_on_this_platform_nothing_is_applied(self):
        with mock.patch.object(gate, "fcntl", None):
            with self.assertRaises(gate.NotNow) as e:
                with gate.applying(self.cfg, "one"):
                    self.fail("no lock, no apply")
        self.assertIn("cannot", str(e.exception))

    def test_a_lock_file_that_cannot_be_opened_refuses(self):
        os.makedirs(self.cfg["state_dir"])
        os.mkdir(self.lock_file)                         # a directory where the lock file should be
        with self.assertRaises(gate.NotNow) as e:
            with gate.applying(self.cfg, "one"):
                self.fail("no lock, no apply")
        self.assertIn("cannot", str(e.exception))

    def test_a_lock_file_replaced_while_locking_is_not_trusted(self):
        real = gate.fcntl.flock

        def replace_then_lock(fd, op):
            if op & gate.fcntl.LOCK_EX:
                os.unlink(self.lock_file)
                open(self.lock_file, "w").close()        # another inode: a second runner would lock THAT one
            return real(fd, op)

        with mock.patch.object(gate.fcntl, "flock", side_effect=replace_then_lock):
            with self.assertRaises(gate.NotNow) as e:
                with gate.applying(self.cfg, "one"):
                    self.fail("the lock held is not the lock file on disk")
        self.assertIn("replaced", str(e.exception))


class PauseCommand(GateCase):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.tmp.name)})
        env.start()
        self.addCleanup(env.stop)

    def test_pause_is_a_command_of_rpl(self):
        self.assertEqual(cli.COMMANDS.get("pause"), "gate")

    def test_status_exit_code_says_whether_applying_is_allowed(self):
        self.assertEqual(captured(gate.main, ["status"])[0], 0)
        rc, out = captured(gate.main, ["on", "--reason", "disk almost full"])
        self.assertEqual(rc, 0)
        rc, out = captured(gate.main, ["status"])
        self.assertEqual(rc, 1)
        self.assertIn("PAUSED", out)
        self.assertIn("disk almost full", out)
        self.assertEqual(captured(gate.main, ["off"])[0], 0)
        self.assertEqual(captured(gate.main, ["status"])[0], 0)

    def test_on_needs_no_reason(self):
        self.assertEqual(captured(gate.main, ["on"])[0], 0)
        self.assertEqual(captured(gate.main, ["status"])[0], 1)

    def test_off_fails_loudly_when_the_switch_cannot_be_removed(self):
        captured(gate.main, ["on"])
        with mock.patch("os.unlink", side_effect=PermissionError(13, "Permission denied")):
            rc, out = captured(gate.main, ["off"])
        self.assertEqual(rc, 1)
        self.assertIn("STILL PAUSED", out)


class PatchBehindTheGate(PatchCase):
    """`rpl patch` checks the switch and takes the lock before it runs a single command."""

    def cfg(self):
        return config.load()

    def assert_untouched(self, host):
        self.assertEqual(host.calls, [], "no command may run")
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual([f for f in os.listdir(self.dir) if ".bak-" in f], [])

    def assert_free(self):
        with gate.applying(self.cfg(), "check"):
            pass

    def test_paused_nothing_runs_and_the_exit_code_says_not_now(self):
        gate.pause_on(self.cfg(), "owner is away")
        host = self.host()
        rc, out = self.run_patch(host)
        self.assertEqual(rc, gate.EXIT_NOT_NOW)
        self.assertEqual(rc, 5)
        self.assertIn("NOT NOW: paused", out)
        self.assertIn("owner is away", out)
        self.assert_untouched(host)

    def test_paused_a_dry_run_still_works_and_says_so(self):
        gate.pause_on(self.cfg(), "owner is away")
        rc, out = self.run_patch(self.host(), "--dry")
        self.assertEqual(rc, 0)
        self.assertIn("paused", out)
        self.assertEqual(self.compose_text(), self.original)

    def test_another_runner_holds_the_lock_nothing_runs(self):
        host = self.host()
        with gate.applying(self.cfg(), "group vpn-1"):
            rc, out = self.run_patch(host)
        self.assertEqual(rc, 5)
        self.assertIn("NOT NOW", out)
        self.assertIn("group vpn-1", out)
        self.assert_untouched(host)

    def test_a_dry_run_does_not_take_the_lock(self):
        with gate.applying(self.cfg(), "another"):
            self.assertEqual(self.run_patch(self.host(), "--dry")[0], 0)

    def test_the_lock_is_held_while_the_service_is_updated(self):
        seen = []

        class Watching(FakeHost):
            def run(inner, cmd, **kw):
                try:
                    with gate.applying(self.cfg(), "intruder"):
                        seen.append("free")
                except gate.NotNow:
                    seen.append("held")
                return FakeHost.run(inner, cmd, **kw)

        rc, _ = self.run_patch(Watching(self.compose))
        self.assertEqual(rc, 0)
        self.assertTrue(seen)
        self.assertEqual(set(seen), {"held"}, "every command of the sequence, the group check included, runs under the lock")

    def test_two_updates_at_once_the_second_is_refused_and_touches_nothing(self):
        other_dir = tempfile.TemporaryDirectory()
        self.addCleanup(other_dir.cleanup)
        other_compose = write_compose(other_dir.name, OLD)
        second = FakeHost(other_compose)
        result = {}

        class First(FakeHost):
            def _dispatch(inner, c):
                if inner._kind(c) == "up" and not result:
                    argv = ["--compose", other_compose, "--service", "app", "--old", OLD, "--new", NEW, "--route", "app.example.test",
                            "--codes", "200", "--no-snapshot"]
                    result["rc"], result["out"] = captured(patch.main, argv, second)
                return FakeHost._dispatch(inner, c)

        rc, _ = self.run_patch(First(self.compose))
        self.assertEqual((rc, result["rc"]), (0, 5))
        self.assertEqual(second.calls, [])
        self.assertIn(f"image: {OLD}", open(other_compose, encoding="utf-8").read())

    def test_the_lock_is_free_after_every_way_out(self):
        cases = {"updated": (self.host, {}, 0),
                 "rolled back": (self.host, {"unhealthy_images": [NEW]}, 2),
                 "rollback failed": (self.host, {"unhealthy_images": [NEW, OLD]}, 4),
                 "refused (group)": (self.host, {"network_mode": "service:vpn-1"}, 3)}
        for name, (make, kw, expected) in cases.items():
            with self.subTest(name=name):
                with open(self.compose, "w", encoding="utf-8") as f:
                    f.write(self.original)
                self.assertEqual(self.run_patch(make(**kw))[0], expected)
                self.assert_free()

    def test_the_lock_is_free_after_an_interruption(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_patch(self.host(raise_on_up=KeyboardInterrupt()))
        self.assert_free()

    def test_a_pause_set_during_an_update_does_not_stop_its_rollback(self):
        class PausedMidway(FakeHost):
            def _dispatch(inner, c):
                if inner._kind(c) == "up":
                    gate.pause_on(self.cfg(), "set while the update runs")
                return FakeHost._dispatch(inner, c)

        host = PausedMidway(self.compose, unhealthy_images=[NEW])
        rc, out = self.run_patch(host)
        self.assertEqual(rc, 2, out)
        self.assertEqual((host.running, self.compose_text()), (OLD, self.original))
        self.assertEqual(self.run_patch(self.host())[0], 5, "the next run is refused")


class ProposalsBehindTheGate(unittest.TestCase):
    """`rpl proposals --apply` starts `rpl patch`, which holds the lock itself; the switch is also checked before starting it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.tmp.name)})
        env.start()
        self.addCleanup(env.stop)
        self.cfg = config.load()
        proposals.save(config.state(self.cfg, "proposals.json"), [PROPOSAL], [], ts=time.time())
        run = mock.patch("subprocess.run", return_value=done(0))
        self.run_mock = run.start()
        self.addCleanup(run.stop)

    def test_paused_apply_starts_nothing(self):
        gate.pause_on(self.cfg, "owner is away")
        rc, out = captured(proposals.main, ["--apply", "app"])
        self.assertEqual(rc, 5)
        self.assertIn("owner is away", out)
        self.run_mock.assert_not_called()

    def test_paused_a_dry_apply_and_a_list_still_work(self):
        gate.pause_on(self.cfg, "owner is away")
        self.assertEqual(captured(proposals.main, ["--list"])[0], 0)
        self.assertEqual(captured(proposals.main, ["--apply", "app", "--dry"])[0], 0)
        self.run_mock.assert_called_once()

    def test_apply_does_not_take_the_lock_itself_or_patch_could_never_get_it(self):
        def patch_takes_the_lock(cmd, **kw):
            with gate.applying(self.cfg, "patch app"):
                return done(0)

        self.run_mock.side_effect = patch_takes_the_lock
        self.assertEqual(captured(proposals.main, ["--apply", "app"])[0], 0)

    def test_the_not_now_exit_code_of_patch_is_passed_on(self):
        self.run_mock.return_value = done(5)
        self.assertEqual(captured(proposals.main, ["--apply", "app"])[0], 5)


if __name__ == "__main__":
    unittest.main()
