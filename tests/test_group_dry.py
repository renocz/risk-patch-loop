"""Closed-list controls and `rpl group --dry`, with a scripted host (no Docker, no network)."""
import contextlib
import io
import json
import os
import tempfile
import types
import unittest
from unittest import mock

from rpl import controls, group

from .fakes import done, rpl_config, write_compose_text

COMPOSE = ("services:\n  tunnel-1:\n    image: registry.example.test/tunnel:1\n  dl-1:\n    image: registry.example.test/dl:1\n"
           "  idx-1:\n    image: registry.example.test/idx:1\n  web-1:\n    image: registry.example.test/web:1\n")
MODES = {"dl-1": "service:tunnel-1", "idx-1": "service:tunnel-1"}


class ScriptedHost:
    """ips: container -> address seen from inside it ('host' for the machine itself); None makes the read fail."""

    def __init__(self, ips=None, health="healthy", recreate=("tunnel-1", "dl-1", "idx-1"), up_rc=0):
        self.ips = {"host": "203.0.113.1", "tunnel-1": "198.51.100.7", "dl-1": "198.51.100.7", "idx-1": "198.51.100.7"}
        self.ips.update(ips or {})
        self.health, self.recreate, self.up_rc, self.calls = health, recreate, up_rc, []

    def now(self):
        return 0.0

    def sleep(self, s):
        pass

    def run(self, cmd, **kw):
        self.calls.append(list(cmd))
        if cmd[0] == "curl":
            return self._ip("host")
        if cmd[:2] == ["docker", "run"]:
            return self._ip(cmd[cmd.index("--network") + 1].split(":", 1)[1])
        if cmd[:2] == ["docker", "inspect"]:
            name = cmd[2]
            return done(0, json.dumps([{"Name": "/" + name, "State": {"Running": True, "Health": {"Status": self.health}}}]))
        rest = cmd[4:]
        if rest[:2] == ["config", "--format"]:
            services = {n: {"network_mode": MODES.get(n, "")} for n in ("tunnel-1", "dl-1", "idx-1", "web-1")}
            return done(0, json.dumps({"services": services}))
        if rest[:1] == ["ps"]:
            return done(0, rest[-1] + "-cid\n")
        if rest[:1] == ["up"]:
            return done(self.up_rc, "", "\n".join(f" Container {n}  Recreate" for n in self.recreate))
        raise AssertionError("unplanned command: %r" % (cmd,))

    def _ip(self, who):
        v = self.ips.get(who)
        return done(0, v + "\n") if v else done(1, "")


def inspect_names(host):                      # `docker inspect <cid>` for container_names(): ids are "<service>-cid"
    return host


class ControlsTest(unittest.TestCase):
    def run_c(self, names, host, members=("tunnel-1", "dl-1", "idx-1")):
        return controls.run(names, list(members), host, "https://probe.example.test", "registry.example.test/curl:1")

    def test_unknown_control_is_an_error_not_a_skip(self):
        with self.assertRaises(ValueError):
            self.run_c(["members_healthy", "rm -rf /"], ScriptedHost())

    def test_healthy_members_ok_and_starting_member_fails(self):
        self.assertEqual(self.run_c(["members_healthy"], ScriptedHost())[0][1], "ok")
        self.assertEqual(self.run_c(["members_healthy"], ScriptedHost(health="starting"))[0][1], "fail")

    def test_exit_differs_ok_fail_unknown(self):
        self.assertEqual(self.run_c(["exit_differs"], ScriptedHost())[0][1], "ok")
        self.assertEqual(self.run_c(["exit_differs"], ScriptedHost(ips={"tunnel-1": "203.0.113.1"}))[0][1], "fail")
        self.assertEqual(self.run_c(["exit_differs"], ScriptedHost(ips={"tunnel-1": None}))[0][1], "unknown")

    def test_unknown_is_never_ok_when_host_address_unreadable(self):
        self.assertEqual(self.run_c(["exit_differs"], ScriptedHost(ips={"host": None}))[0][1], "unknown")

    def test_no_leak_detects_a_dependant_with_another_address(self):
        self.assertEqual(self.run_c(["no_leak"], ScriptedHost())[0][1], "ok")
        self.assertEqual(self.run_c(["no_leak"], ScriptedHost(ips={"idx-1": "203.0.113.1"}))[0][1], "fail")
        self.assertEqual(self.run_c(["no_leak"], ScriptedHost(ips={"idx-1": None}))[0][1], "unknown")

    def test_addresses_are_never_printed(self):
        for _, _, detail in self.run_c(["exit_differs", "no_leak"], ScriptedHost(ips={"idx-1": "203.0.113.1"})):
            self.assertNotIn("203.0.113", detail)
            self.assertNotIn("198.51.100", detail)


class GroupDryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.compose = write_compose_text(self.tmp.name, COMPOSE)
        self.addCleanup(mock.patch.stopall)

    def configure(self, **group_entry):
        entry = {"policy": "ask", "reason": "tunnel", "confirmed": True, "controls": ["members_healthy", "exit_differs", "no_leak"]}
        entry.update(group_entry)
        path = rpl_config(self.tmp.name, groups={"tunnel-1": entry})
        mock.patch.dict(os.environ, {"RPL_CONFIG": path}).start()

    def run_dry(self, host, parent="tunnel-1", extra=("--dry",)):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(group.patch, "container_names", side_effect=lambda f, s, host=None: {s}):
            rc = group.main(["--compose", self.compose, "--parent", parent, *extra], host)
        return rc, out.getvalue()

    def test_ready_when_everything_passes(self):
        self.configure()
        rc, out = self.run_dry(ScriptedHost())
        self.assertEqual(rc, 0, out)
        self.assertIn("tunnel-1 -> dl-1 -> idx-1", out)
        self.assertIn("READY", out)

    def test_without_dry_it_refuses(self):
        self.configure()
        rc, out = self.run_dry(ScriptedHost(), extra=())
        self.assertEqual(rc, 1)
        self.assertIn("not implemented", out)

    def test_dry_run_touching_another_container_is_not_ready(self):
        self.configure()
        rc, out = self.run_dry(ScriptedHost(recreate=("tunnel-1", "dl-1", "idx-1", "web-1")))
        self.assertEqual(rc, 1)
        self.assertIn("nothing else", out)

    def test_dry_run_missing_a_member_is_not_ready(self):
        self.configure()
        self.assertEqual(self.run_dry(ScriptedHost(recreate=("tunnel-1", "dl-1")))[0], 1)

    def test_failed_control_gives_exit_2(self):
        self.configure()
        rc, out = self.run_dry(ScriptedHost(ips={"tunnel-1": "203.0.113.1"}))
        self.assertEqual(rc, 2, out)
        self.assertIn("NOT READY", out)

    def test_unknown_control_name_is_not_ready(self):
        self.configure(controls=["members_healthy", "curl evil.example.test"])
        rc, out = self.run_dry(ScriptedHost())
        self.assertEqual(rc, 1)
        self.assertIn("unknown control", out)

    def test_undeclared_group_is_not_ready(self):
        mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.tmp.name)}).start()
        rc, out = self.run_dry(ScriptedHost())
        self.assertEqual(rc, 1)
        self.assertIn("not declared", out)

    def test_service_that_is_not_a_group_is_refused(self):
        self.configure()
        rc, out = self.run_dry(ScriptedHost(), parent="web-1")
        self.assertEqual(rc, 1)
        self.assertIn("not a group", out)

    def test_dependant_as_parent_is_refused(self):
        self.configure()
        rc, out = self.run_dry(ScriptedHost(), parent="dl-1")
        self.assertEqual(rc, 1)
        self.assertIn("nested", out)

    def test_nothing_that_changes_state_runs(self):
        self.configure()
        host = ScriptedHost()
        self.run_dry(host)
        for c in host.calls:
            self.assertNotEqual(c[4:6], ["up", "-d"] if "--dry-run" not in c else [], c)
            self.assertFalse(any(x in c for x in ("stop", "rm", "kill", "restart")), c)


if __name__ == "__main__":
    unittest.main()
