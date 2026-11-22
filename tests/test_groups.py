"""Update groups: detection from `docker inspect` objects, policy validation, and the refusal message."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from rpl import groups, patch, proposals

from .fakes import FakeHost, done, rpl_config, write_compose_text


def obj(name, mode="default", cid=None):
    return {"Id": cid or name + "-id", "Name": "/" + name, "HostConfig": {"NetworkMode": mode}}


VPN = [obj("vpn-1", cid="abc"), obj("dl-1", "container:abc"), obj("idx-1", "container:abc"), obj("web-1")]


class Detect(unittest.TestCase):
    def test_parent_and_dependants_form_a_group(self):
        self.assertEqual(groups.detect(VPN), {"vpn-1": ["dl-1", "idx-1"]})

    def test_no_shared_network_no_group(self):
        self.assertEqual(groups.detect([obj("web-1"), obj("db-1")]), {})

    def test_unknown_parent_is_not_a_group(self):
        self.assertEqual(groups.detect([obj("dl-1", "container:nowhere")]), {})

    def test_reference_by_name_works(self):
        self.assertEqual(groups.detect([obj("vpn-1"), obj("dl-1", "container:vpn-1")]), {"vpn-1": ["dl-1"]})

    def test_member_group(self):
        det = groups.detect(VPN)
        self.assertEqual([groups.member_group(n, det) for n in ("vpn-1", "dl-1", "web-1")], ["vpn-1", "vpn-1", None])


class Status(unittest.TestCase):
    det = {"vpn-1": ["dl-1"]}

    def st(self, cfg):
        return groups.status(self.det, cfg)["vpn-1"]

    def test_undeclared_group_is_blocked(self):
        s = self.st({})
        self.assertTrue(s["blocked"])
        self.assertIn("not declared", s["problems"][0])

    def test_valid_ask_with_reason(self):
        s = self.st({"vpn-1": {"policy": "ask", "reason": "VPN", "confirmed": True}})
        self.assertEqual((s["blocked"], s["policy"], s["reason"], s["confirmed"]), (False, "ask", "VPN", True))

    def test_ask_without_reason_is_blocked(self):
        self.assertTrue(self.st({"vpn-1": {"policy": "ask", "reason": "  "}})["blocked"])

    def test_never_without_reason_is_blocked(self):
        self.assertTrue(self.st({"vpn-1": {"policy": "never"}})["blocked"])

    def test_invalid_policy_is_blocked(self):
        self.assertTrue(self.st({"vpn-1": {"policy": "yolo", "reason": "x"}})["blocked"])

    def test_auto_needs_no_reason(self):
        self.assertFalse(self.st({"vpn-1": {"policy": "auto", "confirmed": True}})["blocked"])

    def test_confirmed_must_be_literally_true(self):
        self.assertFalse(self.st({"vpn-1": {"policy": "auto", "confirmed": "true"}})["confirmed"])

    def test_nested_group_is_blocked(self):
        det = {"a": ["b"], "b": ["c"]}
        cfg = {"a": {"policy": "auto"}, "b": {"policy": "auto"}}
        st = groups.status(det, cfg)
        self.assertTrue(st["b"]["blocked"])
        self.assertIn("nested", st["b"]["problems"][0])

    def test_declared_but_absent_group_is_reported_not_blocking(self):
        s = groups.status({}, {"gone-1": {"policy": "ask", "reason": "x"}})["gone-1"]
        self.assertTrue(s["orphan"])
        self.assertFalse(s["blocked"])


class Refusal(unittest.TestCase):
    det = {"vpn-1": ["dl-1"]}

    def test_service_outside_any_group_is_not_refused(self):
        self.assertIsNone(groups.refusal("web-1", self.det, {}))

    def test_dependant_and_parent_are_refused_even_when_declared_auto(self):
        cfg = {"vpn-1": {"policy": "auto", "confirmed": True}}
        for name in ("vpn-1", "dl-1"):
            self.assertIn("update group", groups.refusal(name, self.det, cfg))

    def test_reason_is_shown(self):
        r = groups.refusal("dl-1", self.det, {"vpn-1": {"policy": "ask", "reason": "VPN cuts downloads"}})
        self.assertIn("VPN cuts downloads", r)

    def test_undeclared_group_says_why(self):
        self.assertIn("not declared", groups.refusal("dl-1", self.det, {}))


class PatchRefusesAnyGroupMember(unittest.TestCase):
    """`rpl patch` refuses by network_mode, not by name: nothing here is called gluetun."""
    OLD, NEW = "registry.example.test/app:1", "registry.example.test/app:2"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        text = ("services:\n  tunnel-1:\n    image: registry.example.test/tunnel:1\n"
                "  app:\n    image: registry.example.test/app:1\n  plain:\n    image: registry.example.test/plain:1\n")
        self.compose = write_compose_text(self.tmp.name, text)
        self.original = open(self.compose, encoding="utf-8").read()
        env = mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.tmp.name)})
        env.start()
        self.addCleanup(env.stop)

    def run_patch(self, host, service="app", old=None):
        out = io.StringIO()
        argv = ["--compose", self.compose, "--service", service, "--old", old or self.OLD, "--new", self.NEW,
                "--route", "app.example.test", "--codes", "200", "--dry"]
        with contextlib.redirect_stdout(out):
            rc = patch.main(argv, host)
        return rc, out.getvalue()

    def test_dependant_under_an_ordinary_name_is_refused(self):
        rc, out = self.run_patch(FakeHost(self.compose, network_mode="service:tunnel-1"))
        self.assertEqual(rc, 3, out)
        self.assertIn("update group", out)
        self.assertEqual(open(self.compose, encoding="utf-8").read(), self.original)

    def test_container_reference_is_refused(self):
        rc, _ = self.run_patch(FakeHost(self.compose, network_mode="container:tunnel-1"))
        self.assertEqual(rc, 3)

    def test_parent_whose_network_others_use_is_refused(self):
        host = FakeHost(self.compose, service="tunnel-1", others_network={"app": "service:tunnel-1"})
        rc, out = self.run_patch(host, service="tunnel-1", old="registry.example.test/tunnel:1")
        self.assertEqual(rc, 3, out)
        self.assertIn("app", out)

    def test_unrelated_service_next_to_a_group_is_not_refused(self):
        host = FakeHost(self.compose, service="plain", others_network={"app": "service:tunnel-1"})
        rc, out = self.run_patch(host, service="plain", old="registry.example.test/plain:1")
        self.assertEqual(rc, 0, out)


class ProposalsFlagAnyGroupMember(unittest.TestCase):
    def test_dependant_under_an_ordinary_name_is_flagged(self):
        objs = [{"Id": "p1", "Name": "/tunnel-1", "Config": {"Image": "x/tunnel:1", "Labels": {"com.docker.compose.service": "tunnel-1",
                "com.docker.compose.project.config_files": "/srv/c.yaml"}}, "HostConfig": {"NetworkMode": "default"}, "State": {"Running": True}},
                {"Id": "d1", "Name": "/dl-1", "Config": {"Image": "x/dl:1", "Labels": {"com.docker.compose.service": "dl-1",
                "com.docker.compose.project.config_files": "/srv/c.yaml"}}, "HostConfig": {"NetworkMode": "container:p1"}, "State": {"Running": True}}]

        def fake(cmd, **kw):
            return done(0, "a b" if cmd[:3] == ["docker", "ps", "-aq"] else json.dumps(objs))
        with mock.patch("subprocess.run", side_effect=fake):
            res = proposals.running_containers()
        self.assertEqual({k: v["vpn"] for k, v in res.items()}, {"x/tunnel:1": True, "x/dl:1": True})

    def run_with(self, objs):
        """`docker ps -aq` lists everything; a `docker ps -q` (running only) would never show a stopped container."""
        def fake(cmd, **kw):
            if cmd[:2] == ["docker", "ps"]:
                return done(0, " ".join(o["Id"] for o in objs if "a" in cmd[2] or o["State"]["Running"]))
            return done(0, json.dumps([o for o in objs if o["Id"] in cmd[2:]]))
        with mock.patch("subprocess.run", side_effect=fake):
            return proposals.running_containers()

    def container(self, name, mode="default", running=True):
        return {"Id": name + "-id", "Name": "/" + name, "State": {"Running": running}, "HostConfig": {"NetworkMode": mode},
                "Config": {"Image": "x/" + name + ":1", "Labels": {"com.docker.compose.service": name, "com.docker.compose.project.config_files": "/srv/c.yaml"}}}

    def test_a_parent_whose_only_dependant_is_stopped_is_still_flagged(self):
        res = self.run_with([self.container("tunnel-1"), self.container("dl-1", "container:tunnel-1-id", running=False)])
        self.assertTrue(res["x/tunnel-1:1"]["vpn"])

    def test_a_stopped_container_is_not_listed_as_running(self):
        res = self.run_with([self.container("web-1"), self.container("old-1", running=False)])
        self.assertEqual(list(res), ["x/web-1:1"])


if __name__ == "__main__":
    unittest.main()
