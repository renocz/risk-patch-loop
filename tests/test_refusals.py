"""Everything the tool must REFUSE to do: VPN containers, and proposals that are missing, stale or unusable."""
import contextlib
import io
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from rpl import config, patch, proposals

from .fakes import FakeHost, done, rpl_config, write_compose

OLD, NEW = "registry.example.test/app:1", "registry.example.test/app:2"
PROPOSAL = {"id": "app", "service": "app", "compose": "/srv/app/compose.yaml", "from": OLD, "to": NEW, "why": "newer version", "score": 60.0,
            "act_rows": 1, "kev": True, "level": "internet-no-auth", "route": "app.example.test", "codes": "200 302",
            "db": {"container": "app-db-1", "user": "app", "name": "app"}}


def captured(fn, *a, **kw):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = fn(*a, **kw)
    return rc, out.getvalue()


class VpnRefusal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.compose = write_compose(self.tmp.name, OLD)
        self.original = open(self.compose, encoding="utf-8").read()
        env = mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.tmp.name)})
        env.start()
        self.addCleanup(env.stop)

    def patch_argv(self, service="app"):
        return ["--compose", self.compose, "--service", service, "--old", OLD, "--new", NEW, "--route", "app.example.test", "--codes", "200"]

    def assert_refused_before_any_change(self, host, rc, out):
        self.assertEqual(rc, 3, out)
        self.assertIn("REFUSED", out)
        self.assertEqual(open(self.compose, encoding="utf-8").read(), self.original)
        self.assertEqual(host.kinds(), ["inspect-config"], "nothing but the read-only config query may have run")

    def test_service_sharing_the_vpn_network_is_refused(self):
        host = FakeHost(self.compose, vpn=True)                       # network_mode: service:gluetun
        self.assert_refused_before_any_change(host, *captured(patch.main, self.patch_argv(), host))

    def test_network_mode_container_gluetun_is_refused(self):
        host = FakeHost(self.compose, network_mode="container:gluetun")
        self.assert_refused_before_any_change(host, *captured(patch.main, self.patch_argv(), host))

    def test_the_vpn_container_itself_is_refused(self):
        compose = write_compose(self.tmp.name, "registry.example.test/gluetun:1", service="gluetun")
        host = FakeHost(compose, service="gluetun")
        rc, out = captured(patch.main, ["--compose", compose, "--service", "gluetun", "--old", "registry.example.test/gluetun:1", "--new", NEW,
                                        "--route", "r.example.test", "--codes", "200"], host)
        self.assertEqual((rc, "REFUSED" in out), (3, True))

    def test_when_compose_cannot_be_read_the_answer_is_refuse(self):
        host = FakeHost(self.compose, config_ok=False)
        self.assert_refused_before_any_change(host, *captured(patch.main, self.patch_argv(), host))

    def test_dry_flag_does_not_bypass_the_refusal(self):
        host = FakeHost(self.compose, vpn=True)
        self.assert_refused_before_any_change(host, *captured(patch.main, self.patch_argv() + ["--dry"], host))

    def test_ordinary_service_is_not_refused(self):
        host = FakeHost(self.compose)
        rc, _ = captured(patch.main, self.patch_argv() + ["--dry"], host)
        self.assertEqual(rc, 0)


class VpnDetectionInProposals(unittest.TestCase):
    """running_containers() flags the VPN container and everything whose network namespace is the VPN container's."""

    def inspect(self, name, image, mode="default", cid=None, service=None):
        return {"Id": cid or name + "-id", "Name": "/" + name,
                "Config": {"Image": image, "Labels": {"com.docker.compose.service": service or name, "com.docker.compose.project.config_files": "/srv/c.yaml"}},
                "HostConfig": {"NetworkMode": mode}}

    def run_with(self, objs):
        def fake(cmd, **kw):
            return done(0, "id1 id2 id3" if cmd[:3] == ["docker", "ps", "-q"] else json.dumps(objs))
        with mock.patch("subprocess.run", side_effect=fake):
            return proposals.running_containers()

    def test_vpn_and_its_dependents_are_flagged_and_others_are_not(self):
        res = self.run_with([self.inspect("gluetun", "vpn/gluetun:1", cid="abc123"),
                             self.inspect("downloader", "x/downloader:1", mode="container:abc123"),
                             self.inspect("web", "x/web:1")])
        self.assertEqual({k: v["vpn"] for k, v in res.items()}, {"vpn/gluetun:1": True, "x/downloader:1": True, "x/web:1": False})

    def test_without_a_vpn_container_nothing_is_flagged(self):
        res = self.run_with([self.inspect("web", "x/web:1"), self.inspect("db", "x/db:1", mode="container:other")])
        self.assertFalse(any(v["vpn"] for v in res.values()))

    def test_flagged_dependent_is_never_proposed(self):
        res = self.run_with([self.inspect("gluetun", "vpn/gluetun:1", cid="abc"), self.inspect("dl", "x/dl:1", mode="container:abc")])
        row = {"image": "x/dl:1", "score": 70.0, "kev": True, "level": "internet-no-auth", "decision": "ACT"}
        props, skipped = proposals.prepare([row], {"x/dl:1": {"verdict": "COMPLETE", "candidate": "2"}}, {"dl": {"route": "r", "codes": "200"}}, res, {})
        self.assertEqual(props, [])
        self.assertIn("VPN", skipped[0]["reason"])


class ApplyRefusals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.tmp.name)})
        env.start()
        self.addCleanup(env.stop)
        self.path = os.path.join(config.load()["state_dir"], "proposals.json")
        os.makedirs(os.path.dirname(self.path))
        self.run = mock.patch("subprocess.run", return_value=done(0))
        self.run_mock = self.run.start()
        self.addCleanup(self.run.stop)

    def store(self, props=(PROPOSAL,), age_h=0.0):
        proposals.save(self.path, list(props), [], ts=time.time() - age_h * 3600)

    def edit(self, fn):
        """Change the stored file by hand, the way an editor or a stray script could."""
        with open(self.path) as f:
            d = json.load(f)
        fn(d)
        with open(self.path, "w") as f:
            json.dump(d, f)

    def apply(self, *flags, service="app"):
        return captured(proposals.main, ["--apply", service, *flags])

    def test_stored_proposal_is_applied_with_exactly_its_parameters(self):
        self.store()
        rc, _ = self.apply()
        self.assertEqual(rc, 0)
        cmd = self.run_mock.call_args[0][0]
        self.assertEqual(cmd, proposals.build_command(PROPOSAL))
        self.assertEqual(cmd[cmd.index("--new") + 1], NEW)

    def test_unknown_proposal_is_refused_and_nothing_runs(self):
        self.store()
        rc, out = self.apply(service="other-app")
        self.assertEqual(rc, 1)
        self.assertIn("REFUSED: no proposal 'other-app'", out)
        self.run_mock.assert_not_called()

    def test_stale_proposal_is_refused(self):
        self.store(age_h=proposals.VALIDITY_H + 1)
        rc, out = self.apply()
        self.assertEqual(rc, 1)
        self.assertIn("older than", out)
        self.run_mock.assert_not_called()

    def test_proposal_just_inside_the_validity_window_is_accepted(self):
        self.store(age_h=proposals.VALIDITY_H - 1)
        self.assertEqual(self.apply()[0], 0)

    def test_free_arguments_are_not_forwarded_to_patch(self):
        self.store()
        self.apply("--new", "evil/image:latest")
        cmd = self.run_mock.call_args[0][0] if self.run_mock.called else []
        self.assertNotIn("evil/image:latest", cmd)

    def test_dry_and_no_snapshot_are_the_only_extra_flags(self):
        self.store()
        self.apply("--dry", "--no-snapshot")
        cmd = self.run_mock.call_args[0][0]
        self.assertEqual(cmd[-2:], ["--dry", "--no-snapshot"])

    def test_list_shows_proposals_and_what_was_not_proposed(self):
        proposals.save(self.path, [PROPOSAL], [{"image": "x/y:1", "reason": "no proven fix (NONE)"}])
        rc, out = captured(proposals.main, ["--list"])
        self.assertEqual(rc, 0)
        self.assertIn("app", out)
        self.assertIn("(not proposed) x/y:1: no proven fix (NONE)", out)

    # ---- Defect 4 -------------------------------------------------------------------------------------------------
    # The docs say --apply runs "exactly the parameters of the proposal", but the stored file was trusted blindly: a proposal
    # edited after it was computed (and reviewed with --list) was applied as is, and a missing file ended in a traceback.

    def test_proposal_modified_after_it_was_computed_is_refused(self):
        self.store()
        self.edit(lambda d: d["proposals"][0].update({"to": "registry.example.test/app:evil"}))
        rc, out = self.apply()
        self.assertEqual(rc, 1)
        self.assertIn("modified", out)
        self.run_mock.assert_not_called()

    def test_proposal_added_by_hand_is_refused(self):
        self.store()
        self.edit(lambda d: d["proposals"].append(dict(PROPOSAL, id="other", service="other")))
        rc, out = self.apply(service="other")
        self.assertEqual(rc, 1)
        self.run_mock.assert_not_called()

    def test_refreshed_timestamp_does_not_revive_a_stale_proposal(self):
        self.store(age_h=proposals.VALIDITY_H + 5)
        self.edit(lambda d: d.update({"ts": time.time()}))
        rc, out = self.apply()
        self.assertEqual(rc, 1)
        self.run_mock.assert_not_called()

    def test_file_without_a_digest_is_refused(self):
        self.store()
        self.edit(lambda d: d.pop("sha256"))
        self.assertEqual(self.apply()[0], 1)
        self.run_mock.assert_not_called()

    def test_list_refuses_a_modified_file_too(self):
        self.store()
        self.edit(lambda d: d["proposals"][0].update({"to": "x:y"}))
        rc, out = captured(proposals.main, ["--list"])
        self.assertEqual(rc, 1)
        self.assertIn("modified", out)

    def test_computed_proposals_can_be_listed_and_applied_unchanged(self):
        with mock.patch.object(proposals, "compute", return_value=([PROPOSAL], [])):
            self.assertEqual(captured(proposals.main, [])[0], 0)
        self.assertEqual(captured(proposals.main, ["--list"])[0], 0)
        self.assertEqual(self.apply()[0], 0)

    def test_absent_proposals_file_is_a_clear_refusal_not_a_traceback(self):
        os.remove(self.path) if os.path.exists(self.path) else None
        rc, out = self.apply()
        self.assertEqual(rc, 1)
        self.assertIn("REFUSED", out)
        self.run_mock.assert_not_called()

    def test_unreadable_proposals_file_is_a_clear_refusal(self):
        with open(self.path, "w") as f:
            f.write("{truncated")
        rc, out = self.apply()
        self.assertEqual(rc, 1)
        self.assertIn("REFUSED", out)
        self.run_mock.assert_not_called()


class HandMadeProposalsFile(unittest.TestCase):
    """Council point 5: load() assumed d["ts"] was a number and the lists well formed. A file whose digest is correct but whose
    content is malformed (hand-made, or written by another version) raised a Python exception instead of a refusal; a NaN or a
    future timestamp even defeated the 36 h expiry."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.tmp.name)})
        env.start()
        self.addCleanup(env.stop)
        self.path = os.path.join(config.load()["state_dir"], "proposals.json")
        os.makedirs(os.path.dirname(self.path))
        run = mock.patch("subprocess.run", return_value=done(0))
        self.run_mock = run.start()
        self.addCleanup(run.stop)

    def write(self, **content):
        """A file with a CORRECT digest over whatever content is given (so only the shape can be wrong)."""
        d = {"ts": time.time(), "proposals": [dict(PROPOSAL)], "not_proposed": []}
        d.update(content)
        for k in [k for k, v in d.items() if v is KeyError]:
            del d[k]
        d["sha256"] = proposals.digest(d)
        with open(self.path, "w") as f:
            json.dump(d, f)

    def assert_refused(self, *argv):
        for args in (["--apply", "app"], ["--list"]):
            rc, out = captured(proposals.main, args)
            self.assertEqual(rc, 1, (args, out))
            self.assertIn("REFUSED", out)
        self.run_mock.assert_not_called()

    def test_well_formed_file_is_accepted(self):
        self.write()
        self.assertEqual(captured(proposals.main, ["--apply", "app"])[0], 0)

    def test_timestamp_missing_or_not_a_finite_number(self):
        for ts in (KeyError, "now", None, True, [1], float("nan"), float("inf"), float("-inf")):
            with self.subTest(ts=ts):
                self.write(ts=ts)
                self.assert_refused()

    def test_timestamp_in_the_future_does_not_defeat_the_expiry(self):
        self.write(ts=time.time() + 10 * 365 * 24 * 3600)
        self.assert_refused()

    def test_proposals_of_the_wrong_type(self):
        for bad in (KeyError, None, {}, "x", 3, [1], ["x"], [None]):
            with self.subTest(proposals=bad):
                self.write(proposals=bad)
                self.assert_refused()

    def test_not_proposed_of_the_wrong_type(self):
        for bad in (KeyError, None, {}, "x", [1], [{"image": "x"}], [{"image": 1, "reason": "r"}]):
            with self.subTest(not_proposed=bad):
                self.write(not_proposed=bad)
                self.assert_refused()

    def test_proposal_with_a_missing_or_mistyped_field(self):
        for key, bad in (("id", KeyError), ("service", None), ("compose", 3), ("from", KeyError), ("to", ["x"]), ("route", None), ("codes", 200),
                         ("why", KeyError), ("score", "high"), ("score", KeyError), ("db", "x"), ("db", {"container": "c"}), ("db", {"container": 1, "user": "u", "name": "n"})):
            with self.subTest(field=key, value=bad):
                p = dict(PROPOSAL)
                p.pop(key) if bad is KeyError else p.update({key: bad})
                self.write(proposals=[p])
                self.assert_refused()

    def test_top_level_that_is_not_an_object(self):
        for text in ("[]", "null", "3", '"x"'):
            with self.subTest(text=text):
                with open(self.path, "w") as f:
                    f.write(text)
                self.assert_refused()

    def test_apply_without_a_service_name_is_a_refusal_not_an_index_error(self):
        self.write()
        rc, out = captured(proposals.main, ["--apply"])
        self.assertEqual(rc, 1)
        self.assertIn("REFUSED", out)
        self.run_mock.assert_not_called()

    def test_proposal_without_a_database_is_valid(self):
        self.write(proposals=[dict(PROPOSAL, db=None)])
        self.assertEqual(captured(proposals.main, ["--apply", "app"])[0], 0)


if __name__ == "__main__":
    unittest.main()
