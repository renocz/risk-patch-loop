"""`rpl group` applying a group, against tests/fake_group.GroupHost: policy, plan and digests, backup, ordered update, rollback, resume.

Nothing here proves a rollback or a restore on a real host: the host is a model (see the docstring of GroupHost for what it leaves out).
The configuration directories and their backups, however, are real files in a temporary directory.
"""
import contextlib
import io
import json
import os
import shutil
import stat
import tempfile
import time
import unittest
from unittest import mock

from rpl import config, events, gate, group, groupapply, notify

from .fake_group import GroupHost
from .fakes import rpl_config, write_compose_text

R = "registry.example.test/"
D_TUNNEL, D_SUB, D_DL = "sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64
NEW_TUNNEL, NEW_SUB, NEW_DL = f"{R}tunnel:2@{D_TUNNEL}", f"{R}sub:2@{D_SUB}", f"{R}dl:latest@{D_DL}"
COMPOSE = (f"services:\n  tunnel:\n    image: {R}tunnel:1\n  dl:\n    image: {R}dl:latest\n  idx:\n    image: {R}idx:1\n"
           f"  sub:\n    image: {R}sub:1\n  web:\n    image: {R}web:1\n")
PARENT = "proj-tunnel-1"                                  # the group is declared under the parent's CONTAINER name


class GroupCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.realpath(self.tmp.name)
        self.compose = write_compose_text(self.dir, COMPOSE)
        self.original = self.read(self.compose)
        # configuration directories next to the compose file: dl (a directory with a secret, a sub-directory and an inner symlink), idx
        self.dl_cfg, self.idx_cfg = os.path.join(self.dir, "dl", "config"), os.path.join(self.dir, "idx", "config")
        os.makedirs(os.path.join(self.dl_cfg, "db"))
        os.makedirs(self.idx_cfg)
        self.write(os.path.join(self.dl_cfg, "settings.json"), '{"version": 1}')
        self.write(os.path.join(self.dl_cfg, "secret.key"), "s3cret", 0o600)
        self.write(os.path.join(self.dl_cfg, "db", "app.sqlite"), "SQLite format 3\x00 v1")
        os.symlink("settings.json", os.path.join(self.dl_cfg, "current.json"))
        self.write(os.path.join(self.idx_cfg, "idx.conf"), "a = 1\n")
        self.outside = os.path.join(os.path.dirname(self.dir), "bulk-" + os.path.basename(self.dir))      # a bind mount elsewhere: never copied
        self.host = GroupHost(self.compose, "tunnel", ["dl", "idx", "sub"], standalone=["web"],
                              binds={"dl": [self.dl_cfg, self.outside], "idx": [self.idx_cfg]})
        self.fixes = {f"{R}tunnel:1": {"candidate": "2", "candidate_digest": D_TUNNEL},
                      f"{R}sub:1": {"candidate": "2", "candidate_digest": D_SUB}}
        self.registry = {f"{R}tunnel:2": D_TUNNEL, f"{R}sub:2": D_SUB, f"{R}dl:latest": D_DL}
        for name, fn in (("proven_fixes", lambda cfg: self.fixes), ("registry_digest", lambda ref: self.registry.get(ref))):
            p = mock.patch.object(groupapply, name, side_effect=fn)
            p.start()
            self.addCleanup(p.stop)
        guard = mock.patch("subprocess.run", side_effect=AssertionError("a real subprocess was started"))
        guard.start()
        self.addCleanup(guard.stop)
        self.configure()

    def write(self, path, text, mode=0o644):
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path, mode)

    def read(self, path):
        with open(path, encoding="utf-8") as f:
            return f.read()

    def configure(self, policy="auto", reason="", confirmed=True, controls=("members_healthy", "exit_differs", "no_leak"), services=None, **cfg):
        entry = {"policy": policy, "reason": reason, "confirmed": confirmed, "controls": list(controls)}
        if services:
            entry["services"] = services
        if getattr(self, "_env", None):
            self._env.stop()
        self._env = mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.dir, groups={PARENT: entry}, **cfg)})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.cfg = config.load()

    def run_group(self, *flags, parent="tunnel"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = group.main(["--compose", self.compose, "--parent", parent, *flags], self.host)
        return rc, out.getvalue()

    def fingerprint(self):
        rc, out = self.run_group("--plan")
        return [l.split(": ")[1] for l in out.splitlines() if l.startswith("fingerprint: ")][0]

    def journal(self):
        return json.loads(self.read(os.path.join(self.cfg["state_dir"], groupapply.JOURNAL)))

    def backups(self):
        d = self.cfg["backup_dir"]
        return sorted(os.path.join(d, n) for n in os.listdir(d)) if os.path.isdir(d) else []

    def images(self):
        return {s: self.host.c[s]["image"] for s in ("tunnel", "dl", "idx", "sub")}

    def assert_nothing_changed(self):
        self.assertEqual(self.host.verbs(), [], "no stop and no real up")
        self.assertEqual(self.read(self.compose), self.original)

    def assert_back_to_the_original(self):
        self.assertEqual(self.read(self.compose), self.original)
        self.assertEqual(self.images(), {"tunnel": f"{R}tunnel:1", "dl": f"{R}dl:latest", "idx": f"{R}idx:1", "sub": f"{R}sub:1"})
        self.assertTrue(all(self.host.c[s]["running"] for s in ("tunnel", "dl", "idx", "sub")))
        self.assertEqual(self.host.attached(), ["dl", "idx", "sub"], "every dependant is in the namespace of the current parent")


class PolicyTable(GroupCase):
    """One row per policy: who may start the apply, and what it needs."""

    def test_auto_confirmed_applies_without_a_human(self):
        self.configure(policy="auto")
        self.assertEqual(self.run_group()[0], 0)

    def test_auto_not_confirmed_is_refused(self):
        self.configure(policy="auto", confirmed=False)
        rc, out = self.run_group()
        self.assertEqual(rc, 1)
        self.assertIn("not confirmed", out)
        self.assert_nothing_changed()

    def test_ask_without_an_approval_is_refused_and_says_how(self):
        self.configure(policy="ask", reason="VPN: cuts every download")
        rc, out = self.run_group()
        self.assertEqual(rc, 1)
        self.assertIn("VPN: cuts every download", out)
        self.assertIn("--approve", out)
        self.assert_nothing_changed()

    def test_ask_with_the_fingerprint_of_this_plan_applies(self):
        self.configure(policy="ask", reason="VPN")
        self.assertEqual(self.run_group("--approve", self.fingerprint())[0], 0)

    def test_ask_with_another_fingerprint_is_refused(self):
        self.configure(policy="ask", reason="VPN")
        rc, out = self.run_group("--approve", "0123456789abcdef")
        self.assertEqual(rc, 1)
        self.assertIn("another plan", out)
        self.assert_nothing_changed()

    def test_ask_not_confirmed_is_refused_even_when_approved(self):
        self.configure(policy="ask", reason="VPN", confirmed=False)
        fp = self.fingerprint()
        self.assertEqual(self.run_group("--approve", fp)[0], 1)
        self.assert_nothing_changed()

    def test_never_is_refused_whatever_is_given(self):
        self.configure(policy="never", reason="by hand only")
        fp = self.fingerprint()
        rc, out = self.run_group("--approve", fp)
        self.assertEqual(rc, 1)
        self.assertIn("by hand only", out)
        self.assert_nothing_changed()

    def test_a_group_that_is_not_declared_is_refused(self):
        self._env.stop()
        self._env = mock.patch.dict(os.environ, {"RPL_CONFIG": rpl_config(self.dir)})
        self._env.start()
        rc, out = self.run_group()
        self.assertEqual(rc, 1)
        self.assertIn("not declared", out)
        self.assert_nothing_changed()

    def test_the_most_restrictive_service_policy_wins(self):
        for svc_policy, flags, expected in (("never", (), 1), ("ask", (), 1)):
            with self.subTest(service_policy=svc_policy):
                self.configure(policy="auto", services={"dl": {"policy": svc_policy, "reason": "holds the queue"}})
                rc, out = self.run_group(*flags)
                self.assertEqual(rc, expected)
                self.assertIn("holds the queue", out)
                self.assert_nothing_changed()
        self.configure(policy="auto", services={"dl": {"policy": "ask", "reason": "holds the queue"}})
        self.assertEqual(self.run_group("--approve", self.fingerprint())[0], 0)

    def test_a_service_policy_without_a_reason_or_for_a_stranger_is_refused(self):
        for services in ({"dl": {"policy": "ask"}}, {"web": {"policy": "auto"}}, {"dl": {"quiesce": "freeze"}}, {"dl": {"policy": "maybe"}}):
            with self.subTest(services=services):
                self.configure(services=services)
                self.assertEqual(self.run_group()[0], 1)
                self.assert_nothing_changed()

    def test_a_v09_configuration_without_a_groups_key_still_loads_and_blocks_the_group(self):
        path = os.path.join(self.dir, "rpl.json")
        with open(path, "w") as f:
            json.dump({"state_dir": os.path.join(self.dir, "state"), "backup_dir": os.path.join(self.dir, "backups"), "snapshot_command": "true"}, f)
        self.assertEqual(config.load()["groups"], {})
        rc, out = self.run_group()
        self.assertEqual(rc, 1)
        self.assertIn("not declared", out)


class SuccessfulApply(GroupCase):
    def test_parent_first_then_every_dependant_and_all_end_in_the_new_namespace(self):
        rc, out = self.run_group()
        self.assertEqual(rc, 0, out)
        self.assertEqual([s for v, s in self.host.verbs() if v == "up"], ["tunnel", "dl", "idx", "sub"])
        self.assertEqual(self.host.attached(), ["dl", "idx", "sub"])
        self.assertEqual(out.strip().splitlines()[-1], "OK")

    def test_only_members_with_a_proven_fix_get_a_new_image_pinned_by_digest(self):
        self.run_group()
        self.assertEqual(self.images(), {"tunnel": NEW_TUNNEL, "dl": f"{R}dl:latest", "idx": f"{R}idx:1", "sub": NEW_SUB})
        self.assertEqual(self.read(self.compose), self.original.replace(f"{R}tunnel:1", NEW_TUNNEL).replace(f"{R}sub:1", NEW_SUB))

    def test_members_with_a_configuration_directory_are_stopped_dependants_first_before_any_copy_or_recreation(self):
        seen = {}
        self.host.hooks[("up", "tunnel")] = lambda: seen.update(backups=self.backups(), running={s: self.host.c[s]["running"] for s in ("dl", "idx", "sub")})
        self.run_group()
        verbs = self.host.verbs()
        self.assertEqual(verbs[:2], [("stop", "idx"), ("stop", "dl")])
        self.assertEqual(seen["running"], {"dl": False, "idx": False, "sub": True}, "sub mounts no configuration: not stopped")
        self.assertEqual(len(seen["backups"]), 1, "the backup exists before the first recreation")

    def test_quiesce_none_leaves_a_member_running_during_the_backup(self):
        self.configure(services={"dl": {"quiesce": "none"}})
        self.run_group()
        self.assertNotIn(("stop", "dl"), self.host.verbs())

    def test_the_journal_entry_exists_before_anything_is_stopped(self):
        seen = []
        self.host.hooks[("stop", "idx")] = lambda: seen.append(groupapply.unfinished(self.cfg))
        self.run_group()
        self.assertEqual(seen[0]["state"], "started")
        self.assertEqual([m["service"] for m in seen[0]["plan"]["members"]], ["tunnel", "dl", "idx", "sub"])
        self.assertEqual(self.journal()[-1]["result"], "ok")

    def test_the_backup_is_owner_only_and_keeps_modes_symlinks_and_content(self):
        self.run_group()
        root = self.backups()[0]
        self.assertEqual(stat.S_IMODE(os.stat(root).st_mode), 0o700)
        copy = os.path.join(root, "dl", "0")
        self.assertEqual(self.read(os.path.join(copy, "secret.key")), "s3cret")
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(copy, "secret.key")).st_mode), 0o600)
        self.assertEqual(os.readlink(os.path.join(copy, "current.json")), "settings.json")
        self.assertTrue(os.path.exists(os.path.join(root, "idx", "0", "idx.conf")))
        self.assertFalse(os.path.exists(os.path.join(root, "sub")))

    def test_a_bind_mount_outside_the_compose_directory_is_not_copied_and_said_so(self):
        os.mkdir(self.outside)
        self.addCleanup(os.rmdir, self.outside)
        rc, out = self.run_group()
        self.assertEqual(rc, 0)
        self.assertIn("not backed up (outside the compose directory): " + self.outside, out)
        self.assertEqual(sorted(os.listdir(os.path.join(self.backups()[0], "dl"))), ["0"])

    def test_the_result_is_notified_when_channels_are_configured(self):
        self.configure(notifications={"channels": [{"type": "webhook", "url": "https://hooks.example.test/x"}]})
        with mock.patch.object(groupapply.notify, "deliver", return_value={"delivered": [], "queued": [], "given_up": []}) as deliver:
            self.run_group()
        self.assertIn(":ok", deliver.call_args[0][0][0]["key"])


class PlanOnly(GroupCase):
    def test_plan_changes_nothing_and_leaves_no_copy_behind(self):
        rc, out = self.run_group("--plan")
        self.assertEqual(rc, 0, out)
        self.assert_nothing_changed()
        self.assertEqual(self.backups(), [])
        self.assertIn("PLAN READY", out)
        self.assertIn("backup proof: 2 item(s)", out)
        self.assertIn(NEW_TUNNEL, out)

    def test_the_fingerprint_changes_with_a_target_digest_and_with_the_image_that_runs(self):
        first = self.fingerprint()
        self.assertEqual(first, self.fingerprint())
        other = "sha256:" + "d" * 64
        self.fixes[f"{R}sub:1"]["candidate_digest"] = self.registry[f"{R}sub:2"] = other
        second = self.fingerprint()
        self.host.ids[f"{R}idx:1"] = "sha256:rebuilt"
        self.assertEqual(len({first, second, self.fingerprint()}), 3)

    def test_plan_for_policy_never_says_it_would_be_refused(self):
        self.configure(policy="never", reason="by hand only")
        rc, out = self.run_group("--plan")
        self.assertEqual(rc, 1)
        self.assertIn("by hand only", out)

    def test_a_failed_control_makes_the_plan_not_ready(self):
        self.host.leak_images.add(f"{R}tunnel:1")
        rc, out = self.run_group("--plan")
        self.assertEqual(rc, 2)
        self.assertIn("NOT READY", out)


class RefusedBeforeAnythingChanges(GroupCase):
    def refused(self, needle, *flags):
        rc, out = self.run_group(*flags)
        self.assertEqual(rc, 1, out)
        self.assertIn(needle, out)
        self.assert_nothing_changed()
        self.assertEqual(self.backups(), [])

    def test_no_proven_fix_pending_nothing_is_applied(self):
        self.fixes.clear()
        self.refused("not an updater")

    def test_a_tag_that_moved_since_its_fix_was_proven(self):
        self.registry[f"{R}tunnel:2"] = "sha256:" + "e" * 64
        self.refused("moved since its fix was proven")

    def test_a_floating_tag_that_moved_since_its_fix_was_proven(self):
        self.fixes[f"{R}dl:latest"] = {"candidate": "latest", "candidate_digest": D_DL}
        self.assertEqual(self.run_group("--plan")[0], 0)                      # same digest: dl:latest is pinned to it
        self.registry[f"{R}dl:latest"] = "sha256:" + "f" * 64
        self.refused("moved since its fix was proven")

    def test_a_registry_digest_that_cannot_be_read_is_unknown(self):
        del self.registry[f"{R}sub:2"]
        self.refused("UNKNOWN")

    def test_a_fix_proof_without_a_digest_is_unknown(self):
        self.fixes[f"{R}tunnel:1"] = {"candidate": "2"}
        self.refused("UNKNOWN")

    def test_an_approval_given_before_the_tag_moved_no_longer_applies(self):
        self.configure(policy="ask", reason="VPN")
        approved = self.fingerprint()
        moved = "sha256:" + "e" * 64
        self.fixes[f"{R}tunnel:1"]["candidate_digest"] = self.registry[f"{R}tunnel:2"] = moved        # proven again, on another image
        self.refused("another plan", "--approve", approved)

    def test_a_dependant_that_only_docker_knows(self):
        self.host.extras.append({"Id": "x1", "Name": "/other-dl-1", "HostConfig": {"NetworkMode": "container:tunnel-c1"}, "State": {"Running": True}})
        self.refused("only in Docker: other-dl-1")

    def test_docker_that_cannot_be_listed(self):
        self.host.ps_all_rc = 1
        self.refused("cannot be listed")

    def test_a_dry_run_that_would_recreate_something_else(self):
        self.host.dry_extra.append("proj-web-1")
        self.refused("exactly the group's containers")

    def test_a_control_that_does_not_pass_before(self):
        self.host.leak_images.add(f"{R}tunnel:1")
        self.refused("exit_differs")

    def test_a_member_that_is_not_running(self):
        self.host.c["idx"]["running"] = False
        self.refused("no running container")

    def test_a_symlink_that_leaves_the_configuration_directory(self):
        os.symlink("/etc/hostname", os.path.join(self.dl_cfg, "escape"))
        self.refused("leaves the directory")

    def test_a_special_file_in_a_configuration_directory(self):
        os.mkfifo(os.path.join(self.idx_cfg, "pipe"))
        self.refused("special file")

    def test_configuration_heavier_than_the_cap_is_data(self):
        self.configure(group_backup_max_mb=0.00001)
        self.refused("group_backup_max_mb")

    def test_no_snapshot_command_needs_to_be_said_out_loud(self):
        self.configure(snapshot_command=None)
        self.refused("--no-snapshot")
        self.assertEqual(self.run_group("--no-snapshot")[0], 0)

    def test_paused(self):
        gate.pause_on(self.cfg, "owner is away")
        rc, out = self.run_group()
        self.assertEqual(rc, 5)
        self.assertEqual(self.host.calls, [])

    def test_another_run_holds_the_lock(self):
        with gate.applying(self.cfg, "patch app-1"):
            rc, out = self.run_group()
        self.assertEqual(rc, 5)
        self.assertEqual(self.host.calls, [])

    def test_the_group_is_read_again_under_the_lock(self):
        seen = []
        real = self.host.run

        def watching(cmd, **kw):
            if cmd[:3] == ["docker", "ps", "-aq"]:
                try:
                    with gate.applying(self.cfg, "intruder"):
                        seen.append("free")
                except gate.NotNow:
                    seen.append("held")
            return real(cmd, **kw)

        self.host.run = watching
        self.assertEqual(self.run_group()[0], 0)
        self.assertEqual(seen, ["held"])


class ContainerCreatedBeforeThePin(GroupCase):
    """Found on a real host: the compose file was pinned by digest AFTER the parent container was created, so the container's reference
    (`tunnel:1`) is not the text of the file (`tunnel:1@sha256:...`) although it is the same image. What must match is the image ID."""

    def setUp(self):
        super().setUp()
        self.pinned = f"{R}tunnel:1@sha256:" + "9" * 64
        with open(self.compose, "w", encoding="utf-8") as f:
            f.write(self.original.replace(f"{R}tunnel:1", self.pinned))
        self.original = self.read(self.compose)
        self.host.local_ids[self.pinned] = self.host._inspect("tunnel-c1")["Image"]      # same image under both references

    def test_the_same_image_under_another_reference_is_accepted(self):
        rc, out = self.run_group("--plan")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"container created as {R}tunnel:1", out)
        self.assertEqual(self.run_group()[0], 0)
        self.assertEqual(self.images()["tunnel"], NEW_TUNNEL)

    def test_a_rollback_brings_back_the_reference_of_the_file_with_the_same_image_id(self):
        self.host.ids[self.pinned] = self.host.local_ids[self.pinned]
        self.host.fail_up_images.add(NEW_TUNNEL)
        rc, out = self.run_group()
        self.assertEqual(rc, 2, out)
        self.assertEqual((self.images()["tunnel"], self.read(self.compose)), (self.pinned, self.original))

    def test_another_image_under_the_reference_of_the_file_is_refused(self):
        self.host.local_ids[self.pinned] = "sha256:another-image"
        rc, out = self.run_group()
        self.assertEqual(rc, 1)
        self.assertIn("not the image", out)
        self.assert_nothing_changed()

    def test_the_same_text_is_not_enough_when_the_tag_moved_in_the_local_store(self):
        self.host.local_ids[f"{R}idx:1"] = "sha256:pulled-since-the-container-was-created"
        rc, out = self.run_group()
        self.assertEqual(rc, 1)
        self.assertIn("not the image", out)
        self.assert_nothing_changed()

    def test_a_reference_missing_from_the_local_store_cannot_be_compared_and_is_refused(self):
        self.host.local_ids[self.pinned] = None
        rc, out = self.run_group()
        self.assertEqual(rc, 1)
        self.assertIn("cannot be compared", out)
        self.assert_nothing_changed()


class Rollback(GroupCase):
    def migrate_on(self, service):
        """The new version rewrites its configuration when it starts, as a real application would (once: the old image does not)."""
        def migrate():
            self.host.hooks.pop(("up", service), None)
            self.write(os.path.join(self.dl_cfg, "settings.json"), '{"version": 2}')
            self.write(os.path.join(self.dl_cfg, "db", "app.sqlite"), "SQLite format 3\x00 v2 MIGRATED")
            self.write(os.path.join(self.dl_cfg, "new-in-v2.json"), "{}")
            os.chmod(os.path.join(self.dl_cfg, "secret.key"), 0o644)
        self.host.hooks[("up", service)] = migrate

    def assert_configuration_restored(self):
        self.assertEqual(self.read(os.path.join(self.dl_cfg, "settings.json")), '{"version": 1}')
        self.assertEqual(self.read(os.path.join(self.dl_cfg, "db", "app.sqlite")), "SQLite format 3\x00 v1")
        self.assertFalse(os.path.exists(os.path.join(self.dl_cfg, "new-in-v2.json")))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dl_cfg, "secret.key")).st_mode), 0o600)
        self.assertEqual(os.readlink(os.path.join(self.dl_cfg, "current.json")), "settings.json")
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.dl_cfg)) if n != "config"], [], "no leftover next to the directory")

    def test_failure_at_the_parent(self):
        self.host.fail_up_images.add(NEW_TUNNEL)
        rc, out = self.run_group()
        self.assertEqual(rc, 2, out)
        self.assert_back_to_the_original()
        self.assertEqual(self.journal()[-1]["result"], "rollback ok")
        self.assertNotIn(("up", "sub"), self.host.verbs()[:self.host.verbs().index(("up", "tunnel")) + 1])

    def test_failure_at_the_third_dependant_restores_images_and_configuration(self):
        self.migrate_on("dl")
        self.host.unhealthy_images.add(NEW_SUB)
        rc, out = self.run_group()
        self.assertEqual(rc, 2, out)
        self.assert_back_to_the_original()
        self.assert_configuration_restored()
        ups = [s for v, s in self.host.verbs() if v == "up"]
        self.assertEqual(ups, ["tunnel", "dl", "idx", "sub", "tunnel", "dl", "idx", "sub"], "update in order, then rollback in the same order")

    def test_a_control_failing_after_the_parent_stops_before_the_dependants(self):
        self.host.leak_images.add(NEW_TUNNEL)
        rc, out = self.run_group()
        self.assertEqual(rc, 2, out)
        self.assertIn("after the parent", out)
        self.assertEqual([s for v, s in self.host.verbs() if v == "up"][:2], ["tunnel", "tunnel"])
        self.assert_back_to_the_original()

    def test_a_control_failing_once_everything_is_recreated_rolls_back(self):
        self.host.dependant_leak_images.add(NEW_SUB)         # healthy, the right image, but it leaves outside the tunnel
        rc, out = self.run_group()
        self.assertEqual(rc, 2, out)
        self.assertIn("no_leak", out)
        self.assert_back_to_the_original()

    def test_a_member_without_a_new_image_that_comes_back_as_another_image_is_a_failure(self):
        def rebuilt():
            self.host.ids[f"{R}idx:1"] = "sha256:rebuilt-under-the-same-tag"
        self.host.hooks[("up", "idx")] = rebuilt
        rc, out = self.run_group()
        self.assertEqual(rc, 4, out)                        # and the rollback cannot bring the old image ID back either
        self.assertIn("another image", out)

    def test_a_rollback_that_cannot_be_verified_is_loud(self):
        self.configure(notifications={"channels": [{"type": "webhook", "url": "https://hooks.example.test/x"}]})
        self.host.unhealthy_images.update({NEW_SUB, f"{R}idx:1"})
        self.host.hooks[("up", "sub")] = lambda: None
        with mock.patch.object(groupapply.notify, "deliver", return_value={"delivered": [], "queued": [], "given_up": []}) as deliver:
            # idx:1 is unhealthy from the start: let the controls before pass by only breaking it once the update runs
            self.host.unhealthy_images.discard(f"{R}idx:1")
            self.host.hooks[("up", "sub")] = lambda: self.host.unhealthy_images.add(f"{R}idx:1")
            rc, out = self.run_group()
        self.assertEqual(rc, 4, out)
        self.assertIn("ROLLBACK FAILED: CHECK BY HAND", out)
        self.assertEqual(self.journal()[-1]["result"], "rollback FAILED: CHECK BY HAND")
        self.assertIn("rollback-failed", deliver.call_args[0][0][0]["key"])

    def test_a_restore_failure_is_loud_and_leaves_that_member_stopped(self):
        self.migrate_on("dl")
        self.host.unhealthy_images.add(NEW_SUB)

        def damage_the_backup():
            self.host.hooks.pop(("up", "sub"), None)
            self.write(os.path.join(self.backups()[0], "dl", "0", "settings.json"), "damaged")
        self.host.hooks[("up", "sub")] = damage_the_backup
        rc, out = self.run_group()
        self.assertEqual(rc, 4, out)
        self.assertIn("RESTORE FAILED for dl", out)
        self.assertFalse(self.host.c["dl"]["running"], "an old image is not started on a configuration that could not be restored")
        self.assertTrue(self.host.c["idx"]["running"])
        self.assertEqual(self.read(os.path.join(self.dl_cfg, "settings.json")), '{"version": 2}', "a damaged backup is not copied over the live directory")
        self.assertTrue(os.path.isdir(self.backups()[0]), "the backup is kept")

    def test_a_member_that_cannot_be_stopped_is_a_failure_and_the_others_are_started_again(self):
        self.host.stop_fails.add("dl")
        rc, out = self.run_group()
        self.assertEqual(rc, 2, out)
        self.assert_back_to_the_original()

    def test_after_a_rollback_the_next_apply_is_not_blocked(self):
        self.host.fail_up_images.add(NEW_TUNNEL)
        self.assertEqual(self.run_group()[0], 2)
        self.host.fail_up_images.clear()
        self.assertEqual(self.run_group()[0], 0)


class InterruptionAndResume(GroupCase):
    def interrupt_at(self, verb, service):
        def boom():
            self.host.hooks.pop((verb, service))
            raise KeyboardInterrupt()
        self.host.hooks[(verb, service)] = boom
        with self.assertRaises(KeyboardInterrupt):
            self.run_group()

    def test_an_interruption_is_never_silent_the_next_apply_is_refused(self):
        self.interrupt_at("up", "idx")
        self.assertIsNone(self.journal()[-1]["result"])
        rc, out = self.run_group()
        self.assertEqual(rc, 1)
        self.assertIn("--resume", out)

    def test_the_lock_is_free_after_an_interruption(self):
        self.interrupt_at("up", "idx")
        with gate.applying(self.cfg, "check"):
            pass

    def test_resume_after_an_interruption_in_the_middle_of_the_update(self):
        self.interrupt_at("up", "idx")
        self.assertEqual(self.images()["tunnel"], NEW_TUNNEL)
        rc, out = self.run_group("--resume")
        self.assertEqual(rc, 0, out)
        self.assert_back_to_the_original()
        self.assertEqual(self.journal()[-1]["result"], "rollback ok")
        self.assertEqual(self.run_group()[0], 0, "and the group can be applied again")

    def test_resume_after_an_interruption_while_members_were_stopped(self):
        self.interrupt_at("stop", "dl")
        self.assertFalse(self.host.c["idx"]["running"])
        rc, out = self.run_group("--resume")
        self.assertEqual(rc, 0, out)
        self.assert_back_to_the_original()

    def test_resume_with_nothing_unfinished_does_nothing(self):
        rc, out = self.run_group("--resume")
        self.assertEqual(rc, 0)
        self.assert_nothing_changed()

    def test_an_unreadable_journal_refuses(self):
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        self.write(os.path.join(self.cfg["state_dir"], groupapply.JOURNAL), "{ torn")
        rc, out = self.run_group()
        self.assertEqual(rc, 1)
        self.assert_nothing_changed()


UNFINISHED = {"id": "proj-tunnel-1-20261120-000000", "result": None, "backup_root": "/nowhere/group-proj-tunnel-1-20261120-000000"}
WRONG_SHAPE = {                                          # valid JSON, but not a list of objects
    "an object": '{"result": null}',
    "a list of strings": '["x"]',
    "a list with a null": "[null]",
    "a good entry followed by a bad one": json.dumps([UNFINISHED, "x"]),
    "a number": "3",
    "a string": '"unfinished"',
}


class JournalOfTheWrongShape(GroupCase):
    """A journal that is valid JSON but not a list of objects used to be read as empty, so an unfinished apply recorded in a damaged file
    was ignored and the next apply went ahead. It is refused like a torn file."""

    def put(self, text):
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        self.write(os.path.join(self.cfg["state_dir"], groupapply.JOURNAL), text)

    def old_backup(self):
        path = os.path.join(self.cfg["backup_dir"], "group-vpn-1-20260101-000000")
        os.makedirs(path, exist_ok=True)
        long_ago = time.time() - 30 * 86400
        os.utime(path, (long_ago, long_ago))
        return path

    def purge(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = group.main(["--purge"], self.host)
        return rc, out.getvalue()

    def test_reading_it_raises(self):
        for name, text in WRONG_SHAPE.items():
            with self.subTest(name):
                self.put(text)
                with self.assertRaises(ValueError):
                    groupapply._journal(self.cfg)
                with self.assertRaises(ValueError):
                    groupapply.unfinished(self.cfg)

    def test_a_missing_journal_and_a_list_of_objects_still_read(self):
        self.assertEqual(groupapply._journal(self.cfg), [])
        self.put("[]")
        self.assertEqual(groupapply._journal(self.cfg), [])
        self.put(json.dumps([UNFINISHED]))
        self.assertEqual(groupapply.unfinished(self.cfg), UNFINISHED)

    def test_apply_is_refused_and_changes_nothing(self):
        for name, text in WRONG_SHAPE.items():
            with self.subTest(name):
                self.put(text)
                rc, out = self.run_group()
                self.assertEqual(rc, 1, out)
                self.assertIn("REFUSED", out)
                self.assert_nothing_changed()
                self.assertEqual(self.backups(), [])

    def test_resume_is_refused_and_changes_nothing(self):
        for name, text in WRONG_SHAPE.items():
            with self.subTest(name):
                self.put(text)
                rc, out = self.run_group("--resume")
                self.assertEqual(rc, 1, out)
                self.assertIn("cannot be read", out)
                self.assert_nothing_changed()

    def test_the_plan_says_it_is_not_ready(self):
        for name, text in WRONG_SHAPE.items():
            with self.subTest(name):
                self.put(text)
                rc, out = self.run_group("--plan")
                self.assertEqual(rc, 1, out)
                self.assertIn("NOT READY", out)

    def test_purge_is_refused_and_deletes_nothing(self):
        for name, text in WRONG_SHAPE.items():
            with self.subTest(name):
                self.put(text)
                old = self.old_backup()
                rc, out = self.purge()
                self.assertEqual(rc, 1, out)
                self.assertIn("cannot be read", out)
                self.assertTrue(os.path.isdir(old), "the backup that an unfinished apply may need is still there")

    def test_purge_refuses_when_an_entry_to_protect_names_no_backup(self):
        """The set of backups to keep must not become empty by accident: an unfinished apply, or a failed rollback, without a usable path."""
        for name, entry in {"unfinished, no path": {"id": "a", "result": None},
                            "unfinished, empty path": {"id": "a", "result": None, "backup_root": ""},
                            "unfinished, path not a string": {"id": "a", "result": None, "backup_root": 3},
                            "rollback failed, no path": {"id": "a", "result": "rollback FAILED: CHECK BY HAND"}}.items():
            with self.subTest(name):
                self.put(json.dumps([entry]))
                old = self.old_backup()
                rc, out = self.purge()
                self.assertEqual(rc, 1, out)
                self.assertIn("no backup path", out)
                self.assertTrue(os.path.isdir(old))

    def test_purge_still_works_with_a_journal_of_finished_applies(self):
        self.put(json.dumps([{"id": "a", "result": "ok"}, {"id": "b", "result": "rollback ok", "backup_root": "/nowhere/x"}]))
        old = self.old_backup()
        rc, out = self.purge()
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(old))


class Purge(GroupCase):
    def test_old_backups_are_deleted_recent_and_unfinished_ones_are_kept(self):
        d = self.cfg["backup_dir"]
        os.makedirs(d)
        old, recent, other = (os.path.join(d, n) for n in ("group-vpn-1-20260101-000000", "group-vpn-1-20261120-000000", "20260101-0000"))
        for p in (old, recent, other):
            os.mkdir(p)
        long_ago = time.time() - 30 * 86400
        os.utime(old, (long_ago, long_ago))
        os.utime(other, (long_ago, long_ago))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = group.main(["--purge"], self.host)
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(os.listdir(d)), ["20260101-0000", "group-vpn-1-20261120-000000"], "database dumps of rpl patch are not touched")

    def test_the_backup_of_an_unfinished_apply_is_kept_whatever_its_age(self):
        def boom():
            raise KeyboardInterrupt()
        self.host.hooks[("up", "idx")] = boom
        with self.assertRaises(KeyboardInterrupt):
            self.run_group()
        root = self.backups()[0]
        long_ago = time.time() - 30 * 86400
        os.utime(root, (long_ago, long_ago))
        with contextlib.redirect_stdout(io.StringIO()):
            group.main(["--purge"], self.host)
        self.assertTrue(os.path.isdir(root))


    def aged_backup_after(self, hooks=None):
        """Run an apply that fails as set up, make its backup 30 days old, purge, and say whether the backup survived."""
        self.host.unhealthy_images.add(NEW_SUB)
        self.host.hooks.update(hooks or {})
        rc, _ = self.run_group()
        root = self.backups()[0]
        long_ago = time.time() - 30 * 86400
        os.utime(root, (long_ago, long_ago))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            group.main(["--purge"], self.host)
        return rc, os.path.isdir(root), out.getvalue()

    def test_the_backup_of_a_rollback_that_failed_is_kept_whatever_its_age(self):
        # the journal says CHECK BY HAND: this backup is the only copy of the original configuration
        rc, kept, out = self.aged_backup_after({("up", "sub"): lambda: self.host.unhealthy_images.add(f"{R}idx:1")})
        self.assertEqual(rc, 4)
        self.assertTrue(kept)
        self.assertIn("1 kept", out)
        self.assertIn("CHECK BY HAND", out)

    def test_the_backup_of_a_rollback_that_succeeded_is_deleted_after_the_retention(self):
        rc, kept, _ = self.aged_backup_after()
        self.assertEqual(rc, 2)
        self.assertFalse(kept)


class OneMessagePerApply(GroupCase):
    """The messages of the group apply are keyed on the journal entry of THAT apply. `notify.deliver` sends one message per key, forever: a
    key built from the plan alone silenced every later apply of the same plan, which is exactly what an interruption plus `--resume` gives.

    The delivery is the real `notify.deliver` (with its `notifs.json`); only the channel is a double that records the texts."""

    def setUp(self):
        super().setUp()
        self.configure(notifications={"channels": [{"type": "webhook", "url": "https://hooks.example.test/x"}]})
        self.sent = []
        channel = mock.patch.dict(groupapply.notify.CHANNELS, {"webhook": lambda ch, text, poster: self.sent.append(text) or 200})
        channel.start()
        self.addCleanup(channel.stop)

    def texts(self, word):
        return [t for t in self.sent if word in t]

    def interrupt(self):
        def boom():
            self.host.hooks.pop(("up", "idx"))
            raise KeyboardInterrupt()
        self.host.hooks[("up", "idx")] = boom
        with self.assertRaises(KeyboardInterrupt):
            self.run_group()

    def tell(self, **lists):
        """What `_tell` prints when `notify.deliver` answers with these lists."""
        answer = {"delivered": [], "queued": [], "given_up": []}
        answer.update(lists)
        out = io.StringIO()
        with mock.patch.object(groupapply.notify, "deliver", return_value=answer), contextlib.redirect_stdout(out):
            groupapply._tell(self.cfg, "k", "t")
        return out.getvalue()

    def test_two_interrupted_applies_of_the_same_plan_each_announce_their_rollback(self):
        fingerprints = []
        for _ in range(2):
            self.interrupt()
            fingerprints.append(self.journal()[-1]["plan"]["fingerprint"])
            self.assertEqual(self.run_group("--resume")[0], 0)
        self.assertEqual(fingerprints[0], fingerprints[1], "the same plan both times: that is the case")
        self.assertEqual(len(self.texts("rolled back")), 2)

    def test_two_failed_applies_of_the_same_plan_each_announce_their_rollback(self):
        self.host.fail_up_images.add(NEW_TUNNEL)
        for _ in range(2):
            self.assertEqual(self.run_group()[0], 2)
        self.assertEqual(len(self.texts("rolled back")), 2)

    def test_two_failed_rollbacks_of_the_same_plan_are_both_announced(self):
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        plan = {"parent": PARENT, "fingerprint": "f" * 16}
        with mock.patch.object(groupapply, "_rollback", return_value=["dl: could not be restored"]), contextlib.redirect_stdout(io.StringIO()):
            for n in (1, 2):
                entry = {"id": f"{PARENT}-2026112{n}-000000", "plan": plan, "result": None,
                         "backup_root": os.path.join(self.dir, "backups", f"group-{n}")}
                self.assertEqual(groupapply._finish_rollback(entry, self.cfg, self.host, "a control failed"), 4)
        self.assertEqual(len(self.texts("rollback failed")), 2, "a rollback that failed (CHECK BY HAND) is never silent")

    def key_of_the_last_message(self, *flags):
        answer = {"delivered": [], "queued": [], "given_up": []}
        with mock.patch.object(groupapply.notify, "deliver", return_value=answer) as deliver:
            self.run_group(*flags)
        return deliver.call_args[0][0][0]["key"]

    def test_the_key_of_the_success_message_names_the_apply(self):
        key = self.key_of_the_last_message()
        entry_id = self.journal()[-1]["id"]
        self.assertIn(entry_id, key)
        self.assertTrue(key.endswith(":ok"), key)
        self.assertGreater(len(entry_id), len(PARENT), "the identifier carries a time stamp, not only the parent")

    def test_the_key_of_the_rollback_message_names_the_apply(self):
        self.host.fail_up_images.add(NEW_TUNNEL)
        key = self.key_of_the_last_message()
        self.assertIn(self.journal()[-1]["id"], key)
        self.assertTrue(key.endswith(":rolled-back"), key)

    def test_the_key_of_the_failed_rollback_message_names_the_apply(self):
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        entry = {"id": f"{PARENT}-20261121-000000", "plan": {"parent": PARENT, "fingerprint": "f" * 16}, "result": None,
                 "backup_root": os.path.join(self.dir, "backups", "group-1")}
        answer = {"delivered": [], "queued": [], "given_up": []}
        with mock.patch.object(groupapply, "_rollback", return_value=["dl: could not be restored"]), contextlib.redirect_stdout(io.StringIO()), \
                mock.patch.object(groupapply.notify, "deliver", return_value=answer) as deliver:
            groupapply._finish_rollback(entry, self.cfg, self.host, "a control failed")
        key = deliver.call_args[0][0][0]["key"]
        self.assertIn(entry["id"], key)
        self.assertTrue(key.endswith(":rollback-failed"), key)

    def test_a_message_already_delivered_prints_nothing(self):
        self.assertEqual(self.tell(), "", "notify.deliver leaves an already delivered key out of its lists")
        self.assertEqual(self.tell(delivered=["k"]), "")

    def test_telling_the_same_key_twice_is_quiet_the_second_time(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            groupapply._tell(self.cfg, "k", "t")
            groupapply._tell(self.cfg, "k", "t")
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(self.sent, ["t"], "one message per key")

    def test_a_queued_message_says_it_is_queued(self):
        self.assertIn("queued", self.tell(queued=["k"]))

    def test_a_message_given_up_says_so_and_not_that_it_is_queued(self):
        out = self.tell(given_up=["k"])
        self.assertIn("given up", out)
        self.assertNotIn("queued", out)


class JournalRetention(GroupCase):
    """The journal keeps the last 100 entries; an open incident (an apply with no result, a failed rollback) must not be dropped by newer ones."""

    def put(self, entries):
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        self.write(os.path.join(self.cfg["state_dir"], groupapply.JOURNAL), json.dumps(entries))

    def finished(self, n):
        return [{"id": f"done-{i}", "ts": 1000.0 + i, "result": "ok", "plan": {"parent": "p"}} for i in range(n)]

    def test_old_open_incidents_survive_a_hundred_newer_entries(self):
        unfinished = {"id": "old-unfinished", "ts": 1.0, "result": None, "plan": {"parent": "p"}, "backup_root": "/nowhere/a"}
        failed = {"id": "old-failed", "ts": 2.0, "result": "rollback FAILED: CHECK BY HAND", "plan": {"parent": "p"}, "backup_root": "/nowhere/b"}
        self.put([unfinished, failed] + self.finished(150))
        groupapply._record(self.cfg, {"id": "new", "ts": 9999.0, "result": "ok", "plan": {"parent": "p"}})
        ids = [e["id"] for e in groupapply._journal(self.cfg)]
        self.assertIn("old-unfinished", ids)
        self.assertIn("old-failed", ids)
        self.assertEqual(len(ids), 2 + 100)
        self.assertEqual(ids[-1], "new")

    def test_old_finished_entries_are_still_dropped(self):
        self.put(self.finished(150))
        groupapply._record(self.cfg, {"id": "new", "ts": 9999.0, "result": "ok", "plan": {"parent": "p"}})
        ids = [e["id"] for e in groupapply._journal(self.cfg)]
        self.assertEqual(len(ids), 100)
        self.assertNotIn("done-0", ids)

    def test_a_rollback_that_succeeded_is_not_kept_for_ever(self):
        self.put([{"id": "old-ok", "ts": 1.0, "result": "rollback ok", "plan": {"parent": "p"}}] + self.finished(150))
        groupapply._record(self.cfg, {"id": "new", "ts": 9999.0, "result": "ok", "plan": {"parent": "p"}})
        self.assertNotIn("old-ok", [e["id"] for e in groupapply._journal(self.cfg)])

    def test_a_journal_below_the_limit_is_kept_whole(self):
        self.put(self.finished(10))
        groupapply._record(self.cfg, {"id": "new", "ts": 9999.0, "result": "ok", "plan": {"parent": "p"}})
        self.assertEqual(len(groupapply._journal(self.cfg)), 11)


class UnfinishedEntryIncomplete(GroupCase):
    """`--resume` indexes the entry's id, plan and backup path. An entry that lacks one used to end in a traceback, with the incident still open
    and nothing said to the human: it is now refused in words."""

    def put(self, entry):
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        self.write(os.path.join(self.cfg["state_dir"], groupapply.JOURNAL), json.dumps([entry]))

    def good(self):
        return {"id": "p-20261120-000000", "ts": 1000.0, "result": None, "state": "changing", "backup_root": "/nowhere/backup",
                "plan": {"parent": "p", "compose": "/nowhere/compose.yaml", "members": [{"service": "s", "from": "a", "to": "b"}]}}

    def test_each_missing_or_malformed_piece_is_refused_in_words(self):
        cases = {"no id": lambda e: e.pop("id"),
                 "an id that is not a string": lambda e: e.update(id=3),
                 "no plan": lambda e: e.pop("plan"),
                 "a plan that is not an object": lambda e: e.update(plan=[1]),
                 "no parent": lambda e: e["plan"].pop("parent"),
                 "no compose file": lambda e: e["plan"].pop("compose"),
                 "no members": lambda e: e["plan"].pop("members"),
                 "members that are not a list": lambda e: e["plan"].update(members="x"),
                 "a member that is not an object": lambda e: e["plan"].update(members=["x"]),
                 "no backup path": lambda e: e.pop("backup_root"),
                 "a backup path that is not a string": lambda e: e.update(backup_root=3)}
        for name, damage in cases.items():
            with self.subTest(name):
                e = self.good()
                damage(e)
                self.put(e)
                rc, out = self.run_group("--resume")
                self.assertEqual(rc, 1, out)
                self.assertIn("REFUSED", out)
                self.assertIn("cannot be resumed", out)
                self.assert_nothing_changed()

    def test_a_complete_entry_is_still_resumed(self):
        self.assertEqual(groupapply._resume_problem(self.good()), None)
class RetriedByTheCollector(GroupCase):
    """The group apply gives its "updated" and "rolled back" messages to `deliver` once. `rpl notify` produces them again from the journal, with
    the same key and the same text, so a message whose first delivery failed is retried and one that arrived is not sent twice."""

    def setUp(self):
        super().setUp()
        self.configure(notifications={"channels": [{"type": "webhook", "url": "https://hooks.example.test/x"}]})
        self.sent, self.code = [], 200
        channel = mock.patch.dict(groupapply.notify.CHANNELS, {"webhook": lambda ch, text, poster: self.sent.append(text) or self.code})
        channel.start()
        self.addCleanup(channel.stop)

    def notifs(self):
        with open(os.path.join(self.cfg["state_dir"], "notifs.json")) as f:
            return json.load(f)

    def later(self):
        return self.journal()[-1]["ts"] + notify.RETRY_CAP_S + 60

    def collect(self):
        return events.group_result_events(self.cfg, self.journal()[-1]["ts"] + 60)

    def run_collector(self, at):
        events.record(self.cfg, "ok", "", lambda: at)                         # a recent nightly record: otherwise `rpl notify` also reports that
        with contextlib.redirect_stdout(io.StringIO()):
            return events.run(self.cfg, None, lambda: at)

    def test_the_success_message_is_reproduced_with_the_same_key_and_text(self):
        self.assertEqual(self.run_group()[0], 0)
        (key,) = self.notifs()
        self.assertEqual(self.collect(), [{"key": key, "text": self.sent[0]}])

    def test_the_rollback_message_is_reproduced_with_the_same_key_and_text(self):
        self.host.fail_up_images.add(NEW_TUNNEL)
        self.assertEqual(self.run_group()[0], 2)
        (key,) = self.notifs()
        self.assertEqual(self.collect(), [{"key": key, "text": self.sent[0]}])

    def test_a_message_whose_first_delivery_failed_is_sent_by_the_collector_once(self):
        self.code = 500
        self.host.fail_up_images.add(NEW_TUNNEL)
        self.run_group()
        self.assertEqual(len(self.sent), 1)
        self.code = 200
        self.run_collector(self.later())
        self.run_collector(self.later() + 10)
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sent[1], self.sent[0])

    def test_a_message_that_arrived_is_not_sent_again(self):
        self.run_group()
        self.run_collector(self.later())
        self.assertEqual(len(self.sent), 1)

    def test_a_result_older_than_the_window_is_not_replayed(self):
        self.run_group()
        self.assertEqual(events.group_result_events(self.cfg, self.journal()[-1]["ts"] + 73 * 3600), [])

    def test_a_failed_rollback_is_left_to_rpl_watch(self):
        entry = {"id": "a", "ts": 1000.0, "result": "rollback FAILED: CHECK BY HAND", "why": "x", "plan": {"parent": "p", "members": []}}
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        self.write(os.path.join(self.cfg["state_dir"], groupapply.JOURNAL), json.dumps([entry]))
        self.assertEqual(events.group_result_events(self.cfg, 1100.0), [])

    def test_a_journal_that_cannot_be_read_gives_nothing_and_does_not_raise(self):
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        for text in ("{broken", '{"result": null}', '["x"]', "[null]"):
            self.write(os.path.join(self.cfg["state_dir"], groupapply.JOURNAL), text)
            self.assertEqual(events.group_result_events(self.cfg, 1100.0), [])      # `rpl watch` is the one that says it

    def test_an_entry_without_an_id_or_a_plan_is_skipped(self):
        good = {"id": "g", "ts": 1000.0, "result": "ok", "plan": {"parent": "p", "members": [{"service": "s", "to": "img:2"}]}}
        os.makedirs(self.cfg["state_dir"], exist_ok=True)
        self.write(os.path.join(self.cfg["state_dir"], groupapply.JOURNAL),
                   json.dumps([{"ts": 1000.0, "result": "ok", "plan": {"parent": "p"}}, {"id": "n", "ts": 1000.0, "result": "ok"}, good]))
        self.assertEqual([e["key"] for e in events.group_result_events(self.cfg, 1100.0)], ["group:g:ok"])


class TreeSockets(unittest.TestCase):
    """A Unix socket in a configuration directory (qBittorrent's ipc-socket) is a runtime artifact the application recreates; it cannot be copied.
    Only a socket named by the owner is left out: any other special file, or a declared path that is not a socket, is still refused."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.realpath(self.tmp.name)
        os.makedirs(os.path.join(self.root, "sub"))
        with open(os.path.join(self.root, "settings.conf"), "w") as f:
            f.write("a = 1\n")
        self.sock = os.path.join(self.root, "sub", "ipc-socket")
        s = __import__("socket").socket(__import__("socket").AF_UNIX, __import__("socket").SOCK_STREAM)
        s.bind(self.sock)
        s.close()                                                            # the file stays, as after the process of a real application

    def test_a_socket_is_refused_by_default(self):
        size, problem = groupapply.tree_problem(self.root)
        self.assertIn("special file", problem)

    def test_a_declared_socket_is_left_out_and_not_counted(self):
        size, problem = groupapply.tree_problem(self.root, ["sub/ipc-socket"])
        self.assertIsNone(problem)
        self.assertEqual(size, len("a = 1\n"))

    def test_another_socket_that_was_not_declared_is_still_refused(self):
        other = os.path.join(self.root, "other.sock")
        s = __import__("socket").socket(__import__("socket").AF_UNIX, __import__("socket").SOCK_STREAM)
        s.bind(other)
        s.close()
        size, problem = groupapply.tree_problem(self.root, ["sub/ipc-socket"])
        self.assertIn("other.sock", problem)

    def test_a_declared_path_that_is_not_a_socket_is_refused(self):
        size, problem = groupapply.tree_problem(self.root, ["sub/ipc-socket", "settings.conf"])      # the socket is declared too: only the file is wrong
        self.assertIn("not a socket", problem)

    def test_a_declared_path_that_does_not_exist_is_fine(self):
        os.unlink(self.sock)
        size, problem = groupapply.tree_problem(self.root, ["sub/ipc-socket"])
        self.assertIsNone(problem)

    def test_a_pipe_is_refused_even_when_declared(self):
        os.unlink(self.sock)
        os.mkfifo(self.sock)
        size, problem = groupapply.tree_problem(self.root, ["sub/ipc-socket"])
        self.assertIn("not a socket", problem)

    def test_the_copy_and_the_read_back_leave_the_socket_out_and_agree(self):
        dst = os.path.join(self.root + "-copy")
        self.addCleanup(shutil.rmtree, dst, True)
        manifest = groupapply.copy_tree(self.root, dst, ["sub/ipc-socket"])
        self.assertNotIn("./sub/ipc-socket", manifest)
        self.assertIn("./settings.conf", manifest)
        self.assertFalse(os.path.lexists(os.path.join(dst, "sub", "ipc-socket")))
        self.assertEqual(groupapply.read_tree(dst), manifest)
        self.assertEqual(groupapply.read_tree(self.root, ["sub/ipc-socket"]), manifest)

    def test_the_copy_does_not_skip_a_pipe_even_when_its_path_is_declared(self):
        os.unlink(self.sock)
        os.mkfifo(self.sock)
        dst = os.path.join(self.root + "-copy3")
        self.addCleanup(shutil.rmtree, dst, True)
        with self.assertRaises(OSError):
            groupapply.copy_tree(self.root, dst, ["sub/ipc-socket"])

    def test_the_copy_without_the_declaration_still_fails(self):
        dst = os.path.join(self.root + "-copy2")
        self.addCleanup(shutil.rmtree, dst, True)
        with self.assertRaises(OSError):
            groupapply.copy_tree(self.root, dst)


class SocketsInConfiguration(GroupCase):
    def add_socket(self, directory, name="app.sock"):
        sk = __import__("socket")
        s = sk.socket(sk.AF_UNIX, sk.SOCK_STREAM)
        s.bind(os.path.join(directory, name))
        s.close()

    def test_without_the_option_the_plan_is_refused_and_says_how_to_declare_it(self):
        self.add_socket(self.idx_cfg)
        rc, out = self.run_group("--plan")
        self.assertEqual(rc, 1, out)
        self.assertIn("special file", out)
        self.assertIn("ignore_sockets", out)
        self.assertIn("services.idx", out)

    def test_with_the_option_the_plan_is_ready_and_lists_what_is_left_out(self):
        self.add_socket(self.idx_cfg)
        self.configure(services={"idx": {"ignore_sockets": ["app.sock"]}})
        rc, out = self.run_group("--plan")
        self.assertEqual(rc, 0, out)
        self.assertIn("PLAN READY", out)
        self.assertIn("socket left out of the backup", out)
        self.assertIn("app.sock", out)

    def test_the_option_changes_the_fingerprint(self):
        before = self.fingerprint()
        self.configure(services={"idx": {"ignore_sockets": ["app.sock"]}})
        self.assertNotEqual(self.fingerprint(), before)

    def test_without_the_option_the_fingerprint_is_the_one_it_was(self):
        self.assertEqual(self.fingerprint(), self.fingerprint())
        self.configure(services={"idx": {"quiesce": "stop"}})
        before = self.fingerprint()
        self.configure(services={"idx": {"quiesce": "stop", "ignore_sockets": []}})
        self.assertEqual(self.fingerprint(), before)                                      # an empty list is no declaration

    def test_the_apply_backs_up_everything_but_the_socket_and_the_rollback_restores_the_rest(self):
        self.add_socket(self.idx_cfg)
        self.configure(services={"idx": {"ignore_sockets": ["app.sock"]}})
        self.host.fail_up_images.add(NEW_TUNNEL)
        rc, out = self.run_group()
        self.assertEqual(rc, 2, out)                                                      # failed and rolled back
        self.assertIn("rollback ok", out)
        self.assertEqual(self.read(os.path.join(self.idx_cfg, "idx.conf")), "a = 1\n")
        names = [n for _, _, files in os.walk(self.cfg["backup_dir"]) for n in files]
        self.assertIn("idx.conf", names)
        self.assertNotIn("app.sock", names)

    def test_a_declared_path_that_is_a_regular_file_is_refused(self):
        self.configure(services={"idx": {"ignore_sockets": ["idx.conf"]}})
        rc, out = self.run_group("--plan")
        self.assertEqual(rc, 1, out)
        self.assertIn("not a socket", out)

    def test_bad_declarations_are_refused_in_words(self):
        for name, value in (("an absolute path", ["/etc/x"]), ("a path leaving the directory", ["../x"]), ("an empty path", [""]),
                            ("not a list", "app.sock"), ("a list of non-strings", [3]), ("a path with a nul", ["a\x00b"])):
            with self.subTest(name):
                self.configure(services={"idx": {"ignore_sockets": value}})
                rc, out = self.run_group("--plan")
                self.assertEqual(rc, 1, out)
                self.assertIn("ignore_sockets must be a list of paths relative to the mounted directory", out)       # the validation, not a later refusal


class TreeCopy(unittest.TestCase):
    def test_a_copy_reads_back_identical_and_a_changed_byte_or_mode_is_seen(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, "src"), os.path.join(d, "dst")
            os.makedirs(os.path.join(src, "sub"))
            with open(os.path.join(src, "sub", "f"), "w") as f:
                f.write("abc")
            os.chmod(os.path.join(src, "sub"), 0o750)
            manifest = groupapply.copy_tree(src, dst)
            self.assertEqual(groupapply.read_tree(dst), manifest)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(dst, "sub")).st_mode), 0o750)
            self.assertEqual(os.stat(os.path.join(dst, "sub", "f")).st_mtime_ns, os.stat(os.path.join(src, "sub", "f")).st_mtime_ns)
            os.chmod(os.path.join(dst, "sub", "f"), 0o600)
            self.assertNotEqual(groupapply.read_tree(dst), manifest)
            os.chmod(os.path.join(dst, "sub", "f"), 0o644)
            with open(os.path.join(dst, "sub", "f"), "w") as f:
                f.write("abd")
            self.assertNotEqual(groupapply.read_tree(dst), manifest)

    def test_a_single_file_is_copied_and_restored_like_a_directory(self):
        with tempfile.TemporaryDirectory() as d:
            src, bak = os.path.join(d, "tunnel.conf"), os.path.join(d, "bak")
            with open(src, "w") as f:
                f.write("v1")
            os.chmod(src, 0o640)
            manifest = groupapply.copy_tree(src, bak)
            with open(src, "w") as f:
                f.write("v2")
            groupapply.restore_tree(bak, manifest, src)
            self.assertEqual((open(src).read(), stat.S_IMODE(os.stat(src).st_mode)), ("v1", 0o640))
            self.assertEqual(sorted(os.listdir(d)), ["bak", "tunnel.conf"])


if __name__ == "__main__":
    unittest.main()
