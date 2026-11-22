"""`rpl patch` asks Docker, not only its own compose file, whether the service belongs to an update group.

The defect: a dependant declared in ANOTHER compose file, or started with `docker run --network container:<parent>`, is invisible in the
compose file of the parent, so the parent could be patched alone and every dependant cut off its network namespace.
"""
import json

from rpl import gate, config

from .test_patch_integration import PatchCase

DEPENDANT = {"name": "dl-1", "mode": "container:cid-1"}                  # shares the network of the service under test (ID cid-1)
OUTSIDE_PARENT = {"name": "vpn-1", "id": "vpn-id"}


class GroupSeenOnlyByDocker(PatchCase):
    def assert_refused_untouched(self, host, rc, out):
        self.assertEqual(rc, 3, out)
        self.assertIn("REFUSED", out)
        self.assertIn("update group", out)
        self.assertEqual(self.compose_text(), self.original)
        self.assertEqual([k for k in host.kinds() if k in ("snapshot", "dump", "validate", "dry-run", "up", "route")], [], "read-only queries only")

    def test_a_dependant_from_another_compose_project_refuses_the_parent(self):
        host = self.host(others=[DEPENDANT])
        self.assert_refused_untouched(host, *self.run_patch(host))

    def test_a_dependant_that_names_the_parent_instead_of_its_id(self):
        host = self.host(container="proj-app-1", others=[{"name": "dl-1", "mode": "container:proj-app-1"}])
        self.assert_refused_untouched(host, *self.run_patch(host))

    def test_a_stopped_dependant_still_counts(self):
        host = self.host(others=[dict(DEPENDANT, running=False)])
        self.assert_refused_untouched(host, *self.run_patch(host))

    def test_a_service_whose_parent_lives_outside_its_compose_file_is_refused(self):
        host = self.host(docker_mode="container:vpn-id", others=[OUTSIDE_PARENT])
        rc, out = self.run_patch(host)
        self.assert_refused_untouched(host, rc, out)
        self.assertIn("vpn-1", out)

    def test_dry_does_not_bypass_the_refusal(self):
        host = self.host(others=[DEPENDANT])
        self.assert_refused_untouched(host, *self.run_patch(host, "--dry"))

    def test_the_declared_policy_and_reason_are_shown_and_no_policy_allows_it_yet(self):
        for policy in ("never", "ask", "auto"):
            with self.subTest(policy=policy):
                self.use_config(groups={"app": {"policy": policy, "reason": "VPN: by hand only", "confirmed": True}})
                host = self.host(others=[DEPENDANT])
                rc, out = self.run_patch(host)
                self.assert_refused_untouched(host, rc, out)
                self.assertIn("policy " + policy, out)
                self.assertIn("VPN: by hand only", out)

    def test_when_docker_cannot_tell_the_answer_is_refuse(self):
        cases = {"ps fails": {"ps_all_rc": 1}, "inspect fails": {"inspect_all": (1, "")}, "inspect is not JSON": {"inspect_all": (0, "<html>")},
                 "inspect is not a list of containers": {"inspect_all": (0, json.dumps([{"Name": "/x"}]))},
                 "inspect is another JSON": {"inspect_all": (0, json.dumps({"a": 1}))}}
        for name, kw in cases.items():
            with self.subTest(name=name):
                host = self.host(**kw)
                rc, out = self.run_patch(host)
                self.assert_refused_untouched(host, rc, out)
                self.assertIn("cannot be excluded", out)

    def test_a_group_elsewhere_on_the_host_does_not_stop_an_unrelated_service(self):
        host = self.host(others=[OUTSIDE_PARENT, {"name": "dl-1", "mode": "container:vpn-id"}])
        self.assertEqual(self.run_patch(host)[0], 0)

    def test_the_question_is_asked_under_the_shared_lock(self):
        seen = []
        outer = self

        class Watching(type(self.host())):
            def run(inner, cmd, **kw):
                if cmd[:3] == ["docker", "ps", "-aq"]:
                    try:
                        with gate.applying(config.load(), "intruder"):
                            seen.append("free")
                    except gate.NotNow:
                        seen.append("held")
                return super().run(cmd, **kw)

        self.assertEqual(self.run_patch(Watching(outer.compose))[0], 0)
        self.assertEqual(seen, ["held"])
