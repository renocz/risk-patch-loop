import json
import os
import tempfile
import unittest

from rpl import config, inventory, patch, scan


class Scan(unittest.TestCase):
    V = lambda self, cve, sev, fixed="": {"VulnerabilityID": cve, "Severity": sev, "FixedVersion": fixed, "PkgName": "p", "InstalledVersion": "1"}

    def test_classes(self):
        A, B, C = scan.classify({"img": [self.V("CVE-1", "HIGH", "2"), self.V("CVE-2", "HIGH"), self.V("CVE-3", "LOW", "9"), self.V("CVE-4", "MEDIUM")]}, {"CVE-3"})
        self.assertEqual(([r["cve"] for r in A], [r["cve"] for r in B], [r["cve"] for r in C]), (["CVE-1"], ["CVE-3"], ["CVE-2"]))

    def test_kev_counts_even_when_low_and_unfixed(self):
        _, B, _ = scan.classify({"img": [self.V("CVE-9", "LOW")]}, {"CVE-9"})
        self.assertEqual(len(B), 1)

    def test_duplicates_are_counted_once(self):
        A, _, _ = scan.classify({"img": [self.V("CVE-1", "HIGH", "2"), self.V("CVE-1", "HIGH", "2")]}, set())
        self.assertEqual(len(A), 1)

    def test_accepted_findings_are_split_off(self):
        rows = [{"image": "i", "cve": "CVE-1"}, {"image": "i", "cve": "CVE-2"}]
        keep, ok = scan.split_accepted(rows, {"i|CVE-1": "reason"})
        self.assertEqual(([r["cve"] for r in keep], [r["cve"] for r in ok]), (["CVE-2"], ["CVE-1"]))

    def test_unreliable_scan_is_never_ok(self):
        self.assertEqual(scan.scan_failure(1.0, True, [], 5), [])
        self.assertTrue(scan.scan_failure(None, True, [], 5))
        self.assertTrue(scan.scan_failure(100.0, True, [], 5))
        self.assertTrue(scan.scan_failure(1.0, False, [], 5))
        self.assertTrue(scan.scan_failure(1.0, True, ["x"], 5))
        self.assertTrue(scan.scan_failure(1.0, True, [], 0))


class Inventory(unittest.TestCase):
    AUTH = ["auth", "forward"]

    def c(self, labels=None, ports=None, mode="default", mounts=None, privileged=False):
        return {"Config": {"Image": "x/app:1", "Labels": labels or {}}, "Mounts": mounts or [],
                "HostConfig": {"NetworkMode": mode, "PortBindings": ports or {}, "Privileged": privileged}}

    def test_labels_give_host_and_auth(self):
        labels = {"traefik.enable": "true", "traefik.http.routers.a.rule": "Host(`a.example.org`)", "traefik.http.routers.a.middlewares": "myforward@docker"}
        e = inventory.analyse(self.c(labels), {"a.example.org"}, self.AUTH)
        self.assertEqual((e["level"], e["hosts"], e["auth"]), ("internet-auth", ["a.example.org"], True))

    def test_internet_without_auth(self):
        labels = {"traefik.enable": "true", "traefik.http.routers.a.rule": "Host(`a.example.org`)"}
        self.assertEqual(inventory.analyse(self.c(labels), {"a.example.org"}, self.AUTH)["level"], "internet-no-auth")

    def test_internet_is_unknown_without_a_host_list(self):
        labels = {"traefik.enable": "true", "traefik.http.routers.a.rule": "Host(`a.example.org`)"}
        e = inventory.analyse(self.c(labels), None, self.AUTH)
        self.assertEqual(e["internet"], "unknown")
        self.assertEqual(e["level"], "lan-proxy")

    def test_lan_port_vs_localhost(self):
        self.assertEqual(inventory.analyse(self.c(ports={"80/tcp": [{"HostIp": "", "HostPort": "8080"}]}), set(), self.AUTH)["level"], "lan-port")
        self.assertEqual(inventory.analyse(self.c(ports={"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}), set(), self.AUTH)["level"], "localhost")

    def test_host_port_is_reported_not_the_container_port(self):
        e = inventory.analyse(self.c(ports={"8080/tcp": [{"HostIp": "", "HostPort": "9999"}]}), set(), self.AUTH)
        self.assertEqual(e["ports"], ["0.0.0.0:9999->8080/tcp"])

    def test_docker_socket_and_privileged_are_flagged(self):
        e = inventory.analyse(self.c(mounts=[{"Source": "/var/run/docker.sock"}], privileged=True), set(), self.AUTH)
        self.assertEqual(e["sensitive_mounts"], ["/var/run/docker.sock"])
        self.assertIn("privileged", e["rights"])

    def labels(self, *hosts, auth=False, router="a"):
        labels = {"traefik.enable": "true", f"traefik.http.routers.{router}.rule": " || ".join(f"Host(`{h}`)" for h in hosts)}
        if auth:
            labels[f"traefik.http.routers.{router}.middlewares"] = "myforward@docker"
        return labels

    def test_a_host_behind_a_gate_outside_the_labels_is_internet_auth(self):
        """The owner's tunnel puts an access gateway in front of some hosts: nothing in the Traefik labels shows it."""
        e = inventory.analyse(self.c(self.labels("a.example.org")), {"a.example.org"}, self.AUTH, {"a.example.org"})
        self.assertEqual(e["level"], "internet-auth")
        self.assertFalse(e["auth"])                                             # `auth` still says what the labels say
        self.assertTrue(e["gated"])

    def test_a_host_that_is_not_listed_as_gated_is_unchanged(self):
        e = inventory.analyse(self.c(self.labels("a.example.org")), {"a.example.org"}, self.AUTH, {"b.example.org"})
        self.assertEqual((e["level"], e["gated"]), ("internet-no-auth", False))

    def test_no_gated_list_changes_nothing(self):
        for gated in (None, set()):
            e = inventory.analyse(self.c(self.labels("a.example.org")), {"a.example.org"}, self.AUTH, gated)
            self.assertEqual((e["level"], e["gated"]), ("internet-no-auth", False))

    def test_every_host_of_the_container_must_be_gated(self):
        both = self.labels("a.example.org", "b.example.org")
        only_a = inventory.analyse(self.c(both), {"a.example.org", "b.example.org"}, self.AUTH, {"a.example.org"})
        self.assertEqual(only_a["level"], "internet-no-auth")
        all_of_them = inventory.analyse(self.c(both), {"a.example.org", "b.example.org"}, self.AUTH, {"a.example.org", "b.example.org"})
        self.assertEqual(all_of_them["level"], "internet-auth")

    def test_one_router_gated_and_another_not_is_not_gated(self):
        labels = self.labels("a.example.org", router="a")
        labels.update(self.labels("b.example.org", router="b"))
        e = inventory.analyse(self.c(labels), {"a.example.org", "b.example.org"}, self.AUTH, {"a.example.org"})
        self.assertEqual(e["level"], "internet-no-auth")

    def test_a_router_without_a_host_is_not_covered_by_the_gate(self):
        labels = self.labels("a.example.org", router="a")
        labels["traefik.http.routers.b.rule"] = "PathPrefix(`/api`)"                # no host name: nothing to find in the gated list
        e = inventory.analyse(self.c(labels), {"a.example.org"}, self.AUTH, {"a.example.org"})
        self.assertEqual(e["level"], "internet-no-auth")

    def test_a_gate_does_not_double_count_with_a_forward_auth_label(self):
        e = inventory.analyse(self.c(self.labels("a.example.org", auth=True)), {"a.example.org"}, self.AUTH, {"a.example.org"})
        self.assertEqual((e["level"], e["auth"], e["gated"]), ("internet-auth", True, False))

    def test_a_gated_host_that_is_not_published_does_not_become_exposed_or_protected_on_the_lan(self):
        """The gate sits in the tunnel: a request from the LAN straight to the proxy does not pass it."""
        e = inventory.analyse(self.c(self.labels("a.example.org")), set(), self.AUTH, {"a.example.org"})
        self.assertEqual((e["internet"], e["level"]), ("no", "lan-proxy"))
        e = inventory.analyse(self.c(self.labels("a.example.org")), None, self.AUTH, {"a.example.org"})
        self.assertEqual((e["internet"], e["level"]), ("unknown", "lan-proxy"))

    def test_the_hosts_file_reader(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ok = os.path.join(d, "ok.json")
            json.dump(["a.example.org", "b.example.org"], open(ok, "w"))
            self.assertEqual(inventory.read_hosts_file(ok, "gated_hosts_file"), {"a.example.org", "b.example.org"})
            self.assertIsNone(inventory.read_hosts_file(None, "gated_hosts_file"))
            self.assertIsNone(inventory.read_hosts_file(os.path.join(d, "missing.json"), "gated_hosts_file"))
            for name, content in (("broken", "{"), ("object", '{"a": 1}'), ("numbers", "[1, 2]"), ("empty name", '[""]')):
                bad = os.path.join(d, name + ".json")
                open(bad, "w").write(content)
                with self.subTest(name):
                    with self.assertRaises(SystemExit) as cm:
                        inventory.read_hosts_file(bad, "gated_hosts_file")
                    self.assertIn("gated_hosts_file", str(cm.exception))

    def test_the_gated_hosts_file_path_is_resolved_next_to_the_configuration(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, "rpl.json")
            json.dump({"gated_hosts_file": "gated.json", "tunnel_hosts_file": "tunnel.json"}, open(conf, "w"))
            with mock.patch.dict(os.environ, {"RPL_CONFIG": conf}):
                cfg = config.load()
            self.assertEqual(cfg["gated_hosts_file"], os.path.join(os.path.dirname(os.path.abspath(conf)), "gated.json"))
            self.assertEqual(cfg["tunnel_hosts_file"], os.path.join(os.path.dirname(os.path.abspath(conf)), "tunnel.json"))

    def run_inventory(self, tunnel, gated):
        """`rpl inventory` with a fake Docker (two containers), a configuration and its lists on disk; returns (printed text, inventory.json)."""
        import contextlib
        import io
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            conf = {"state_dir": os.path.join(d, "state")}
            if tunnel is not None:
                json.dump(tunnel, open(os.path.join(d, "tunnel.json"), "w"))
                conf["tunnel_hosts_file"] = "tunnel.json"
            if gated is not None:
                json.dump(gated, open(os.path.join(d, "gated.json"), "w"))
                conf["gated_hosts_file"] = "gated.json"
            json.dump(conf, open(os.path.join(d, "rpl.json"), "w"))
            conts = []
            for i, host in enumerate(("a.example.org", "b.example.org")):
                c = self.c(self.labels(host, router=f"r{i}"))
                c.update({"Id": f"id{i}", "Name": f"/app-{i}"})
                conts.append(c)

            def fake_run(cmd, **kw):
                out = " ".join(["id0", "id1"]) if cmd[1] == "ps" else json.dumps(conts)
                return mock.Mock(stdout=out, returncode=0)
            out = io.StringIO()
            with mock.patch.dict(os.environ, {"RPL_CONFIG": os.path.join(d, "rpl.json")}), mock.patch("subprocess.run", fake_run), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(inventory.main([]), 0)
            return out.getvalue(), json.load(open(os.path.join(d, "state", "inventory.json")))

    def test_the_command_reads_both_lists_and_says_how_many_hosts_it_believes(self):
        text, inv = self.run_inventory(["a.example.org", "b.example.org"], ["a.example.org"])
        self.assertEqual(inv["app-0"]["level"], "internet-auth")
        self.assertEqual(inv["app-1"]["level"], "internet-no-auth")
        self.assertIn("1 gated host(s) believed", text)

    def test_the_command_without_a_gated_list_is_what_it_was(self):
        text, inv = self.run_inventory(["a.example.org", "b.example.org"], None)
        self.assertEqual({e["level"] for e in inv.values()}, {"internet-no-auth"})
        self.assertNotIn("gated", text)

    def test_the_command_refuses_a_gated_list_that_is_not_a_list(self):
        import tempfile as _t
        with self.assertRaises(SystemExit) as cm:
            self.run_inventory(["a.example.org"], {"a.example.org": True})
        self.assertIn("gated_hosts_file", str(cm.exception))

    def test_shared_network_inherits_the_more_exposed_level(self):
        inv = {"vpn": {"level": "lan-port", "network_of": None}, "dep": {"level": "internal", "network_of": "abc123"}}
        inventory.inherit(inv, {"abc123def": "vpn"})
        self.assertEqual((inv["dep"]["level"], inv["dep"]["network_of"]), ("lan-port", "vpn"))

    def test_diff(self):
        old = {"a": {"level": "internal"}}
        new = {"a": {"level": "lan-port"}, "b": {"level": "internal"}}
        self.assertEqual(inventory.diff(old, new), ["~ a: internal -> lan-port (level)", "+ b: internal"])


class Pin(unittest.TestCase):
    def test_one_image_line_exactly(self):
        lines = ["services:\n", "  a:\n", "    image: x/a:1\n", "  b:\n", "    image: x/a:1 # again\n"]
        self.assertIsNone(patch.find_image_line(lines, "x/a:1"))
        self.assertEqual(patch.find_image_line(lines[:3], "x/a:1"), 2)

    def test_dry_pin_shows_the_change_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "compose.yaml")
            open(f, "w").write("services:\n  a:\n    image: x/a:1\n")
            ok, msg, _ = patch.pin(f, "x/a:1", "x/a:2")
            self.assertTrue(ok)
            self.assertIn("+     image: x/a:2", msg)
            self.assertIn("x/a:1", open(f).read())

    def test_unknown_reference_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "compose.yaml")
            open(f, "w").write("services:\n  a:\n    image: x/a:1\n")
            self.assertFalse(patch.pin(f, "x/other:1", "x/other:2")[0])


if __name__ == "__main__":
    unittest.main()
