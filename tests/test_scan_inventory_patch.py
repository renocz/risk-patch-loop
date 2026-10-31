import os
import tempfile
import unittest

from rpl import inventory, patch, scan


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
