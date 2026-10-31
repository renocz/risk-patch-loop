import unittest

from rpl import risk


class Score(unittest.TestCase):
    def test_exposure_orders_scores(self):
        s = lambda lvl: risk.score("HIGH", False, lvl, False)
        order = ["internet-no-auth", "internet-auth", "lan-port", "lan-proxy-auth", "localhost", "internal"]
        vals = [s(x) for x in order]
        self.assertEqual(vals, sorted(vals, reverse=True))
        self.assertEqual(len(set(vals)), len(vals))

    def test_kev_socket_and_role_raise_the_score(self):
        base = risk.score("HIGH", False, "internet-auth", False)
        self.assertGreater(risk.score("HIGH", True, "internet-auth", False), base)
        self.assertGreater(risk.score("HIGH", False, "internet-auth", True), base)
        self.assertGreater(risk.score("HIGH", False, "internet-auth", False, risk.POINTS_CONTROL), base)

    def test_critical_on_internal_service_stays_low(self):
        self.assertLess(risk.score("CRITICAL", False, "internal", False), risk.T_PLAN)

    def test_kev_on_exposed_service_is_act(self):
        self.assertEqual(risk.decision(risk.score("HIGH", True, "internet-no-auth", False), True), "ACT")

    def test_no_fix_means_watch_only(self):
        self.assertEqual(risk.decision(risk.score("CRITICAL", True, "internet-no-auth", True), False), "WATCH (no fix)")

    def test_unknown_level_is_never_treated_as_internal(self):
        self.assertGreater(risk.score("HIGH", False, "unknown", False), risk.score("HIGH", False, "internal", False))
        self.assertGreater(risk.FACTOR["unknown"], risk.FACTOR["lan-proxy-auth"])


INV = {
    "a": {"image": "x/app:1", "level": "internal", "sensitive_mounts": [], "rights": []},
    "b": {"image": "x/app:1", "level": "internet-auth", "sensitive_mounts": ["/var/run/docker.sock"], "rights": []},
    "c": {"image": "x/db:1", "level": "internal", "sensitive_mounts": [], "rights": []},
}


class Inventory(unittest.TestCase):
    def test_shared_image_takes_the_most_exposed_level(self):
        e = risk.exposure_by_image(INV)
        self.assertEqual(e["x/app:1"], ("internet-auth", True))
        self.assertEqual(e["x/db:1"], ("internal", False))

    def test_evaluate_sorts_and_decides(self):
        fin = {"A": [{"image": "x/app:1", "cve": "CVE-1", "pkg": "p", "fixed": "2", "severity": "HIGH"},
                     {"image": "x/db:1", "cve": "CVE-2", "pkg": "p", "fixed": "2", "severity": "HIGH"}],
               "B": [{"image": "x/app:1", "cve": "CVE-3", "pkg": "q", "fixed": "", "severity": "HIGH"}], "C": []}
        rows = risk.evaluate(fin, INV)
        self.assertEqual(rows[0]["cve"], "CVE-3")
        self.assertEqual(rows[0]["decision"], "WATCH (no fix)")
        self.assertEqual({r["cve"]: r["decision"] for r in rows}["CVE-2"], "WATCH")

    def test_image_missing_from_inventory_is_unknown(self):
        fin = {"A": [{"image": "y/z:1", "cve": "CVE-9", "pkg": "p", "fixed": "2", "severity": "HIGH"}], "B": [], "C": []}
        self.assertEqual(risk.evaluate(fin, INV)[0]["level"], "unknown")

    def test_role_bonus_applies_by_container_name(self):
        roles = {"control_plane": ["c"], "untrusted_input": []}
        self.assertEqual(risk.bonus_by_image(INV, roles)["x/db:1"], risk.POINTS_CONTROL)


class Backtest(unittest.TestCase):
    def test_agreement_and_false_acts(self):
        inv = {"s1": {"level": "internet-no-auth"}, "s2": {"level": "internal"}}
        labels = [{"service": "s1", "severity": "HIGH", "kev": True, "verdict": "A"},
                  {"service": "s2", "severity": "HIGH", "kev": False, "verdict": "R"},
                  {"service": "s2", "severity": "CRITICAL", "kev": False, "verdict": "A"}]
        rows, agree, found, false = risk.backtest(inv, labels)
        self.assertEqual((agree, found, false), (2, 1, 0))


if __name__ == "__main__":
    unittest.main()
