import csv
import json
import os
import tempfile
import unittest

from rpl import sample


def finding(image, cve, decision, fixed="1.2.3", level="lan-proxy", kev=False, sensitive=False, score=50.0):
    return {"image": image, "cve": cve, "pkg": "libx", "severity": "HIGH", "kev": kev, "level": level, "sensitive": sensitive,
            "fixed": fixed, "score": score, "decision": decision}


def host_rows(prefix, n_act, n_plan, n_watch, n_nofix=0):
    rows = []
    for i in range(n_act):
        rows.append(finding(f"{prefix}/a{i}", f"CVE-2026-1{i:03d}", "ACT", score=60))
    for i in range(n_plan):
        rows.append(finding(f"{prefix}/p{i}", f"CVE-2026-2{i:03d}", "PLAN", score=30))
    for i in range(n_watch):
        rows.append(finding(f"{prefix}/w{i}", f"CVE-2026-3{i:03d}", "WATCH", score=10))
    for i in range(n_nofix):
        rows.append(finding(f"{prefix}/n{i}", f"CVE-2026-4{i:03d}", "WATCH (no fix)", fixed=""))
    return rows


def write_risk(path, rows):
    json.dump({"rows": rows, "summary": []}, open(path, "w"))


class DrawTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = []
        for name, rows in (("home", host_rows("h", 40, 40, 40, 5)), ("lab", host_rows("l", 40, 40, 40, 5))):
            p = os.path.join(self.tmp.name, f"{name}.json")
            write_risk(p, rows)
            self.paths.append(f"{name}={p}")

    def hosts(self):
        return sample.load_hosts(sample.parse_pairs(self.paths, "--host"))

    def test_same_seed_same_sample_other_seed_other_sample(self):
        a = sample.draw(self.hosts(), 100, 7)["rows"]
        b = sample.draw(self.hosts(), 100, 7)["rows"]
        c = sample.draw(self.hosts(), 100, 8)["rows"]
        self.assertEqual([r["id"] for r in a], [r["id"] for r in b])
        self.assertNotEqual(sorted(r["id"] for r in a), sorted(r["id"] for r in c))

    def test_one_host_is_refused_unless_said_out_loud(self):
        one = dict(list(self.hosts().items())[:1])
        with self.assertRaises(SystemExit) as cm:
            sample.draw(one, 50, 1)
        self.assertIn("--single-host", str(cm.exception))
        self.assertEqual(len(sample.draw(one, 50, 1, allow_single_host=True)["rows"]), 50)

    def test_single_host_is_written_in_the_manifest(self):
        out = os.path.join(self.tmp.name, "one")
        args = sample.argparse.Namespace(host=self.paths[:1], seed=3, size=50, out=out, allow_short=False, single_host=True)
        self.assertEqual(sample.cmd_draw(args), 0)
        manifest = json.load(open(os.path.join(out, "manifest.json")))
        self.assertTrue(manifest["single_host"])
        self.assertEqual(manifest["hosts"], 1)

    def test_two_hosts_are_not_marked_single_host(self):
        out = os.path.join(self.tmp.name, "two")
        args = sample.argparse.Namespace(host=self.paths, seed=3, size=50, out=out, allow_short=False)
        sample.cmd_draw(args)
        manifest = json.load(open(os.path.join(out, "manifest.json")))
        self.assertFalse(manifest["single_host"])

    def test_act_and_plan_plus_watch_are_equally_numerous(self):
        res = sample.draw(self.hosts(), 100, 1)
        decisions = [r["decision"] for r in res["rows"]]
        self.assertEqual(len(decisions), 100)
        self.assertEqual(decisions.count("ACT"), 50)
        self.assertEqual(decisions.count("PLAN") + decisions.count("WATCH"), 50)
        self.assertEqual(decisions.count("PLAN"), 25)

    def test_findings_without_a_fix_are_never_drawn(self):
        res = sample.draw(self.hosts(), 100, 1)
        self.assertTrue(all(r["fixed"] for r in res["rows"]))
        self.assertTrue(all(r["decision"] in ("ACT", "PLAN", "WATCH") for r in res["rows"]))

    def test_one_host_is_refused(self):
        hosts = self.hosts()
        hosts.pop("lab")
        with self.assertRaises(SystemExit):
            sample.draw(hosts, 100, 1)

    def test_too_few_findings_is_refused_unless_a_trial_draw(self):
        p = os.path.join(self.tmp.name, "small.json")
        write_risk(p, host_rows("s", 3, 3, 3))
        hosts = sample.load_hosts(sample.parse_pairs([f"a={p}", self.paths[0]], "--host"))
        hosts["a"] = hosts["a"]
        small = {"a": hosts["a"], "b": [dict(r, host="b", id=sample.row_id("b", r["image"], r["cve"], r["pkg"])) for r in hosts["a"]]}
        with self.assertRaises(SystemExit):
            sample.draw(small, 100, 1)
        res = sample.draw(small, 100, 1, allow_short=True)
        self.assertEqual(res["strata"]["ACT"], 6)
        self.assertEqual(len(res["rows"]), 12)

    def test_the_reviewers_sheet_has_no_score_and_no_decision_and_is_not_in_strata_order(self):
        res = sample.draw(self.hosts(), 100, 3)
        sheet = sample.blind_rows(res["rows"], 3)
        text = json.dumps(sheet)
        for word in ("score", "decision", "ACT", "PLAN", "WATCH"):
            self.assertNotIn(word, text)
        self.assertEqual(set(sheet[0]), set(sample.SHEET_FIELDS))
        by_id = {r["id"]: r["decision"] for r in res["rows"]}
        first_half = [by_id[s["id"]] for s in sheet[:50]]
        self.assertGreater(first_half.count("ACT"), 5)
        self.assertLess(first_half.count("ACT"), 45)

    def test_draw_command_writes_the_three_files_and_needs_the_criteria_file(self):
        out = os.path.join(self.tmp.name, "out")
        cwd = os.getcwd()
        os.chdir(self.tmp.name)
        try:
            args = sample.argparse.Namespace(host=self.paths, seed=5, size=100, out=out, allow_short=False)
            with self.assertRaises(SystemExit):
                sample.cmd_draw(args)
            os.makedirs("docs")
            open(sample.CRITERIA, "w").write("criteria")
            self.assertEqual(sample.cmd_draw(args), 0)
        finally:
            os.chdir(cwd)
        for name in ("sample.json", "manifest.json", "sheet.csv"):
            self.assertTrue(os.path.exists(os.path.join(out, name)))
        manifest = json.load(open(os.path.join(out, "manifest.json")))
        self.assertEqual(manifest["seed"], 5)
        self.assertEqual(len(manifest["ids"]), 100)
        self.assertEqual(set(manifest["inputs"]), {"home", "lab"})
        self.assertNotIn("score", open(os.path.join(out, "manifest.json")).read())


class ResultTest(unittest.TestCase):
    def rows(self):
        rows = []
        for i in range(10):
            rows.append({"id": f"a{i}", "decision": "ACT"})
        for i in range(10):
            rows.append({"id": f"p{i}", "decision": "PLAN"})
        for i in range(10):
            rows.append({"id": f"w{i}", "decision": "WATCH"})
        return rows

    def answers(self, act_ids, unsure_ids=()):
        out = {}
        for r in self.rows():
            out[r["id"]] = "act" if r["id"] in act_ids else ("unsure" if r["id"] in unsure_ids else "defer")
        return out

    def test_rate_counts_act_verdicts_ranked_below_act(self):
        act = {"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "p0", "w0"}
        ans = self.answers(act)
        res = sample.resolve(self.rows(), ans, dict(ans))
        r = sample.rate(self.rows(), res["truth"], False)
        self.assertEqual((r["act_verdicts"], r["ranked_below_act"]), (10, 2))
        self.assertAlmostEqual(r["rate"], 0.2)
        lo, hi = r["ci95"]
        self.assertLess(lo, 0.2)
        self.assertGreater(hi, 0.2)

    def test_unsure_is_reported_both_ways(self):
        ans = self.answers({"a0", "a1"}, unsure_ids={"p0", "p1", "p2"})
        res = sample.resolve(self.rows(), ans, dict(ans))
        strict = sample.rate(self.rows(), res["truth"], False)
        loose = sample.rate(self.rows(), res["truth"], True)
        self.assertEqual((strict["act_verdicts"], strict["ranked_below_act"]), (2, 0))
        self.assertEqual((loose["act_verdicts"], loose["ranked_below_act"]), (5, 3))

    def test_disagreement_goes_to_the_third_reviewer_and_is_counted(self):
        first = self.answers({"a0", "p0"})
        second = self.answers({"a0"})
        res = sample.resolve(self.rows(), first, second)
        self.assertEqual(res["disagreements"], ["p0"])
        self.assertEqual(res["unresolved"], ["p0"])
        third = self.answers({"p0"})
        res = sample.resolve(self.rows(), first, second, third)
        self.assertEqual(res["unresolved"], [])
        self.assertEqual(res["truth"]["p0"], "act")
        self.assertEqual(len(res["disagreements"]), 1)

    def test_wilson_interval_known_values(self):
        lo, hi = sample.wilson(0, 10)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.2775, places=3)
        lo, hi = sample.wilson(5, 10)
        self.assertAlmostEqual(lo, 0.2366, places=3)
        self.assertAlmostEqual(hi, 0.7634, places=3)
        self.assertIsNone(sample.wilson(0, 0))

    def test_no_act_verdict_means_no_rate(self):
        ans = self.answers(set())
        res = sample.resolve(self.rows(), ans, dict(ans))
        self.assertIsNone(sample.rate(self.rows(), res["truth"], False)["rate"])

    def test_kappa(self):
        a = {"x": "act", "y": "defer", "z": "act", "t": "defer"}
        self.assertAlmostEqual(sample.kappa(a, dict(a)), 1.0)
        b = {"x": "defer", "y": "act", "z": "defer", "t": "act"}
        self.assertAlmostEqual(sample.kappa(a, b), -1.0)


class SheetTest(unittest.TestCase):
    def sheet(self, rows):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="")
        self.addCleanup(os.unlink, tmp.name)
        w = csv.DictWriter(tmp, fieldnames=sample.SHEET_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow(dict({k: "" for k in sample.SHEET_FIELDS}, **r))
        tmp.close()
        return tmp.name

    def test_a_good_sheet_is_read_case_insensitively(self):
        p = self.sheet([{"id": "a", "answer": "ACT"}, {"id": "b", "answer": " Defer "}])
        self.assertEqual(sample.read_sheet(p, {"a", "b"}, "x"), {"a": "act", "b": "defer"})

    def test_blank_unknown_wrong_or_duplicate_rows_are_refused(self):
        for rows in ([{"id": "a", "answer": "act"}, {"id": "b", "answer": ""}],
                     [{"id": "a", "answer": "act"}, {"id": "zzz", "answer": "act"}],
                     [{"id": "a", "answer": "act"}, {"id": "b", "answer": "maybe"}],
                     [{"id": "a", "answer": "act"}, {"id": "a", "answer": "act"}, {"id": "b", "answer": "act"}],
                     [{"id": "a", "answer": "act"}]):
            with self.assertRaises(SystemExit):
                sample.read_sheet(self.sheet(rows), {"a", "b"}, "x")

    def test_reviewer_names_must_differ_and_look_like_name_equals_path(self):
        with self.assertRaises(SystemExit):
            sample.parse_pairs(["ann=a.csv", "ann=b.csv"], "--reviewer")
        with self.assertRaises(SystemExit):
            sample.parse_pairs(["a.csv"], "--reviewer")


if __name__ == "__main__":
    unittest.main()
