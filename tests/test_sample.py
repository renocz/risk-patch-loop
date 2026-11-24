import csv
import json
import os
import tempfile
import unittest
from unittest import mock

from rpl import config, sample


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
        self.assertEqual(res["strata"], {"ACT": 6, "PLAN": 6, "WATCH": 6})
        self.assertEqual(len(res["rows"]), 18)                              # everything there is: ACT and the rest no longer have to be equally numerous

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


class WeightedRateTest(unittest.TestCase):
    """The draw takes as many ACT rows as PLAN + WATCH rows, whatever their number in the host. A rate computed from that sample without
    weights treats the strata as equal in size and reports far too few misses when the rows below ACT are much more numerous."""

    def build(self, act, plan, watch, sizes=(50, 25, 25)):
        """act, plan, watch: how many 'act' answers in each stratum; sizes: how many rows were labelled in each."""
        rows, truth = [], {}
        for decision, hits, n in (("ACT", act, sizes[0]), ("PLAN", plan, sizes[1]), ("WATCH", watch, sizes[2])):
            for i in range(n):
                ident = f"{decision}{i}"
                rows.append({"id": ident, "decision": decision})
                truth[ident] = "act" if i < hits else "defer"
        return rows, truth

    def test_the_unweighted_rate_understates_when_the_rows_below_act_are_far_more_numerous(self):
        rows, truth = self.build(30, 2, 1)
        unweighted = sample.rate(rows, truth, False)
        weighted = sample.weighted_rate(rows, truth, {"ACT": 200, "PLAN": 1000, "WATCH": 1000}, False)
        self.assertAlmostEqual(unweighted["rate"], 3 / 33)                     # about 9 %: "target met"
        self.assertAlmostEqual(weighted["estimate"], 0.5)                      # (1000*2/25 + 1000*1/25) / (200*30/50 + 80 + 40)

    def test_with_strata_as_large_as_their_samples_both_rates_agree(self):
        rows, truth = self.build(30, 2, 1)
        weighted = sample.weighted_rate(rows, truth, {"ACT": 50, "PLAN": 25, "WATCH": 25}, False)
        self.assertAlmostEqual(weighted["estimate"], 3 / 33)

    def test_no_act_answer_gives_no_estimate(self):
        rows, truth = self.build(0, 0, 0)
        w = sample.weighted_rate(rows, truth, {"ACT": 200, "PLAN": 1000, "WATCH": 1000}, False)
        self.assertIsNone(w["estimate"])
        self.assertIsNone(w["ci95"])

    def test_the_interval_contains_the_estimate_and_stays_between_zero_and_one(self):
        rows, truth = self.build(30, 2, 1)
        w = sample.weighted_rate(rows, truth, {"ACT": 200, "PLAN": 1000, "WATCH": 1000}, False)
        lo, hi = w["ci95"]
        self.assertLessEqual(0.0, lo)
        self.assertLess(lo, w["estimate"])
        self.assertLess(w["estimate"], hi)
        self.assertLessEqual(hi, 1.0)

    def test_the_interval_ends_are_the_ones_worked_out_by_hand(self):
        """Wilson per stratum at z = 2.394: ACT 30/50 -> 0.4323 to 0.7472, PLAN 2/25 -> 0.0174 to 0.2993, WATCH 1/25 -> 0.0053 to 0.2463; the ends of
        the ratio at the corners: 22.65 / (22.65 + 149.44) and 545.55 / (545.55 + 86.46)."""
        rows, truth = self.build(30, 2, 1)
        lo, hi = sample.weighted_rate(rows, truth, {"ACT": 200, "PLAN": 1000, "WATCH": 1000}, False)["ci95"]
        self.assertAlmostEqual(lo, 0.1316, places=3)
        self.assertAlmostEqual(hi, 0.8632, places=3)

    def test_the_interval_covers_the_true_rate_at_least_95_percent_of_the_time(self):
        """Simulated labelling (fixed seed): the true host rate is known, the sample is drawn as the draw does (50 ACT, 25 PLAN, 25 WATCH)."""
        import random
        for (pa, pp, pw), avail in (((0.6, 0.08, 0.04), (200, 1000, 1000)), ((0.6, 0.02, 0.01), (200, 1000, 1000)), ((0.7, 0.10, 0.05), (300, 500, 1500))):
            rng = random.Random(1)
            true = (avail[1] * pp + avail[2] * pw) / (avail[0] * pa + avail[1] * pp + avail[2] * pw)
            covered = trials = 0
            for _ in range(400):
                rows, truth = [], {}
                for dec, p, n in (("ACT", pa, 50), ("PLAN", pp, 25), ("WATCH", pw, 25)):
                    for i in range(n):
                        rid = f"{dec}{i}"
                        rows.append({"id": rid, "decision": dec})
                        truth[rid] = "act" if rng.random() < p else "defer"
                w = sample.weighted_rate(rows, truth, {"ACT": avail[0], "PLAN": avail[1], "WATCH": avail[2]}, False)
                if w["estimate"] is None:
                    continue
                trials += 1
                covered += w["ci95"][0] <= true <= w["ci95"][1]
            self.assertGreaterEqual(covered / trials, 0.95, (pa, pp, pw))

    def test_the_interval_is_not_a_point_when_no_miss_was_found(self):
        """0 misses in 50 labelled rows below ACT does not mean a rate of 0."""
        rows, truth = self.build(30, 0, 0)
        w = sample.weighted_rate(rows, truth, {"ACT": 200, "PLAN": 1000, "WATCH": 1000}, False)
        self.assertEqual(w["estimate"], 0.0)
        self.assertGreater(w["ci95"][1], 0.2)                                  # with 1000+1000 rows below ACT, 50 labelled: wide

    def test_more_labels_with_the_same_proportions_narrow_the_interval(self):
        small = sample.weighted_rate(*self.build(30, 2, 1), {"ACT": 200, "PLAN": 1000, "WATCH": 1000}, False)
        big = sample.weighted_rate(*self.build(120, 8, 4, sizes=(200, 100, 100)), {"ACT": 200, "PLAN": 1000, "WATCH": 1000}, False)
        self.assertAlmostEqual(small["estimate"], big["estimate"])
        self.assertLess(big["ci95"][1] - big["ci95"][0], small["ci95"][1] - small["ci95"][0])

    def test_unsure_counted_as_act_raises_the_estimate(self):
        rows, truth = self.build(30, 2, 1)
        truth["PLAN5"] = "unsure"
        avail = {"ACT": 200, "PLAN": 1000, "WATCH": 1000}
        self.assertGreater(sample.weighted_rate(rows, truth, avail, True)["estimate"], sample.weighted_rate(rows, truth, avail, False)["estimate"])

    def test_without_the_population_sizes_no_weighted_estimate_is_made(self):
        rows, truth = self.build(30, 2, 1)
        for avail in (None, {}, {"ACT": 200}, {"ACT": 200, "PLAN": "x", "WATCH": 1}):
            with self.subTest(avail=avail):
                w = sample.weighted_rate(rows, truth, avail, False)
                self.assertIsNone(w["estimate"])
                self.assertIn("reason", w)

    def test_a_stratum_that_exists_in_the_host_but_was_not_labelled_is_reported(self):
        rows, truth = self.build(30, 2, 0, sizes=(50, 25, 0))
        w = sample.weighted_rate(rows, truth, {"ACT": 200, "PLAN": 1000, "WATCH": 1000}, False)
        self.assertIsNone(w["estimate"])
        self.assertIn("WATCH", w["reason"])

    def test_an_empty_stratum_in_the_host_is_not_a_problem(self):
        rows, truth = self.build(30, 2, 0, sizes=(50, 25, 0))
        w = sample.weighted_rate(rows, truth, {"ACT": 200, "PLAN": 1000, "WATCH": 0}, False)
        self.assertIsNotNone(w["estimate"])


class FeasibleDrawTest(unittest.TestCase):
    """A host with few ACT rows (18 of 2,142 in the case that prompted this): the draw takes all of them and fills up to the size with rows
    below ACT, instead of refusing because ACT and PLAN + WATCH cannot be equally numerous. The result weights the strata."""

    def host(self, n_act, n_plan, n_watch):
        rows = []
        for dec, n in (("ACT", n_act), ("PLAN", n_plan), ("WATCH", n_watch)):
            rows += [dict(finding(f"{dec}/i{i}", f"CVE-2026-{i:04d}", dec), host="h", id=f"{dec}{i}") for i in range(n)]
        return {"h": rows}

    def test_few_act_rows_are_all_drawn_and_the_rest_comes_from_below_act(self):
        res = sample.draw(self.host(18, 222, 1902), 100, 7, allow_single_host=True)
        self.assertEqual(res["strata"], {"ACT": 18, "PLAN": 41, "WATCH": 41})
        self.assertEqual(len(res["rows"]), 100)
        self.assertEqual({r["id"] for r in res["rows"] if r["decision"] == "ACT"}, {f"ACT{i}" for i in range(18)})

    def test_a_small_plan_stratum_is_drawn_whole_and_watch_fills_the_rest(self):
        res = sample.draw(self.host(10, 5, 500), 100, 7, allow_single_host=True)
        self.assertEqual(res["strata"], {"ACT": 10, "PLAN": 5, "WATCH": 85})

    def test_a_small_watch_stratum_is_drawn_whole_and_plan_fills_the_rest(self):
        res = sample.draw(self.host(10, 500, 5), 100, 7, allow_single_host=True)
        self.assertEqual(res["strata"], {"ACT": 10, "PLAN": 85, "WATCH": 5})
        self.assertEqual(len(res["rows"]), 100)

    def test_with_many_act_rows_the_halves_are_still_equal(self):
        res = sample.draw(self.host(300, 300, 300), 100, 7, allow_single_host=True)
        self.assertEqual(res["strata"], {"ACT": 50, "PLAN": 25, "WATCH": 25})

    def test_an_odd_size_is_met_exactly(self):
        res = sample.draw(self.host(300, 300, 300), 101, 7, allow_single_host=True)
        self.assertEqual(len(res["rows"]), 101)
        self.assertEqual(res["strata"]["ACT"], 50)

    def test_too_few_findings_overall_is_still_refused_unless_a_trial_draw(self):
        with self.assertRaises(SystemExit) as cm:
            sample.draw(self.host(10, 20, 30), 100, 7, allow_single_host=True)
        self.assertIn("--allow-short", str(cm.exception))
        self.assertEqual(len(sample.draw(self.host(10, 20, 30), 100, 7, allow_short=True, allow_single_host=True)["rows"]), 60)

    def test_the_draw_is_still_deterministic(self):
        a = sample.draw(self.host(18, 222, 1902), 100, 7, allow_single_host=True)["rows"]
        b = sample.draw(self.host(18, 222, 1902), 100, 7, allow_single_host=True)["rows"]
        self.assertEqual([r["id"] for r in a], [r["id"] for r in b])

    def test_the_manifest_gives_the_population_sizes_the_weights_need(self):
        res = sample.draw(self.host(18, 222, 1902), 100, 7, allow_single_host=True)
        self.assertEqual(res["available"], {"ACT": 18, "PLAN": 222, "WATCH": 1902})


class ScoringFingerprintTest(unittest.TestCase):
    """The measure describes ONE score. The manifest of a draw records what the score was made of, and `result` refuses to describe another."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = self.tmp.name
        self.cwd = os.getcwd()
        os.chdir(self.d)
        self.addCleanup(os.chdir, self.cwd)
        os.makedirs("docs")
        open(sample.CRITERIA, "w").write("criteria")
        for name, content in (("roles.json", '{"x": 1}'), ("tunnel.json", '["a.example.org"]'), ("gated.json", '["a.example.org"]')):
            open(os.path.join(self.d, name), "w").write(content)
        json.dump({"state_dir": os.path.join(self.d, "state"), "roles_file": "roles.json", "tunnel_hosts_file": "tunnel.json",
                   "gated_hosts_file": "gated.json"}, open(os.path.join(self.d, "rpl.json"), "w"))
        patcher = mock.patch.dict(os.environ, {"RPL_CONFIG": os.path.join(self.d, "rpl.json")})
        patcher.start()
        self.addCleanup(patcher.stop)

    def host_rows(self):
        rows = []
        for dec, n in (("ACT", 6), ("PLAN", 6), ("WATCH", 6)):
            rows += [finding(f"{dec}/i{i}", f"CVE-2026-{i:04d}", dec) for i in range(n)]
        return rows

    def draw(self):
        path = os.path.join(self.d, "risk.json")
        write_risk(path, self.host_rows())
        out = os.path.join(self.d, "out")
        args = sample.argparse.Namespace(host=[f"h={path}", f"i={path}x"][:1], seed=3, size=18, out=out, allow_short=True, single_host=True)
        self.assertEqual(sample.cmd_draw(args), 0)
        return out

    def manifest(self, out):
        return json.load(open(os.path.join(out, "manifest.json")))

    def result(self, out, allow=False):
        """Label the sample (every row 'defer', a first row 'act'), run `result`; returns (code, printed text)."""
        import contextlib
        import io
        data = json.load(open(os.path.join(out, "sample.json")))
        rows = data["rows"]
        sheets = []
        for name in ("alice", "bob"):
            sp = os.path.join(self.d, f"{name}.csv")
            with open(sp, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=sample.SHEET_FIELDS)
                w.writeheader()
                for i, r in enumerate(rows):
                    w.writerow({"id": r["id"], "answer": "act" if i == 0 else "defer"})
            sheets.append(f"{name}={sp}")
        args = sample.argparse.Namespace(sample=os.path.join(out, "sample.json"), reviewer=sheets, tiebreak=None, out=None,
                                         allow_changed_scoring=allow)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sample.cmd_result(args)
        return rc, buf.getvalue()

    def edit_manifest(self, out, change):
        path = os.path.join(out, "sample.json")
        data = json.load(open(path))
        change(data["manifest"]["scoring"])
        json.dump(data, open(path, "w"))

    def test_the_manifest_records_the_files_the_thresholds_and_the_inputs(self):
        from rpl import risk
        sc = self.manifest(self.draw())["scoring"]
        pkg = os.path.dirname(os.path.abspath(sample.__file__))
        self.assertEqual(sc["files"], {"risk.py": sample.sha256_file(os.path.join(pkg, "risk.py")),
                                       "inventory.py": sample.sha256_file(os.path.join(pkg, "inventory.py"))})
        self.assertEqual((sc["t_act"], sc["t_plan"]), (risk.T_ACT, risk.T_PLAN))
        self.assertEqual(sc["inputs"]["roles_file"], sample.sha256_file(os.path.join(self.d, "roles.json")))
        self.assertEqual(sc["inputs"]["tunnel_hosts_file"], sample.sha256_file(os.path.join(self.d, "tunnel.json")))
        self.assertEqual(sc["inputs"]["gated_hosts_file"], sample.sha256_file(os.path.join(self.d, "gated.json")))

    def set_config(self, **extra):
        cfg = json.load(open(os.path.join(self.d, "rpl.json")))
        cfg.update(extra)
        json.dump(cfg, open(os.path.join(self.d, "rpl.json"), "w"))

    def test_the_whole_procedure_through_the_command_line(self):
        """A dry run of the procedure as it will be run: draw, two sheets, result, then an input of the score changes (exit 4), then the override."""
        import contextlib
        import io
        path = os.path.join(self.d, "risk.json")
        write_risk(path, self.host_rows())
        out = os.path.join(self.d, "cli")

        def run(argv):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    code = sample.main(argv)
                except SystemExit as e:
                    code = e.code
            return code, buf.getvalue()

        code, text = run(["draw", "--host", f"h={path}", "--single-host", "--seed", "7", "--size", "18", "--allow-short", "--out", out])
        self.assertEqual(code, 0, text)
        rows = json.load(open(os.path.join(out, "sample.json")))["rows"]
        sheets = []
        for name in ("alice", "bob"):
            sp = os.path.join(self.d, f"{name}.csv")
            with open(sp, "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=sample.SHEET_FIELDS)
                w.writeheader()
                for i, r in enumerate(rows):
                    w.writerow({"id": r["id"], "answer": "act" if i == 0 else "defer"})
            sheets += ["--reviewer", f"{name}={sp}"]
        sample_json = os.path.join(out, "sample.json")
        code, text = run(["result", "--sample", sample_json] + sheets)
        self.assertEqual(code, 0, text)
        open(os.path.join(self.d, "roles.json"), "w").write('{"x": 2}')
        code, text = run(["result", "--sample", sample_json] + sheets)
        self.assertEqual(code, 4, text)
        self.assertIn("roles_file", text)
        code, text = run(["result", "--sample", sample_json] + sheets + ["--allow-changed-scoring"])
        self.assertEqual(code, 0, text)
        self.assertIn("WARNING", text)

    def test_the_words_that_make_a_middleware_a_login_are_part_of_the_score(self):
        out = self.draw()
        self.set_config(auth_middleware_words=["auth", "sso"])
        code, text = self.result(out)
        self.assertEqual(code, 4, text)
        self.assertIn("auth_middleware_words", text)

    def test_the_same_middleware_words_are_accepted(self):
        out = self.draw()
        self.set_config(auth_middleware_words=list(config.DEFAULTS["auth_middleware_words"]))
        code, text = self.result(out)
        self.assertNotEqual(code, 4, text)

    def test_the_order_of_the_middleware_words_does_not_matter(self):
        out = self.draw()
        self.set_config(auth_middleware_words=list(reversed(config.DEFAULTS["auth_middleware_words"])))
        code, text = self.result(out)
        self.assertNotEqual(code, 4, text)

    def test_the_manifest_records_the_scan_environment_without_a_path(self):
        os.makedirs(os.path.join(self.d, "state"))
        json.dump({"ts": 1.0, "A": [], "B": [], "C": [], "images": [],
                   "trivy": {"image": "ghcr.io/example/trivy:0.50.0", "db_updated_at": "2026-11-24T02:00:00Z", "db_version": 2}},
                  open(os.path.join(self.d, "state", "findings.json"), "w"))
        m = self.manifest(self.draw())
        self.assertEqual(m["scan_environment"], {"trivy_image": "ghcr.io/example/trivy:0.50.0", "db_updated_at": "2026-11-24T02:00:00Z",
                                                 "db_version": 2, "findings_ts": 1.0})
        self.assertNotIn(self.d, json.dumps(m))

    def test_a_scan_environment_that_is_not_known_is_recorded_as_none(self):
        self.assertIsNone(self.manifest(self.draw())["scan_environment"])

    def test_an_input_that_is_not_configured_is_recorded_as_none(self):
        json.dump({"state_dir": os.path.join(self.d, "state")}, open(os.path.join(self.d, "rpl.json"), "w"))
        os.remove(os.path.join(self.d, "roles.json"))                         # roles_file defaults to roles.json next to the configuration
        self.assertEqual(self.manifest(self.draw())["scoring"]["inputs"],
                         {"roles_file": None, "tunnel_hosts_file": None, "gated_hosts_file": None})

    def test_the_published_manifest_holds_hashes_not_paths_or_contents(self):
        text = open(os.path.join(self.draw(), "manifest.json")).read()
        self.assertNotIn(self.d, text)
        self.assertNotIn("a.example.org", text)

    def test_the_same_score_is_accepted(self):
        rc, text = self.result(self.draw())
        self.assertEqual(rc, 0, text)
        self.assertNotIn("score changed", text)

    def test_a_changed_scoring_file_is_refused_and_named(self):
        out = self.draw()
        self.edit_manifest(out, lambda sc: sc["files"].update({"risk.py": "0" * 64}))
        rc, text = self.result(out)
        self.assertEqual(rc, 4, text)
        self.assertIn("the score changed since the draw", text)
        self.assertIn("risk.py", text)
        self.assertNotIn("estimated for the host", text)                          # no rate is printed for another score

    def test_a_changed_inventory_file_is_refused(self):
        out = self.draw()
        self.edit_manifest(out, lambda sc: sc["files"].update({"inventory.py": "1" * 64}))
        rc, text = self.result(out)
        self.assertEqual(rc, 4, text)
        self.assertIn("inventory.py", text)

    def test_a_changed_threshold_is_refused(self):
        out = self.draw()
        self.edit_manifest(out, lambda sc: sc.update({"t_act": 99}))
        rc, text = self.result(out)
        self.assertEqual(rc, 4, text)
        self.assertIn("t_act", text)

    def test_a_changed_roles_file_is_refused(self):
        out = self.draw()
        open(os.path.join(self.d, "roles.json"), "w").write('{"x": 2}')
        rc, text = self.result(out)
        self.assertEqual(rc, 4, text)
        self.assertIn("roles_file", text)

    def test_a_changed_gated_list_is_refused(self):
        out = self.draw()
        open(os.path.join(self.d, "gated.json"), "w").write('[]')
        rc, text = self.result(out)
        self.assertEqual(rc, 4, text)
        self.assertIn("gated_hosts_file", text)

    def test_an_input_not_recorded_at_the_draw_is_said_not_refused(self):
        out = self.draw()
        self.edit_manifest(out, lambda sc: sc["inputs"].update({"roles_file": None}))
        rc, text = self.result(out)
        self.assertEqual(rc, 0, text)
        self.assertIn("roles_file was not recorded", text)

    def test_the_override_goes_on_and_says_so_loudly(self):
        out = self.draw()
        self.edit_manifest(out, lambda sc: sc["files"].update({"risk.py": "0" * 64}))
        rc, text = self.result(out, allow=True)
        self.assertEqual(rc, 0, text)
        self.assertIn("WARNING: the score changed since the draw", text)
        self.assertIn("estimated for the host", text)

    def test_a_sample_drawn_before_the_fingerprint_is_read_with_a_warning(self):
        out = self.draw()
        path = os.path.join(out, "sample.json")
        data = json.load(open(path))
        del data["manifest"]["scoring"]
        json.dump(data, open(path, "w"))
        rc, text = self.result(out)
        self.assertEqual(rc, 0, text)
        self.assertIn("drawn before the score was fingerprinted", text)


class ResultCommandWeighted(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = self.tmp.name

    def run_result(self, available, with_strata=True, unsure=(), misses=True):
        rows = []
        for decision, n in (("ACT", 50), ("PLAN", 25), ("WATCH", 25)):
            rows += [{"id": f"{decision}{i}", "decision": decision} for i in range(n)]
        manifest = {"available_with_fix": available} if with_strata else {}
        path = os.path.join(self.d, "sample.json")
        json.dump({"manifest": manifest, "rows": rows}, open(path, "w"))
        acts = {f"ACT{i}" for i in range(30)} | ({"PLAN0", "PLAN1", "WATCH0"} if misses else set())
        sheets = []
        for name in ("alice", "bob"):
            sp = os.path.join(self.d, f"{name}.csv")
            with open(sp, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=sample.SHEET_FIELDS)
                w.writeheader()
                for r in rows:
                    w.writerow({"id": r["id"], "answer": "act" if r["id"] in acts else ("unsure" if r["id"] in unsure else "defer")})
            sheets.append(f"{name}={sp}")
        out = os.path.join(self.d, "out.json")
        args = sample.argparse.Namespace(sample=path, reviewer=sheets, tiebreak=None, out=out)
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sample.cmd_result(args)
        return rc, buf.getvalue(), json.load(open(out))

    def test_the_command_prints_the_estimate_for_the_host_and_judges_the_target_on_it(self):
        rc, text, out = self.run_result({"ACT": 200, "PLAN": 1000, "WATCH": 1000})
        self.assertEqual(rc, 0)
        self.assertIn("estimated for the host", text)
        self.assertIn("50.0%", text)
        self.assertIn("in the sample", text)                                   # the unweighted number is still shown, said to be about the sample
        self.assertIn("decision rule (unsure as defer): the lower end of the interval (13.2%) is above 10%: the score must change", text)
        self.assertAlmostEqual(out["weighted"]["unsure_as_defer"]["estimate"], 0.5)

    def test_a_low_lower_end_requires_no_change_and_says_it_does_not_show_a_low_rate(self):
        rc, text, out = self.run_result({"ACT": 18, "PLAN": 20, "WATCH": 30}, misses=False)
        self.assertEqual(rc, 0)
        self.assertIn("decision rule (unsure as defer): the lower end of the interval (0.0%) is not above 10%: the rule requires no change", text)
        self.assertIn("does not show that the rate is under 10%", text)
        self.assertRegex(text, r"\(upper end \d+\.\d%\)")

    def test_unsure_counted_as_act_gives_a_higher_estimate_for_the_host(self):
        rc, text, out = self.run_result({"ACT": 200, "PLAN": 1000, "WATCH": 1000}, unsure={"PLAN5", "PLAN6", "WATCH5"})
        self.assertEqual(rc, 0)
        self.assertGreater(out["weighted"]["unsure_as_act"]["estimate"], out["weighted"]["unsure_as_defer"]["estimate"])

    def test_without_population_sizes_the_command_says_it_cannot_estimate_for_the_host(self):
        rc, text, out = self.run_result(None, with_strata=False)
        self.assertEqual(rc, 0)
        self.assertIn("cannot be estimated for the host", text)
        self.assertIn("the decision rule cannot be applied", text)
        self.assertNotIn("host estimate", text)


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


class DuplicateRowsTest(unittest.TestCase):
    """On a real host `risk.json` holds the same (image, CVE, package) twice (one line per target or per installed copy). The draw used to refuse
    the whole file; the population is the set of distinct findings, so duplicates collapse to one row, the one the score ranks highest."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = self.tmp.name
        self.cwd = os.getcwd()
        os.chdir(self.d)
        self.addCleanup(os.chdir, self.cwd)
        os.makedirs("docs")
        open(sample.CRITERIA, "w").write("criteria")
        patcher = mock.patch.dict(os.environ, {"RPL_CONFIG": os.path.join(self.d, "rpl.json")})
        patcher.start()
        self.addCleanup(patcher.stop)
        json.dump({"state_dir": os.path.join(self.d, "state")}, open(os.path.join(self.d, "rpl.json"), "w"))

    def load(self, rows, counted=None):
        path = os.path.join(self.d, "risk.json")
        write_risk(path, rows)
        return sample.load_hosts([("h", path)], counted) if counted is not None else sample.load_hosts([("h", path)])

    def test_identical_findings_become_one_row(self):
        row = finding("img/a", "CVE-2026-0001", "WATCH", score=10)
        self.assertEqual(len(self.load([row, dict(row)])["h"]), 1)

    def test_the_row_kept_is_the_one_ranked_highest_whatever_the_order(self):
        low = finding("img/a", "CVE-2026-0001", "WATCH", score=10)
        high = dict(low, score=60, decision="ACT", fixed="9.9")
        for rows in ([low, high], [high, low]):
            kept = self.load(rows)["h"]
            self.assertEqual([(r["score"], r["decision"], r["fixed"]) for r in kept], [(60, "ACT", "9.9")])

    def test_a_tie_is_broken_by_the_content_not_the_order(self):
        a = finding("img/a", "CVE-2026-0001", "PLAN", score=30)
        b = dict(a, fixed="2.0")
        self.assertEqual(self.load([a, b])["h"], self.load([b, a])["h"])

    def test_the_collapsed_count_is_reported(self):
        row = finding("img/a", "CVE-2026-0001", "WATCH", score=10)
        other = finding("img/b", "CVE-2026-0002", "WATCH", score=10)
        counted = {}
        self.load([row, dict(row), dict(row), other], counted)
        self.assertEqual(counted, {"h": 2})

    def test_a_row_without_a_fix_is_not_a_duplicate_of_one_with_a_fix(self):
        fixed = finding("img/a", "CVE-2026-0001", "WATCH", score=10)
        nofix = dict(fixed, fixed="", decision="WATCH (no fix)")
        counted = {}
        rows = self.load([fixed, nofix], counted)["h"]
        self.assertEqual((len(rows), counted), (1, {"h": 0}))

    def test_draw_still_refuses_ids_that_are_twice_in_what_it_is_given(self):
        row = dict(finding("img/a", "CVE-2026-0001", "ACT", score=60), host="h", id="same")
        with self.assertRaises(SystemExit):
            sample.draw({"h": [row, dict(row)]}, 10, 1, allow_short=True, allow_single_host=True)

    def test_the_manifest_says_how_many_duplicates_were_collapsed(self):
        rows = host_rows("x", 6, 6, 6)
        rows.append(dict(rows[0]))
        rows.append(dict(rows[7]))
        path = os.path.join(self.d, "risk.json")
        write_risk(path, rows)
        out = os.path.join(self.d, "out")
        args = sample.argparse.Namespace(host=[f"h={path}"], seed=3, size=18, out=out, allow_short=True, single_host=True)
        self.assertEqual(sample.cmd_draw(args), 0)
        self.assertEqual(json.load(open(os.path.join(out, "manifest.json")))["duplicates_collapsed"], {"h": 2})


if __name__ == "__main__":
    unittest.main()
