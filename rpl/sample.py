"""Measure the score's false-negative rate: draw a labelling sample, then compute the rate from the labels.

  rpl sample draw   --host NAME=risk.json (twice or more) --seed N --out DIR [--size 100]
  rpl sample result --sample DIR/sample.json --reviewer NAME=sheet.csv (twice) [--tiebreak NAME=sheet.csv]

This is roadmap criterion 3 of the README. The draw is deterministic (the order comes from a SHA-256 of the seed and the
finding, not from a random-number generator whose output could change between Python versions), so anyone with the same
risk.json files, seed and size gets the same sample. Reviewers get `sheet.csv`, which never contains the score or the
decision; `sample.json` holds them and stays with whoever computes the result. The draw is stratified (as many ACT rows as PLAN + WATCH rows), so `result`
prints the rate in the sample AND an estimate for the host, weighted by the size of each stratum (`weighted_rate`), and applies the decision rule to
the latter: the score must change when the LOWER end of the 95% interval is above 10%; otherwise nothing is required, and nothing is shown about a low rate.
The manifest of a draw records what the score is made of (`scoring`: the hashes of risk.py and inventory.py, the thresholds, and the hashes of the
owner's roles, tunnel and gate lists named in the configuration), and `result` refuses to describe another score (exit 4, `--allow-changed-scoring`
goes on and says so). Run both with the configuration that produced the risk.json.
No network call, no dependency.
"""
import argparse
import csv
import hashlib
import json
import math
import os
import sys

from . import __version__, config, risk

ANSWERS = ("act", "defer", "unsure")
SHEET_FIELDS = ["id", "host", "image", "cve", "pkg", "severity", "kev", "exposure", "sensitive_access", "fixed_version", "answer", "notes"]
CRITERIA = os.path.join("docs", "labelling-criteria.md")


SCORING_FILES = ("risk.py", "inventory.py")           # the code that turns findings and containers into a level and a decision
SCORING_INPUTS = ("roles_file", "tunnel_hosts_file", "gated_hosts_file")
SCORING_SETTINGS = ("auth_middleware_words",)         # configuration values the score reads (inventory.py): hashed, order ignored


def scoring_fingerprint(cfg):
    """What the score is made of, as hashes: the two modules, the thresholds, and the owner's input files named in the configuration (None when a
    file is not configured or does not exist). Hashes only: the manifest is published, it must hold neither a path nor the content of a list."""
    pkg = os.path.dirname(os.path.abspath(__file__))
    inputs = {}
    for key in SCORING_INPUTS:
        path = (cfg or {}).get(key)
        inputs[key] = sha256_file(path) if path and os.path.exists(path) else None
    settings = {}
    for key in SCORING_SETTINGS:
        value = (cfg or {}).get(key)
        settings[key] = None if value is None else hashlib.sha256(json.dumps(sorted(value) if isinstance(value, list) else value).encode()).hexdigest()
    return {"files": {name: sha256_file(os.path.join(pkg, name)) for name in SCORING_FILES},
            "t_act": risk.T_ACT, "t_plan": risk.T_PLAN, "inputs": inputs, "settings": settings}


def scoring_changes(recorded, now):
    """(changes, not_recorded): what differs between the fingerprint of the draw and the current one, and the inputs one side cannot tell."""
    changes, unknown = [], []
    for name in SCORING_FILES:
        if recorded["files"].get(name) != now["files"][name]:
            changes.append(f"{name} is not the file the sample was drawn with")
    for key in ("t_act", "t_plan"):
        if recorded.get(key) != now[key]:
            changes.append(f"{key} was {recorded.get(key)} at the draw and is {now[key]} now")
    for key in SCORING_INPUTS:
        then, current = (recorded.get("inputs") or {}).get(key), now["inputs"][key]
        if then is None or current is None:
            if then != current:
                unknown.append(key)
        elif then != current:
            changes.append(f"{key} is not the file the sample was drawn with")
    for key in SCORING_SETTINGS:
        then, current = (recorded.get("settings") or {}).get(key), (now.get("settings") or {}).get(key)
        if then is None or current is None:
            if then != current:
                unknown.append(key)
        elif then != current:
            changes.append(f"{key} is not the setting the sample was drawn with")
    return changes, unknown


def scan_environment(cfg):
    """What the findings behind the draw were scanned with, from findings.json of the configured state directory (None when unknown).
    No path: the manifest is published."""
    try:
        data = json.load(open(config.state(cfg, "findings.json")))
        t = data["trivy"]
        return {"trivy_image": t.get("image"), "db_updated_at": t.get("db_updated_at"), "db_version": t.get("db_version"), "findings_ts": data.get("ts")}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def _config():
    try:
        return config.load()
    except Exception:                                                        # an unreadable configuration must not stop a draw from saying what it can
        return {}


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def row_id(host, image, cve, pkg):
    return hashlib.sha256(f"{host}|{image}|{cve}|{pkg}".encode()).hexdigest()[:12]


def parse_pairs(items, what):
    pairs = []
    for item in items:
        name, sep, path = item.partition("=")
        if not sep or not name or not path:
            raise SystemExit(f"{what} must look like NAME=path, got '{item}'")
        pairs.append((name, os.path.expanduser(path)))
    names = [n for n, _ in pairs]
    if len(set(names)) != len(names):
        raise SystemExit(f"{what} names must be different: {names}")
    return pairs


def load_hosts(pairs):
    """{host: [rows with a known fix]}. Rows without a fix are left out: the ground truth needs 'a fix exists', so they
    could never deserve ACT and would only cost labelling time without touching the rate."""
    hosts = {}
    for name, path in pairs:
        try:
            data = json.load(open(path))
            rows = data["rows"]
        except (OSError, ValueError, KeyError, TypeError):
            raise SystemExit(f"{path}: not a risk.json written by 'rpl risk'")
        hosts[name] = [dict(r, host=name, id=row_id(name, r.get("image", ""), r.get("cve", ""), r.get("pkg", "")))
                       for r in rows if r.get("fixed")]
    return hosts


def order_key(seed, tag, ident):
    return hashlib.sha256(f"{seed}|{tag}|{ident}".encode()).hexdigest()


def pick(rows, n, seed, tag):
    return sorted(rows, key=lambda r: order_key(seed, tag, r["id"]))[:n]


def draw(hosts, size, seed, allow_short=False, allow_single_host=False):
    """Stratified draw. The ACT rows come first: half of the sample, or all of them when the host has fewer than that (a host where the score ranks
    few findings ACT is the usual case: 18 of 2,142 on the author's). The rest of the sample comes from PLAN and WATCH, as evenly as the findings
    allow. The strata are not as large as the host's, so `result` weights them (`weighted_rate`)."""
    if len(hosts) < 2 and not allow_single_host:
        raise SystemExit("the sample comes from one host only: pass --single-host to accept that and have it written in the manifest "
                         "(the measurement then says it covers one host)")
    rows = [r for rs in hosts.values() for r in rs]
    ids = [r["id"] for r in rows]
    if len(set(ids)) != len(ids):
        raise SystemExit("duplicate findings in the inputs (same host, image, CVE and package twice)")
    act = [r for r in rows if r.get("decision") == "ACT"]
    plan = [r for r in rows if r.get("decision") == "PLAN"]
    watch = [r for r in rows if r.get("decision") == "WATCH"]
    n_act = min(size // 2, len(act))
    below = size - n_act
    n_plan = min(len(plan), (below + 1) // 2)
    n_watch = min(len(watch), below - n_plan)
    n_plan = min(len(plan), below - n_watch)
    chosen = pick(act, n_act, seed, "act") + pick(plan, n_plan, seed, "plan") + pick(watch, n_watch, seed, "watch")
    available = {"ACT": len(act), "PLAN": len(plan), "WATCH": len(watch)}
    if len(chosen) < size and not allow_short:
        raise SystemExit(f"only {len(chosen)} findings with a fix can be drawn (available with a fix: {available}); "
                         f"the criterion needs {size}. Use --allow-short for a trial draw.")
    return {"rows": chosen, "available": available,
            "strata": {"ACT": n_act, "PLAN": n_plan, "WATCH": n_watch}}


def blind_rows(rows, seed):
    """What reviewers see, in an order that does not follow the strata. No score, no decision."""
    out = []
    for r in sorted(rows, key=lambda r: order_key(seed, "sheet", r["id"])):
        out.append({"id": r["id"], "host": r["host"], "image": r.get("image", ""), "cve": r.get("cve", ""), "pkg": r.get("pkg", ""),
                    "severity": r.get("severity") or "", "kev": "yes" if r.get("kev") else "no", "exposure": r.get("level", "unknown"),
                    "sensitive_access": "yes" if r.get("sensitive") else "no", "fixed_version": r.get("fixed", ""), "answer": "", "notes": ""})
    return out


def write_sheet(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SHEET_FIELDS)
        w.writeheader()
        w.writerows(rows)


def read_sheet(path, expected_ids, who):
    try:
        rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
    except OSError as e:
        raise SystemExit(f"{who}: {e}")
    answers = {}
    for r in rows:
        ident = (r.get("id") or "").strip()
        val = (r.get("answer") or "").strip().lower()
        if ident not in expected_ids:
            raise SystemExit(f"{who}: row '{ident}' is not in the sample")
        if ident in answers:
            raise SystemExit(f"{who}: row '{ident}' appears twice")
        if val not in ANSWERS:
            raise SystemExit(f"{who}: row '{ident}' has answer '{val}', expected one of {', '.join(ANSWERS)}")
        answers[ident] = val
    missing = len(expected_ids) - len(answers)
    if missing:
        raise SystemExit(f"{who}: {missing} of {len(expected_ids)} rows are missing or unanswered")
    return answers


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def kappa(a, b):
    ids = list(a)
    n = len(ids)
    observed = sum(1 for i in ids if a[i] == b[i]) / n
    expected = sum((sum(1 for i in ids if a[i] == v) / n) * (sum(1 for i in ids if b[i] == v) / n) for v in ANSWERS)
    return None if expected == 1 else (observed - expected) / (1 - expected)


def resolve(sample_rows, first, second, tiebreak=None):
    """Truth per finding: the two reviewers' answer when they agree, else the tie-break reviewer's. Disagreements are
    counted and reported. Returns {"truth": {...}, "disagreements": [...], "unresolved": [...]}."""
    truth, disagreements, unresolved = {}, [], []
    for r in sample_rows:
        i = r["id"]
        if first[i] == second[i]:
            truth[i] = first[i]
        else:
            disagreements.append(i)
            if tiebreak is None:
                unresolved.append(i)
            else:
                truth[i] = tiebreak[i]
    return {"truth": truth, "disagreements": disagreements, "unresolved": unresolved}


def rate(sample_rows, truth, unsure_is_act):
    wanted = ("act", "unsure") if unsure_is_act else ("act",)
    act_rows = [r for r in sample_rows if truth[r["id"]] in wanted]
    missed = [r for r in act_rows if r["decision"] != "ACT"]
    n = len(act_rows)
    ci = wilson(len(missed), n)
    return {"act_verdicts": n, "ranked_below_act": len(missed), "rate": (len(missed) / n if n else None),
            "ci95": list(ci) if ci else None}


Z_STRATA = 2.394          # two-sided 95% for three intervals at once (Bonferroni: 1 - 0.05 / 3 per stratum)


def weighted_rate(sample_rows, truth, available, unsure_is_act):
    """The rate of 'act' verdicts the score ranks below ACT, ESTIMATED FOR THE HOST. The draw takes as many ACT rows as PLAN + WATCH rows, whatever
    their number in the host, so the plain rate of `rate()` describes the sample: it treats the strata as equal in size and understates the
    rate when the rows below ACT are much more numerous. Here each stratum (ACT, PLAN, WATCH) is weighted by its size in the host
    (`available`, the manifest's `available_with_fix`):

        estimate = sum over PLAN and WATCH of N_s * p_s  /  sum over the three strata of N_s * p_s      (p_s: share of 'act' among the labelled rows of s)

    The interval is conservative and deterministic: a Wilson interval for each p_s at the level that gives 95% for the three together, and the
    ends of the ratio taken at the corners (it grows with the PLAN and WATCH shares and falls with the ACT share). With no 'act' answer in a
    stratum the interval is not a point. The finite-population correction is left out (it would only narrow the interval).
    Returns {"estimate", "ci95"} or {"estimate": None, "ci95": None, "reason": ...}."""
    strata = ("ACT", "PLAN", "WATCH")
    none = lambda why: {"estimate": None, "ci95": None, "reason": why}
    if not isinstance(available, dict) or any(isinstance(available.get(s), bool) or not isinstance(available.get(s), int) or available[s] < 0 for s in strata):
        return none("the manifest does not give the number of findings with a fix in each stratum (available_with_fix)")
    wanted = ("act", "unsure") if unsure_is_act else ("act",)
    n, k = {}, {}
    for s in strata:
        labelled = [truth[r["id"]] for r in sample_rows if r["decision"] == s]
        n[s], k[s] = len(labelled), sum(1 for v in labelled if v in wanted)
        if available[s] > 0 and n[s] == 0:
            return none(f"the host has {available[s]} {s} findings with a fix and none of them was labelled")
    weight = {s: (available[s] * k[s] / n[s] if n[s] else 0.0) for s in strata}
    total = sum(weight.values())
    if total == 0:
        return none("no 'act' answer in the sample")
    estimate = (weight["PLAN"] + weight["WATCH"]) / total
    lo = {s: (available[s] * wilson(k[s], n[s], Z_STRATA)[0] if n[s] else 0.0) for s in strata}
    hi = {s: (available[s] * wilson(k[s], n[s], Z_STRATA)[1] if n[s] else 0.0) for s in strata}
    below_lo, below_hi = lo["PLAN"] + lo["WATCH"], hi["PLAN"] + hi["WATCH"]
    low = below_lo / (below_lo + hi["ACT"]) if below_lo + hi["ACT"] > 0 else 0.0
    high = below_hi / (below_hi + lo["ACT"]) if below_hi + lo["ACT"] > 0 else 0.0
    return {"estimate": estimate, "ci95": [low, high]}


def fmt_weighted(w):
    lo, hi = w["ci95"]
    return f"{w['estimate'] * 100:.1f}% (95% interval {lo * 100:.1f}% to {hi * 100:.1f}%, conservative)"


def fmt(r):
    if r["rate"] is None:
        return "no 'act' verdict, no rate"
    lo, hi = r["ci95"]
    return f"{r['ranked_below_act']}/{r['act_verdicts']} = {r['rate'] * 100:.1f}% (95% interval {lo * 100:.1f}% to {hi * 100:.1f}%)"


def cmd_draw(args):
    if not os.path.exists(CRITERIA):
        raise SystemExit(f"{CRITERIA} is missing: the written criteria must exist, and be committed, before the draw")
    pairs = parse_pairs(args.host, "--host")
    hosts = load_hosts(pairs)
    res = draw(hosts, args.size, args.seed, args.allow_short, getattr(args, "single_host", False))
    os.makedirs(args.out, exist_ok=True)
    manifest = {"rpl_version": __version__, "seed": args.seed, "size": len(res["rows"]), "requested": args.size,
                "hosts": len(hosts), "single_host": len(hosts) < 2,
                "strata": res["strata"], "available_with_fix": res["available"],
                "inputs": {name: sha256_file(path) for name, path in pairs},
                "criteria_sha256": sha256_file(CRITERIA), "scoring": scoring_fingerprint(_config()), "scan_environment": scan_environment(_config()),
                "ids": sorted(r["id"] for r in res["rows"])}
    with open(os.path.join(args.out, "sample.json"), "w") as f:
        json.dump({"manifest": manifest, "rows": res["rows"]}, f, ensure_ascii=False, indent=1, sort_keys=True)
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1, sort_keys=True)
    write_sheet(os.path.join(args.out, "sheet.csv"), blind_rows(res["rows"], args.seed))
    print(f"drawn {manifest['size']} findings from {len(hosts)} host(s): {res['strata']} (available with a fix: {res['available']})")
    if manifest["single_host"]:
        print("WARNING: one host only, written in manifest.json: the rate describes that host, not Docker hosts in general")
    print(f"{args.out}/sheet.csv goes to the reviewers (no score, no decision); sample.json stays with you; manifest.json can be published")
    return 0


def cmd_result(args):
    data = json.load(open(args.sample))
    rows = data["rows"]
    recorded = (data.get("manifest") or {}).get("scoring")
    if not isinstance(recorded, dict) or not isinstance(recorded.get("files"), dict):
        print("warning: this sample was drawn before the score was fingerprinted: it cannot be checked that the score is the one it was drawn with")
    else:
        changes, unknown = scoring_changes(recorded, scoring_fingerprint(_config()))
        for key in unknown:
            print(f"warning: {key} was not recorded at the draw, or is not configured now: it cannot be compared")
        if changes:
            if not getattr(args, "allow_changed_scoring", False):
                print("REFUSED: the score changed since the draw, so this measure would describe another score:\n  " + "\n  ".join(changes)
                      + "\nrun it with the configuration and the version of the draw, or draw again; --allow-changed-scoring goes on anyway")
                return 4
            print("WARNING: the score changed since the draw, the numbers below describe the score of the draw, not the current one:\n  "
                  + "\n  ".join(changes))
    expected = {r["id"] for r in rows}
    pairs = parse_pairs(args.reviewer, "--reviewer")
    if len(pairs) != 2:
        raise SystemExit("give exactly 2 --reviewer NAME=sheet.csv (a third reviewer goes in --tiebreak)")
    first, second = (read_sheet(p, expected, n) for n, p in pairs)
    tie = None
    if args.tiebreak:
        tpairs = parse_pairs([args.tiebreak], "--tiebreak")
        if tpairs[0][0] in (pairs[0][0], pairs[1][0]):
            raise SystemExit("the tie-break reviewer must be a third person")
        tie = read_sheet(tpairs[0][1], expected, tpairs[0][0])
    res = resolve(rows, first, second, tie)
    agree = len(rows) - len(res["disagreements"])
    k = kappa(first, second)
    ktxt = f" (kappa {k:.2f})" if k is not None else ""
    print(f"sample {len(rows)} findings, reviewers {pairs[0][0]} and {pairs[1][0]}: agree on {agree}, disagree on {len(res['disagreements'])}{ktxt}")
    if res["unresolved"]:
        print(f"{len(res['unresolved'])} disagreements need the third reviewer (--tiebreak); no rate before that:")
        print(", ".join(res["unresolved"]))
        return 3
    unsure = sum(1 for v in res["truth"].values() if v == "unsure")
    strict = rate(rows, res["truth"], False)
    loose = rate(rows, res["truth"], True)
    print(f"'unsure' as the final answer: {unsure}")
    print(f"in the sample (not the host: it holds as many ACT rows as PLAN + WATCH rows), 'unsure' counted as defer: {fmt(strict)}")
    print(f"in the sample (not the host), 'unsure' counted as act: {fmt(loose)}")
    available = (data.get("manifest") or {}).get("available_with_fix")
    weighted = {"unsure_as_defer": weighted_rate(rows, res["truth"], available, False), "unsure_as_act": weighted_rate(rows, res["truth"], available, True)}
    judged = False
    for key, label in (("unsure_as_defer", "unsure as defer"), ("unsure_as_act", "unsure as act")):
        w = weighted[key]
        if w["estimate"] is None:
            print(f"cannot be estimated for the host ({label}): {w['reason']}")
            continue
        judged = True
        print(f"estimated for the host, {label}: {fmt_weighted(w)}")
        lo, hi = w["ci95"]
        if lo > 0.10:
            print(f"decision rule ({label}): the lower end of the interval ({lo * 100:.1f}%) is above 10%: the score must change and the measurement be repeated")
        else:
            print(f"decision rule ({label}): the lower end of the interval ({lo * 100:.1f}%) is not above 10%: the rule requires no change, "
                  f"and this does not show that the rate is under 10% (upper end {hi * 100:.1f}%)")
    if not judged:
        print("the decision rule cannot be applied: no estimate for the host")
    by = {}
    for r in rows:
        by.setdefault(r["decision"], {"act": 0, "defer": 0, "unsure": 0})[res["truth"][r["id"]]] += 1
    print("final answers by what the score said:", json.dumps(by, sort_keys=True))
    out = {"sample": os.path.basename(args.sample), "disagreements": len(res["disagreements"]), "unsure": unsure,
           "unsure_as_defer": strict, "unsure_as_act": loose, "weighted": weighted, "by_score_decision": by}
    if args.out:
        with open(args.out, "w") as f:
            json.dump(out, f, indent=1, sort_keys=True)
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="rpl sample", description="false-negative measurement (roadmap criterion 3)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("draw", help="draw the labelling sample and write the blind sheet")
    d.add_argument("--host", action="append", required=True, metavar="NAME=risk.json", help="one per host; at least 2, or pass --single-host")
    d.add_argument("--single-host", action="store_true", help="accept a draw from one host, recorded in the manifest")
    d.add_argument("--seed", type=int, required=True, help="publish it")
    d.add_argument("--size", type=int, default=100)
    d.add_argument("--out", required=True)
    d.add_argument("--allow-short", action="store_true", help="accept fewer findings than --size (trial draw)")
    d.set_defaults(fn=cmd_draw)
    r = sub.add_parser("result", help="compute the rate from the reviewers' sheets")
    r.add_argument("--sample", required=True)
    r.add_argument("--reviewer", action="append", required=True, metavar="NAME=sheet.csv")
    r.add_argument("--tiebreak", metavar="NAME=sheet.csv")
    r.add_argument("--out", help="write the numbers as JSON")
    r.add_argument("--allow-changed-scoring", action="store_true", help="go on although the score is not the one the sample was drawn with (said loudly)")
    r.set_defaults(fn=cmd_result)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
