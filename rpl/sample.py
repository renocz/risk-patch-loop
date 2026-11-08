"""Measure the score's false-negative rate: draw a labelling sample, then compute the rate from the labels.

  rpl sample draw   --host NAME=risk.json (twice or more) --seed N --out DIR [--size 100]
  rpl sample result --sample DIR/sample.json --reviewer NAME=sheet.csv (twice) [--tiebreak NAME=sheet.csv]

This is roadmap criterion 3 of the README. The draw is deterministic (the order comes from a SHA-256 of the seed and the
finding, not from a random-number generator whose output could change between Python versions), so anyone with the same
risk.json files, seed and size gets the same sample. Reviewers get `sheet.csv`, which never contains the score or the
decision; `sample.json` holds them and stays with whoever computes the result. No network call, no dependency.
"""
import argparse
import csv
import hashlib
import json
import math
import os
import sys

from . import __version__

ANSWERS = ("act", "defer", "unsure")
SHEET_FIELDS = ["id", "host", "image", "cve", "pkg", "severity", "kev", "exposure", "sensitive_access", "fixed_version", "answer", "notes"]
CRITERIA = os.path.join("docs", "labelling-criteria.md")


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


def draw(hosts, size, seed, allow_short=False):
    """Stratified draw. The ACT rows and the PLAN + WATCH rows are as numerous as each other, and PLAN and WATCH
    share the second half as evenly as the findings allow."""
    if len(hosts) < 2:
        raise SystemExit("the sample must come from at least 2 hosts' scans (roadmap criterion 3)")
    rows = [r for rs in hosts.values() for r in rs]
    ids = [r["id"] for r in rows]
    if len(set(ids)) != len(ids):
        raise SystemExit("duplicate findings in the inputs (same host, image, CVE and package twice)")
    act = [r for r in rows if r.get("decision") == "ACT"]
    plan = [r for r in rows if r.get("decision") == "PLAN"]
    watch = [r for r in rows if r.get("decision") == "WATCH"]
    n_act = min(size // 2, len(act))
    n_plan = min(len(plan), (n_act + 1) // 2)
    n_watch = min(len(watch), n_act - n_plan)
    n_plan = min(len(plan), n_act - n_watch)
    if n_plan + n_watch < n_act:
        n_act = n_plan + n_watch
    chosen = pick(act, n_act, seed, "act") + pick(plan, n_plan, seed, "plan") + pick(watch, n_watch, seed, "watch")
    available = {"ACT": len(act), "PLAN": len(plan), "WATCH": len(watch)}
    if len(chosen) < size and not allow_short:
        raise SystemExit(f"only {len(chosen)} findings can be drawn with ACT and PLAN+WATCH equally numerous "
                         f"(available with a fix: {available}); the criterion needs {size}. Use --allow-short for a trial draw.")
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
    res = draw(hosts, args.size, args.seed, args.allow_short)
    os.makedirs(args.out, exist_ok=True)
    manifest = {"rpl_version": __version__, "seed": args.seed, "size": len(res["rows"]), "requested": args.size,
                "strata": res["strata"], "available_with_fix": res["available"],
                "inputs": {name: sha256_file(path) for name, path in pairs},
                "criteria_sha256": sha256_file(CRITERIA), "ids": sorted(r["id"] for r in res["rows"])}
    with open(os.path.join(args.out, "sample.json"), "w") as f:
        json.dump({"manifest": manifest, "rows": res["rows"]}, f, ensure_ascii=False, indent=1, sort_keys=True)
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1, sort_keys=True)
    write_sheet(os.path.join(args.out, "sheet.csv"), blind_rows(res["rows"], args.seed))
    print(f"drawn {manifest['size']} findings from {len(hosts)} hosts: {res['strata']} (available with a fix: {res['available']})")
    print(f"{args.out}/sheet.csv goes to the reviewers (no score, no decision); sample.json stays with you; manifest.json can be published")
    return 0


def cmd_result(args):
    data = json.load(open(args.sample))
    rows = data["rows"]
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
    print(f"act verdicts ranked below ACT, 'unsure' counted as defer: {fmt(strict)}")
    print(f"act verdicts ranked below ACT, 'unsure' counted as act:   {fmt(loose)}")
    for key, r in (("unsure as defer", strict), ("unsure as act", loose)):
        if r["rate"] is not None:
            print(f"target 10% ({key}): point estimate {'met' if r['rate'] <= 0.10 else 'NOT met'}, upper end of the interval {'under' if r['ci95'][1] <= 0.10 else 'above'} 10%")
    by = {}
    for r in rows:
        by.setdefault(r["decision"], {"act": 0, "defer": 0, "unsure": 0})[res["truth"][r["id"]]] += 1
    print("final answers by what the score said:", json.dumps(by, sort_keys=True))
    out = {"sample": os.path.basename(args.sample), "disagreements": len(res["disagreements"]), "unsure": unsure,
           "unsure_as_defer": strict, "unsure_as_act": loose, "by_score_decision": by}
    if args.out:
        with open(args.out, "w") as f:
            json.dump(out, f, indent=1, sort_keys=True)
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="rpl sample", description="false-negative measurement (roadmap criterion 3)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("draw", help="draw the labelling sample and write the blind sheet")
    d.add_argument("--host", action="append", required=True, metavar="NAME=risk.json", help="one per host, at least 2")
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
    r.set_defaults(fn=cmd_result)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
