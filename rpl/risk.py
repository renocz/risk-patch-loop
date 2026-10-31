"""Step 3, risk score: severity + KEV + sensitive access + role, scaled by the container's REAL exposure. No model, no network call.

  score    = (severity points + KEV points + sensitive-access points + role points) x exposure factor
  severity CRITICAL 40, HIGH 25;  KEV +35;  Docker socket or elevated rights +10
  role     control plane (identity provider, reverse proxy, tunnel, container management) +15; parses untrusted input +10
           (both lists are written by hand in roles.json)
  exposure internet-no-auth 1.0, internet-auth 0.85, lan-port 0.55, lan-proxy 0.5, lan-proxy-auth 0.4, localhost 0.25, internal 0.2, unknown 0.6
  decision >= 45 ACT; >= 25 PLAN; otherwise WATCH. No known fix: "WATCH (no fix)" whatever the score.

A score is a way to order work, not a verdict. The roles were chosen by hand, and the thresholds were tuned on one owner's opinions (see docs/results.md).
"""
import json
import sys

from . import config

POINTS_SEVERITY = {"CRITICAL": 40, "HIGH": 25}
POINTS_KEV = 35
POINTS_ACCESS = 10
POINTS_CONTROL = 15
POINTS_UNTRUSTED = 10
FACTOR = {"internet-no-auth": 1.0, "internet-auth": 0.85, "lan-port": 0.55, "lan-proxy": 0.5, "lan-proxy-auth": 0.4,
          "localhost": 0.25, "internal": 0.2, "unknown": 0.6}
T_ACT, T_PLAN = 45, 25
ORDER = ["internet-no-auth", "internet-auth", "lan-port", "lan-proxy", "lan-proxy-auth", "localhost", "internal"]


def sensitive_access(e):
    return bool(e.get("sensitive_mounts")) or "privileged" in e.get("rights", [])


def score(severity, kev, level, sensitive, bonus=0):
    base = POINTS_SEVERITY.get(severity, 10) + (POINTS_KEV if kev else 0) + (POINTS_ACCESS if sensitive else 0) + bonus
    return round(base * FACTOR.get(level, FACTOR["unknown"]), 1)


def decision(value, has_fix):
    if not has_fix:
        return "WATCH (no fix)"
    if value >= T_ACT:
        return "ACT"
    if value >= T_PLAN:
        return "PLAN"
    return "WATCH"


def load_roles(cfg):
    try:
        return json.load(open(cfg["roles_file"]))
    except (OSError, ValueError, TypeError):
        return {"control_plane": [], "untrusted_input": []}


def role_bonus(name, roles):
    return (POINTS_CONTROL if name in roles.get("control_plane", []) else 0) + (POINTS_UNTRUSTED if name in roles.get("untrusted_input", []) else 0)


def exposure_by_image(inventory):
    """{image: (most exposed level among containers sharing it, any sensitive access)}."""
    res = {}
    for e in inventory.values():
        img, lvl = e.get("image"), e.get("level", "unknown")
        cur = res.get(img)
        if cur is None or (lvl in ORDER and (cur[0] not in ORDER or ORDER.index(lvl) < ORDER.index(cur[0]))):
            res[img] = (lvl, sensitive_access(e) or (cur[1] if cur else False))
        else:
            res[img] = (cur[0], cur[1] or sensitive_access(e))
    return res


def bonus_by_image(inventory, roles):
    res = {}
    for name, e in inventory.items():
        res[e.get("image")] = max(res.get(e.get("image"), 0), role_bonus(name, roles))
    return res


def evaluate(findings, inventory, roles=None):
    """Rows sorted by descending score. Class B rows are KEV; A have a fix; C have none."""
    expo = exposure_by_image(inventory)
    bonus = bonus_by_image(inventory, roles or {})
    rows = []
    for cls in ("A", "B", "C"):
        for r in findings.get(cls, []):
            lvl, sens = expo.get(r["image"], ("unknown", False))
            kev = cls == "B"
            v = score(r.get("severity", "?"), kev, lvl, sens, bonus.get(r["image"], 0))
            rows.append({"image": r["image"], "cve": r["cve"], "pkg": r["pkg"], "severity": r.get("severity"), "kev": kev, "level": lvl,
                         "sensitive": sens, "fixed": r.get("fixed") or "", "score": v, "decision": decision(v, bool(r.get("fixed")))})
    return sorted(rows, key=lambda x: (-x["score"], x["image"], x["cve"]))


def summary(rows, n=8):
    counts = {}
    for r in rows:
        k = r["decision"].split(" (")[0]
        counts[k] = counts.get(k, 0) + 1
    best = {}
    for r in rows:
        if r["decision"] in ("ACT", "PLAN") and (r["image"] not in best or r["score"] > best[r["image"]]["score"]):
            best[r["image"]] = r
    top = sorted(best.values(), key=lambda r: -r["score"])[:n]
    lines = [f"ACT {counts.get('ACT', 0)} · PLAN {counts.get('PLAN', 0)} · WATCH {counts.get('WATCH', 0)} (rows)"]
    lines += [f"{r['decision']} {r['score']:.0f} · {r['image']}: {r['cve']} {r['pkg']} ({r['severity']}{', KEV' if r['kev'] else ''}) · {r['level']}" for r in top]
    return lines


def backtest(inventory, labels, roles=None, threshold=T_PLAN):
    """Replay owner verdicts. labels: [{"service", "severity", "kev", "verdict": "A" (act) | "R" (report/defer)}].
    Returns (rows, agreement, acts_found, false_acts); the baseline "always R" is reported by the caller."""
    out = []
    for lab in labels:
        e = inventory.get(lab["service"], {})
        v = score(lab["severity"], lab.get("kev", False), e.get("level", "unknown"), sensitive_access(e), role_bonus(lab["service"], roles or {}))
        out.append({"service": lab["service"], "score": v, "predicted": "A" if v >= threshold else "R", "verdict": lab["verdict"]})
    agree = sum(1 for r in out if r["predicted"] == r["verdict"])
    found = sum(1 for r in out if r["verdict"] == "A" and r["predicted"] == "A")
    false = sum(1 for r in out if r["verdict"] == "R" and r["predicted"] == "A")
    return out, agree, found, false


def main(argv):
    cfg = config.load()
    inv = json.load(open(config.state(cfg, "inventory.json")))
    roles = load_roles(cfg)
    if "--backtest" in argv:
        labels = json.load(open(argv[argv.index("--backtest") + 1]))
        rows, agree, found, false = backtest(inv, labels, roles)
        n_a = sum(1 for lab in labels if lab["verdict"] == "A")
        print(f"baseline 'always R': {len(labels) - n_a}/{len(labels)} ({n_a} verdicts A)")
        print(f"score: agreement {agree}/{len(labels)} · A found {found}/{n_a} · false A {false}/{len(labels) - n_a}")
        return 0
    rows = evaluate(json.load(open(config.state(cfg, "findings.json"))), inv, roles)
    json.dump({"rows": rows, "summary": summary(rows)}, open(config.state(cfg, "risk.json"), "w"), ensure_ascii=False)
    print("\n".join(summary(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
