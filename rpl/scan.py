"""Step 1, scan: Trivy on the images that are RUNNING, plus the CISA KEV list. Writes state/findings.json.

Three classes:
  A  HIGH/CRITICAL with a fixed version available
  B  in the CISA KEV list (exploited in the wild), any severity, fixed or not
  C  HIGH/CRITICAL without a fix and not in KEV (counted only)
A scan that could not do its job is never reported as "OK": a stale vulnerability database, an unavailable KEV list or an image that
could not be analysed makes the scan unreliable, and findings.json is then not rewritten.

Images are scanned by their ID (sha256), not by name: a container started from an image pinned by digest leaves the old tag in the local
store, and scanning the tag would report the old image.
"""
import datetime
import json
import os
import subprocess
import sys
import time
import urllib.request

from . import config

HIGH = ("HIGH", "CRITICAL")
DB_MAX_AGE_H = 72


def classify(per_image, kev):
    """per_image: {image: [Trivy vulnerabilities]}; kev: set of CVE ids. Returns (A, B, C) lists of dicts."""
    A, B, C = [], [], []
    for image, vulns in per_image.items():
        seen = set()
        for v in vulns:
            cve = v.get("VulnerabilityID", "")
            key = (cve, v.get("PkgName", ""), v.get("InstalledVersion", ""))
            if not cve or key in seen:
                continue
            seen.add(key)
            row = {"image": image, "cve": cve, "pkg": v.get("PkgName", "?"), "installed": v.get("InstalledVersion", "?"),
                   "fixed": v.get("FixedVersion", "") or "", "severity": v.get("Severity", "?")}
            if cve in kev:
                B.append(row)
            elif row["severity"] in HIGH and row["fixed"]:
                A.append(row)
            elif row["severity"] in HIGH:
                C.append(row)
    k = lambda r: (r["image"], r["cve"])
    return sorted(A, key=k), sorted(B, key=k), sorted(C, key=k)


def split_accepted(rows, accepted):
    """Separate findings the owner reviewed and accepted ("image|CVE" -> reason) from the rest."""
    keep, ok = [], []
    for r in rows:
        (ok if f"{r['image']}|{r['cve']}" in accepted else keep).append(r)
    return keep, ok


def scan_failure(db_age_h, kev_ok, not_analysed, total):
    """Reasons why the scan must NOT be declared reliable (empty list = reliable)."""
    reasons = []
    if db_age_h is None:
        reasons.append("age of the vulnerability database unknown")
    elif db_age_h > DB_MAX_AGE_H:
        reasons.append(f"vulnerability database too old ({db_age_h:.0f} h)")
    if not kev_ok:
        reasons.append("CISA KEV list unavailable")
    if total == 0:
        reasons.append("no running image found")
    if not_analysed:
        reasons.append(f"{len(not_analysed)} image(s) not analysed: " + ", ".join(not_analysed[:5]))
    return reasons


def run(cmd, timeout=600):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def images_running():
    """({display name: image id}, sorted names) for the running containers."""
    p = run(["docker", "ps", "--format", "{{.Image}}|{{.ID}}"], 60)
    if p.returncode != 0:
        return {}
    ids = {}
    for line in p.stdout.splitlines():
        if "|" not in line:
            continue
        name, cid = line.strip().split("|", 1)
        if name not in ids:
            r = run(["docker", "inspect", "-f", "{{.Image}}", cid], 30)
            ids[name] = r.stdout.strip() if r.returncode == 0 and r.stdout.strip().startswith("sha256:") else name
    return ids


def scan_image(cfg, ref):
    p = run(["docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", f"{cfg['trivy_cache']}:/root/.cache/trivy",
             cfg["trivy_image"], "image", "--quiet", "--format", "json", "--scanners", "vuln", ref], 900)
    if p.returncode != 0:
        return None
    try:
        d = json.loads(p.stdout)
    except ValueError:
        return None
    return [v for r in (d.get("Results") or []) for v in (r.get("Vulnerabilities") or [])]


def db_age_hours(cfg):
    try:
        m = json.load(open(os.path.join(cfg["trivy_cache"], "db", "metadata.json")))
        t = datetime.datetime.fromisoformat(m["UpdatedAt"].replace("Z", "+00:00"))
        return (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() / 3600
    except (OSError, ValueError, KeyError):
        return None


def load_kev(cfg):
    """(set of CVE ids, ok). Falls back to the cached copy if the download fails, and says so (ok=False)."""
    cache = config.state(cfg, "kev.json")
    try:
        d = json.load(urllib.request.urlopen(urllib.request.Request(cfg["kev_url"], headers={"User-Agent": "risk-patch-loop"}), timeout=30))
        with open(cache, "w") as f:
            json.dump(d, f)
        return {v["cveID"] for v in d.get("vulnerabilities", [])}, True
    except Exception:
        try:
            return {v["cveID"] for v in json.load(open(cache)).get("vulnerabilities", [])}, False
        except (OSError, ValueError):
            return set(), False


def main(argv):
    cfg = config.load()
    dry = "--dry" in argv
    t0 = time.time()
    ids = images_running()
    kev, kev_ok = load_kev(cfg)
    per_image, not_analysed = {}, []
    for name, ref in sorted(ids.items()):
        v = scan_image(cfg, ref)
        (not_analysed.append(name) if v is None else per_image.__setitem__(name, v))
    A, B, C = classify(per_image, kev)
    try:
        accepted = json.load(open(cfg["accepted_file"]))
    except (OSError, ValueError, TypeError):
        accepted = {}
    A, a_ok = split_accepted(A, accepted)
    B, b_ok = split_accepted(B, accepted)
    C, c_ok = split_accepted(C, accepted)
    reasons = scan_failure(db_age_hours(cfg), kev_ok, not_analysed, len(ids))
    print(f"{len(ids)} images: {len(B)} KEV, {len(A)} fixable HIGH/CRITICAL, {len(C)} without a fix, {len(a_ok) + len(b_ok) + len(c_ok)} accepted"
          + (" | UNRELIABLE: " + "; ".join(reasons) if reasons else "") + f" ({time.time() - t0:.0f} s)")
    if dry or reasons:
        return 1 if reasons else 0
    with open(config.state(cfg, "findings.json"), "w") as f:
        json.dump({"ts": time.time(), "A": A, "B": B, "C": C, "images": sorted(ids)}, f)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
