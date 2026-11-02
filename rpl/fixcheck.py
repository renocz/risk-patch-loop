"""Step 4, fix check: does a newer published version REALLY fix what the score says to act on? Read-only: nothing is pulled into Docker.

For each image with ACT rows:
  1. list the versions published in the registry (anonymous API: ghcr.io, Docker Hub; lscr.io is ghcr.io/linuxserver);
  2. pick a candidate: the newest of the same major series, else the newest overall (a moving tag such as "latest": the same reference, read again);
  3. scan the candidate FROM THE REGISTRY (trivy --image-src remote) and count how many ACT rows it removes.
Verdict per image: COMPLETE (all ACT rows gone), PARTIAL, NONE, or NO NEWER VERSION. Limit: a candidate tag can be a pre-release.
"""
import json
import re
import subprocess
import sys
import time
import urllib.request

from . import config, risk

VERSION = re.compile(r"^(v?)(\d+(?:\.\d+)*)$")


def split_ref(ref):
    """'lscr.io/linuxserver/bazarr:latest' -> (registry, repository, tag). Digests (@sha256) are ignored."""
    ref = ref.split("@")[0]
    tag = "latest"
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if "." in parts[0] or ":" in parts[0]:
        reg, repo = parts[0], "/".join(parts[1:])
    else:
        reg, repo = "docker.io", ref if len(parts) > 1 else f"library/{ref}"
    if reg == "lscr.io":
        reg = "ghcr.io"          # lscr.io is a front for ghcr.io/linuxserver
    return reg, repo, tag


def version(tag):
    m = VERSION.match(tag)
    return (m.group(1), tuple(int(x) for x in m.group(2).split("."))) if m else None


def choose_candidate(current_tag, tags):
    """(candidate tag, reason) or (None, reason). A non-versioned tag returns itself: the same reference is read again."""
    cur = version(current_tag)
    if cur is None:
        return current_tag, "moving tag: the same reference is read again from the registry"
    prefix, v = cur
    newer = [(version(t)[1], t) for t in tags if version(t) and version(t)[0] == prefix and len(version(t)[1]) == len(v) and version(t)[1] > v]
    if not newer:
        return None, "no newer version published"
    same_major = [x for x in newer if x[0][0] == v[0]]
    pick = max(same_major or newer)
    return pick[1], "newest of the same major series" if same_major else "newest overall (other major series: possibly breaking)"


def outcome(act_rows, remaining):
    """act_rows: ACT rows {cve, pkg}; remaining: set of (cve, pkg) still present in the candidate."""
    keys = {(r["cve"], r["pkg"]) for r in act_rows}
    left = {k for k in keys if k in remaining}
    gone = len(keys) - len(left)
    return {"act": len(keys), "removed": gone, "remaining": len(left),
            "verdict": "COMPLETE" if keys and not left else ("PARTIAL" if gone else "NONE")}


def get_json(url, headers=None):
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=headers or {"User-Agent": "risk-patch-loop"}), timeout=30))


# Anonymous registry endpoints. Kept in one table so that tests can point them at a local fake registry.
ENDPOINTS = {
    "ghcr.io": {"token": "https://ghcr.io/token?scope=repository:{repo}:pull", "api": "https://ghcr.io"},
    "docker.io": {"token": "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull",
                  "api": "https://registry-1.docker.io"},
}


def registry_auth(reg, repo):
    """(bearer token, API base URL) for a supported registry, or None."""
    ep = ENDPOINTS.get(reg)
    if ep is None:
        return None
    return get_json(ep["token"].format(repo=repo))["token"], ep["api"]


def list_tags(reg, repo):
    auth = registry_auth(reg, repo)
    if auth is None:
        return None
    tok, api = auth
    return get_json(f"{api}/v2/{repo}/tags/list?n=10000", {"Authorization": f"Bearer {tok}", "User-Agent": "risk-patch-loop"}).get("tags") or []


def scan_remote(cfg, ref):
    p = subprocess.run(["docker", "run", "--rm", "-v", f"{cfg['trivy_cache']}:/root/.cache/trivy", cfg["trivy_image"], "image", "--quiet",
                        "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--image-src", "remote", "--format", "json", ref],
                       capture_output=True, text=True, timeout=900)
    if p.returncode:
        return None
    d = json.loads(p.stdout)
    return {(v.get("VulnerabilityID"), v.get("PkgName")) for r in d.get("Results", []) for v in (r.get("Vulnerabilities") or [])}


def main(argv):
    cfg = config.load()
    dry = "--dry" in argv
    maxn = int(argv[argv.index("--max") + 1]) if "--max" in argv else 12
    inv = json.load(open(config.state(cfg, "inventory.json")))
    rows = risk.evaluate(json.load(open(config.state(cfg, "findings.json"))), inv, risk.load_roles(cfg))
    by_image = {}
    for r in rows:
        if r["decision"] == "ACT":
            by_image.setdefault(r["image"].split("@")[0], []).append(r)
    images = sorted(by_image, key=lambda i: -max(r["score"] for r in by_image[i]))[:maxn]
    out = {"ts": time.time(), "images": []}
    for ref in images:
        reg, repo, tag = split_ref(ref)
        e = {"image": ref, "act": len(by_image[ref]), "max_score": max(r["score"] for r in by_image[ref])}
        try:
            tags = list_tags(reg, repo)
        except Exception as ex:
            tags, e["registry_error"] = None, ex.__class__.__name__
        if tags is None:
            e["verdict"] = "UNKNOWN (registry not supported or unreachable)"
        else:
            cand, why = choose_candidate(tag, tags)
            e["candidate"], e["reason"] = cand, why
            if cand is None:
                e["verdict"] = "NO NEWER VERSION"
            elif dry:
                e["verdict"] = "(dry: not scanned)"
            else:
                remaining = scan_remote(cfg, f"{reg}/{repo}:{cand}" if reg != "docker.io" else f"{repo}:{cand}")
                e.update({"verdict": "SCAN FAILED"} if remaining is None else outcome(by_image[ref], remaining))
        out["images"].append(e)
        print(json.dumps(e, ensure_ascii=False))
    if not dry:
        json.dump(out, open(config.state(cfg, "fixcheck.json"), "w"), ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
