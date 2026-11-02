"""Step 5, proposals: updates READY to be approved. Nothing is executed here: the script prepares, a human decides.

A service is proposed only if ALL of these hold:
  - it has an ACT row in the risk score;
  - the fix check PROVED a fix (verdict COMPLETE);
  - it is described in patch-apps.json (health route, accepted statuses, database to dump);
  - it is not a VPN container or a service sharing its network.
Otherwise it is listed with the reason. `rpl proposals --apply <service>` runs `rpl patch` with EXACTLY the parameters of the proposal
(never a free argument), and refuses a proposal older than 36 h.
"""
import json
import subprocess
import sys
import time
import urllib.request

from . import config, fixcheck, risk

VALIDITY_H = 36


def new_reference(current, candidate, registry_digest):
    """(new reference or None, reason). Moving tag: the same tag pinned by digest (None if already at that digest); versioned tag: repo:candidate."""
    no_digest, _, current_digest = current.partition("@")
    last = no_digest.rsplit("/", 1)[-1]
    base, tag = (no_digest.rsplit(":", 1) if ":" in last else (no_digest, "latest"))
    if candidate == tag:
        if registry_digest and registry_digest != current_digest:
            return f"{no_digest}@{registry_digest}", "moving tag: pinned to the registry digest"
        return None, "already at the registry digest"
    return f"{base}:{candidate}", "newer version"


def prepare(act_rows, fixes, apps, containers, digests):
    """act_rows: ACT rows; fixes: {image: fix-check entry}; apps: patch-apps.json; containers: {image: {service, compose, current_image, vpn}};
    digests: {image: registry digest}. Returns (proposals, not_proposed)."""
    by_image = {}
    for r in act_rows:
        by_image.setdefault(r["image"].split("@")[0], []).append(r)     # an image pinned by digest is still the same image
    props, skipped = [], []
    for image, rows in by_image.items():
        fc = fixes.get(image) or {}
        if fc.get("verdict") != "COMPLETE":
            skipped.append({"image": image, "reason": "no proven fix (" + str(fc.get("verdict", "fix check not run")) + ")"})
            continue
        info = containers.get(image)
        if not info:
            skipped.append({"image": image, "reason": "no running container for this image"})
            continue
        if info.get("vpn"):
            skipped.append({"image": image, "reason": "shares a VPN container's network: dedicated procedure and explicit decision"})
            continue
        app = apps.get(info["service"])
        if not app:
            skipped.append({"image": image, "reason": f"service '{info['service']}' is not in patch-apps.json (health route and database to describe)"})
            continue
        new, why = new_reference(info["current_image"], fc.get("candidate"), digests.get(image))
        if not new:
            skipped.append({"image": image, "reason": why})
            continue
        props.append({"id": info["service"], "service": info["service"], "compose": info["compose"], "from": info["current_image"], "to": new,
                      "why": why, "score": max(r["score"] for r in rows), "act_rows": len(rows), "kev": any(r["kev"] for r in rows),
                      "level": rows[0]["level"], "route": app["route"], "codes": app["codes"], "db": app.get("db")})
    props.sort(key=lambda p: -p["score"])
    return props, skipped


def build_command(p, dry=False):
    """The `rpl patch` command of a proposal: the proposal's values only, never a free argument."""
    cmd = [sys.executable, "-m", "rpl", "patch", "--compose", p["compose"], "--service", p["service"], "--old", p["from"], "--new", p["to"],
           "--route", p["route"], "--codes", p["codes"]]
    if p.get("db"):
        cmd += ["--db-container", p["db"]["container"], "--db-user", p["db"]["user"], "--db-name", p["db"]["name"]]
    if dry:
        cmd.append("--dry")
    return cmd


def registry_digest(ref):
    reg, repo, tag = fixcheck.split_ref(ref)
    auth = fixcheck.registry_auth(reg, repo)
    if auth is None:
        return None
    tok, api = auth
    url = f"{api}/v2/{repo}/manifests/{tag}"
    accept = ("application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
              "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
    req = urllib.request.Request(url, method="HEAD", headers={"Authorization": f"Bearer {tok}", "User-Agent": "risk-patch-loop", "Accept": accept})
    return urllib.request.urlopen(req, timeout=30).headers.get("Docker-Content-Digest")


def running_containers():
    ids = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True).stdout.split()
    objs = json.loads(subprocess.run(["docker", "inspect", *ids], capture_output=True, text=True).stdout)
    vpn_id = next((c["Id"] for c in objs if "gluetun" in c["Name"]), None)       # network_mode: service:vpn shows up as container:<id>
    res = {}
    for c in objs:
        lab = c["Config"].get("Labels") or {}
        svc, files = lab.get("com.docker.compose.service"), (lab.get("com.docker.compose.project.config_files") or "").split(",")[0]
        if not svc or not files:
            continue
        mode = c["HostConfig"].get("NetworkMode") or ""
        res.setdefault(c["Config"]["Image"].split("@")[0], {
            "service": svc, "compose": files, "current_image": c["Config"]["Image"],
            "vpn": "gluetun" in c["Name"] or (vpn_id is not None and mode == f"container:{vpn_id}") or "gluetun" in mode})
    return res


def compute(cfg):
    inv = json.load(open(config.state(cfg, "inventory.json")))
    rows = [r for r in risk.evaluate(json.load(open(config.state(cfg, "findings.json"))), inv, risk.load_roles(cfg)) if r["decision"] == "ACT"]
    fixes = {e["image"].split("@")[0]: e for e in json.load(open(config.state(cfg, "fixcheck.json"))).get("images", [])}
    apps = {k: v for k, v in json.load(open(cfg["apps_file"])).items() if not k.startswith("_")}
    digests = {}
    for img in {r["image"].split("@")[0] for r in rows}:
        last = img.rsplit("/", 1)[-1]
        tag = img.rsplit(":", 1)[-1] if ":" in last else "latest"
        if (fixes.get(img) or {}).get("candidate") == tag:
            try:
                digests[img] = registry_digest(img)
            except Exception:
                pass
    return prepare(rows, fixes, apps, running_containers(), digests)


def main(argv):
    cfg = config.load()
    path = config.state(cfg, "proposals.json")
    if "--list" in argv or "--apply" in argv:
        d = json.load(open(path))
        if (time.time() - d["ts"]) / 3600 > VALIDITY_H:
            print(f"REFUSED: proposals are older than {VALIDITY_H} h, compute them again")
            return 1
        if "--list" in argv:
            for p in d["proposals"]:
                print(f"{p['id']:14s} score {p['score']:5.1f}  {p['from']}  ->  {p['to']}  [{p['why']}]  route {p['route']} {p['codes']}" + ("  +db" if p.get("db") else ""))
            for n in d["not_proposed"]:
                print(f"(not proposed) {n['image']}: {n['reason']}")
            return 0
        svc = argv[argv.index("--apply") + 1]
        p = next((x for x in d["proposals"] if x["id"] == svc), None)
        if not p:
            print(f"REFUSED: no proposal '{svc}' (see --list)")
            return 1
        return subprocess.run(build_command(p, "--dry" in argv) + (["--no-snapshot"] if "--no-snapshot" in argv else [])).returncode
    props, skipped = compute(cfg)
    json.dump({"ts": time.time(), "proposals": props, "not_proposed": skipped}, open(path, "w"), ensure_ascii=False)
    print(f"{len(props)} proposal(s), {len(skipped)} not proposed")
    for p in props:
        print(f" - {p['service']}: {p['from']} -> {p['to']} (score {p['score']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
