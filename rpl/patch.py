"""Step 6, patch ONE service, with automatic rollback if the check fails.

Sequence: snapshot -> (database dump) -> pin the new image in the compose file -> dry run (only this service may be recreated) -> recreate ->
check (container running and healthy, AND a route through the reverse proxy answers with an expected status) -> on failure: restore the old
compose file, recreate the service, check again, record the result.

Never touches a service that shares another container's network namespace through a VPN container whose name contains "gluetun":
those need their own procedure and an explicit decision.

Limits, written down: the rollback puts the previous IMAGE back, not the data (a database migrated by the new version needs the dump or the
snapshot); the route check tests one route, not the whole application.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time

from . import config

REFUSED_NAMES = ("gluetun",)
RECREATE = re.compile(r"Container\s+(\S+)\s+Recreate")     # "[DRY-RUN MODE - ]Container <name>  Recreate[d|ing]"


class Host:
    """Everything `rpl patch` does to the outside world: run a command, wait, read the clock.
    Tests inject a fake with the same three methods, so no real Docker, curl or sleep is involved."""

    def run(self, cmd, **kw):
        return subprocess.run(cmd, capture_output=True, text=True, **kw)

    def sleep(self, seconds):
        time.sleep(seconds)

    def now(self):
        return time.time()


HOST = Host()


def compose(f, *a, host=HOST):
    return host.run(["docker", "compose", "-f", f, *a])


# ---- pinning -------------------------------------------------------------------------------------------------------

def find_image_line(lines, old):
    idx = [i for i, l in enumerate(lines) if l.lstrip().startswith("image:") and l.split("image:", 1)[1].strip().split("#")[0].strip() == old]
    return idx[0] if len(idx) == 1 else None


def pin(compose_file, old, new, apply=False, host=HOST):
    """Replace ONE `image:` value. Backup with a timestamp (seconds), `docker compose config -q` after writing, old file restored on refusal.
    Returns (ok, message, backup path)."""
    with open(compose_file, encoding="utf-8") as f:
        lines = f.read().splitlines(keepends=True)
    i = find_image_line(lines, old)
    if i is None:
        return False, f"'{old}' must appear exactly once on an image: line", None
    new_line = lines[i].replace(old, new, 1)
    msg = f"- {lines[i].rstrip()}\n+ {new_line.rstrip()}"
    if not apply:
        return True, msg + "\n(dry: nothing written)", None
    backup = f"{compose_file}.bak-{datetime.datetime.now():%Y%m%d-%H%M%S}"
    shutil.copy2(compose_file, backup)
    lines[i] = new_line
    with open(compose_file, "w", encoding="utf-8") as f:
        f.write("".join(lines))
    r = host.run(["docker", "compose", "-f", compose_file, "config", "-q"])
    if r.returncode:
        shutil.copy2(backup, compose_file)
        return False, "docker compose refused the new file, old file restored: " + r.stderr.strip()[:200], backup
    return True, msg + f"\nwritten (backup {backup})", backup


# ---- checks --------------------------------------------------------------------------------------------------------

def shares_vpn_network(compose_file, service, host=HOST):
    cfg = compose(compose_file, "config", "--format", "json", host=host)
    if cfg.returncode:
        return True                       # cannot tell: refuse
    svc = json.loads(cfg.stdout).get("services", {}).get(service, {})
    mode = svc.get("network_mode") or ""
    return any(n in service or n in mode for n in REFUSED_NAMES)


def healthy(compose_file, service, timeout, host=HOST):
    end = host.now() + timeout
    while host.now() < end:
        cid = compose(compose_file, "ps", "-q", service, host=host).stdout.strip().splitlines()
        if cid:
            st = json.loads(host.run(["docker", "inspect", cid[0]]).stdout)[0]["State"]
            health = (st.get("Health") or {}).get("Status")
            if st.get("Running") and health in (None, "healthy"):
                return True, health or "no healthcheck"
        host.sleep(5)
    return False, f"not healthy after {timeout} s"


def route_ok(url, route_host, codes, timeout, host=HOST):
    end = host.now() + timeout
    code = "?"
    while host.now() < end:
        code = host.run(["curl", "-sk", "-o", "/dev/null", "-m", "15", "-H", f"Host: {route_host}", "-w", "%{http_code}", url]).stdout.strip()
        if code in codes:
            return True, code
        host.sleep(5)
    return False, code


def journal(cfg, entry):
    path = config.state(cfg, "patches.json")
    try:
        data = json.load(open(path))
    except (OSError, ValueError):
        data = []
    data.append(entry)
    json.dump(data[-200:], open(path, "w"), ensure_ascii=False)


# ---- the sequence --------------------------------------------------------------------------------------------------

def main(argv, host=HOST):
    p = argparse.ArgumentParser(prog="rpl patch")
    p.add_argument("--compose", required=True)
    p.add_argument("--service", required=True)
    p.add_argument("--old", required=True)
    p.add_argument("--new", required=True)
    p.add_argument("--route", required=True, help="host name tested through the reverse proxy after the update")
    p.add_argument("--codes", required=True, help="accepted HTTP statuses, e.g. '200 302' (401 for a route behind forward-auth)")
    p.add_argument("--db-container")
    p.add_argument("--db-user")
    p.add_argument("--db-name")
    p.add_argument("--dry", action="store_true")
    p.add_argument("--no-snapshot", action="store_true", help="required when no snapshot_command is configured")
    a = p.parse_args(argv)
    cfg = config.load()
    codes = a.codes.split()
    if shares_vpn_network(a.compose, a.service, host):
        print("REFUSED: VPN container or a service sharing its network: dedicated procedure and an explicit decision required")
        return 3
    ok, msg, _ = pin(a.compose, a.old, a.new, host=host)
    print(msg)
    if not ok:
        return 1
    if a.dry:
        print("(dry) planned: snapshot, " + ("database dump, " if a.db_container else "") + "pin, dry run, recreate, check, rollback on failure")
        return 0
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    # 1. snapshot
    if cfg.get("snapshot_command"):
        s = host.run(cfg["snapshot_command"] if isinstance(cfg["snapshot_command"], list) else ["sh", "-c", cfg["snapshot_command"]])
        print(s.stdout.strip())
        if s.returncode:
            print("snapshot FAILED: nothing was changed")
            return 1
    elif not a.no_snapshot:
        print("REFUSED: no snapshot_command configured; say --no-snapshot out loud to go without one")
        return 1
    # 2. database dump (PostgreSQL)
    if a.db_container:
        d = os.path.join(cfg["backup_dir"], stamp)
        os.makedirs(d, exist_ok=True)
        dump = f"{a.service}-{stamp}.dump"
        r1 = host.run(["docker", "exec", "-w", "/tmp", a.db_container, "pg_dump", "-U", a.db_user, "-Fc", "-f", f"/tmp/{dump}", a.db_name])
        r2 = host.run(["docker", "cp", f"{a.db_container}:/tmp/{dump}", os.path.join(d, dump)])
        r3 = host.run(["docker", "exec", "-w", "/tmp", a.db_container, "pg_restore", "-l", f"/tmp/{dump}"])
        if r1.returncode or r2.returncode or r3.returncode or len(r3.stdout.splitlines()) < 5:
            print("database dump FAILED: nothing was changed", (r1.stderr + r2.stderr + r3.stderr)[:200])
            return 1
        print(f"dump: {os.path.join(d, dump)} ({os.path.getsize(os.path.join(d, dump)) // 1048576} MB, {len(r3.stdout.splitlines())} objects readable): delete within 7 days")
    # 3. pin
    ok, msg, backup = pin(a.compose, a.old, a.new, apply=True, host=host)
    print(msg)
    if not ok:
        return 1
    # 4. dry run: only this service may be recreated
    dry = compose(a.compose, "up", "-d", "--no-deps", "--dry-run", a.service, host=host)
    if dry.returncode:
        shutil.copy2(backup, a.compose)
        print("dry run FAILED: old file restored: " + (dry.stderr or dry.stdout).strip()[-200:])
        return 1
    recreated = set(RECREATE.findall(dry.stdout + dry.stderr))
    print("dry run would recreate", sorted(recreated))
    if len(recreated) > 1:
        shutil.copy2(backup, a.compose)
        print("FAILED: more than one container would be recreated: old file restored")
        return 1
    # 5. recreate and check
    u = compose(a.compose, "up", "-d", "--no-deps", a.service, host=host)
    print((u.stdout + u.stderr).strip()[-300:])
    if u.returncode:
        # e.g. the new image cannot be pulled: Docker leaves the OLD container running, which would pass the check below
        ok1, e1 = False, "docker compose up failed: " + (u.stderr or u.stdout).strip()[-200:]
        print(e1)
    else:
        ok1, e1 = healthy(a.compose, a.service, cfg["health_timeout_s"], host)
    ok2, c2 = route_ok(cfg["route_check_url"], a.route, codes, cfg["route_timeout_s"], host) if ok1 else (False, "-")
    print(f"check: container {e1}; route {a.route}: HTTP {c2} (expected {codes})")
    if ok1 and ok2:
        journal(cfg, {"ts": host.now(), "service": a.service, "from": a.old, "to": a.new, "result": "ok"})
        print("OK")
        return 0
    # 6. rollback
    print("CHECK FAILED: ROLLBACK")
    shutil.copy2(backup, a.compose)
    compose(a.compose, "up", "-d", "--no-deps", a.service, host=host)
    okb, eb = healthy(a.compose, a.service, cfg["health_timeout_s"], host)
    okr, cr = route_ok(cfg["route_check_url"], a.route, codes, cfg["route_timeout_s"], host) if okb else (False, "-")
    print(f"after rollback: container {eb}; route HTTP {cr}")
    journal(cfg, {"ts": host.now(), "service": a.service, "from": a.old, "to": a.new, "result": "rollback " + ("ok" if okb and okr else "CHECK BY HAND")})
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
