"""Step 6, patch ONE service, with automatic rollback if the check fails.

Sequence: snapshot -> (database dump) -> pin the new image in the compose file -> dry run (only this service may be recreated) -> recreate ->
check (container healthy, running the NEW image, AND a route through the reverse proxy answers with an expected status) -> on failure: restore the old
compose file, recreate the service, check again, record the result.

Never touches a service that shares another container's network namespace through a VPN container whose name contains "gluetun":
those need their own procedure and an explicit decision.

Exit codes: 0 updated; 1 refused or stopped before the service was touched; 2 the update failed its check and was rolled back (the old image
runs again, verified); 3 refused: VPN; 4 the update failed AND the rollback could not be verified: check by hand.

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
# All checked with fullmatch: '$' would accept a trailing newline.
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")                        # Docker / Compose / PostgreSQL identifiers
IMAGE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]*")               # no whitespace, no newline, nothing a YAML line could carry
HOST_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(?::[0-9]{1,5})?")
HTTP_CODES = re.compile(r"[1-5][0-9]{2}(?: +[1-5][0-9]{2})*")
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

SERVICE_KEY = re.compile(r"""^["']?([A-Za-z0-9_.-]+)["']?\s*:\s*(#.*)?$""")


def service_block(lines, service):
    """(first, last+1) line indexes of the body of `service` under the top-level `services:` key, or None.
    Understands block-style YAML only (comments, blank lines and quoted keys are fine); anchors, merges and flow style are not followed."""
    in_services, child = False, None
    start = None
    for i, line in enumerate(lines):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if start is not None and indent <= child:
            return start, i
        if indent == 0:
            in_services, child = text.split("#")[0].strip() == "services:", None
            continue
        if not in_services:
            continue
        if child is None:
            child = indent
        if indent == child and start is None:
            m = SERVICE_KEY.match(text)
            if m and m.group(1) == service:
                start = i + 1
    return (start, len(lines)) if start is not None else None


def find_image_line(lines, old, block=None):
    """Index of the ONE `image:` line whose value is `old` (within `block` = (first, last+1) if given), else None."""
    lo, hi = block if block else (0, len(lines))
    idx = [i for i in range(lo, hi) if lines[i].lstrip().startswith("image:") and lines[i].split("image:", 1)[1].strip().split("#")[0].strip() == old]
    return idx[0] if len(idx) == 1 else None


def pin(compose_file, old, new, apply=False, host=HOST, service=None):
    """Replace ONE `image:` value. With `service`, only a line inside that service's block qualifies. Backup with a timestamp (seconds),
    `docker compose config -q` after writing, old file restored on refusal. Returns (ok, message, backup path)."""
    with open(compose_file, encoding="utf-8") as f:
        lines = f.read().splitlines(keepends=True)
    block = None
    if service:
        block = service_block(lines, service)
        if block is None:
            return False, f"cannot locate the block of service '{service}' in {compose_file} (anchors or flow style?): refusing to guess", None
    i = find_image_line(lines, old, block)
    if i is None:
        where = f" of service '{service}'" if service else ""
        return False, f"'{old}' must appear exactly once on an image: line{where}", None
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

def invalid_arguments(a):
    """A reason to refuse the arguments before anything is run, or None."""
    for flag, value, rx, what in (("--service", a.service, NAME, "name"), ("--db-container", a.db_container, NAME, "name"),
                                  ("--db-user", a.db_user, NAME, "name"), ("--db-name", a.db_name, NAME, "name"),
                                  ("--old", a.old, IMAGE_REF, "image reference"), ("--new", a.new, IMAGE_REF, "image reference"),
                                  ("--route", a.route, HOST_NAME, "host name (letters, digits, dots, hyphens, optional :port)"),
                                  ("--codes", a.codes, HTTP_CODES, "list of HTTP status codes separated by spaces, e.g. '200 302'")):
        if value is not None and not rx.fullmatch(value):
            return f"{flag} {value!r} is not a valid {what}"
    given = [a.db_container, a.db_user, a.db_name]
    if any(given) and not all(given):
        return "--db-container, --db-user and --db-name go together"
    return None


def service_problem(compose_file, service, old, host=HOST):
    """Why this service cannot be pinned from `old` (as `docker compose config` resolves it), or None."""
    cfg = compose(compose_file, "config", "--format", "json", host=host)
    if cfg.returncode:
        return f"cannot read {compose_file}: " + cfg.stderr.strip()[:200]
    svc = json.loads(cfg.stdout).get("services", {}).get(service)
    if svc is None:
        return f"service '{service}' is not defined in {compose_file}"
    if svc.get("build"):
        return f"service '{service}' is built locally (build:): there is no pulled image to pin"
    if svc.get("image") != old:
        return f"service '{service}' uses image '{svc.get('image')}', not '{old}'"
    return None


def container_names(compose_file, service, host=HOST):
    """Names of the existing containers (running or not) of a service, from `compose ps -a -q` + `docker inspect`.
    The dry run prints container names, not service names, and the name depends on the project (or on container_name:)."""
    ids = compose(compose_file, "ps", "-a", "-q", service, host=host).stdout.split()
    if not ids:
        return set()
    r = host.run(["docker", "inspect", *ids])
    try:
        return {c["Name"].lstrip("/") for c in json.loads(r.stdout)} if r.returncode == 0 else set()
    except (ValueError, KeyError, TypeError):
        return set()


def running_image(compose_file, service, host=HOST):
    """{"ref": image reference the container was created with, "id": image ID} of the service's running container, or None."""
    ids = compose(compose_file, "ps", "-q", service, host=host).stdout.split()
    if not ids:
        return None
    r = host.run(["docker", "inspect", ids[0]])
    try:
        c = json.loads(r.stdout)[0]
        return {"ref": c["Config"]["Image"], "id": c["Image"]}
    except (ValueError, KeyError, IndexError, TypeError):
        return None


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
    reason = invalid_arguments(a)
    if reason:
        print("REFUSED: " + reason)
        return 1
    if shares_vpn_network(a.compose, a.service, host):
        print("REFUSED: VPN container or a service sharing its network: dedicated procedure and an explicit decision required")
        return 3
    problem = service_problem(a.compose, a.service, a.old, host)
    if problem:
        print("REFUSED: " + problem)
        return 1
    ok, msg, _ = pin(a.compose, a.old, a.new, host=host, service=a.service)
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
    ok, msg, backup = pin(a.compose, a.old, a.new, apply=True, host=host, service=a.service)
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
    expected = container_names(a.compose, a.service, host)
    if len(recreated) != 1 or recreated != expected:
        shutil.copy2(backup, a.compose)
        print(f"FAILED: the dry run must show exactly one container recreated, the one of service '{a.service}' "
              f"({', '.join(sorted(expected)) or 'no container found for it'}); it showed {', '.join(sorted(recreated)) or 'none'}: old file restored")
        return 1
    # 5. recreate and check
    before = running_image(a.compose, a.service, host)
    u = compose(a.compose, "up", "-d", "--no-deps", a.service, host=host)
    print((u.stdout + u.stderr).strip()[-300:])
    img = None
    if u.returncode:
        # e.g. the new image cannot be pulled: Docker leaves the OLD container running, which would pass the check below
        ok1, e1 = False, "docker compose up failed: " + (u.stderr or u.stdout).strip()[-200:]
        print(e1)
    else:
        ok1, e1 = healthy(a.compose, a.service, cfg["health_timeout_s"], host)
        if ok1:
            img = running_image(a.compose, a.service, host)
            if not img or img["ref"] != a.new:
                ok1, e1 = False, f"container runs {img['ref'] if img else 'an unknown image'}, not {a.new}"
    ok2, c2 = route_ok(cfg["route_check_url"], a.route, codes, cfg["route_timeout_s"], host) if ok1 else (False, "-")
    print(f"check: container {e1}; route {a.route}: HTTP {c2} (expected {codes})" + (f"; image {img['ref']}" if ok1 and img else ""))
    if ok1 and ok2:
        journal(cfg, {"ts": host.now(), "service": a.service, "from": a.old, "to": a.new, "result": "ok"})
        print("OK")
        return 0
    # 6. rollback: success means the OLD image is the one running (same reference, same image ID as before), healthy, and the route answers
    print("CHECK FAILED: ROLLBACK")
    shutil.copy2(backup, a.compose)
    ru = compose(a.compose, "up", "-d", "--no-deps", a.service, host=host)
    if ru.returncode:
        okb, eb = False, "docker compose up failed: " + (ru.stderr or ru.stdout).strip()[-200:]
    else:
        okb, eb = healthy(a.compose, a.service, cfg["health_timeout_s"], host)
    img = running_image(a.compose, a.service, host) if okb else None
    if okb and (not img or img["ref"] != a.old or (before and img["id"] != before["id"])):
        okb, eb = False, f"container runs {img['ref'] + ' (' + img['id'] + ')' if img else 'an unknown image'}, not the original {a.old}"
    okr, cr = route_ok(cfg["route_check_url"], a.route, codes, cfg["route_timeout_s"], host) if okb else (False, "-")
    good = okb and okr
    print(f"after rollback: container {eb}; route HTTP {cr}" + (f"; image {img['ref']}" if good else "") + ("" if good else ": ROLLBACK FAILED, CHECK BY HAND"))
    journal(cfg, {"ts": host.now(), "service": a.service, "from": a.old, "to": a.new, "result": "rollback ok" if good else "rollback FAILED: CHECK BY HAND"})
    return 2 if good else 4


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
