"""Applying an update group: `rpl group --compose F --parent P [--plan | --approve FINGERPRINT | --resume]` and `rpl group --purge`.

A group (rpl/groups.py) is a parent container and the containers that live in its network namespace. It is patched as one unit, and only
when at least one member has a PROVEN security fix pending: rpl is not an updater.

Policy (effective policy = the most restrictive of the group's and of its services'):

    policy   who starts it                    what is needed
    auto     the nightly run, no human        confirmed: true
    ask      a human, at the command line     confirmed: true AND --approve <fingerprint of the plan> (or typed at the prompt)
    never    nobody                           always refused, with the reason

The plan (`--plan`, which changes nothing) lists, parent first: each member, the image it runs (reference and image ID), and for the members
with a proven fix the new reference PINNED BY DIGEST. Its fingerprint covers all of that. The digest must be the one the fix check scanned
(`candidate_digest` in fixcheck.json) AND the one the registry serves now; a missing or different digest is UNKNOWN and refused. The apply
recomputes the plan under the shared lock, so an approval given for another plan (a tag that moved, a member that appeared) is refused.

Sequence of an apply, all under the shared lock (rpl/gate.py):
  1. plan, from the compose file AND from Docker (every container, stopped ones included); the two views must name the same members,
     and each member must run the image its reference in the file names in the local store (same image ID; the text may differ);
  2. policy, rehearsal (Docker's own dry run must recreate exactly the group), configured controls, restorability of every configuration
     directory (bind mounts located under the compose file's directory: no symlink leaving it, no special file, size cap, ownership);
  3. snapshot command (as `rpl patch`);
  4. a journal entry is written BEFORE anything is stopped;
  5. quiesce: members with `quiesce: stop` (the default for a member that mounts a configuration directory) are stopped, dependants first;
  6. backup of each configuration directory (and of the compose file) into <backup_dir>/group-<parent>-<stamp>/, mode 0700, file modes,
     owners and symlinks kept, then re-read and compared;
  7. the new images are pinned; the parent is recreated, then EVERY dependant in order, with or without a new image (a dependant that is
     not recreated stays in the old, dead namespace); after each: healthy, the expected image (members without a new image must keep the
     same image ID); after all: the configured controls;
  8. on any failure, rollback: compose file restored, members stopped, each configuration directory restored from the backup, parent
     then dependants recreated, each must run its original reference with its original image ID, controls again.

Exit codes: 0 applied (or plan ready, or resumed); 1 refused, nothing changed; 2 failed and rolled back, verified (for --plan: a control
did not pass); 4 the rollback or a restore FAILED: CHECK BY HAND; 5 not now (paused, or another run holds the lock).

An interruption leaves the journal entry open: every later apply is refused until `rpl group ... --resume`, which performs the rollback
above from the journal. Services are never left stopped without that entry.

Backups hold configuration, hence secrets. They are owner-only (0700), kept `group_backup_retention_days` (7), removed by
`rpl group --purge`, except the backup of an apply that never finished or whose rollback failed: those stay until a human deletes them.

Limits, written down:
  - only fakes were used to test this: no real group was ever applied or rolled back with it;
  - a restore puts back configuration DIRECTORIES found under the compose file's directory; named volumes, bind mounts elsewhere and
    databases in other containers are not backed up and not restored;
  - a member whose restore fails is left STOPPED (starting an old image on a configuration the new one changed could damage it);
  - "healthy" is Docker's health check or, without one, "running"; the controls are the closed list of rpl/controls.py;
  - the fix proof is bound to a digest only for fix checks run with this version; older fixcheck.json files are refused;
  - the fingerprint is an integrity check, not authentication: whoever can run the command can compute it.
"""
import datetime
import hashlib
import json
import os
import shutil
import stat
import sys
import time

from . import config, controls, gate, groupmsg, groups, notify, patch

JOURNAL = "group-journal.json"
QUIESCE = ("stop", "none")
STRICTNESS = {"auto": 0, "ask": 1, "never": 2}
FIX_VALIDITY_H = 36


class Refused(Exception):
    """The group cannot be applied; nothing was changed. str() is the reason."""


# ---- what is proven, and what the registry serves ------------------------------------------------------------------

def proven_fixes(cfg):
    """{image without digest: fix-check entry} for the images that have an ACT row AND a fix proven COMPLETE less than 36 h ago."""
    from . import risk
    try:
        inv = json.load(open(config.state(cfg, "inventory.json")))
        findings = json.load(open(config.state(cfg, "findings.json")))
        fix = json.load(open(config.state(cfg, "fixcheck.json")))
        act = {r["image"].split("@")[0] for r in risk.evaluate(findings, inv, risk.load_roles(cfg)) if r["decision"] == "ACT"}
        age_h = (time.time() - float(fix["ts"])) / 3600
        entries = {e["image"].split("@")[0]: e for e in fix.get("images", []) if e.get("verdict") == "COMPLETE"}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise Refused("the scan, the inventory or the fix check cannot be read: run them first (no proof, no patch)")
    if not 0 <= age_h <= FIX_VALIDITY_H:
        raise Refused(f"the fix check is older than {FIX_VALIDITY_H} h: run it again")
    return {image: e for image, e in entries.items() if image in act}


def registry_digest(ref):
    """The digest the registry serves for `ref` now, or None when it cannot be read."""
    from . import proposals
    try:
        return proposals.registry_digest(ref)
    except Exception:
        return None


def local_image_id(ref, host):
    """The image ID `ref` resolves to in Docker's local store, or None when it is not there or cannot be read."""
    r = host.run(["docker", "image", "inspect", "-f", "{{.Id}}", ref])
    out = (r.stdout or "").strip()
    return out if r.returncode == 0 and out and "\n" not in out else None


def target(current, fix):
    """The reference to pin for a member whose image has a proven fix, or None when it already runs it. Raises Refused on UNKNOWN."""
    no_digest = current.split("@")[0]
    last = no_digest.rsplit("/", 1)[-1]
    base, tag = no_digest.rsplit(":", 1) if ":" in last else (no_digest, "latest")
    cand, proven = fix.get("candidate"), fix.get("candidate_digest")
    if not isinstance(cand, str) or not patch.NAME.fullmatch(cand):
        raise Refused(f"the fix check names no usable candidate for {no_digest}")
    if not proven:
        raise Refused(f"UNKNOWN: the fix proven for {no_digest} carries no digest (fix check from an older version, or the image moved "
                      "during the scan): run `rpl fixcheck` again")
    now = registry_digest(f"{base}:{cand}")
    if not now:
        raise Refused(f"UNKNOWN: the registry digest of {base}:{cand} cannot be read, so it cannot be compared with the one that was proven")
    if now != proven:
        raise Refused(f"{base}:{cand} moved since its fix was proven (the registry serves another digest): run `rpl fixcheck` again")
    new = f"{base}:{cand}@{now}"
    return None if new == current else new


# ---- configuration directories: check, copy, re-read, restore ------------------------------------------------------

def _inside(path, root):
    return path == root or path.startswith(root + os.sep)


def tree_problem(path):
    """(bytes, None) when `path` (a directory or a file) can be backed up and restored faithfully, else (0, reason)."""
    root, me, total = os.path.realpath(path), os.geteuid(), 0
    stack = [root]
    try:
        while stack:
            p = stack.pop()
            st = os.lstat(p)
            if me != 0 and st.st_uid != me:
                return 0, f"{p} belongs to another user: its owner could not be restored (run as that user or as root)"
            if stat.S_ISLNK(st.st_mode):
                if not _inside(os.path.realpath(p), root):
                    return 0, f"the symlink {p} leaves the directory: its target would not be in the backup"
            elif stat.S_ISDIR(st.st_mode):
                stack += [os.path.join(p, n) for n in os.listdir(p)]
            elif stat.S_ISREG(st.st_mode):
                total += st.st_size
            else:
                return 0, f"{p} is a special file (socket, pipe or device): it cannot be backed up"
    except OSError as e:
        return 0, f"cannot read {e.filename}: {e.strerror}"
    return total, None


def copy_tree(src, dst):
    """Copy a directory or a file with its modes, owners, times and symlinks. Returns {relative path: [kind, content hash or link target, mode]}."""
    manifest = {}

    def one(s, d, rel):
        st = os.lstat(s)
        mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(s), d)
            manifest[rel] = ["link", os.readlink(s), 0]
        elif stat.S_ISDIR(st.st_mode):
            os.mkdir(d, 0o700)
            for n in sorted(os.listdir(s)):
                one(os.path.join(s, n), os.path.join(d, n), rel + "/" + n)
            manifest[rel] = ["dir", "", mode]
        elif stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(s, "rb") as f, os.fdopen(os.open(d, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as g:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
                    g.write(chunk)
            manifest[rel] = ["file", h.hexdigest(), mode]
        else:
            raise OSError(f"{s} is a special file")
        now = os.lstat(d)
        if (now.st_uid, now.st_gid) != (st.st_uid, st.st_gid):
            os.chown(d, st.st_uid, st.st_gid, follow_symlinks=False)
        if not stat.S_ISLNK(st.st_mode):
            os.chmod(d, mode)
            os.utime(d, ns=(st.st_atime_ns, st.st_mtime_ns))

    one(src, dst, ".")
    return manifest


def read_tree(path):
    """The manifest of what is on disk at `path`, read back (same shape as copy_tree's)."""
    manifest = {}

    def one(p, rel):
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode):
            manifest[rel] = ["link", os.readlink(p), 0]
        elif stat.S_ISDIR(st.st_mode):
            for n in sorted(os.listdir(p)):
                one(os.path.join(p, n), rel + "/" + n)
            manifest[rel] = ["dir", "", stat.S_IMODE(st.st_mode)]
        else:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            manifest[rel] = ["file", h.hexdigest(), stat.S_IMODE(st.st_mode)]

    one(path, ".")
    return manifest


def _remove(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        os.unlink(path)


def restore_tree(backup, manifest, dest):
    """Put `backup` back at `dest`: copied next to it, re-read and compared with the manifest, then swapped in. Raises on any doubt."""
    if read_tree(backup) != manifest:
        raise OSError(f"the backup {backup} is not what was written (re-read differs)")
    tmp, old = dest + ".rpl-restore", dest + ".rpl-old"
    _remove(tmp)
    _remove(old)
    if copy_tree(backup, tmp) != manifest:
        _remove(tmp)
        raise OSError(f"the copy restored from {backup} differs from the backup")
    if os.path.lexists(dest):
        os.rename(dest, old)
    os.rename(tmp, dest)
    _remove(old)


# ---- the plan ------------------------------------------------------------------------------------------------------

def _entry_problem(entry, services):
    """What is wrong with the per-service part of a group's configuration, or None."""
    per = entry.get("services") or {}
    if not isinstance(per, dict):
        return "'services' must be an object"
    for svc, opt in per.items():
        if svc not in services:
            return f"'services' names '{svc}', which is not a member of the group"
        if not isinstance(opt, dict):
            return f"the options of service '{svc}' must be an object"
        if "policy" in opt:
            if opt["policy"] not in groups.POLICIES:
                return f"service '{svc}': policy must be one of " + ", ".join(groups.POLICIES)
            if opt["policy"] in ("ask", "never") and not str(opt.get("reason") or "").strip():
                return f"service '{svc}': policy '{opt['policy']}' needs a non-empty reason"
        if opt.get("quiesce", "stop") not in QUIESCE:
            return f"service '{svc}': quiesce must be one of " + ", ".join(QUIESCE)
    return None


def build_plan(a, cfg, host):
    """The plan of the group whose parent service is a.parent, or raises Refused. Reads only."""
    from . import group
    compose_file = os.path.abspath(a.compose)
    found, why = group.members_from_compose(a.compose, a.parent, host)
    if not found:
        raise Refused(why)
    order = [found[0]] + found[1]
    cfgj = patch.compose(a.compose, "config", "--format", "json", host=host)
    try:
        services = json.loads(cfgj.stdout)["services"] if cfgj.returncode == 0 else None
    except (ValueError, KeyError, TypeError):
        services = None
    if not isinstance(services, dict):
        raise Refused("cannot read " + a.compose)
    # each service: exactly one container, running what the file says
    members = []
    for svc in order:
        names = patch.container_names(a.compose, svc, host)
        if len(names) != 1:
            raise Refused(f"service '{svc}' must have exactly one container (found {len(names)})")
        running = patch.running_image(a.compose, svc, host)
        if running is None:
            raise Refused(f"service '{svc}' has no running container: start it first (a rollback could not be verified)")
        image = (services.get(svc) or {}).get("image")
        if (services.get(svc) or {}).get("build") or not image:
            raise Refused(f"service '{svc}' is built locally or has no image: there is nothing to pin or to roll back to")
        # The image must be the one the file names, compared by image ID: the TEXT may differ (a file pinned by digest after the
        # container was created) and the same text may name another image (a tag pulled again since). A rollback recreates the member
        # from the file, so this is also what makes "the same image ID as before" reachable.
        local = local_image_id(image, host)
        if local is None:
            raise Refused(f"service '{svc}': {image} is not in the local image store, so it cannot be compared with the image that runs")
        if running["id"] != local:
            raise Refused(f"service '{svc}' runs {running['ref']} ({running['id']}), which is not the image {image} names here ({local}): "
                          "recreate it first")
        members.append({"service": svc, "container": sorted(names)[0], "from": image, "from_id": running["id"], "to": None,
                        "created_as": running["ref"]})
    # Docker's view must name the same members: a dependant living elsewhere would be cut off
    ps = host.run(["docker", "ps", "-aq"])
    try:
        detected = groups.detect(json.loads(host.run(["docker", "inspect", *ps.stdout.split()]).stdout)) if ps.returncode == 0 and ps.stdout.split() else None
    except (ValueError, KeyError, TypeError, AttributeError):
        detected = None
    if detected is None:
        raise Refused("Docker's containers cannot be listed or inspected: the members of the group cannot be established")
    parent = members[0]["container"]
    in_file, in_docker = {m["container"] for m in members[1:]}, set(detected.get(parent, []))
    if in_file != in_docker:
        only_docker, only_file = sorted(in_docker - in_file), sorted(in_file - in_docker)
        raise Refused("the compose file and Docker do not name the same dependants of '" + parent + "'"
                      + (": only in Docker: " + ", ".join(only_docker) if only_docker else "")
                      + ("; only in the compose file: " + ", ".join(only_file) if only_file else "")
                      + ": a group spread over several compose files is not supported")
    # policy
    entry = (cfg.get("groups") or {}).get(parent)
    st = groups.status(detected, {parent: entry} if entry is not None else {})[parent]
    if st["problems"]:
        raise Refused("group '" + parent + "': " + "; ".join(st["problems"]))
    problem = _entry_problem(entry, order)
    if problem:
        raise Refused("group '" + parent + "': " + problem)
    per = entry.get("services") or {}
    policies = [(st["policy"], st["reason"])] + [(o["policy"], str(o.get("reason") or "").strip()) for o in per.values() if "policy" in o]
    policy, reason = max(policies, key=lambda pr: STRICTNESS[pr[0]])
    # targets: only proven fixes, bound to the digest that was scanned and that the registry still serves
    fixes = proven_fixes(cfg)
    for m in members:
        fix = fixes.get(m["from"].split("@")[0])
        if fix:
            m["to"] = target(m["from"], fix)
            if m["to"]:
                ok, msg, _ = patch.pin(a.compose, m["from"], m["to"], host=host, service=m["service"])
                if not ok:
                    raise Refused(msg)
    if not any(m["to"] for m in members):
        raise Refused("no member of this group has a proven security fix pending: nothing to apply (rpl is not an updater)")
    # what to back up, and whether it could be restored
    base, total = os.path.realpath(os.path.dirname(compose_file)), 0
    for m in members:
        m["items"], m["skipped"] = [], []
        for v in (services[m["service"]].get("volumes") or []):
            src = v.get("source") if isinstance(v, dict) and v.get("type") == "bind" else None
            if not src:
                continue
            real = os.path.realpath(src)
            if _inside(real, base) and real != base and os.path.lexists(real):
                size, problem = tree_problem(real)
                if problem:
                    raise Refused(f"service '{m['service']}' could not be restored: {problem}")
                total += size
                m["items"].append(real)
            else:
                m["skipped"].append(src)
        m["quiesce"] = (per.get(m["service"]) or {}).get("quiesce", "stop" if m["items"] else "none")
    cap = float(cfg.get("group_backup_max_mb", 2048)) * 1048576
    if total > cap:
        raise Refused(f"the configuration directories weigh {total // 1048576} MB, more than group_backup_max_mb: this looks like data, not configuration")
    os.makedirs(cfg["backup_dir"], exist_ok=True)
    if shutil.disk_usage(cfg["backup_dir"]).free < 2 * total + 1048576:
        raise Refused("not enough free space in backup_dir for the backup and its restore")
    body = {"parent": parent, "compose": compose_file,
            "members": [{k: m[k] for k in ("service", "container", "from", "from_id", "to")} for m in members]}
    fingerprint = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
    return {"parent": parent, "parent_service": order[0], "compose": compose_file, "members": members, "policy": policy, "reason": reason,
            "confirmed": st["confirmed"], "controls": list(entry.get("controls") or []), "bytes": total, "fingerprint": fingerprint}


def show(plan):
    print("group " + plan["parent"] + ": policy " + plan["policy"] + (" (" + plan["reason"] + ")" if plan["reason"] else "")
          + (", confirmed" if plan["confirmed"] else ", NOT confirmed"))
    for m in plan["members"]:
        print(f"  {m['service']}: {m['from']}" + (f"  ->  {m['to']}" if m["to"] else "  (no new image: recreated only)")
              + f"  [quiesce {m['quiesce']}; backup: {', '.join(m['items']) or 'nothing'}]")
        if m.get("created_as") and m["created_as"] != m["from"]:
            print(f"    container created as {m['created_as']}: same image ID as the file's reference")
        for s in m["skipped"]:
            print(f"    not backed up (outside the compose directory): {s}")
    print("fingerprint: " + plan["fingerprint"])


def preflight(plan, a, cfg, host):
    """(exit code, message) of the rehearsal and of the controls on the current state; (0, None) when both pass."""
    order = [m["service"] for m in plan["members"]]
    dry = patch.compose(a.compose, "up", "-d", "--no-deps", "--force-recreate", "--dry-run", *order, host=host)
    if dry.returncode:
        return 1, "the dry run failed: " + (dry.stderr or dry.stdout).strip()[-200:]
    recreated, expected = set(patch.RECREATE.findall(dry.stdout + dry.stderr)), {m["container"] for m in plan["members"]}
    if recreated != expected:
        return 1, ("the dry run must recreate exactly the group's containers (" + ", ".join(sorted(expected)) + "); it showed "
                   + (", ".join(sorted(recreated)) or "none"))
    bad = run_controls(plan, plan["controls"], cfg, host)
    return (2, "a control did not pass: " + bad) if bad else (0, None)


def run_controls(plan, names, cfg, host):
    """None when every named control is ok on the group (parent first), else what failed. Unknown is not ok."""
    try:
        results = controls.run(names, [m["container"] for m in plan["members"]], host, cfg["probe_url"], cfg["probe_image"])
    except ValueError as e:
        return str(e)
    bad = [f"{n}: {verdict.upper()} ({detail})" for n, verdict, detail in results if verdict != "ok"]
    return "; ".join(bad) or None


# ---- journal -------------------------------------------------------------------------------------------------------

def _journal(cfg):
    """The journal entries. No file is an empty journal. A file that cannot be read, or that is valid JSON but not a list of objects,
    raises (OSError or ValueError): reading it as empty would hide an unfinished apply recorded in a damaged file."""
    try:
        with open(config.state(cfg, JOURNAL), encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
        raise ValueError(f"the group journal is not a list of objects: check {JOURNAL} in the state directory by hand")
    return data


JOURNAL_KEEP = 100


def _open_incident(e):
    """An entry nobody has dealt with: an apply that never recorded a result, or a rollback that failed (`rpl watch` alerts on both)."""
    return isinstance(e, dict) and (e.get("result") is None or str(e.get("result")).startswith("rollback FAILED"))


def _kept(data):
    """The last JOURNAL_KEEP entries, plus every older open incident: newer entries must not make `rpl watch` and the purge forget one."""
    return [e for e in data[:-JOURNAL_KEEP] if _open_incident(e)] + data[-JOURNAL_KEEP:]


def _save(cfg, data):
    path = config.state(cfg, JOURNAL)
    with os.fdopen(os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        json.dump(_kept(data), f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(path + ".tmp", path)


def unfinished(cfg):
    """The journal entry of an apply that started and never recorded its result, or None. An unreadable journal raises."""
    return next((e for e in _journal(cfg) if e.get("result") is None), None)


def _record(cfg, entry, **changes):
    entry.update(changes)
    data = [e for e in _journal(cfg) if e.get("id") != entry["id"]] + [entry]
    _save(cfg, data)


def _tell(cfg, key, text):
    """A notification, when channels are configured. Never changes the outcome."""
    if not (cfg.get("notifications") or {}).get("channels"):
        return
    try:
        out = notify.deliver([{"key": key, "text": text}], cfg)
        # `deliver` leaves a key it already delivered out of every list: that is not "queued"
        if key in out["given_up"]:
            print("notification given up after repeated failures (see notifs.json)")
        elif key in out["queued"]:
            print("notification not delivered yet (queued, see notifs.json)")
    except Exception as e:
        print("notification could not be sent: " + type(e).__name__)


# ---- apply, rollback, resume ---------------------------------------------------------------------------------------

def _recreate(compose_file, m, expected_ref, same_id, cfg, host):
    """Recreate one member and check it. None when it is healthy and runs `expected_ref` (and the image ID `same_id` when given), else why not."""
    u = patch.compose(compose_file, "up", "-d", "--no-deps", "--force-recreate", m["service"], host=host)
    if u.returncode:
        return f"{m['service']}: docker compose up failed: " + (u.stderr or u.stdout).strip()[-200:]
    ok, detail = patch.healthy(compose_file, m["service"], cfg["health_timeout_s"], host)
    if not ok:
        return f"{m['service']}: {detail}"
    img = patch.running_image(compose_file, m["service"], host)
    if not img or img["ref"] != expected_ref:
        return f"{m['service']}: runs {img['ref'] if img else 'an unknown image'}, not {expected_ref}"
    if same_id and img["id"] != same_id:
        return f"{m['service']}: runs another image ({img['id']}) than before ({same_id}) under the same reference"
    return None


def _change(plan, entry, cfg, host):
    """Steps 5 to 7. None when the group runs its new images and the controls pass, else the reason of the failure."""
    compose_file, members, root = plan["compose"], plan["members"], entry["backup_root"]
    for m in reversed(members):
        if m["quiesce"] == "stop":
            r = patch.compose(compose_file, "stop", m["service"], host=host)
            if r.returncode:
                return f"{m['service']} could not be stopped: " + (r.stderr or r.stdout).strip()[-200:]
    _record(cfg, entry, state="quiesced")
    items = []
    try:
        os.mkdir(root, 0o700)
        os.chmod(root, 0o700)
        for m in members:
            for i, src in enumerate(m["items"]):
                dst = os.path.join(root, m["service"], str(i))
                os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
                manifest = copy_tree(src, dst)
                if read_tree(dst) != manifest:
                    return f"the backup of {src} does not read back as written"
                items.append({"service": m["service"], "source": src, "backup": dst, "manifest": manifest})
        shutil.copy2(compose_file, os.path.join(root, "compose-file"))
    except OSError as e:
        return f"backup failed: {e.strerror or e}"
    _record(cfg, entry, state="backed-up", items=items)
    print(f"backup: {root} ({len(items)} item(s), owner-only; delete within {cfg.get('group_backup_retention_days', 7)} days: rpl group --purge)")
    before = patch.service_images(compose_file, host)
    _record(cfg, entry, state="changing")
    for m in members:
        if m["to"]:
            ok, msg, _ = patch.pin(compose_file, m["from"], m["to"], apply=True, host=host, service=m["service"])
            print(msg)
            if not ok:
                return f"{m['service']}: the new image could not be pinned"
    after, wanted = patch.service_images(compose_file, host), {m["service"]: m["to"] for m in members if m["to"]}
    if before is None or after is None or {n: i for n, i in after.items() if before.get(n) != i} != wanted:
        return "the edit of the compose file changed something else than the planned images"
    for m in members:
        why = _recreate(compose_file, m, m["to"] or m["from"], None if m["to"] else m["from_id"], cfg, host)
        if why:
            return why
        print(f"{m['service']}: recreated, healthy, runs {m['to'] or m['from']}")
        if m is members[0] and "exit_differs" in plan["controls"]:
            bad = run_controls(plan, ["exit_differs"], cfg, host)
            if bad:
                return "after the parent: " + bad
    return run_controls(plan, plan["controls"], cfg, host)


def _rollback(entry, cfg, host):
    """Step 8, from the journal entry alone. Returns the list of problems (empty: everything is back and verified)."""
    plan, problems, failed = entry["plan"], [], set()
    compose_file, members = plan["compose"], plan["members"]
    saved = os.path.join(entry["backup_root"], "compose-file")
    if entry.get("state") == "changing":
        try:
            shutil.copy2(saved, compose_file)
        except OSError as e:
            return [f"the compose file could not be restored from {saved}: {e.strerror}"]
        for m in reversed(members):
            if patch.compose(compose_file, "stop", m["service"], host=host).returncode:
                problems.append(f"{m['service']} could not be stopped before its restore")
                failed.add(m["service"])
        for it in entry.get("items") or []:
            if it["service"] in failed:
                continue
            try:
                restore_tree(it["backup"], it["manifest"], it["source"])
            except Exception as e:
                problems.append(f"RESTORE FAILED for {it['service']} ({it['source']}): {e}; left stopped")
                failed.add(it["service"])
    for m in members:
        if m["service"] in failed:
            continue
        why = _recreate(compose_file, m, m["from"], m["from_id"], cfg, host)
        if why:
            problems.append(why)
    if not problems:
        bad = run_controls(plan, plan["controls"], cfg, host)
        if bad:
            problems.append("after the rollback: " + bad)
    return problems


def _finish_rollback(entry, cfg, host, why):
    problems = _rollback(entry, cfg, host)
    parent = entry["plan"]["parent"]
    # The keys name THIS apply (its journal entry), not the plan: `notify.deliver` sends one message per key for ever, and the same plan
    # is applied again after every interruption and `--resume`. A key built from the plan alone made the second failure silent.
    if problems:
        for p in problems:
            print("  " + p)
        print("ROLLBACK FAILED: CHECK BY HAND (backup kept in " + entry["backup_root"] + ")")
        _record(cfg, entry, result="rollback FAILED: CHECK BY HAND", problems=problems, why=why)
        _tell(cfg, groupmsg.group_key(entry["id"], "rollback-failed"), groupmsg.text(parent, "rollback-failed", why))
        return 4
    print("rollback ok: every member runs its original image again, configuration restored, controls passed")
    _record(cfg, entry, result="rollback ok", why=why)
    _tell(cfg, groupmsg.group_key(entry["id"], "rolled-back"), groupmsg.text(parent, "rolled-back", why))
    return 2


def _approved(plan, a):
    if plan["policy"] == "never":
        return "policy never" + (": " + plan["reason"] if plan["reason"] else "")
    if not plan["confirmed"]:
        return "the group is not confirmed: check its member list, then set \"confirmed\": true in the configuration"
    if plan["policy"] == "auto":
        return None
    given = a.approve
    if given is None and sys.stdin is not None and sys.stdin.isatty():
        given = input(f"policy ask ({plan['reason']}). Type the fingerprint {plan['fingerprint']} to apply this plan: ").strip()
    if given != plan["fingerprint"]:
        return ("policy ask (" + plan["reason"] + "): a human must approve THIS plan: --approve " + plan["fingerprint"]
                + (" (the fingerprint given is that of another plan: something changed, read the plan again)" if given else ""))
    return None


def _locked(a, cfg, what, fn, host):
    try:
        with gate.applying(cfg, what + " " + a.parent):
            return fn(a, cfg, host)
    except gate.NotNow as e:
        print("NOT NOW: " + str(e) + ": nothing was touched")
        return gate.EXIT_NOT_NOW


def apply(a, cfg, host):
    return _locked(a, cfg, "group", _apply, host)


def _apply(a, cfg, host):
    try:
        if unfinished(cfg):
            raise Refused("an earlier group apply never finished: run `rpl group --compose ... --parent ... --resume` first")
        plan = build_plan(a, cfg, host)
    except (Refused, OSError, ValueError) as e:
        print("REFUSED: " + str(e))
        return 1
    show(plan)
    why = _approved(plan, a)
    if why:
        print("REFUSED: " + why)
        return 1
    rc, msg = preflight(plan, a, cfg, host)
    if rc:
        print("REFUSED: " + msg + ": nothing was changed")
        return 1
    if cfg.get("snapshot_command"):
        s = host.run(cfg["snapshot_command"] if isinstance(cfg["snapshot_command"], list) else ["sh", "-c", cfg["snapshot_command"]])
        if s.returncode:
            print("snapshot FAILED: nothing was changed")
            return 1
    elif not a.no_snapshot:
        print("REFUSED: no snapshot_command configured; say --no-snapshot out loud to go without one")
        return 1
    stamp, n = datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), 1
    while os.path.lexists(os.path.join(cfg["backup_dir"], f"group-{plan['parent']}-{stamp}")):      # two applies in the same second
        n += 1
        stamp = stamp.split(".")[0] + f".{n}"
    entry = {"id": f"{plan['parent']}-{stamp}", "ts": host.now(), "result": None, "state": "started", "plan": plan,
             "backup_root": os.path.join(cfg["backup_dir"], f"group-{plan['parent']}-{stamp}")}
    _record(cfg, entry)                                  # BEFORE anything is stopped: an interruption is never silent
    try:
        why = _change(plan, entry, cfg, host)
        if why is None:
            _record(cfg, entry, result="ok")
            print("OK")
            _tell(cfg, groupmsg.group_key(entry["id"], "ok"), groupmsg.text(plan["parent"], "ok", members=plan["members"]))
            return 0
        print("FAILED: " + why + ": ROLLBACK")
        return _finish_rollback(entry, cfg, host, why)
    except BaseException:
        print("ABORTED by an unexpected error or an interruption. Members may be stopped or half updated. Nothing else will be applied "
              f"to a group until you run: rpl group --compose {a.compose} --parent {a.parent} --resume")
        raise


def resume(a, cfg, host):
    return _locked(a, cfg, "group resume", _resume, host)


def _resume_problem(entry):
    """None when the journal entry holds what a rollback reads (id, plan with parent, compose file and members, backup path), else what is missing.
    An entry written by this tool has all of it; one that was edited or damaged by hand may not."""
    plan = entry.get("plan")
    if not isinstance(entry.get("id"), str) or not entry["id"]:
        return "it has no id"
    if not isinstance(plan, dict):
        return "it has no plan"
    for key in ("parent", "compose"):
        if not isinstance(plan.get(key), str) or not plan[key]:
            return f"its plan has no {key}"
    members = plan.get("members")
    if not isinstance(members, list) or not all(isinstance(m, dict) and isinstance(m.get("service"), str) for m in members):
        return "its plan has no usable list of members"
    if not isinstance(entry.get("backup_root"), str) or not entry["backup_root"]:
        return "it names no backup"
    return None


def _resume(a, cfg, host):
    try:
        entry = unfinished(cfg)
    except (OSError, ValueError) as e:
        print("REFUSED: the group journal cannot be read: " + str(e))
        return 1
    if entry is None:
        print("nothing to resume: no group apply is unfinished")
        return 0
    why = _resume_problem(entry)
    if why:
        print(f"REFUSED: the unfinished apply cannot be resumed: {why}. Check by hand: repair the journal entry or do the rollback yourself.")
        return 1
    print(f"unfinished apply of group {entry['plan']['parent']} (stopped at '{entry.get('state')}'): rolling back")
    rc = _finish_rollback(entry, cfg, host, "interrupted at '" + str(entry.get("state")) + "'")
    return 0 if rc == 2 else rc


def plan_only(a, cfg, host):
    """--plan: everything the apply would check, a backup of every configuration directory re-read in a temporary place, nothing changed."""
    try:
        if unfinished(cfg):
            print("WARNING: an earlier group apply never finished: run --resume first")
        plan = build_plan(a, cfg, host)
    except (Refused, OSError, ValueError) as e:
        print("NOT READY: " + str(e))
        return 1
    show(plan)
    rc, msg = preflight(plan, a, cfg, host)
    if rc:
        print("NOT READY: " + msg)
        return rc
    proof, n = os.path.join(cfg["backup_dir"], f"group-proof-{os.getpid()}"), 0
    try:
        os.mkdir(proof, 0o700)
        for m in plan["members"]:
            for src in m["items"]:
                dst = os.path.join(proof, str(n))
                manifest = copy_tree(src, dst)
                if read_tree(dst) != manifest:
                    print(f"NOT READY: the backup of {src} does not read back as written")
                    return 1
                n += 1
    except OSError as e:
        print(f"NOT READY: backup proof failed: {e.strerror or e}")
        return 1
    finally:
        _remove(proof)
    print(f"backup proof: {n} item(s) copied while running and read back identical, then deleted (the real backup is taken with the members stopped)")
    why = _approved(plan, a) if plan["policy"] != "ask" else None
    if why:
        print("PLAN ONLY, it would be refused: " + why)
        return 1
    print("PLAN READY, nothing changed. To apply: rpl group --compose " + a.compose + " --parent " + a.parent
          + (" --approve " + plan["fingerprint"] if plan["policy"] == "ask" else ""))
    return 0


def purge(cfg, days=None):
    """Delete the group backups older than the retention. Kept whatever their age: the backup of an apply that never finished, and
    the backup of a rollback that FAILED (it is then the only copy of the original configuration, and a human has not said it is done)."""
    days = float(cfg.get("group_backup_retention_days", 7) if days is None else days)
    try:
        protect = [e for e in _journal(cfg) if e.get("result") is None or str(e.get("result")).startswith("rollback FAILED")]
    except (OSError, ValueError):
        print("REFUSED: the group journal cannot be read, so the backups that must be kept cannot be told apart")
        return 1
    if not all(isinstance(e.get("backup_root"), str) and e["backup_root"] for e in protect):
        # the set to keep must not shrink in silence: an entry to protect that names no backup would let its backup be deleted
        print("REFUSED: an unfinished or failed group apply in the journal has no backup path, so the backups that must be kept cannot be told apart")
        return 1
    keep = {e["backup_root"] for e in protect}
    removed = kept = 0
    for name in sorted(os.listdir(cfg["backup_dir"])) if os.path.isdir(cfg["backup_dir"]) else []:
        path = os.path.join(cfg["backup_dir"], name)
        if not name.startswith("group-") or os.path.islink(path) or not os.path.isdir(path):
            continue
        if path in keep:
            print(f"kept whatever its age: {path} (unfinished apply, or rollback FAILED: CHECK BY HAND; delete it yourself once the group is in order)")
            kept += 1
            continue
        if (time.time() - os.lstat(path).st_mtime) / 86400 <= days:
            kept += 1
            continue
        shutil.rmtree(path)
        removed += 1
    print(f"{removed} group backup(s) deleted, {kept} kept (retention {days:g} days)")
    return 0
