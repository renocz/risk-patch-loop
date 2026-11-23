"""`rpl notify`: collect events from the state the other modules leave behind and hand them to rpl.notify.deliver.

    rpl notify                         collect and deliver; run it from a timer of its own
    rpl notify --record ok|failed [--reason TEXT]    the nightly job calls this as its last line, once per run

Events (the key carries what makes a message new, so each is sent once, see rpl/notify.py):
  nightly run missing or failed   from nightly.json, written by `--record`; no record, an unreadable one, or one older than `nightly_max_hours`
                                  (36) is "missing"; `failed` carries the reason given
  patch result                    entries of patches.json (rpl patch) younger than `events_window_hours` (72): ok, rollback ok, rollback FAILED, aborted
  exclusion with a fix pending    an image of proposals.json "not_proposed" for which fixcheck.json holds a COMPLETE verdict (a proven fix) that the
                                  tool will not apply by itself: not in patch-apps.json, member of an update group, no running container
  new application                 a container name of inventory.json that was not there when the baseline (apps-known.json) was written
  error                           a state file that cannot be read or has the wrong shape, or a source that made the collector fail: never silence

Everything except "new application" is computed again from the files on every run, so an event whose delivery failed is simply produced again and
retried by deliver (deliver only retries what it is given). "New application" is remembered in apps-known.json, and a name is added there only once
its message was delivered.

Limits, written down:
  - it reports what the files say. It never runs Docker, Trivy or a registry, and it cannot tell that a nightly job is dead unless the job calls
    `--record` and this command runs from a different timer; a job that forgets to call it looks like a missing run (the safe direction);
  - the first run has no baseline: the containers present are recorded without a message, so an application that was there before is never announced;
  - results older than the window, and a fix check older than the nightly run that should have replaced it, are not looked at;
  - "exclusion" covers only what proposals.json lists; findings accepted by hand (accepted.json) are not reported, the files do not say if they have a fix;
  - an application that appears and disappears between two runs is not seen; a removed one is never reported;
  - "delivered" means the receiving service answered 2xx. Two runs at the same instant share notifs.json without a lock and can both send;
  - a group apply left unfinished is NOT reported here, on purpose: `rpl watch` does it and must not depend on this command.
"""
import json
import os
import sys
import time

from . import config, notify

NIGHTLY = "nightly.json"
KNOWN = "apps-known.json"
STATUSES = ("ok", "failed")
DEFAULT_NIGHTLY_MAX_H = 36
DEFAULT_WINDOW_H = 72
TEXT_MAX = 300


def _clean(value, n=TEXT_MAX):
    return " ".join(str(value).split())[:n]


def _number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


class Unreadable(Exception):
    pass


def _load(cfg, name):
    """The parsed file, or None when it does not exist. Raises Unreadable."""
    try:
        with open(config.state(cfg, name), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise Unreadable(f"cannot be read ({type(e).__name__})")


def _error(cfg, name, problem):
    try:
        stamp = int(os.stat(config.state(cfg, name)).st_mtime)
    except OSError:
        stamp = "unknown"
    return {"key": f"error:{name}:{stamp}", "text": f"rpl: {name} {_clean(problem)}: what it holds is not being reported until it is fixed."}


# ---- sources: each takes (cfg, now) and returns events; an Unreadable becomes an error event --------------------------

def nightly_events(cfg, now):
    data = _load(cfg, NIGHTLY)
    max_h = float(cfg.get("nightly_max_hours", DEFAULT_NIGHTLY_MAX_H))
    if data is None:
        return [notify.missing_run(None, now)]
    if not (isinstance(data, dict) and _number(data.get("ts")) and data.get("status") in STATUSES):
        raise Unreadable("has the wrong shape (expected ts and a status of ok or failed)")
    out = []
    if data["status"] == "failed":
        out.append({"key": f"nightly-failed:{int(data['ts'])}",
                    "text": "The nightly run failed" + (": " + _clean(data["reason"]) if data.get("reason") else " (no reason recorded).")})
    late = notify.missing_run(data["ts"], now, max_h)
    if late:
        out.append(late)
    return out


def patch_events(cfg, now):
    data = _load(cfg, "patches.json")
    if data is None:
        return []
    if not (isinstance(data, list) and all(isinstance(e, dict) and _number(e.get("ts")) for e in data)):
        raise Unreadable("has the wrong shape (expected a list of entries with a time)")
    window = 3600 * float(cfg.get("events_window_hours", DEFAULT_WINDOW_H))
    out = []
    for e in data:
        if now - e["ts"] > window:
            continue
        svc, res = _clean(e.get("service", "?"), 80), _clean(e.get("result", "?"), 80)
        out.append({"key": f"patch:{svc}:{int(e['ts'])}",
                    "text": f"rpl patch of {svc} ({_clean(e.get('from', '?'), 100)} -> {_clean(e.get('to', '?'), 100)}): {res}."})
    return out


def exclusion_events(cfg, now):
    props = _load(cfg, "proposals.json")
    if props is None:
        return []
    if not (isinstance(props, dict) and isinstance(props.get("not_proposed", []), list)
            and all(isinstance(n, dict) for n in props.get("not_proposed", []))):
        raise Unreadable("has the wrong shape (expected not_proposed to be a list)")
    skipped = props.get("not_proposed", [])
    if not skipped:
        return []
    try:
        fix = _load(cfg, "fixcheck.json")
    except Unreadable as e:
        return [_error(cfg, "fixcheck.json", str(e))]
    images = (fix or {}).get("images", []) if isinstance(fix, dict) or fix is None else None
    if images is None or not all(isinstance(i, dict) for i in images):
        return [_error(cfg, "fixcheck.json", "has the wrong shape (expected images to be a list)")]
    proven = {str(i.get("image", "")).split("@")[0]: i for i in images if i.get("verdict") == "COMPLETE"}
    out = []
    for n in skipped:
        image = str(n.get("image", "")).split("@")[0]
        reason = _clean(n.get("reason", ""), 200)
        if image not in proven or reason.startswith("already at"):
            continue
        cand = _clean(proven[image].get("candidate", "?"), 60)
        out.append({"key": f"excluded:{image}:{cand}",
                    "text": f"{image} has a proven security fix ({cand}) that rpl will not apply by itself: {reason}. Decide by hand."})
    return out


def _known(cfg):
    data = _load(cfg, KNOWN)
    if data is None:
        return None
    if not (isinstance(data, dict) and isinstance(data.get("names"), list)):
        raise Unreadable("has the wrong shape (expected names to be a list)")
    return {str(n) for n in data["names"]}


def _inventory(cfg):
    inv = _load(cfg, "inventory.json")
    if inv is not None and not isinstance(inv, dict):
        raise Unreadable("has the wrong shape (expected an object of containers)")
    return None if inv is None else sorted(str(n) for n in inv)


def new_app_events(cfg, now):
    names = _inventory(cfg)
    if names is None:
        return []
    try:
        known = _known(cfg)
    except Unreadable as e:
        return [_error(cfg, KNOWN, str(e))]
    if known is None:
        return []                                         # no baseline yet: run() writes it
    return [{"key": f"new-app:{_clean(n, 120)}", "text": f"New application: container {_clean(n, 120)} was not there before (see rpl inventory)."}
            for n in names if n not in known]


SOURCES = (("nightly.json", nightly_events), ("patches.json", patch_events), ("proposals.json", exclusion_events), ("inventory.json", new_app_events))


def collect(cfg, now=time.time):
    t = now()
    out = []
    for name, fn in SOURCES:
        try:
            out += fn(cfg, t)
        except Unreadable as e:
            out.append(_error(cfg, name, str(e)))
        except Exception as e:                             # a bug here must not turn into silence
            out.append(_error(cfg, name, "made the collector fail (" + type(e).__name__ + ")"))
    return out


# ---- state this command keeps -------------------------------------------------------------------------------------

def _write(cfg, name, data):
    path = config.state(cfg, name)
    with os.fdopen(os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(path + ".tmp", path)


def record(cfg, status, reason="", now=time.time):
    """The nightly job's last line: it ran to its end (ok) or it did not (failed, with a reason)."""
    if status not in STATUSES:
        raise ValueError("status must be one of " + ", ".join(STATUSES))
    _write(cfg, NIGHTLY, {"ts": now(), "status": status, "reason": _clean(reason)})


def _baseline(cfg):
    """First run only: remember the containers that are there, without a message. A baseline that exists (even unreadable) is never rewritten."""
    try:
        names = _inventory(cfg)
        if names is not None and _known(cfg) is None:
            _write(cfg, KNOWN, {"names": names})
            print(f"baseline recorded: {len(names)} containers are taken as known, none is announced")
    except Unreadable:
        pass                                              # reported as an error event by collect


def _remember(cfg, delivered):
    names = {k[len("new-app:"):] for k in delivered if k.startswith("new-app:")}
    if names:
        known = _known(cfg) or set()
        _write(cfg, KNOWN, {"names": sorted(known | names)})


def run(cfg, poster=notify.post, now=time.time):
    _baseline(cfg)
    evs = collect(cfg, now)
    if not evs:
        print("no event")
        return 0
    for ev in evs:
        print("EVENT: " + ev["text"])
    if not (cfg.get("notifications") or {}).get("channels"):
        print("no notification channel configured: the lines above are the only report")
        return 1
    try:
        out = notify.deliver(evs, cfg, poster, now)
        _remember(cfg, out["delivered"])
    except Exception as e:
        print("notification could not be sent: " + type(e).__name__)
        return 1
    print(f"{len(out['delivered'])} delivered, {len(out['queued'])} queued, {len(out['given_up'])} given up")
    return 1 if out["queued"] or out["given_up"] else 0


def main(argv):
    cfg = config.load()
    if not argv:
        return run(cfg)
    if argv[0] == "--record" and len(argv) in (2, 4) and (len(argv) == 2 or argv[2] == "--reason"):
        try:
            record(cfg, argv[1], argv[3] if len(argv) == 4 else "")
        except ValueError as e:
            print("REFUSED: " + str(e))
            return 2
        return 0
    print("usage: rpl notify [--record ok|failed [--reason TEXT]]")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
