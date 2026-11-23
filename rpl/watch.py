"""`rpl watch`: tell a human about the two open incidents of the group journal: a group apply that never recorded its result, and a rollback
that failed while its backup is still there.

A process stopped by SIGTERM (a scheduler, `systemctl stop`) prints nothing: the only trace is an entry of the group journal
(`group-journal.json`) without a result, which blocks every later group apply until `rpl group ... --resume`. This check reads that file and
nothing else, so it works when the nightly job is dead. Run it from its own timer, every few minutes.

A failed rollback (`CHECK BY HAND`) stays open for as long as its backup directory exists: `rpl group --purge` never deletes it, so deleting it by
hand, once the services are repaired, is the acknowledgement. Until then `watch` prints the alert on every run, and sends the message under the
group apply's own key (`group_key`): the group apply gives its message to `rpl.notify` only once, so a first delivery that failed is retried here
(the key is the same, so a message that did arrive is not sent twice). No grace and no time window apply: that apply is over, and the incident does
not expire.

Exit codes: 0 nothing open; 1 at least one open incident (an unfinished apply, or a failed rollback with its backup); 2 the journal cannot be read (never "OK": it is reported like an unfinished one).
The alert is always printed (a cron mail or a journald line is then the channel of last resort); when `notifications` has channels it is also
delivered through rpl.notify, one message per journal entry.

Limits, written down:
  - a failed rollback is told only while its backup path exists: deleting the backup without repairing closes the incident (it is the human's act);
    an entry that names no usable backup path stays open for ever; the journal keeps 100 entries, so an incident older than that is forgotten;
  - an entry younger than `group_unfinished_grace_minutes` (default 60) is taken for an apply in progress and not reported; an interrupted apply is
    therefore reported after that delay, and an apply that really runs longer than the delay gives a false alarm;
  - the journal is read with plain file access, not under the shared lock: a read during a write sees the old or the new file (the writer replaces it
    atomically), never a half file;
  - a failed delivery is retried on the next run only while the entry is still open; once `--resume` closes it nothing more is sent;
  - the journal is written mode 0600 by the account that runs `rpl group`: a timer under another account gets a PermissionError and exit 2 (reported,
    never "OK"), so run it as the account that applies;
  - it does not run Docker and does not know whether services are really stopped: it reports the record, not the state of the host;
  - it depends on notifs.json (shared with `rpl notify`) for "one message per entry"; two runs at the same instant can both send.
"""
import json
import os
import sys
import time

from . import config, notify

JOURNAL = "group-journal.json"          # the name groupapply.py writes (a test keeps the two equal)
DEFAULT_GRACE_MIN = 60


def group_key(entry_id, outcome):
    """The notification key of a group apply: one per apply (its journal entry id) and outcome ("ok", "rolled-back", "rollback-failed").
    The group apply and `rpl watch` both use it, so `rpl.notify` sends a given message once, whoever gives it first."""
    return f"group:{entry_id}:{outcome}"
CLOCK_SKEW_S = 300                      # a start time further in the future than this is not trusted


def _read(cfg):
    """(entries, problem). A missing file is an empty journal; anything unreadable or not shaped like the journal is a problem."""
    path = config.state(cfg, JOURNAL)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return [], None
    except PermissionError:
        return None, ("cannot be read (PermissionError: the journal is mode 0600, so run `rpl watch` as the account that runs `rpl group`)")
    except (OSError, ValueError) as e:
        return None, f"cannot be read ({type(e).__name__})"
    if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
        return None, "cannot be read (not a list of entries)"
    return data, None


def _old_enough(entry, now, grace_s):
    ts = entry.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return True                                       # no usable start time: report rather than assume it is recent
    if ts > now + CLOCK_SKEW_S:
        return True                                       # a future time would hide the entry for ever
    return now - ts >= grace_s


def check(cfg, now=time.time):
    """{"unfinished": [{"id", "parent", "state", "since"}], "problem": str or None}."""
    entries, problem = _read(cfg)
    if problem:
        return {"unfinished": [], "failed_rollbacks": [], "problem": problem}
    grace_s = 60 * float(cfg.get("group_unfinished_grace_minutes", DEFAULT_GRACE_MIN))
    t = now()
    out = []
    for e in entries:
        if e.get("result") is None and _old_enough(e, t, grace_s):
            plan = e.get("plan") if isinstance(e.get("plan"), dict) else {}
            out.append({"id": str(e.get("id", "?"))[:120], "parent": str(plan.get("parent", "?"))[:120], "state": str(e.get("state", "?"))[:60],
                        "since": e.get("ts") if isinstance(e.get("ts"), (int, float)) else None})
    failed = []
    for e in entries:
        if str(e.get("result")).startswith("rollback FAILED"):
            root = e.get("backup_root")
            if not (isinstance(root, str) and root) or os.path.exists(root):
                plan = e.get("plan") if isinstance(e.get("plan"), dict) else {}
                failed.append({"id": str(e.get("id", "?"))[:120], "parent": str(plan.get("parent", "?"))[:120],
                               "backup": root if isinstance(root, str) and root else None})
    return {"unfinished": out, "failed_rollbacks": failed, "problem": problem}


def _when(ts):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts)) if ts is not None else "an unknown time"


def events(result, cfg):
    evs = []
    if result["problem"]:
        stamp = notify.file_stamp(config.state(cfg, JOURNAL))
        evs.append({"key": f"group-journal-unreadable:{stamp}", "critical": True,
                    "text": f"rpl: the group journal {result['problem']}. A group apply may be unfinished: check {JOURNAL} in the state directory by hand."})
    for f in result["failed_rollbacks"]:
        where = f"its backup is kept in {f['backup']}" if f["backup"] else "its journal entry names no backup"
        evs.append({"key": group_key(f["id"], "rollback-failed"), "critical": True,
                    "text": f"rpl: the rollback of the group apply {f['id']} (group {f['parent']}) FAILED: check by hand. Services may be stopped or "
                            f"half restored and {where}. This alert stops when that backup directory is deleted, after you have repaired the services."})
    for u in result["unfinished"]:
        evs.append({"key": f"group-unfinished:{u['id']}", "critical": True,
                    "text": f"rpl: the group apply {u['id']} (group {u['parent']}, started {_when(u['since'])}) never recorded a result; it stopped at "
                            f"'{u['state']}'. Services may be stopped or half updated and every later group apply is refused. "
                            "Run `rpl group --compose <file> --parent <parent> --resume` to roll back."})
    return evs


def run(cfg, poster=notify.post, now=time.time):
    result = check(cfg, now)
    evs = events(result, cfg)
    for ev in evs:
        print("ALERT: " + ev["text"])
    if evs and (cfg.get("notifications") or {}).get("channels"):
        try:
            out = notify.deliver(evs, cfg, poster, now)
            if out["queued"] or out["given_up"]:
                print(f"notification not delivered ({len(out['queued'])} queued, {len(out['given_up'])} given up; see notifs.json)")
        except Exception as e:
            print("notification could not be sent: " + type(e).__name__)
    elif evs:
        print("no notification channel configured: this line is the only alert")
    if result["problem"]:
        return 2
    return 1 if result["unfinished"] or result["failed_rollbacks"] else 0


def main(argv):
    if argv:
        print("usage: rpl watch   (no option; see rpl/watch.py)")
        return 2
    return run(config.load())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
