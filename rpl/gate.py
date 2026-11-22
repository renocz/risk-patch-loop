"""The pause switch and the shared lock: what every command checks before it APPLIES anything.

    with gate.applying(cfg, "patch app-1"):      # raises gate.NotNow when paused, or when another run holds the lock
        ...                                      # the only place where containers or compose files may be changed

Pause switch: the file PAUSED in the state directory. If anything exists at that path (a file made by `rpl pause on`, an empty file made
with `touch`, even a directory), nothing is applied. `rpl pause on [--reason TEXT] | off | status`. When the switch cannot be read (state
directory unreadable), the answer is "paused": the tool never applies because it could not tell.

Shared lock: an exclusive, non-blocking `flock` on the file apply.lock in the state directory, held from before the first check until the
end of the run, rollback included. A second run is refused at once; it does not wait. The kernel drops the lock when the process dies, so a
crash or a kill leaves no stale lock. The file itself is never deleted, and it names the last holder (pid, what, since).

A command that is refused here exits with EXIT_NOT_NOW (5): nothing was touched, the same command may work later.

Limits, written down:
  - the switch and the lock live in the state directory: two runners only exclude each other if they use the same `state_dir`;
  - the switch is read when a run starts (twice: before the lock and under it). A run that already started is NOT interrupted: stopping
    between a recreation and its check or rollback would be worse than finishing;
  - read-only commands (scan, inventory, risk, fixcheck, proposals without --apply, every --dry) ignore both;
  - `flock` needs a Unix system and a file system that supports it; without it nothing is applied. Only a local file system was tested;
  - whoever can write the state directory can remove the switch or the lock file: this is a safety catch between cooperating runners, not
    an access control;
  - deleting apply.lock while a run holds it would let a second run in. Nothing in rpl deletes it.
"""
import argparse
import contextlib
import json
import os
import sys
import time

from . import config

try:
    import fcntl
except ImportError:                                  # not a Unix system: no lock, so nothing can be applied
    fcntl = None

PAUSE_FILE = "PAUSED"
LOCK_FILE = "apply.lock"
EXIT_NOT_NOW = 5


class NotNow(Exception):
    """Applying is not allowed at this moment (paused, or another run holds the lock). str() is the reason to print."""


def _clean(text, limit=200):
    """Text from a state file, safe to print on a terminal: one line, printable characters only."""
    return "".join(ch if ch.isprintable() else " " for ch in str(text))[:limit].strip()


def _when(ts):
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(float(ts)))
    except (TypeError, ValueError, OverflowError, OSError):
        return "an unknown time"


# ---- pause switch --------------------------------------------------------------------------------------------------

def paused(cfg):
    """None when applying is allowed; otherwise the reason to show. Cannot tell counts as paused."""
    try:
        path = config.state(cfg, PAUSE_FILE)
    except OSError as e:
        return f"cannot tell whether the pause switch is set (state directory: {e.strerror}): treated as paused"
    try:
        os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return f"cannot tell whether the pause switch is set ({e.strerror}): treated as paused"
    try:
        with open(path, encoding="utf-8") as f:
            info = json.loads(f.read(4096))
        reason, since = _clean(info.get("reason") or ""), _when(info.get("ts"))
    except (OSError, ValueError, AttributeError):
        return f"paused (switch {path}, no reason recorded)"
    return f"paused since {since}" + (f": {reason}" if reason else " (no reason given)")


def pause_on(cfg, reason="", now=None):
    path = config.state(cfg, PAUSE_FILE)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time() if now is None else now, "reason": reason or ""}, f, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError:
        if not os.path.lexists(path):                # something already sits there (a directory): that pauses too
            raise


def pause_off(cfg):
    """True when a switch was removed, False when there was none. Raises OSError when it cannot be removed."""
    path = config.state(cfg, PAUSE_FILE)
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            os.rmdir(path)
        else:
            os.unlink(path)
    except FileNotFoundError:
        return False
    return True


# ---- shared lock ---------------------------------------------------------------------------------------------------

def _holder(fd):
    try:
        info = json.loads(os.pread(fd, 1024, 0).decode("utf-8"))
        return f"pid {int(info['pid'])}, '{_clean(info['what'])}', since {_when(info.get('since'))}"
    except (OSError, ValueError, KeyError, TypeError):
        return "holder unknown"


def _take(cfg, what):
    """An open file descriptor holding the lock; closing it releases the lock. Raises NotNow."""
    if fcntl is None:
        raise NotNow("cannot take the shared lock on this system (no flock): nothing is applied without it")
    try:
        path = config.state(cfg, LOCK_FILE)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)       # not inherited by child processes
    except OSError as e:
        raise NotNow(f"cannot open the shared lock file ({e.strerror}): nothing is applied without it")
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise NotNow("another run holds the shared lock (" + _holder(fd) + ")")
        except OSError as e:
            raise NotNow(f"cannot take the shared lock ({e.strerror}): nothing is applied without it")
        try:
            mine, on_disk = os.fstat(fd), os.stat(path)
            same = (mine.st_dev, mine.st_ino) == (on_disk.st_dev, on_disk.st_ino)
        except OSError:
            same = False
        if not same:                                 # another runner would lock the new file and get in
            raise NotNow("the shared lock file was replaced while it was being locked: nothing is applied")
        os.ftruncate(fd, 0)
        os.pwrite(fd, json.dumps({"pid": os.getpid(), "what": what, "since": time.time()}).encode("utf-8"), 0)
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextlib.contextmanager
def applying(cfg, what):
    """Everything that changes a container or a compose file runs inside this block. Raises NotNow before the block when paused or locked."""
    why = paused(cfg)
    if why:
        raise NotNow(why)
    fd = _take(cfg, what)
    try:
        why = paused(cfg)                            # set while we were getting the lock
        if why:
            raise NotNow(why)
        yield
    finally:
        os.close(fd)


# ---- rpl pause -----------------------------------------------------------------------------------------------------

def main(argv):
    p = argparse.ArgumentParser(prog="rpl pause", description="Stop every runner from applying anything, until `rpl pause off`.")
    p.add_argument("action", choices=("on", "off", "status"))
    p.add_argument("--reason", default="", help="shown wherever a run is refused")
    a = p.parse_args(argv)
    cfg = config.load()
    try:
        if a.action == "on":
            pause_on(cfg, a.reason)
            print("PAUSED: nothing will be applied until `rpl pause off`. A run that already started is not interrupted.")
            return 0
        if a.action == "off":
            print("resumed" if pause_off(cfg) else "was not paused")
            why = paused(cfg)
            if why:
                print("STILL PAUSED: " + why)
                return 1
            return 0
    except OSError as e:
        print(("STILL PAUSED" if a.action == "off" else "NOT PAUSED") + f": the switch could not be changed ({e.strerror})")
        return 1
    why = paused(cfg)
    print("PAUSED: " + why if why else "not paused")
    return 1 if why else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
