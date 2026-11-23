"""Notifications: channels from the config, delivery confirmed, retries, one message per event key.

Config (rpl.json):
    "notifications": {"channels": [
        {"type": "telegram", "token_file": "~/.rpl/tg.token", "chat_id": "123"},
        {"type": "webhook", "url": "https://hooks.example.test/x", "secret_file": "~/.rpl/hook.secret", "allow_private": false}],
     "max_attempts": 20}

Rules, each covered by a test:
  - an event is marked delivered only when EVERY channel confirmed it (HTTP 2xx); otherwise it stays queued and is retried, up to
    `max_attempts`, and the state is visible in notifs.json (tries, last error);
  - a failed event is retried after 30 s, then 60 s, doubling up to one hour (`next_try` in notifs.json), counted in elapsed time: a run that finds
    the event still waiting leaves it queued and does not count a try, so a timer every minute does not use up `max_attempts` in twenty minutes;
  - notifs.json is written by several processes (`rpl watch`, `rpl notify`, the group apply): each event's state is written alone, under a lock
    on notifs.json.lock, after reading the file again, so one run never erases what another recorded; if the lock cannot be taken within
    LOCK_WAIT_S the write goes on without it (a possible duplicate message, never a lost mark or a stopped alert);
  - one message per event key (the key carries the version, e.g. "fix:app-1:CVE-2026-0001:2.4.1");
  - secrets are read from files that must not be readable by group or others, and are never printed, logged or put in the state file;
  - the webhook resolves the host ONCE, refuses private, loopback and link-local addresses (unless allow_private), connects to the
    address it checked, and does not follow redirects.
Limits, written down: how long 20 tries last depends on how often the caller runs (about 13 h at one run per minute, about 20 h at one per hour); the delay does not read a `Retry-After` header; a channel that hangs holds a run for the 15 s timeout, per channel and per event;
"delivered" means the receiving service answered 2xx, not that a person read it. The nightly-run check is a function
(`missing_run`) the caller runs from a timer that does not depend on the nightly job. A channel that confirmed an event is remembered
(`sent` in notifs.json: a short hash of the channel's type and target, never the URL): when one of two channels fails, only the failed one is
retried. A channel that confirmed and then failed to be recorded (a crash between the two) can be sent the event twice.
"""
import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import time
from urllib.parse import urlsplit

try:
    import fcntl
except ImportError:                    # not a Unix system: no lock, see _locked
    fcntl = None

from . import config

DEFAULT_MAX_ATTEMPTS = 20
RETRY_BASE_S = 30                    # wait after the first failure; doubles with each one
RETRY_CAP_S = 3600                   # never wait longer than this between two tries
LOCK_WAIT_S = 5.0                    # how long a state update waits for the lock before it goes on without it


class NotifyError(Exception):
    pass


def read_secret(path):
    """The first line of a file that only its owner can read. Raises NotifyError with a message that never contains the secret."""
    path = os.path.expanduser(path)
    try:
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            raise NotifyError(f"secret file {path} must not be readable by group or others (mode {mode:o}); chmod 600")
        with open(path, encoding="utf-8") as f:
            value = f.readline().strip()
    except OSError as e:
        raise NotifyError(f"cannot read secret file {path}: {e.strerror}")
    if not value:
        raise NotifyError(f"secret file {path} is empty")
    return value


def forbidden_address(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified


def resolve(host, port):
    return sorted({ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})


def post(url, body, headers, allow_private=False, resolver=resolve, timeout=15):
    """POST `body` (bytes) and return the HTTP status. Resolves once, checks every address, connects to the checked one, never follows redirects."""
    u = urlsplit(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        raise NotifyError("the URL must be http(s) with a host")
    if u.scheme == "http" and not allow_private:
        raise NotifyError("plain http is refused unless allow_private is set")
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        addrs = resolver(u.hostname, port)
    except OSError:
        raise NotifyError("the host name does not resolve")
    if not addrs:
        raise NotifyError("the host name does not resolve")
    if not allow_private and any(forbidden_address(a) for a in addrs):
        raise NotifyError("the destination resolves to a private, loopback or link-local address (set allow_private to accept it)")
    raw = socket.create_connection((addrs[0], port), timeout=timeout)
    try:
        if u.scheme == "https":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname)
        conn = http.client.HTTPConnection(u.hostname, port, timeout=timeout)
        conn.sock = raw
        conn.request("POST", (u.path or "/") + ("?" + u.query if u.query else ""), body, dict(headers, Host=u.netloc))
        return conn.getresponse().status
    finally:
        raw.close()


def send_telegram(ch, text, poster):
    token = read_secret(ch["token_file"])
    return poster("https://api.telegram.org/bot" + token + "/sendMessage", json.dumps({"chat_id": ch["chat_id"], "text": text}).encode(),
                  {"Content-Type": "application/json"}, False)


def send_webhook(ch, text, poster):
    headers = {"Content-Type": "application/json"}
    if ch.get("secret_file"):
        headers["Authorization"] = "Bearer " + read_secret(ch["secret_file"])
    return poster(ch["url"], json.dumps({"text": text}).encode(), headers, bool(ch.get("allow_private")))


CHANNELS = {"telegram": send_telegram, "webhook": send_webhook}


def channel_id(ch):
    """A stable short identifier of a channel (its type and target), so the state file can say which channels confirmed an event without naming
    a URL or a chat: a hash, never the target itself (a webhook URL often carries its token)."""
    target = ch.get("url") or ch.get("chat_id") or ""
    return hashlib.sha256(json.dumps([ch.get("type"), str(target)]).encode("utf-8")).hexdigest()[:12]


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


@contextlib.contextmanager
def _locked(lock_path):
    """An exclusive lock on `lock_path` while the block runs. If it cannot be taken within LOCK_WAIT_S (another process stuck, no flock, an
    unwritable directory) the block runs without it: a lock must never stop an alert, and a possible duplicate is better than a lost mark."""
    fd = None
    try:
        if fcntl is not None:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            end = time.monotonic() + LOCK_WAIT_S
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= end:
                        break
                    time.sleep(0.05)
    except OSError:
        pass
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)                                  # closing the descriptor releases the lock


def _commit(path, key, st):
    """Record the state of ONE key. The file is read again under the lock and only this key is replaced, so what another process recorded in
    the meantime (a delivery mark, a queued event) is kept. The sends themselves are outside the lock."""
    with _locked(path + ".lock"):
        state = _load(path)
        state[key] = st
        tmp = f"{path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)      # owner-only whatever the umask: container and image names, last errors
        try:
            os.fchmod(fd, 0o600)                                              # also when a leftover temporary file already existed with other rights
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
        os.replace(tmp, path)


def deliver(events, cfg, poster=post, now=time.time):
    """events: [{"key": str, "text": str}]. Returns {"delivered": [...], "queued": [...], "given_up": [...]}; state in notifs.json."""
    notif = cfg.get("notifications") or {}
    channels = notif.get("channels") or []
    cap = int(notif.get("max_attempts") or DEFAULT_MAX_ATTEMPTS)
    path = config.state(cfg, "notifs.json")
    out = {"delivered": [], "queued": [], "given_up": []}
    for ev in events:
        key = ev["key"]
        st = _load(path).get(key)                         # read again for each event: another process may have recorded it meanwhile
        if not isinstance(st, dict) or "tries" not in st or "delivered" not in st:
            st = {"delivered": False, "tries": 0}
        if st["delivered"]:
            continue                                      # one message per key
        if st["tries"] >= cap:
            out["given_up"].append(key)
            continue
        t = now()
        due = st.get("next_try")
        if st["tries"] and isinstance(due, (int, float)) and t < due <= t + RETRY_CAP_S:
            out["queued"].append(key)                         # waiting for its delay: not a try (a time further ahead than the cap is not trusted)
            continue
        st["tries"] += 1
        st["last_try"] = t
        errors = []
        if not channels:
            errors.append("no channel configured")
        sent = list(st.get("sent") or [])                     # channels that already confirmed this event: not sent it again
        for ch in channels:
            cid = channel_id(ch)
            if cid in sent:
                continue
            fn = CHANNELS.get(ch.get("type"))
            try:
                if fn is None:
                    raise NotifyError("unknown channel type " + repr(ch.get("type")))
                status = fn(ch, ev["text"], poster)
                if not (200 <= int(status) < 300):
                    raise NotifyError("HTTP " + str(status))
                sent.append(cid)
            except NotifyError as e:
                errors.append(f"{ch.get('type')}: {e}")
            except Exception as e:                        # a network error text may carry a URL with a token: keep only its type
                errors.append(f"{ch.get('type')}: {type(e).__name__}")
        if errors:
            st["sent"] = sent
            st["last_error"] = "; ".join(errors)
            st["next_try"] = t + min(RETRY_BASE_S * 2 ** (st["tries"] - 1), RETRY_CAP_S)
            out["queued"].append(key)
        else:
            st["delivered"] = True
            st.pop("sent", None)
            st.pop("last_error", None)
            st.pop("next_try", None)
            out["delivered"].append(key)
        _commit(path, key, st)
    return out


def file_stamp(path):
    """A short stamp of a file's CONTENT, for a notification key that must change when the file changes (a damaged file that is damaged in another
    way is another message). A file that cannot be read gets its modification time in nanoseconds; one that does not exist, "unknown"."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read(1 << 20)).hexdigest()[:12]
    except OSError:
        try:
            return str(os.stat(path).st_mtime_ns)
        except OSError:
            return "unknown"


def missing_run(last_run_ts, now_ts, max_hours=36):
    """An event when the nightly run has not happened for `max_hours` (or never), else None. Meant for a timer independent of the nightly job."""
    if last_run_ts is None:
        return {"key": "nightly-missing:never", "text": "The nightly run has never completed."}
    age_h = (now_ts - last_run_ts) / 3600
    if age_h > max_hours:
        return {"key": f"nightly-missing:{int(last_run_ts)}", "text": f"The nightly run has not completed for {age_h:.0f} h."}
    return None
