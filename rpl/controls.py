"""Controls for an update group: a CLOSED list of read-only checks.

The configuration chooses control TYPES by name (`"controls": ["members_healthy", ...]`). It never supplies a command, a path to run or a
URL to fetch: the probe endpoint and the probe image are two plain settings (`probe_url`, `probe_image`), used only by the controls below.
An unknown control name is an error, not a skipped check. IP addresses are compared, never printed.

Each control returns (verdict, detail) with verdict "ok", "fail" or "unknown". "unknown" is never counted as ok.
"""
import json

from . import patch

CONTROLS = ("members_healthy", "exit_differs", "no_leak")


def _inspect(name, host):
    r = host.run(["docker", "inspect", name])
    try:
        return json.loads(r.stdout)[0] if r.returncode == 0 else None
    except (ValueError, IndexError, TypeError):
        return None


def members_healthy(members, host, **_):
    bad = []
    for m in members:
        c = _inspect(m, host)
        st = (c or {}).get("State") or {}
        if not c or not st.get("Running") or (st.get("Health") or {}).get("Status") not in (None, "healthy"):
            bad.append(m)
    return ("fail", "not running or not healthy: " + ", ".join(bad)) if bad else ("ok", f"{len(members)} member(s) healthy")


def _ip(cmd, host):
    r = host.run(cmd)
    out = (r.stdout or "").strip()
    return out if r.returncode == 0 and 0 < len(out) <= 45 and " " not in out and "\n" not in out else None


def _host_ip(probe_url, host):
    return _ip(["curl", "-s", "-m", "15", probe_url], host)


def _ip_via(container, probe_url, probe_image, host):
    return _ip(["docker", "run", "--rm", "--network", "container:" + container, "--entrypoint", "curl", probe_image, "-s", "-m", "15", probe_url], host)


def exit_differs(members, host, probe_url, probe_image, **_):
    """The parent's public address differs from the host's own."""
    mine, theirs = _host_ip(probe_url, host), _ip_via(members[0], probe_url, probe_image, host)
    if not mine or not theirs:
        return "unknown", "an address could not be read"
    return ("fail", "the parent exits with the host's own address") if mine == theirs else ("ok", "the parent exits with another address")


def no_leak(members, host, probe_url, probe_image, **_):
    """Every dependant exits with the parent's address (they share its namespace, so a difference means a leak or a wrong mode)."""
    first = _ip_via(members[0], probe_url, probe_image, host)
    if not first:
        return "unknown", "the parent's address could not be read"
    bad = []
    for m in members[1:]:
        ip = _ip_via(m, probe_url, probe_image, host)
        if ip is None:
            return "unknown", f"the address seen from {m} could not be read"
        if ip != first:
            bad.append(m)
    return ("fail", "different exit address: " + ", ".join(bad)) if bad else ("ok", "all dependants exit like the parent")


def run(names, members, host, probe_url, probe_image):
    """[(name, verdict, detail)] for the named controls. Raises ValueError on a name outside the closed list."""
    unknown = [n for n in names if n not in CONTROLS]
    if unknown:
        raise ValueError("unknown control(s): " + ", ".join(unknown) + "; allowed: " + ", ".join(CONTROLS))
    fns = {"members_healthy": members_healthy, "exit_differs": exit_differs, "no_leak": no_leak}
    return [(n,) + fns[n](members, host, probe_url=probe_url, probe_image=probe_image) for n in names]
