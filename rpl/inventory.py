"""Step 2, inventory: how exposed is each container, from what is really configured (docker inspect + Traefik labels).

Levels, from most to least exposed:
  internet-no-auth    published to the Internet (host in the tunnel list) with no forward-auth middleware on its route
  internet-auth       published to the Internet behind a forward-auth middleware
  lan-port            a port published on all interfaces of the host: reachable from the LAN without the reverse proxy
  lan-proxy           reachable on the LAN through the reverse proxy only, no forward-auth
  lan-proxy-auth      same, behind a forward-auth middleware
  localhost           published on 127.0.0.1 only
  internal            no port, no route
Internet exposure is "unknown" (never guessed) until a list of published host names is given (config key tunnel_hosts_file).
A container that shares another container's network (network_mode: container:X) inherits that container's level.
"""
import json
import os
import re
import subprocess
import sys

from . import config

ORDER = ["internet-no-auth", "internet-auth", "lan-port", "lan-proxy", "lan-proxy-auth", "localhost", "internal"]
SENSITIVE = ("/var/run/docker.sock", "/run/docker.sock")


def routers(labels, auth_words):
    """{router: {"hosts": [...], "auth": bool}} from traefik.http.routers.* labels."""
    r = {}
    for k, v in labels.items():
        m = re.match(r"traefik\.http\.routers\.([^.]+)\.(rule|middlewares)$", k)
        if not m:
            continue
        e = r.setdefault(m.group(1), {"hosts": [], "auth": False})
        if m.group(2) == "rule":
            e["hosts"] += re.findall(r"Host\(`([^`]+)`\)", v)
        elif any(w in v.lower() for w in auth_words):
            e["auth"] = True
    return r


def analyse(c, tunnel, auth_words):
    """One entry from one `docker inspect` object. tunnel: set of published host names, or None if unknown."""
    cfg, hc = c["Config"], c["HostConfig"]
    labels = cfg.get("Labels") or {}
    mode = hc.get("NetworkMode", "")
    ports = []
    for p, binds in (hc.get("PortBindings") or {}).items():
        for b in binds or []:
            ports.append((b.get("HostIp") or "0.0.0.0", b.get("HostPort") or "?", p))
    if mode == "host":
        ports.append(("0.0.0.0", "all", "all"))
    rts = routers(labels, auth_words) if labels.get("traefik.enable") == "true" else {}
    hosts = sorted({h for e in rts.values() for h in e["hosts"]})
    auth = bool(rts) and all(e["auth"] for e in rts.values())
    sensitive = [m["Source"] for m in c.get("Mounts", []) if m.get("Source") in SENSITIVE]
    rights = [x for x, on in (("privileged", hc.get("Privileged")), ("pid=host", hc.get("PidMode") == "host"), ("net=host", mode == "host")) if on]
    rights += [f"cap:{x}" for x in (hc.get("CapAdd") or [])]
    internet = ("unknown" if hosts else "no") if tunnel is None else ("yes" if any(h in tunnel for h in hosts) else "no")
    if internet == "yes":
        level = "internet-auth" if auth else "internet-no-auth"
    elif any(ip not in ("127.0.0.1", "::1") for ip, _, _ in ports):
        level = "lan-port"
    elif rts:
        level = "lan-proxy-auth" if auth else "lan-proxy"
    elif ports:
        level = "localhost"
    else:
        level = "internal"
    return {"image": cfg.get("Image"), "level": level, "internet": internet, "hosts": hosts, "auth": auth,
            "ports": sorted(f"{ip}:{hp}->{cp}" for ip, hp, cp in ports), "network_of": mode[10:] if mode.startswith("container:") else None,
            "sensitive_mounts": sensitive, "rights": rights}


def inherit(inv, ids):
    """Containers sharing another container's network take the more exposed of the two levels. ids: {container id: name}."""
    for e in inv.values():
        ref = e.get("network_of")
        target = ref if ref in inv else next((n for i, n in ids.items() if ref and i.startswith(ref)), None)
        if target in inv:
            e["network_of"] = target
            if ORDER.index(inv[target]["level"]) < ORDER.index(e["level"]):
                e["level"] = inv[target]["level"]
    return inv


def diff(old, new):
    out = []
    for n in sorted(set(old) | set(new)):
        a, b = old.get(n), new.get(n)
        if a is None:
            out.append(f"+ {n}: {b['level']}")
        elif b is None:
            out.append(f"- {n}")
        elif a != b:
            out.append(f"~ {n}: {a['level']} -> {b['level']} ({', '.join(k for k in b if a.get(k) != b[k])})")
    return out


def main(argv):
    cfg = config.load()
    auth_words = cfg["auth_middleware_words"]
    tunnel = None
    if cfg.get("tunnel_hosts_file") and os.path.exists(cfg["tunnel_hosts_file"]):
        tunnel = set(json.load(open(cfg["tunnel_hosts_file"])))
    ids_ = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True, check=True).stdout.split()
    conts = json.loads(subprocess.run(["docker", "inspect", *ids_], capture_output=True, text=True, check=True).stdout)
    inv = {c["Name"].lstrip("/"): analyse(c, tunnel, auth_words) for c in conts}
    inv = inherit(inv, {c["Id"]: c["Name"].lstrip("/") for c in conts})
    path = config.state(cfg, "inventory.json")
    old = json.load(open(path)) if os.path.exists(path) else None
    json.dump(inv, open(path, "w"), indent=1, sort_keys=True)
    if old is None:
        counts = {k: sum(1 for e in inv.values() if e["level"] == k) for k in ORDER}
        print(f"{len(inv)} containers; Internet exposure: {'unknown (no tunnel_hosts_file)' if tunnel is None else 'read'}; " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    else:
        print("\n".join(diff(old, inv)) or "no change")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
