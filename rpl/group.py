"""rpl group --dry: rehearse the update of a group without changing anything.

Shows the order (parent first), asks Docker which containers a forced recreation of the members would touch, requires that this is exactly
the group and nothing else, and runs the configured controls BEFORE. Applying a group does not exist yet: without --dry the command refuses.

Exit codes: 0 ready; 1 refused or not ready; 2 a configured control failed or could not tell.
Limits, written down: no backup or restore proof yet; the dry run does not pull images; controls run on the current state, not after an update.
"""
import argparse
import json

from . import config, controls, groups, patch


def members_from_compose(compose_file, parent, host):
    """(parent service, [dependant services]) read from `docker compose config`, or (None, reason)."""
    cfg = patch.compose(compose_file, "config", "--format", "json", host=host)
    if cfg.returncode:
        return None, "cannot read " + compose_file
    services = json.loads(cfg.stdout).get("services", {})
    if parent not in services:
        return None, f"service '{parent}' is not defined in {compose_file}"
    if (services[parent].get("network_mode") or "").startswith(("service:", "container:")):
        return None, f"'{parent}' is itself a dependant: nested groups are not supported"
    deps = sorted(n for n, s in services.items() if (s.get("network_mode") or "") in (f"service:{parent}", f"container:{parent}"))
    if not deps:
        return None, f"no service uses the network of '{parent}': not a group"
    return (parent, deps), None


def main(argv, host=patch.HOST):
    p = argparse.ArgumentParser(prog="rpl group")
    p.add_argument("--compose", required=True)
    p.add_argument("--parent", required=True, help="service whose network the others share")
    p.add_argument("--dry", action="store_true", help="required: applying a group is not implemented")
    a = p.parse_args(argv)
    if not a.dry:
        print("REFUSED: applying a group is not implemented; use --dry")
        return 1
    if not patch.NAME.fullmatch(a.parent):
        print(f"REFUSED: --parent {a.parent!r} is not a valid name")
        return 1
    cfg = config.load()
    found, why = members_from_compose(a.compose, a.parent, host)
    if not found:
        print("REFUSED: " + why)
        return 1
    parent, deps = found
    order = [parent] + deps
    entry = (cfg.get("groups") or {}).get(parent)
    st = groups.status({parent: deps}, {parent: entry} if entry is not None else {})[parent]
    print("group: " + " -> ".join(order) + f"  (policy {st['policy']}, " + ("confirmed" if st["confirmed"] else "not confirmed") + ")")
    if st["problems"]:
        print("NOT READY: " + "; ".join(st["problems"]))
        return 1
    dry = patch.compose(a.compose, "up", "-d", "--no-deps", "--force-recreate", "--dry-run", *order, host=host)
    if dry.returncode:
        print("NOT READY: the dry run failed: " + (dry.stderr or dry.stdout).strip()[-200:])
        return 1
    recreated = set(patch.RECREATE.findall(dry.stdout + dry.stderr))
    expected = set()
    for s in order:
        expected |= patch.container_names(a.compose, s, host)
    print("dry run would recreate", sorted(recreated))
    if not expected or recreated != expected:
        print("NOT READY: the dry run must recreate exactly the group's containers (" + ", ".join(sorted(expected)) + "), nothing else")
        return 1
    names = (entry or {}).get("controls") or []
    try:
        results = controls.run(names, sorted(expected), host, cfg["probe_url"], cfg["probe_image"])
    except ValueError as e:
        print("NOT READY: " + str(e))
        return 1
    for n, verdict, detail in results:
        print(f"control {n}: {verdict.upper()} ({detail})")
    if any(v != "ok" for _, v, _ in results):
        print("NOT READY: a control did not pass")
        return 2
    print("READY (rehearsal only: nothing changed, no backup or restore proof yet)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
