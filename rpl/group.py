"""rpl group: rehearse, plan, apply or resume the update of a group (a parent container and the containers sharing its network).

    rpl group --compose F --parent P --dry                  quick rehearsal (below), changes nothing
    rpl group --compose F --parent P --plan                 the full plan, its fingerprint and a backup proof, changes nothing
    rpl group --compose F --parent P [--approve FP]         apply (rpl/groupapply.py: policy, backup, ordered update, rollback)
    rpl group --compose F --parent P --resume               roll back an apply that was interrupted
    rpl group --purge                                       delete group backups older than the retention

--dry shows the order (parent first), asks Docker which containers a forced recreation of the members would touch, requires that this is
exactly the group and nothing else, and runs the configured controls on the current state.

Exit codes of --dry: 0 ready; 1 refused or not ready; 2 a configured control failed or could not tell. The others are in rpl/groupapply.py.
Limits, written down: --dry reads the members from the compose file only and looks its group up under the parent's SERVICE name, while
--plan and the apply use Docker too and the parent's CONTAINER name; the dry run does not pull images.
"""
import argparse
import json

from . import config, controls, groupapply, groups, patch


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
    p.add_argument("--compose")
    p.add_argument("--parent", help="service whose network the others share")
    p.add_argument("--dry", action="store_true", help="quick rehearsal: order, Docker's own dry run, controls")
    p.add_argument("--plan", action="store_true", help="the full plan with its fingerprint and a backup proof; changes nothing")
    p.add_argument("--approve", metavar="FINGERPRINT", help="policy ask: the fingerprint of the plan a human read")
    p.add_argument("--resume", action="store_true", help="roll back a group apply that was interrupted")
    p.add_argument("--purge", action="store_true", help="delete group backups older than group_backup_retention_days")
    p.add_argument("--no-snapshot", action="store_true", help="required when no snapshot_command is configured")
    a = p.parse_args(argv)
    cfg = config.load()
    if a.purge:
        return groupapply.purge(cfg)
    if not a.compose or not a.parent:
        print("REFUSED: --compose and --parent are required")
        return 1
    if not patch.NAME.fullmatch(a.parent):
        print(f"REFUSED: --parent {a.parent!r} is not a valid name")
        return 1
    if sum((a.dry, a.plan, a.resume)) > 1:
        print("REFUSED: --dry, --plan and --resume exclude each other")
        return 1
    if a.plan:
        return groupapply.plan_only(a, cfg, host)
    if a.resume:
        return groupapply.resume(a, cfg, host)
    if not a.dry:
        return groupapply.apply(a, cfg, host)
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
