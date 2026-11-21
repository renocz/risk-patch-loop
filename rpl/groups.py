"""Update groups: containers that must be handled together because they share a network namespace.

A container started with `network_mode: container:<parent>` (a VPN container and the services behind it is the usual case) lives in the
parent's network namespace. Recreating the parent breaks every dependant, so the parent and its dependants form a GROUP: one unit, parent first.

This module only DESCRIBES groups. It changes nothing:

  detect(objs)               groups found in `docker inspect` objects
  status(detected, cfg)      each group with the policy and reason the owner wrote in the config, and what is wrong with it
  refusal(name, ...)         why a single service of a group must not be patched on its own, or None

The owner declares each group under its parent's container name, in the `groups` key of rpl.json:

    "groups": {"vpn-1": {"policy": "ask", "reason": "VPN: recreating it cuts every download", "confirmed": true}}

policy is "auto", "ask" or "never". "ask" and "never" need a non-empty reason, shown wherever the group is mentioned. A group that is
detected but not declared, has an invalid policy, lacks a reason, or is nested in another group is BLOCKED and reported. Nothing here ever
answers "fine" when it cannot tell.

Limit, written down: patching a whole group (parent first, dependants recreated after it) does not exist yet. Until it does, every member of a
detected group is refused by `rpl patch` and never proposed, whatever the policy.
"""
POLICIES = ("auto", "ask", "never")


def detect(objs):
    """{parent name: sorted dependant names} from `docker inspect` objects. Only a parent that is present in `objs` counts: a container
    whose network is `container:<unknown id>` belongs to no group we can see."""
    by_id = {c["Id"]: c["Name"].lstrip("/") for c in objs}
    names = set(by_id.values())
    found = {}
    for c in objs:
        mode = (c.get("HostConfig") or {}).get("NetworkMode") or ""
        if not mode.startswith("container:"):
            continue
        ref = mode.split(":", 1)[1]
        parent = by_id.get(ref) or (ref if ref in names else None)
        if parent and parent != c["Name"].lstrip("/"):
            found.setdefault(parent, set()).add(c["Name"].lstrip("/"))
    return {p: sorted(m) for p, m in sorted(found.items())}


def status(detected, cfg_groups):
    """{parent: {"members": [parent, *dependants], "policy", "reason", "confirmed", "problems": [...], "blocked": bool}}."""
    cfg_groups = cfg_groups or {}
    members_of = {m for deps in detected.values() for m in deps}
    out = {}
    for parent, deps in detected.items():
        entry = cfg_groups.get(parent)
        problems = []
        policy = reason = None
        confirmed = False
        if not isinstance(entry, dict):
            problems.append("group detected but not declared in the configuration (policy and reason are missing)")
        else:
            policy, reason, confirmed = entry.get("policy"), (entry.get("reason") or "").strip(), entry.get("confirmed") is True
            if policy not in POLICIES:
                problems.append("policy must be one of " + ", ".join(POLICIES))
            elif policy in ("ask", "never") and not reason:
                problems.append("policy '" + policy + "' needs a non-empty reason")
        if parent in members_of:
            problems.append("nested group: this container is itself a dependant of another group (not supported)")
        out[parent] = {"members": [parent] + list(deps), "policy": policy, "reason": reason or None, "confirmed": confirmed,
                       "problems": problems, "blocked": bool(problems)}
    for parent in cfg_groups:
        if parent not in detected:
            out[parent] = {"members": [parent], "policy": (cfg_groups[parent] or {}).get("policy") if isinstance(cfg_groups[parent], dict) else None,
                           "reason": None, "confirmed": False, "problems": ["declared in the configuration but no container shares its network"],
                           "blocked": False, "orphan": True}
    return out


def member_group(name, detected):
    """The parent name of the group `name` belongs to (as parent or dependant), or None."""
    for parent, deps in detected.items():
        if name == parent or name in deps:
            return parent
    return None


def refusal(name, detected, cfg_groups):
    """Why `name` must not be patched on its own, or None when it is in no group."""
    parent = member_group(name, detected)
    if parent is None:
        return None
    st = status(detected, cfg_groups)[parent]
    where = "its network is the one of '" + parent + "'" if name != parent else "other containers use its network"
    detail = "; ".join(st["problems"]) if st["problems"] else (
        "policy " + str(st["policy"]) + (": " + st["reason"] if st["reason"] else "") + ("" if st["confirmed"] else " (not confirmed)"))
    return ("'" + name + "' belongs to an update group (" + where + ", " + detail + "): a group is patched as a whole, "
            "which this version cannot do yet; dedicated procedure and an explicit decision required")
