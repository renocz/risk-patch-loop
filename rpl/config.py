"""Configuration: one JSON file (path in the RPL_CONFIG variable, else ./rpl.json). Every key has a default, so an empty file works.

Nothing here is a secret. Paths may use ~ and are expanded.
"""
import json
import os

DEFAULTS = {
    # where the tool keeps its own files (findings, inventory, proposals, patch journal)
    "state_dir": "~/.local/share/rpl",
    # Trivy runs as a container; the cache directory is mounted into it
    "trivy_image": "aquasec/trivy:0.74.0",
    "trivy_cache": "~/.cache/trivy",
    # CISA Known Exploited Vulnerabilities feed
    "kev_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # hand-maintained files (see examples/)
    "apps_file": "patch-apps.json",       # services allowed to be proposed, with their health route and database
    "roles_file": "roles.json",           # control-plane services and services that parse untrusted input
    "accepted_file": "accepted.json",     # {"image|CVE-...": "reason"}: findings reviewed and accepted
    "tunnel_hosts_file": None,            # JSON list of host names published to the Internet by a tunnel or a port forward
    # label of a Traefik middleware that makes a route require a login before the app is reached
    "auth_middleware_words": ["auth", "oauth", "authelia", "authentik", "tinyauth", "forward"],
    # command run before an update to take a restorable snapshot; it must exit 0, or the update is refused.
    # null means "no snapshot command": the update then needs --no-snapshot, said out loud.
    "snapshot_command": None,
    # where the reverse proxy listens locally, to test a route by Host header after an update
    "route_check_url": "https://127.0.0.1/",
    # where database dumps go
    "backup_dir": "~/rpl-backups",
    # update groups (see rpl/groups.py): {"<parent>": {"policy": "ask", "reason": "...", "confirmed": true, "controls": ["members_healthy"]}}
    "groups": {},
    # notification channels (see rpl/notify.py): {"channels": [{"type": "telegram"|"webhook", ...}], "max_attempts": 20}
    "notifications": {},
    # the two settings the closed-list controls use: a URL that answers with the caller's public address, and an image that has curl
    "probe_url": "https://api.ipify.org",
    "probe_image": "curlimages/curl:8.11.1",
    # group apply (rpl/groupapply.py): backups of configuration directories go to <backup_dir>/group-*, owner-only
    "group_backup_retention_days": 7,     # `rpl group --purge` deletes older ones
    "group_backup_max_mb": 2048,          # more than this is data, not configuration: the apply is refused
    # `rpl watch` (rpl/watch.py): an open group-journal entry younger than this is taken for an apply in progress
    "group_unfinished_grace_minutes": 60,
    # `rpl notify` (rpl/events.py): hours without a recorded nightly run before it is "missing"; patch results older than the window are not replayed
    "nightly_max_hours": 36,
    "events_window_hours": 72,
    # how many minutes to wait for a health check / route after an update
    "health_timeout_s": 180,
    "route_timeout_s": 150,
}


def load():
    path = os.environ.get("RPL_CONFIG") or "rpl.json"
    cfg = dict(DEFAULTS)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    base = os.path.dirname(os.path.abspath(path)) if os.path.exists(path) else os.getcwd()
    for k in ("state_dir", "trivy_cache", "backup_dir"):
        cfg[k] = os.path.expanduser(cfg[k])
    for k in ("apps_file", "roles_file", "accepted_file", "tunnel_hosts_file"):
        if cfg.get(k):
            p = os.path.expanduser(cfg[k])
            cfg[k] = p if os.path.isabs(p) else os.path.join(base, p)
    return cfg


def state(cfg, name):
    os.makedirs(cfg["state_dir"], exist_ok=True)
    return os.path.join(cfg["state_dir"], name)
