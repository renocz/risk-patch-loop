# Design

## The loop

```
scan ──► inventory ──► risk score ──► fix check ──► proposals ──► (a human says yes) ──► patch (with rollback)
 nightly    nightly        nightly        nightly       nightly                              one service at a time
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="design-decisions-dark.png">
  <img alt="Diagram: every night, read-only, rpl scans the running images, inventories how reachable each container is, scores the findings, checks in the registry that a candidate really fixes them, and prepares proposals; after your yes, one service gets a snapshot and database dump, a pinned image and a dry run, a recreation and a check, and an automatic rollback if the check fails." src="design-decisions.png">
</picture>

1. **scan** (`rpl scan`): Trivy on the images that are running, plus the CISA KEV list. Three classes: A (HIGH/CRITICAL with a fix), B (KEV, exploited in the wild, any severity), C (no fix). A scan that could not do its job is never reported "OK".
2. **inventory** (`rpl inventory`): for each container, how exposed it really is, from `docker inspect` and Traefik labels: Internet with or without a forward-auth login, LAN port, LAN through the proxy, localhost, internal; plus Docker socket and elevated rights. Internet exposure is *unknown* until you provide the list of published host names (a tunnel configuration, a firewall rule export): it is never guessed.
3. **risk score** (`rpl risk`): `(severity + KEV + sensitive access + role) x exposure factor`. Readable in one line, no model, no network call. See the module docstring for the points.
4. **fix check** (`rpl fixcheck`): for images with "act" rows, read the registry, pick a candidate version, scan *the candidate from the registry*, and say whether it removes the findings: complete, partial, none, or no newer version.
5. **proposals** (`rpl proposals`): a service is proposed only if it has an "act" row, a *proven* fix, is described in `patch-apps.json`, and is not a VPN container or a service sharing its network. Everything else is listed with the reason.
6. **patch** (`rpl patch`, or `rpl proposals --apply <service>`): snapshot, database dump, pin the new image, dry run (only that service may be recreated), recreate, check (healthy + a route through the reverse proxy answers with an expected status), automatic rollback if the check fails.

## Decisions, and why

**Nothing is applied without a human saying yes.** `rpl proposals` prepares; `rpl proposals --apply <service>` runs exactly the parameters of a stored proposal (never a free argument, refused if older than 36 h). If you run an AI agent next to this, the safe arrangement is the one in [agent-ops-guardrails](https://github.com/renocz/agent-ops-guardrails): the agent may run the read-only steps freely, and the `--apply` step waits for an approval the agent cannot give itself.

**A fix is proven before it is proposed.** Bumping a tag changes nothing if the maintainer has not published a rebuilt image. In the author's first week, updating blindly would have changed nothing for 5 of 12 images (docs/results.md).

**Scan by image ID, not by name.** A container started from an image pinned by digest leaves the previous tag in the local store; scanning the tag reports the old image.

**Moving tags are pinned by digest.** `image: app:latest` becomes `image: app:latest@sha256:...`: the version in service is then known and repeatable.

**The rollback restores the image, not the data.** For a service with a PostgreSQL database, the dump (verified readable with `pg_restore -l`) and the snapshot are the safety net. Stateful migrations are the part the tool cannot undo.

**Update groups are refused.** A service whose network namespace belongs to another container, and that container, are recreated only by hand: recreating the parent breaks the services behind it. `rpl/groups.py` describes these groups from `network_mode` (`service:X`, `container:X`); `rpl patch` reads the compose file, `rpl proposals` reads `docker inspect`. The name "gluetun" stays refused as a safety net in `REFUSED_NAMES` (`rpl/patch.py`). The `groups` config key (policy, reason, confirmed, controls) is validated by `rpl.groups.status` and not yet used to allow anything.

**Notifications.** `rpl/notify.py` sends events to the channels of the `notifications` config. "Delivered" means every channel answered 2xx; anything else stays queued with its error and is retried up to a cap, so nothing disappears silently. Secrets live in owner-only files, never in the config or the state. The webhook checks the address it actually connects to (private, loopback, link-local refused by default) and follows no redirect. Only the library exists: no command yet gathers events from the other modules.

**Group rehearsal.** `rpl group --dry` (`rpl/group.py`) never changes anything: it checks that Docker's own dry run of a forced recreation touches exactly the group's containers, then runs the controls named in the config (`rpl/controls.py`, a closed list: members healthy, exit address differs from the host's, dependants exit like the parent). "Unknown" (an address could not be read) is never counted as passing. Limits: the exit-address controls need outbound access to `probe_url` and pull `probe_image`; they prove the state now, not after an update; no backup or restore proof exists yet.

**One switch, one lock.** Everything that applies goes through `gate.applying()` (`rpl/gate.py`). The pause switch is a file, `PAUSED`, in the state directory: if anything exists at that path nothing is applied, so `touch` is enough in an emergency, and a switch that cannot be read counts as paused. The lock is a non-blocking `flock` on `apply.lock`: a second run is refused at once (exit code 5, the same as paused: "not now, nothing touched") instead of queueing behind an update nobody is watching, and the kernel releases it when the process dies, so a crash leaves no stale lock to clean by hand. `rpl patch` takes it before its first check, the group refusal included, and keeps it through the rollback; the switch is read before the lock and again under it, never afterwards, because stopping between a recreation and its rollback is worse than finishing. `rpl proposals --apply` checks the switch and lets the `rpl patch` it starts hold the lock. Read-only steps and dry runs ignore both. Limits: both files are per state directory, they stop cooperating runners and not someone who can write that directory, and `flock` was only exercised on Linux on a local file system.

**Honest limits.** The route check proves one route answers. The score was tuned on one owner's twenty verdicts. The rollback has not been triggered in production. See `docs/results.md`.

## What it does not do

- It does not patch the host operating system, only container images.
- It does not run a vulnerability scan of source code or of images that are not running.
- It does not decide for you: a score orders work, it is not a verdict.
- It does not hide that a finding has no fix: those stay on the list as "WATCH (no fix)".
