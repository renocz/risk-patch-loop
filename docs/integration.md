# Driving rpl from another program

For someone who runs `rpl` from a service, a script or an agent of their own, or who moves an existing tool onto it. This is the contract: what `rpl` reads, what it writes, what its commands answer, and what it does not promise.

Derived from the code of the repository, not from a run of any integration: it was never tested against an external program, and the shapes of the state files can change between versions. It is kept in step with the code by `tests/test_integration_doc.py` (the configuration keys, the state file names and the commands must match), not by a run of a client.

## Rules for an integrator

- **Pin a tag.** Take a released tag (0.10.0 or later), not `main`. The CLI and its exit codes are what you rely on; the state files are for reading, and their shapes are not a stable interface.
- **Give `rpl` a state directory of its own** (`state_dir`). It writes fixed file names there (table below). Another tool's `notifs.json` in the same directory is kept aside, not overwritten (`notifs.json.unreadable-<stamp>`), and `apply.lock` is a plain `flock` on that name: a tool that locks the same file excludes `rpl`, and `rpl` writes its own text into it.
- **One account.** Run `rpl group`, `rpl watch` and `rpl notify` as the same account: the group journal is mode 0600. Another account reads it as unreadable and `rpl watch` exits 2.
- **Do not edit the state files by hand.** The one acknowledgement `rpl` expects from a human is deleting the backup directory named in a failed-rollback alert, after the services are repaired.
- **Do not automate `--approve`.** A group under policy `ask` needs a person to pass the fingerprint of the plan they read. An integration that passes it by itself removes the guarantee the policy gives.
- **Read exit codes, not messages.** The texts are for people and change.
- **A key `rpl` does not know is ignored without a word** in the configuration file (a private key such as `groupes` does nothing): the group is then "not declared". Check what `rpl` reads with `--plan` before relying on a configuration.

## Commands

| Command | What it does | Exit codes |
|---|---|---|
| `scan` | Trivy on the running images, the CISA KEV list; writes `findings.json` | 0 done; 1 UNRELIABLE (stale database, KEV list unavailable, an image not analysed): nothing is written |
| `inventory` | How exposed each container is (Traefik labels, the tunnel and gate lists); writes `inventory.json` | 0 |
| `risk` | The score and the decision (ACT, PLAN, WATCH); writes `risk.json`; `--backtest` replays labels | 0 |
| `fixcheck` | Which candidate versions really remove the ACT findings (scanned from the registry, nothing pulled); writes `fixcheck.json` with the digest it scanned | 0 |
| `proposals` | Updates ready to approve (`proposals.json`); `--list`; `--apply <service>` runs `patch` with the stored parameters only | `--apply`: those of `patch`; 1 refused; 5 not now |
| `patch` | One service: snapshot, dump, pin, dry run, recreate, health and route check, verified automatic rollback | 0 updated; 1 refused or stopped before the service was touched; 2 failed its check and was rolled back (verified); 3 refused: member of an update group; 4 failed AND the rollback could not be verified: check by hand; 5 not now (paused, or the shared lock is held) |
| `group` | An update group: `--plan` (changes nothing), `--approve <fingerprint>`, `--resume` after an interruption, `--purge`, `--dry` | 0 applied, or plan ready, or resumed; 1 refused, nothing changed (for `--plan`: NOT READY); 2 failed and rolled back (verified; for `--plan`: a control did not pass); 4 the rollback or a restore failed: check by hand; 5 not now |
| `pause` | `on [--reason TEXT]`, `off`, `status`: the switch that stops every apply | `status` exits 1 while paused, 0 otherwise |
| `sample` | The false-negative measure: `draw` and `result` | `result`: 0; 3 disagreements need the third reviewer; 4 the score changed since the draw |
| `watch` | Reports the open incidents of the group journal (an apply that never recorded a result, a failed rollback whose backup still exists) | 0 nothing open; 1 at least one open incident; 2 the journal cannot be read (never "OK") |
| `notify` | Collects events from the state files and delivers them; `--record ok|failed [--reason TEXT]` is the nightly job's last line | 0 nothing to say, or everything delivered; 1 something was not delivered (queued, given up, no channel); 2 bad usage |

`watch` and `notify` are meant to run from timers of their own, not from the nightly job: a process stopped by SIGTERM prints nothing, and `watch` is then the only warning.

## Configuration keys

One JSON file, path in `RPL_CONFIG`, else `./rpl.json`. Every key has a default, so an empty file works. Relative paths are resolved next to the file. Keys starting with `_` are comments.

| Key | Meaning |
|---|---|
| `state_dir` | where `rpl` keeps its own files (default `~/.local/share/rpl`) |
| `trivy_image` | the Trivy container image |
| `trivy_cache` | the cache directory mounted into it |
| `kev_url` | the CISA Known Exploited Vulnerabilities feed |
| `apps_file` | `patch-apps.json`: the services allowed to be proposed, with their health route and database |
| `roles_file` | `roles.json`: control-plane services and services that parse untrusted input (they weigh more) |
| `accepted_file` | `accepted.json`: findings reviewed and accepted |
| `tunnel_hosts_file` | JSON list of host names published to the Internet; without it the Internet exposure is "unknown", never guessed |
| `gated_hosts_file` | JSON list of host names behind an authentication gate outside the proxy labels (believed, not tested; only for hosts also in the tunnel list) |
| `auth_middleware_words` | words that make a Traefik middleware name count as a login |
| `snapshot_command` | run before an update; must exit 0 or the update is refused; `null` means `--no-snapshot` must be said out loud |
| `route_check_url` | where the reverse proxy listens locally, to test a route by `Host` header |
| `backup_dir` | database dumps and the group backups (owner-only) |
| `groups` | update groups, see below |
| `notifications` | `{"channels": [...], "max_attempts": 20, "run_budget_s": 45}`; a channel is `{"type": "telegram" or "webhook", ...}` and may set `timeout_s` |
| `probe_url` | an address that answers with the caller's public address (the group controls `exit_differs` and `no_leak`) |
| `probe_image` | an image that has `curl`, for those controls |
| `group_backup_retention_days` | `rpl group --purge` deletes older group backups (7) |
| `group_backup_max_mb` | more than this under the compose directory is data, not configuration: the apply is refused (2048) |
| `group_unfinished_grace_minutes` | `watch` takes a younger open entry for an apply in progress (60) |
| `nightly_max_hours` | hours without `notify --record` before the nightly run is "missing" (36) |
| `events_window_hours` | patch and group results older than this are not announced again (72) |
| `health_timeout_s` | minutes-worth of waiting for a health check after a recreation, in seconds (180) |
| `route_timeout_s` | the same for a route after an update, in seconds (150) |

### Declaring a group

A group is a container that shares another container's network (a VPN container and what runs behind it). It is declared under the parent's CONTAINER name:

```json
"groups": {"proj-vpn-1": {"policy": "ask", "reason": "VPN: recreating it cuts every download", "confirmed": true,
                          "controls": ["members_healthy", "exit_differs", "no_leak"],
                          "services": {"indexer": {"quiesce": "none"},
                                       "torrent": {"ignore_sockets": ["App/ipc-socket"]}}}}
```

`policy` is `auto` (the nightly run, no human), `ask` (a person passes `--approve <fingerprint>`) or `never`; `auto` and `ask` need `"confirmed": true`; `ask` and `never` need a reason; the most restrictive policy of the group and its services wins. `controls` is a closed list of names (no command comes from the configuration). `quiesce` is `stop` (the default for a member that mounts a configuration directory) or `none`. `ignore_sockets` names Unix sockets, relative to the mounted directory, that the application creates again: they are left out of the backup and shown in the plan; any other special file is refused.

## State files

In `state_dir`. "Written by" is the command that creates or changes it. All are JSON except the lock files.

| File | Written by | Notes |
|---|---|---|
| `findings.json` | `scan` | not written when the scan is UNRELIABLE |
| `kev.json` | `scan` | the KEV list, kept for when the feed is unavailable |
| `inventory.json` | `inventory` | one entry per container: level, hosts, `auth`, `gated`, ports |
| `risk.json` | `risk` | the rows (score, decision) and a summary; the input of `sample draw` |
| `fixcheck.json` | `fixcheck` | verdict and `candidate_digest` per image; a group apply refuses a proof older than 36 hours or without a digest |
| `proposals.json` | `proposals` | refused by `--apply` after 36 hours or if the compose file changed |
| `patches.json` | `patch` | the journal of single-service updates; the last 200 entries |
| `group-journal.json` | `group` | written BEFORE anything is stopped; an entry without a result blocks every later group apply until `--resume`; mode 0600; keeps the last 100 entries and every older open incident |
| `notifs.json` | `notify`, `watch`, `group` | one entry per message key: delivered, tries, next try, which channels confirmed; mode 0600; no URL or token |
| `notifs.json.lock` | `notify`, `watch`, `group` | the lock around writes to `notifs.json` (owner-only) |
| `notifs.json.unreadable-<stamp>` | any of them | a `notifs.json` that was not an object `rpl` can read, kept aside byte for byte |
| `nightly.json` | `notify --record` | `{ts, status, reason}`: the nightly job's last line |
| `apps-known.json` | `notify` | the containers announced as known (a name is added once its message is delivered) |
| `PAUSED` | `pause on` | its existence stops every apply; a switch that cannot be read counts as paused |
| `apply.lock` | `patch`, `group` | one `flock` held for the whole of an apply, rollback included |

### Notification keys

One message is sent per key (so a message is retried, never repeated): `group:<apply id>:ok`, `:rolled-back`, `:rollback-failed`; `group-unfinished:<apply id>`; `group-journal-unreadable:<stamp>`; `nightly-missing:never` or `:<timestamp>`; `nightly-failed:<timestamp>`; `patch:<service>:<timestamp>`; `excluded:<image>:<candidate>`; `new-app:<container>`; `error:<file>:<stamp>`. An event may be critical (an apply that never finished, a failed rollback, an unreadable state, a missing or failed nightly run, a patch that needs a human): critical events go first and the run's time budget never holds one.

## What it does not cover

- **Phase 2:** no API, no UI, no queue. The CLI, its exit codes and the state files are all there is.
- **No stable schema** for the state files, and no promise that a file written by one version is read by another: pin a tag, and read through the commands.
- **A private format** (another language's keys, another tool's files) is never read: the migration is done on the side of the program that drives `rpl`, to the formats above.
- **What it was tested with:** a model of Docker and of a registry, real files and sockets in temporary directories, and, on the author's host, supervised runs of the commands above (see `docs/results.md`). It was never tested against an external program that drives it, nor against a remote webhook or Telegram.
