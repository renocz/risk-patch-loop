# Changelog

## Unreleased

### Notifications: what the second round of measures changed
- A text cut to fit a notification (a nightly failure reason over 300 characters) now ends with an ellipsis; it was cut silently. `rpl watch` names the cause of a `PermissionError` (the group journal is mode 0600: run it as the account that runs `rpl group`). `docs/trial/notify.md` says so. 3 new tests, failing before (suite: 474, Python 3.11, 3.12, 3.13).
- Measured, not changed: a complete apply of the trial group takes 3.5 to 3.7 s (4 runs, tiny group, says nothing about a real one). Written as limits: `Retry-After` ignored, `max_attempts` counts runs not time (a minute timer gives up sending after about 20 minutes), a hanging channel holds a run 15 s. See `docs/results.md`.

### Notifications, step 5 of the v0.10 plan
- `rpl watch` (`rpl/watch.py`): reports every entry of `group-journal.json` that has no result, a group apply that never finished (a process stopped by SIGTERM prints nothing). It reads that file only: no dependency on the nightly job, on `rpl notify`, on Docker or on any other state file. Exit 0 clean, 1 unfinished, 2 journal unreadable (a journal that is not a list of objects counts as unreadable, never as clean). The alert is always printed, and delivered through `rpl/notify.py` when channels are configured, one message per journal entry. An entry younger than `group_unfinished_grace_minutes` (60) is taken for an apply in progress; a start time that is missing, not a number or in the future is reported.
- `rpl notify` (`rpl/events.py`): collects events from the other modules' state files and hands them to `notify.deliver`: nightly run missing or failed, patch results (last 72 h), an image excluded from proposals although a fix is proven, a new application, an unreadable or malformed state file (an error event, never silence). Events are recomputed on every run so a failed delivery is retried; only new applications are remembered (`apps-known.json`), after delivery. `rpl notify --record ok|failed [--reason TEXT]` is the nightly job's last line (`nightly.json`). New settings: `group_unfinished_grace_minutes`, `nightly_max_hours`, `events_window_hours`.
- Not done, written in README "Known limits" and `docs/results.md`: nothing has run from a real timer or against a real channel; a first run announces no existing application; a nightly job that does not call `--record` reads as missing; no lock around `notifs.json`; accepted findings (`accepted.json`) are not reported as exclusions; a per-channel memory is still missing. 58 new tests, written before the code (suite: 467, Python 3.11, 3.12 and 3.13; 3.9 not run, CI will).
- Not changed: the score, the group apply. Noticed, not fixed (separate tasks): `groupapply._journal` reads a journal that is valid JSON but not a list as empty; the group apply's `rolled-back` and `rollback-failed` messages are keyed on the plan fingerprint, so a second failure of the same plan sends nothing (found by the supervised trial).

- `docs/trial/notify.md`: the procedure for a supervised trial of `rpl watch` and `rpl notify` (real webhook, real SIGTERM, a timer alone, a channel cut during an event, the nightly script under `set -e`), revised after a second opinion. Run once on 23 November 2026 with a loopback receiver (`docs/results.md`), and corrected from what that run found; 4 tests keep its options and its nightly script valid (suite: 471, Python 3.11, 3.12, 3.13).

### Earlier in this release

Integration tests for the parts 0.9.0 left untested, the defects they exposed, and repository hygiene.

### Groups
- `rpl/groups.py`: update groups (containers sharing a network namespace) detected from `network_mode`, with a validated `groups` config (policy `auto`/`ask`/`never`, mandatory reason for `ask` and `never`, `confirmed`); a group that is undeclared, invalid or nested is reported as blocked.
- `rpl patch` and `rpl proposals` refuse every member of such a group whatever its name (a dependant under an ordinary name was not refused before); "gluetun" stays refused as a safety net. Exit code 3 now means "update group".
- Not done: patching a whole group, and enforcing the policy; every member is refused regardless of policy. 23 new tests (suite: 248, run on Python 3.9.6 only, 3.12 left to CI).

### Group controls and rehearsal
- `rpl/controls.py`: a closed list of read-only controls (`members_healthy`, `exit_differs`, `no_leak`) chosen by name in the `groups` config; an unknown name is an error, the config never supplies a command, and addresses are compared but never printed. Only `probe_url` and `probe_image` are settings.
- `rpl group --compose F --parent P --dry`: group order (parent first), the batch a forced recreation would touch (must be exactly the group), the configured controls. Exit 0 ready, 1 refused or not ready, 2 a control failed or could not tell. Without `--dry` it refuses: applying a group does not exist.
- Not done: backup and restore proof, controls after an update. 16 new tests (suite: 264, Python 3.9.6 only), all with a scripted host.

### Notifications
- `rpl/notify.py`: channels from the config (`telegram`, `webhook`); an event counts as delivered only when every channel answered 2xx, otherwise it stays queued and is retried up to `max_attempts` (state in `notifs.json`: tries, last error); one message per event key.
- Secrets come from files named in the config, refused unless only the owner can read them, and never reach the state file or an error message. The webhook resolves the host once, refuses private, loopback and link-local addresses unless `allow_private`, connects to the address it checked and does not follow redirects.
- `notify.missing_run` builds the "nightly run missing" event for a timer independent of the nightly job.
- Not done: a CLI command that collects events from the other modules (only the library exists), per-channel delivery memory (a partial failure resends to both channels), delivery to a real Telegram or webhook (tested with doubles and a local 127.0.0.1 server only). 20 new tests (suite: 284, Python 3.9.6 only).

### Pause switch and shared lock
- `rpl/gate.py`: `rpl pause on [--reason TEXT] | off | status` sets a file-based switch in the state directory (`PAUSED`; `touch` works too). While it is set, `rpl patch` and `rpl proposals --apply` apply nothing and exit with the new code 5 ("not now, nothing touched"); a switch that cannot be read counts as paused. Dry runs and read-only commands are not affected.
- One shared lock (`apply.lock`, a non-blocking `flock`): `rpl patch` holds it from before its first check, the group refusal included, until the end, rollback included. A second run is refused at once with code 5 and the holder's pid; it does not wait. A killed process leaves no stale lock. Without `flock` (not a Unix system) nothing is applied.
- Not done: `rpl group` has no apply yet, so it does not use the lock; group detection under the lock belongs to the group apply. Limits: per state directory, not an access control, a run that already started is not interrupted, tested on Linux on a local file system only (see `docs/results.md`). 39 new tests (suite: 323, run on Python 3.9.25, 3.12.3 and 3.13.18 on 22 November 2026).
- README: the test count in "Status" said 225 while the suite had 284 since the previous change; it now says 323.

### Fixed: purge and failed rollbacks
- `rpl group --purge` deleted, once older than the retention, the backup of a group whose rollback had FAILED (`CHECK BY HAND`): the only copy of the original configuration. Only the backup of an apply with no result at all was protected. Both are now kept whatever their age and named in the output; a human deletes them. Found by reading the code, reproduced by a test that failed before the fix. 2 new tests (suite: 409, run on Python 3.9.25, 3.12.3 and 3.13.18 on 22 November 2026). Not verified on a real host.

### Trial kit
- `docs/trial/`: the script and the step-by-step procedure used for the supervised trial of `rpl group` on a disposable test group (22 November 2026), with the interruption done by SIGTERM at two moments, as it was replayed. It narrows the scan to the trial project and supplies no result. 5 tests keep it in step with the command (suite: 407, run on Python 3.9.25, 3.12.3 and 3.13.18); they do not run Docker, so the procedure itself is only as current as its last run by hand.

### Group apply
- `rpl group --compose F --parent P` now applies a group (`rpl/groupapply.py`), only when a member has a proven security fix pending: plan from the compose file and from Docker (the two must name the same members), policy, rehearsal, controls, snapshot, journal entry, members stopped (`quiesce: stop`, default for a member that mounts a configuration directory), backup of the configuration directories under the compose file's directory (owner-only, modes, owners and symlinks kept, re-read), new images pinned by digest, parent recreated then every dependant, controls; on failure, per-member restore and recreation in order, verified (exit 2), or `CHECK BY HAND` (exit 4).
- Policies, now enforced: `auto` (nightly run, no human), `ask` (a human passes `--approve <fingerprint>`), `never`; `auto` and `ask` need `confirmed: true`; per-service `policy` and `quiesce` under `services`; the most restrictive policy wins. The group is declared under the parent's container name.
- `--plan` prints the plan and its fingerprint and proves that every configuration directory copies and reads back, without changing anything. `--resume` rolls back an interrupted apply; until then every group apply is refused. `--purge` deletes group backups older than `group_backup_retention_days` (7). New settings: `group_backup_retention_days`, `group_backup_max_mb`.
- `rpl fixcheck` records `candidate_digest`, the digest of the candidate it scanned (identical before and after the scan, otherwise null). The group apply refuses a fix whose digest is missing, cannot be read from the registry, or differs from the one the registry serves now.
- Fixed before merge, found by the owner's first `--plan` on a real host: the plan compared the container's reference with the text of the compose file, so a container created before its file was pinned by digest made the group inapplicable. It now compares image IDs (the running image against what the file's reference resolves to locally), which also refuses the same text naming another image; a reference missing from the local store is refused.
- A batch that cannot be restored is refused before anything changes: symlink leaving a configuration directory, special file, files of another owner when not root, more than `group_backup_max_mb`.
- Decision 4 of the plan (group state recomputed after 6 hours, distrusted after 3 days) is not implemented: no state file exists, the group is read from Docker on every call.
- Supervised trial on the author's host, on a disposable test group (22 November 2026, `docs/results.md`): the whole chain from scan to apply, exit 0, dependants in the new parent's namespace; two applies killed with SIGTERM, each refused afterwards until `--resume` rolled it back. A killed process prints no `ABORTED` line: only the journal protects, and nothing notifies an unfinished apply yet.
- Not done, and limits: never run on a real VPN group or on a real application; a group that is not exposed almost never scores ACT, so it is almost never patched; named volumes, bind mounts outside the compose directory and databases in other containers are not backed up; a group over several compose files is refused; nothing starts a group apply on its own (policy `auto` is honoured when a scheduler calls the command); `rpl patch` and `rpl proposals` still do not bind a versioned tag to a digest; `rpl group --dry` is unchanged. 68 new tests (suite: 402, run on Python 3.9.25, 3.12.3 and 3.13.18 on 22 November 2026), 63 of them written after the code and checked by removing 30 rules one at a time (29 caught). One success and one provoked failure on a sandbox Docker 29.10.0 (`docs/results.md`).

### Groups seen only by Docker
- Fixed: `rpl patch` decided group membership from its own compose file only, so a dependant of another compose project, or one started with `docker run --network container:<parent>`, did not stop the parent from being patched alone. It now also inspects every container of the host, stopped ones included, under the shared lock, and refuses (exit code 3, with the configured policy and reason); when Docker cannot be listed, inspected or parsed, it refuses. Reproduced on real Docker 29.10.0 before and after the fix (`docs/results.md`).
- Fixed: `rpl proposals` detected groups among running containers only; a parent whose dependants were all stopped was not flagged. Groups are now detected over every container; only running ones are proposed.
- Unchanged: every member of a group is refused whatever its policy, and `confirmed` is not enforced. 11 new tests (suite: 334, run on Python 3.9.25, 3.12.3 and 3.13.18 on 22 November 2026); 9 of them failed before the fix.

### Results
- Roadmap criterion 1 met on 14 November 2026: three automatic rollbacks (route at an unexpected status, container never healthy, `docker compose up` failing) on a real service of the author's host, failures injected on purpose, each `rollback ok` with the original image back. A first attempt at the route case did not count (test setup error, written up in `docs/results.md`). Limits: a stateless service, no database, no failure nobody provoked.

### Measurement
- `rpl sample draw --single-host`: a draw from one host is accepted only when said out loud; the manifest records `hosts` and `single_host`, a warning is printed, and the published rate must say it describes that host (owner decision of 14 November 2026). Two hosts remain the default requirement. Reviewers may be a person or a panel of models counted as one reviewer, published as "1 human + 1 model panel".

### Roadmap
- 1.0 now requires two things: rollbacks exercised on a real service (done) and a false-negative rate measured on one host with the author and a model panel as reviewers, published as it comes out (target at most 10% of "act" missed, no minimum sample size, limits written). The independent second host, a human second reviewer and another reverse proxy move to after 1.0, by the owner's decision of 14 November 2026.

### Tests
- Fingerprint test (council 11/11): the pinned reference and the SHA-256 of the proposals file are the same from computation to `--list` to `--apply`, neither step rewrites the file, and a digest changed after review is refused.
- 144 tests added (54 -> 198), standard library only, doubles only: a fake registry on a free local port, a fake Docker host injected into `rpl patch`, mocked Trivy/Docker for `rpl scan`. `tests/__init__.py` fails any test that touches a host other than 127.0.0.1.
- Registry reading: newer tag found, no newer tag, unreadable registry (500, 401, 404, not JSON, no token, unreachable) is UNKNOWN, never a verdict.
- `rpl patch`: the full sequence (snapshot, dump, pin, dry run, recreate, check) and the automatic rollback (unhealthy container, bad route status, rollback that itself fails): compose file restored byte for byte, old image running, result journaled.
- Refusals: VPN containers, invalid names, missing, stale or modified proposals.
- `rpl scan` never reports a reliable scan when Trivy, Docker, the KEV list or the vulnerability database failed, and leaves `findings.json` alone.

### Fixed
- `rpl patch` no longer reports OK when `docker compose up` fails (the old container kept running and passed the check).
- `rpl patch`: a failing dry run stops the update; container names in the dry-run output are parsed whatever the prefix; service, database and image names are validated; a service missing from the Compose file is refused.
- `rpl proposals`: `--list` and `--apply` refuse a proposals file modified after it was computed (SHA-256, integrity not authentication) and refuse cleanly when it is missing or unreadable. Files written by 0.9.0 are refused (compute again).
- `rpl fixcheck`: tag lists are read across pages, an empty list is UNKNOWN instead of "no newer version", and `registry_detail` says what failed.
- `examples/rpl.json` is now in the repository.

### Fixed after the final council review of the merged code
- `rpl patch`: an unexpected error or an interruption (Ctrl-C) after the pin restores the compose file, prints `ABORTED ... CHECK BY HAND` and journals `aborted: CHECK BY HAND`.
- `rpl patch` refuses, before any change, a service that has no running container: a rollback could not be proven to restore it.
- `rpl patch`: the resolved image of every other service must be unchanged by the pin (a shared YAML anchor would change another service's image too); otherwise the old file is restored.
- A route check whose `curl` exited non-zero is not an answer, even if it printed an accepted status.

### Fixed after review
- `rpl patch`: the dry run must show exactly one recreation, of the service's own container (zero, two, another service or unreadable output are refused and the compose file is restored).
- `rpl patch`: the pin is bound to the requested service (Compose must resolve its image to `--old`, the edited line must lie in its block, `build:` services are refused).
- `rpl patch`: the image that runs is verified after the update and after the rollback (reference and image ID); the rollback's `compose up` exit code is no longer ignored. **Exit codes:** a rollback that cannot be verified now exits 4 and is journaled `rollback FAILED: CHECK BY HAND`; 2 means a verified rollback. Scripts that treated 2 as "check by hand" should also handle 4.
- `rpl patch`: `--route` and `--codes` are validated; names and image references are matched with `fullmatch` (a trailing newline was accepted).
- `rpl proposals`: the shape of the proposals file is validated (types, finite and not-future timestamp); `--apply` without a name is a refusal.

### Documentation (council review of 11/11/2026, summary of the README only)
- The score is now described as **not validated** (14/20 against 13/20 for the trivial answer shows no added value); precision and false negatives are unmeasured.
- Known limits added: the Docker socket is root-equivalent (protect `--apply`), data migrations and restores are not covered, VPN handling is a refusal by name and not a protection.
- Roadmap to 1.0 made stricter: "independent" second host defined (a different owner, not just a new proxy), rollbacks must happen on a real service, at least 30 "act" verdicts, precision and confusion matrix published, a new test set.

### Documentation
- Behaviour of real Docker 29.9.2 / Compose v5.6.1 checked by hand and written in `docs/results.md`; "Known limits" now say that images are not signature-verified.
- `SECURITY.md`, `CONTRIBUTING.md`, issue templates (bug, proposal) and a pull request template.
- README (English and French): "Known limits" and "Roadmap to 1.0" with measurable criteria.
- `docs/results.md`: the defects above and what the fakes cannot prove.

## 0.9.0 (2026-11-02)

First public cut of a tool used for one week on one host.

- `rpl scan`: Trivy on running images (by image ID) + CISA KEV; a scan that cannot do its job is never "OK".
- `rpl inventory`: real exposure per container from `docker inspect` and Traefik labels; Internet exposure is "unknown" until host names are provided.
- `rpl risk`: readable score (severity + KEV + sensitive access + role) x exposure factor, with a replay against the owner's verdicts.
- `rpl fixcheck`: registry read and remote scan of the candidate version; verdicts COMPLETE / PARTIAL / NONE / no newer version.
- `rpl proposals`: updates ready to approve; `--apply` runs the stored proposal only.
- `rpl patch`: snapshot, database dump, pin, dry run, recreate, check, automatic rollback; refuses VPN containers.
- 54 unit tests; the registry and Docker parts are not covered by tests.
