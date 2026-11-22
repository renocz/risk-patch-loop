# Changelog

## Unreleased

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
