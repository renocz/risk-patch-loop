# What was measured, and what was not

All numbers come from one homelab (one host, 65 containers, one owner), over the week of 25-31 October 2026. They are field numbers, not a benchmark.

## The scan, in numbers (31/10/2026)

- 65 running images scanned: **2,297** fixable HIGH/CRITICAL lines, **2,053** HIGH/CRITICAL lines with no fix, **32** lines in the CISA KEV list (27 after the scanner defect below was fixed).
- Severity alone does not help: 2,297 fixable lines is not a to-do list.

## The score, replayed against the owner's verdicts

The owner gave a verdict, "act" (A) or "defer" (R), on 20 real findings from two daily alerts (7 A, 13 R).

| Method | Agreement | A found | False A |
|---|---|---|---|
| Always answer "R" (the baseline) | 13/20 | 0/7 | 0/13 |
| An AI scoring service, given only service, package, severity and KEV flag (no exposure) | 7/20 | 7/7 | 13/13 |
| This score, without roles | 12/20 | 3/7 | 4/13 |
| This score, with roles (control plane, untrusted input) | 14/20 | 5/7 | 4/13 |

How to read it, honestly:
- 14/20 beats the "always R" baseline (13/20) by one. What the score adds is ranking: it finds 5 of 7 "act" cases with 4 false alarms, where the AI service said "act" to everything.
- **The roles were chosen after seeing these verdicts.** This is a replay, not an independent validation. The real test is the observation period, not this table.
- Twenty cases and one person's opinions are a small sample.

## The fix check

On 31/10, for 12 images with "act" rows, the registry was read and each candidate version scanned from the registry (nothing pulled into Docker):

- 7 images: a candidate removes **all** the "act" findings (paperless 3.3.4 -> 3.4.1, traefik v3.7.16 -> v3.7.17, five `latest` images of one maintainer);
- 2 images: the candidate removes none (a newer tag of one application, and a beta tag read again from the registry for another);
- 3 images: no newer version published at all. For these, updating changes nothing, and saying so is the point.

Applying "act" findings blindly (bump the tag) would have changed nothing for 5 of the 12 images.

## Updates done through the loop

paperless (with a database dump), traefik (all routes cut for a few seconds), radarr, sonarr, bazarr (same application version, rebuilt image). After each: container healthy, route answered with the expected status, and a local scan of the running image showed the exploited-in-the-wild finding gone. Outages: 5 to 40 seconds each.

**The automatic rollback has never fired in production.** Every update passed its check. It was exercised three times on purpose (2 November 2026) on a disposable service of the real Docker host, not on a real application. Each time `rpl patch` moved the service from an image that serves HTTP 200 to a broken one, the check failed, the old image came back (same image ID as before the update), the route answered 200 again, the compose file was restored, the journal recorded `rollback ok`, and the exit code was 2:

1. an image that runs but serves nothing (the route check fails);
2. an image that runs but never becomes healthy (its `HEALTHCHECK` fails; the check gave up after 25 s);
3. a `docker compose up` that fails because the new container cannot start (the container runtime reports an exec error).

Also seen: a first attempt was refused because the operator gave a wrong Compose project name (no container found for the service), and nothing was changed. Engine: Docker 29.9.2, Compose v5.0.0.

### Rollbacks on a real service (14 November 2026)

Roadmap criterion 1 asks for three automatic rollbacks on a real service. They were run with failures injected on purpose, on a small stateless web page of the same Docker host (no database, low traffic, nothing else touched), one failure at a time with the owner's agreement, a snapshot before each and `rpl patch` as published (commit 133e5b8). The route check targeted `/` of that service, which answers 404 by design (the page sits behind a secret path), so 404 was the expected status. Three test images were derived from the service's own image:

| Case | Injected failure | What `rpl patch` printed | Result |
|---|---|---|---|
| A | healthy container, every route except the health page answers 503 | `container healthy; route: HTTP 503 (expected 404)` then `CHECK FAILED: ROLLBACK` | `rollback ok`, exit 2, about 1 min 30 of outage |
| B | container that never becomes healthy | `container not healthy after 90 s` then `CHECK FAILED: ROLLBACK` | `rollback ok`, exit 2, about 2 min |
| C | `docker compose up` fails (entrypoint does not exist: runtime error `exec ... no such file or directory`) | `docker compose up failed` then `CHECK FAILED: ROLLBACK` | `rollback ok`, exit 2, about 1 min |

After each case: container healthy, original image back (same image ID as before the update), route 404, health page 200, compose file identical to the original, same number of containers (70). Test images and backup files were deleted afterwards.

A first attempt at case A **did not count**: the route check had been pointed at the health page, which the test image served with 200, so the update was (correctly) judged successful and the service ran the test image for about 35 seconds until it was put back by hand. The mistake was in the test setup, not in `rpl`: a route check only sees the route it is given.

What these three do not prove: a service with a database (the rollback restores the image, not the data), a real port conflict (case C is a start failure), a failure nobody provoked, or behaviour under heavy traffic. The criterion is met as written, with those limits.

What the 2 November tests did not prove: a real port conflict (case 3 is a start failure, another cause of a failing `up`), a rollback does not restore data, and a disposable service is not a real application. Roadmap criterion 1 (3 rollbacks on a real service) was met afterwards, see the section above. Treat the rollback as tested, not as proven.

## Defects the tool had, found by using it

1. The scan looked at images by **name**. An image pinned by digest leaves the old tag in the local store, so the scan kept reporting an exploited-in-the-wild finding on containers that were already fixed (32 lines became 27 once images were scanned by ID).
2. The pinning step named its backup to the minute: two pins in the same minute overwrote each other's backup. Timestamps now include seconds.
3. The first version of the "is this service really exposed" inventory printed the container port instead of the port published on the host, which would have led to closing the wrong ports.

## Defects found by writing integration tests (after 0.9.0)

Found by driving the code with fakes, then by a review of the pull request, not by using it in production. Each has a test that failed before the fix. None of them showed up in the first week.

1. `rpl patch` reported **OK** when `docker compose up` failed: the old container kept running, stayed healthy and answered, so the check passed. The compose file stayed pinned to an image that was not running. (Confirmed on real Docker, see below: the exit code is 1 and the old container is left untouched.)
2. A failing dry run did not stop the update. The container name was read as the second word of the dry-run line: correct on Compose v5.6.1 (no prefix), wrong under any prefix, hence hardened. (An earlier version of this page said the prefix "DRY-RUN MODE -" was a bug of the original code; on the Compose version checked here that prefix does not exist.)
3. Service, database and image names were not validated; a service missing from the Compose file failed late instead of being refused.
4. `rpl proposals --apply` ran whatever the stored file said, although the docs promised the exact computed proposal; a missing file ended in a traceback.
5. `fixcheck` ignored the registry's `Link: rel="next"` pagination and treated an empty tag list as "no newer version" (from the distribution spec; the real registries' behaviour at `n=10000` was not checked).
6. `examples/rpl.json`, named in the quick start, was never committed (`.gitignore` matched it).

Found by the pull request review, each confirmed by reading the code and fixed with a failing test first:

7. The dry run was accepted when it showed **zero** recognised recreations (unreadable output, another Compose format, nothing to recreate), and the name was never compared with the service's own container. It must now show exactly one recreation, of that container.
8. The pin replaced the one `image:` line equal to `--old` anywhere in the file, whichever service it belonged to; `service_defined` only checked that the service existed. With a variable image or an `--old` owned by another service, another service's line could be edited. The pin is now bound to the service (resolved image equals `--old`, line inside its block, `build:` refused).
9. The rollback's own `docker compose up` exit code was ignored and only health and route were checked: a failed rollback leaving the **new** image running, healthy and answering was journaled `rollback ok`. After an update and after a rollback the image that runs is now verified (reference and image ID). A failed rollback exits 4.
10. `--route` and `--codes` were not validated; and the name checks of defect 3 used `re.match` with `$`, which accepts a trailing newline (their test passed for the wrong reason).
11. A proposals file with a correct digest but a malformed content (no numeric `ts`, wrong types) raised a Python exception; a NaN or far-future timestamp defeated the 36 h expiry.

## Checked by hand against real Docker (2 November 2026, once, not in CI)

Environment: Docker Engine 29.9.2 and Docker Compose v5.6.1, a Docker daemon started inside the cloud sandbox for this purpose, a project of two `busybox:1.36` services running `sleep`, cleaned up afterwards.

- `docker compose up -d --no-deps --dry-run web` with a changed image: exit code 0, **everything on stderr, nothing on stdout**, lines of the form ` Container rpltest-web-1 Recreate`, ` ... Recreated`, then ` Container <id prefix>_rpltest-web-1 Starting` / `Started`. No "DRY-RUN MODE" prefix. The name is `<project>-<service>-1`, not the service name. The test fixture `REAL_DRY_RUN` is this output.
- `docker compose up -d --no-deps web` with an image tag that does not exist: **exit code 1**, and the existing container is **left untouched** (same container ID, still running, same image). This is the behaviour defect 1 relies on.
- `docker inspect` of a Compose container: `Config.Image` is the reference exactly as written in the compose file, digest included (`busybox@sha256:...`); `Image` is the image ID. `docker compose config --format json` resolves `${VAR:-default}` and shows `build` (and no `image`) for a locally built service.
- The new helpers `container_names`, `running_image`, `service_problem` and `service_block` gave the expected answers on that project (container `rpltest-web-1`; an `--old` that does not match, an unknown service and a `build:` service refused; two services sharing the same image line told apart).

**Not verified:** any other Docker or Compose version; real ghcr.io / Docker Hub pagination and tag lists; Trivy; PostgreSQL dumps; `compose up` failing in other ways than a missing image (port conflict, failing healthcheck); and the **automatic rollback on a real failure**, which was deliberately not exercised and is still unproven.

## Group apply (22 November 2026)

`rpl group` now applies a group (`rpl/groupapply.py`). What follows is what was run: first in a cloud sandbox, then once on the author's host on a disposable test group (last part of this section). **No real VPN group, and no real application, was ever updated or rolled back with it.**

Automated, with a model of Docker (`tests/fake_group.py`) and real files for the configuration directories and their backups:

- 65 tests in `tests/test_group_apply.py` and 3 in `tests/test_registry_integration.py` (the fix check recording the digest it scanned). Suite: 402, passing on Python 3.9.25, 3.12.3 and 3.13.18.
- The cases asked for: success (parent first, then every dependant, all attached to the new parent); failure at the parent; failure at the third dependant with a configuration the new version had rewritten (content, modes, symlink and removed files back); a restore that fails (exit 4, that member left stopped, backup kept); a tag, floating or not, whose digest moved since its fix was proven (refused), a digest that cannot be read and a proof without a digest (UNKNOWN, refused). Also: one row per policy, `confirmed`, the most restrictive service policy, an approval given before a tag moved, a dependant only Docker knows, a symlink leaving a configuration directory, a special file, the size cap, the pause switch and the lock, an interruption at two different moments followed by `--resume`, the purge, a v0.9 configuration without a `groups` key.
- These tests were written after the code, not before. To check that they can fail, 30 rules of `rpl/groupapply.py` were removed one at a time and the tests rerun: 29 removals fail at least one test (one, "all controls after the last recreation", was not covered at first; a test was added). The thirtieth removes one of two successive checks of the backup before a restore; the other still catches a damaged backup.

By hand, once, on real Docker (Engine 29.10.0, Compose v5.7.1, a daemon started in the sandbox; a project of `busybox` containers running `sleep`: a parent, two dependants with `network_mode: service:<parent>` and a configuration directory each, one unrelated service; removed afterwards). The proof side (fix check and registry digest) was supplied by a small driver script; everything Docker-related was the real code path, with the control `members_healthy` only:

- `--plan`: the three members, the two directories, the fingerprint, `PLAN READY`; `docker compose config --format json` reports a bind mount as `{"type": "bind", "source": <absolute path>, "target": ...}`, which is what the code reads.
- Apply without `--approve` under policy `ask`: refused. With the fingerprint: exit 0; the parent and one dependant ran `busybox:1.37@sha256:...`; the dependant without a new image was recreated on its own image; both dependants' `NetworkMode` named the ID of the NEW parent container; the backup directory was `drwx------`, the 0600 file and the symlink were kept.
- A provoked failure (a digest that does not exist, so the parent's `compose up` fails): `FAILED ... ROLLBACK`, `rollback ok`, exit 2; the three members ran their original images, the compose file was byte-identical to the original, the configuration read the same on the host and from inside the recreated dependant, the journal said `rollback ok`, and the next `--plan` was not blocked.

**What the fakes cannot prove, and what was not verified:** a real VPN container, a real tunnel, the controls `exit_differs` and `no_leak` against real addresses; an application that really migrates its configuration or an embedded database; a failure at a dependant, a failed restore, an interruption and `--resume` on real Docker (model only); images with a real `HEALTHCHECK`; a registry (the digest comparison ran against a local fake registry and dictionaries, not Docker Hub or ghcr.io); file ownership (the sandbox runs as root with root-owned files, so the `chown` path was never taken); large directories; a host where the runner is not root; the nightly run starting a group under policy `auto` (nothing calls `rpl group` on its own yet). The model does not pull images, has no volumes, no timing and no real health checks.

**First trial on a real host, and the defect it found (22 November 2026).** The owner ran `--plan` (read-only) on his host, Python 3.11, against a real group. It was refused: the plan required the container's reference to equal the text of the compose file, and the parent container had been created before the file was pinned by digest (`repo:tag` in the container, `repo:tag@sha256:...` in the file, the same image). A real group was therefore not applicable without recreating the parent first. The plan now compares image IDs: the image that runs must be the one the file's reference resolves to in the local store (`docker image inspect`); a reference missing from the local store cannot be compared and is refused. This is also stricter than before: the same text naming another image (a tag pulled again since the container was created) is now refused. 5 tests, all failing before the fix. Checked on sandbox Docker 29.10.0 (containerd image store): a container's `.Image`, `docker image inspect repo:tag`, `repo:tag@digest` and `repo@digest` gave the same ID, and an unknown digest exits 1. Not verified: the fixed `--plan` on the owner's host; the classic (non-containerd) image store. The same trial showed that the plan needs the scan, inventory and fix-check state of this tool on the host: without them it refuses (no proof, no patch), by design.

**The whole chain on a sandbox Docker, once (22 November 2026, second commit).** A trial group was built for the owner's supervised trial and run first in the sandbox (Engine 29.10.0, Compose v5.7.1): a parent and two dependants on an internal network without published ports, the parent and one dependant on `alpine:3.18.0`, the other on `busybox:1.36`. With the unmodified commands: `rpl scan` (narrowed to the trial project by a wrapper around `images_running`) found 9 fixable HIGH/CRITICAL rows; `rpl risk` gave 9 ACT rows; `rpl fixcheck` chose `3.24.4`, verdict COMPLETE, and recorded the digest read from Docker Hub; `rpl group --plan` pinned both members to that digest; an apply interrupted with SIGINT right after the backup left two members stopped, the next apply was refused, and `--resume` brought the three members back (`rollback ok`); a full apply then exited 0 with both dependants in the new parent's namespace, and a new scan showed 0 fixable rows. Two sandbox-only deviations: the CISA KEV feed was blocked by the environment and replaced by an empty list, and the Trivy container was given the sandbox's proxy. A finding of this run: a container without a published port or a route is "internal" (factor 0.2), so its score cannot exceed 22 and never reaches ACT; the trial declares an exposure with a Traefik label and a tunnel-hosts file. This supersedes two lines of the list above: the digest comparison has now run once against Docker Hub, and an interruption followed by `--resume` once on real Docker. A failure at a dependant and a failed restore remain model-only.

**Supervised trial on the author's host (22 November 2026).** Docker Engine 29.10.0, Compose 5.8.0, Python 3.11.2, image store fuse-overlayfs, code at commit 542599c. The same trial group (a parent and two dependants on an internal network, no published port, `alpine:3.18.0` and `busybox:1.36`, its own configuration, state and backup directories), run by the owner's local agent from a written procedure with the unmodified commands; the owner read each plan and gave its fingerprint.

- Scan with the real CISA KEV feed and Trivy without a proxy (the two things the sandbox could not do): `2 images: 0 KEV, 9 fixable HIGH/CRITICAL`, exit 0, not unreliable. `rpl risk`: 9 ACT rows. `rpl fixcheck`: `3.24.4`, COMPLETE, the same digest as in the sandbox.
- `--plan`: both `alpine` members pinned to that digest, `busybox` recreated only, two configuration directories, `PLAN READY`, nothing changed. Apply without `--approve`: refused, exit 1.
- Full apply: exit 0; both dependants' `NetworkMode` named the ID of the new parent container; backup directories `drwx------`; the configuration read the same from inside a dependant; the compose file had two images pinned by digest; the next scan showed 0 fixable rows and the next `--plan` answered "not an updater".
- Two applies killed with SIGTERM from a non-interactive script, on a fresh trial group. Run A, killed right after the `backup:` line: by the time the signal arrived the parent's image line was already pinned and the journal said `changing` (the intended "stopped at `backed-up`" was therefore not exercised on this host; it was in the sandbox). Run B, killed right after `parent: recreated`: parent on the new image, dependants stopped, two image lines pinned. In both: exit code 143, no `ABORTED` line (the process dies without running any cleanup), the next apply refused with "an earlier group apply never finished", `--resume` printed `rollback ok` and exited 0, and afterwards the three containers ran their original images, the compose file was the original, the configuration (content, mode 0600, symlink) was back and both dependants were in the current parent's namespace.
- A mistake in the procedure, not in the tool: the first interruption used SIGINT on a background job of a non-interactive shell, which ignores it (`SigIgn` showed SIGINT and SIGQUIT), so that apply simply completed. Reproduced in the sandbox, where the same two SIGTERM kills gave the results above, run A stopping at `backed-up`.

What this trial does not show: a real VPN group or a real application; a failure at a dependant; a failed restore; file ownership; policy `auto`. And two things it brought out: a process stopped by SIGTERM (a scheduler, `systemctl stop`) never prints `ABORTED`, so only the journal protects and nothing notifies an unfinished apply yet; and a group that is not exposed cannot be patched at all, because its score cannot reach ACT (an internal container tops out at 22 against a threshold of 45).

**A defect of the purge, found afterwards by reading the code (22 November 2026).** `rpl group --purge` protected the backup of an apply that never recorded a result, not the backup of a rollback that failed: seven days after a `CHECK BY HAND`, a purge would have deleted the only copy of the original configuration. Reproduced with the model (a rollback that fails, a backup aged 30 days, a purge: the directory was gone), fixed, and both backups are now kept until a human deletes them. Never seen on a host: no rollback has failed on one.

Gaps found in the earlier group code while doing this, left as they are: `rpl group --dry` looks the group up under the parent's **service** name, while `rpl patch`, `--plan` and the apply use its **container** name; `--dry` passes the containers to the controls in alphabetical order, so "the parent first" only holds when its name sorts first (the answer is the same while all members share one namespace); the control "a route answers with an expected status" is still missing from the closed list.

## A group that only Docker could see (22 November 2026)

Found by reading the code while verifying the group work, then reproduced. `rpl patch` decided group membership from its own compose file only; `groups.refusal` was called by nothing. A dependant declared in another compose project, or started with `docker run --network container:<parent>`, did not make `rpl patch` refuse the parent: it could have been recreated alone, cutting every dependant off its network namespace. `rpl proposals` listed running containers only, so a parent whose dependants were all stopped was not flagged.

Fix: `rpl patch` also inspects every container of the host (stopped ones included) and refuses with exit code 3 when the service's container is a parent or a dependant; when Docker cannot be listed, inspected or parsed, it refuses. `rpl proposals` detects groups over every container.

- 11 new tests (suite: 334, passing on Python 3.9.25, 3.12.3 and 3.13.18). Before the fix, 8 of the 9 `rpl patch` tests and 1 of the 2 `rpl proposals` tests failed; the two that passed are controls (an unrelated group elsewhere does not stop a patch; a stopped container is not listed as running). Three existing tests assert the exact command sequence and were updated for the two new read-only queries.
- Checked by hand, once, on real Docker (Engine 29.10.0, Compose v5.7.1, a daemon started in the cloud sandbox, `busybox:1.36` containers running `sleep`, removed afterwards), with `rpl patch --dry` on a parent service. On the parent commit (97c9e32): exit 0 while a `docker run --network container:<parent>` dependant existed. With the fix: exit 3 with a dependant from another compose project, exit 3 with that dependant stopped, exit 3 with a `docker run` dependant, exit 0 once the dependant was removed, exit 0 for an unrelated service of the same file. In all cases Docker reported the dependant's `HostConfig.NetworkMode` as `container:<full ID of the parent>`, including when the compose file named the parent.

**Not verified:** a real (non-dry) patch on that host; a host with many containers (one `docker inspect` receives every ID); another Docker version; Podman. A container removed between the listing and the inspection makes the inspection fail, which refuses the patch (read in the code and Docker's behaviour assumed, not provoked). A dependant attached by hand after the check and before the recreation is not seen: the lock only excludes other `rpl` runs.

## Pause switch and shared lock (22 November 2026)

Run in a cloud sandbox, not on the author's host: Linux 6.18, ext file system, no Docker involved.

- 39 new tests (`tests/test_gate.py`), suite of 323, all passing on Python 3.9.25, 3.12.3 and 3.13.18. Before `rpl patch` and `rpl proposals` were wired to the new module, 8 of the 39 failed (the 6 `rpl patch` ones, the paused `--apply`, the `pause` command).
- Two of the lock tests start a real second Python process: one holds the lock while the test is refused, one is killed with SIGKILL and the lock is free straight afterwards. The others take the lock twice inside one process, which `flock` also refuses.
- Each rule of `rpl/gate.py` was removed in turn and the tests rerun: 10 of 11 removals failed at least one test (no second switch check under the lock, no check that the lock file is still the one on disk, an unreadable switch or state directory read as "not paused", no `flock`, lock never released, reason printed raw, no first switch check, no refusal without `fcntl`, lock file mode). The eleventh (errors swallowed when removing the switch) changes nothing visible: `rpl pause off` reads the switch again and says `STILL PAUSED`.
- By hand, once, through the command line with two processes: `rpl pause on`, `status` (exit 1), `rpl patch` refused with exit 5 before any Docker command, `pause off`; then `rpl patch` refused with exit 5 while another process held the lock, naming its pid.

**Not verified:** two real updates competing on a real Docker host; a nightly job and a manual run colliding; NFS or any network file system; macOS or another Unix; Windows (no `fcntl`: the code refuses, only simulated by a test); runners under different user accounts (the lock file is created with mode 0600, so a second account is refused rather than admitted, by reading the code, not by a test). The test "a child process does not keep the lock" passes partly because Python closes inherited descriptors when it starts a process.

## Notifications: `rpl watch` and `rpl notify` (23 November 2026)

Two additions on top of `rpl/notify.py`: `rpl/watch.py` (a group apply that never recorded a result) and `rpl/events.py` (collects events and calls `notify.deliver`). Written test first: the tests were run against stubs returning nothing and failed on their assertions before any rule existed (`tests/test_watch.py`: 22 tests, 19 failing or erroring; `tests/test_events.py`: 35 tests, 26 failing), then the code was written.

- Suite: 471 tests (409 before; 4 of them keep `docs/trial/notify.md` valid), passing on Python 3.11.2, 3.12 and 3.13.18. Not run on 3.9 (not installed in the sandbox); the new files were only checked to parse with 3.9 syntax. CI runs 3.9 and 3.12.
- Mutation check, by hand: 15 rules of the two modules were removed one at a time (the open-entry test, the future-timestamp guard, the unreadable-journal paths, the exit codes, the baseline, the delivered-only memory, the window, the proven-fix filter, the catch-all around a source) and the tests rerun: 14 failed at first, the 15th (the catch-all that turns a crashing source into an error event) survived, a test was added, and all 15 now fail at least one test.
- One test writes an entry with the group apply's own `_record` and checks that `rpl watch` sees it open, then closed.

**What was not verified:** a real SIGTERM against a real group apply followed by `rpl watch` (the entry shape comes from `groupapply._record`, not from a killed process); delivery to a real Telegram or webhook; a real systemd timer or cron; a nightly job that calls `rpl notify --record`; the real size of the grace period (60 minutes is a guess, no apply duration was measured on a real host, and an apply that runs longer than the grace gives a false alarm); two `rpl watch` / `rpl notify` runs at the same instant (they share `notifs.json` without a lock); the container names of a real inventory on the first baseline.

**Found while writing it, not fixed:** `groupapply._journal` returns an empty list for a journal that is valid JSON but not a list, so the group apply would read it as "nothing unfinished"; `rpl watch` reports it as unreadable instead. The group apply was not touched.

### Supervised trial of `rpl watch` and `rpl notify` (23 November 2026)

Procedure `docs/trial/notify.md` at commit 4768ca6, run by the owner's local agent on the author's host (an LXC container, run as root; Docker 29.10.0, Compose 5.8.0, Python 3.11.2, systemd 252) on the disposable trial group. **The channel was a temporary HTTP receiver on the loopback interface (with `allow_private`), not a remote service: nothing went to Telegram or to a real webhook.** The code, the real `rpl.json`, the real state and the real nightly job were not touched.

- `rpl watch`: exit 0 and silent on a clean state. Two applies killed by SIGTERM, one right after `backup:` (journal state `backed-up`) and one after `parent: recreated` (state `changing`), both exit 143: `watch` at once gave exit 0 (grace of 1 minute, set for the test), at +70 s exit 1 with an `ALERT` line and one message, a second run exit 1 with no second message, the next apply was refused, `--resume` printed `rollback ok`, the three containers ran their original images again, and `watch` returned to exit 0. A journal holding `{"result": null}`: exit 2 and one message; restored: exit 0.
- Timer alone (two throw-away system units, every minute, nothing else running, no `rpl watch` by hand): a third kill at 17:19:22 UTC, the alert at 17:20:29, the message received 67 s after the kill, several later ticks printing `ALERT`, one message. No permission error reading the secret, as root.
- `rpl notify`: first run `baseline recorded: 78 containers`; a container added while the channel pointed to a name that does not resolve: `1 queued`, exit 1, `notifs.json` with `tries` 1 and `last_error` `webhook: the host name does not resolve`, no URL or token in it; channel restored: delivered once, then nothing; the removed container never reported.
- Nightly script copy under `set -e`: success writes `ok`, no message; `scan` replaced by `false` writes `failed` (the trap runs) and one message `The nightly run failed: nightly exited 1`; a record aged by 40 h gives one message `has not completed for 40 h`, none on the next run.
- Ten messages received in all; none carried the secret or a path of a home directory. A delivery took 2 ms on the loopback receiver, which says nothing about a remote service. No false alert and no duplicate alert.

**Defect found by this trial, in the group apply (not fixed in this change, a separate task is open):** the messages `rolled-back` and `rollback-failed` of `rpl group` are keyed on parent, plan fingerprint and outcome. After the first resume, the later resumes of the same plan sent nothing and printed `notification not delivered yet (queued, see notifs.json)`, although nothing was queued: `notify.deliver` leaves an already delivered key out of its lists, and `_tell` reads that as "not delivered". Read in the code afterwards: a second failed rollback of the same plan, including `CHECK BY HAND`, would be silent. `rpl watch` does not cover this case (the entry has a result by then).

**Where the procedure was wrong or silent, now corrected in `notify.md`:** `rpl notify` has no test option (step 0 gave one); the first `rpl notify` also reports a missing nightly run when no job records one; the group apply sends its own first `rolled back` message; a receiver on the same host needs `allow_private`; `systemctl --user` does not work as root in an LXC container (system units were used, written by the agent from the description, not from a model); a monitoring tool on the host also alerts on the killed containers.

**Not verified:** a remote webhook or Telegram (latency, quota, network failure, formatting); a timer under a non-root account and the secret read by another account; a user unit; a server restart with the timer active; a timer that stops; the duration of a normal apply (every apply of the trial was interrupted, so the grace of 60 minutes is still a guess); a nightly job that really runs from cron or a timer; two runs at the same instant.

### Second round of measures (23 November 2026, same host, main at d907e47)

Same host and tooling as the trial above (LXC container, root; Docker 29.10.0, Compose 5.8.0, Python 3.11.2, systemd 252), run by the owner's local agent.

- **Duration of a complete apply**, four times on fresh trial groups (3 members, configuration directories of 75 and 9 bytes): 3.50, 3.52, 3.56 and 3.68 s (median of the first three 3.52 s). For the fourth: backup at +2.2 s, parent recreated at +2.9 s, `dep-a` at +3.3 s, `dep-b` at +3.6 s. Seven `rpl watch` runs during the applies: all exit 0. **This says nothing about the 60-minute grace for a real group**: the trial group is tiny (no VPN, no data, no health check that waits). The grace stays a guess, confirmed by the owner, not measured on anything real.
- **Timer under a non-root account.** The journal written by an apply run as root is mode 0600 root: the non-root timer could not read it and `rpl watch` exited 2 with `journal cannot be read (PermissionError)` instead of reporting the unfinished apply, also after a resume, until the file's rights were changed by hand. With the journal made readable (an owner change within the second of the kill): kill 17:53:34, `ALERT` from the timer at 17:55:01, message received 86.6 s after the kill, three ticks printing `ALERT`, one message, the secret (0600, owned by that account) read without error; the `cannot be read` alert itself is not subject to the grace (a message at +51.7 s in another pass); the resume restored the original state. So the check failed loudly, not silently, but a timer under another account does not do its job unless the journal's rights are arranged. The procedure and the `rpl watch` message now say to run it as the account that runs `rpl group`. Not done: a shared group or an ACL (the journal holds the plan; its mode was left as the group apply writes it).
- **Channel failures, on a receiver on the loopback interface (allow_private) that the agent made fail on purpose; no remote webhook was provided, so latency and quota were not measured against a real service.** 5 deliveries: 2 ms each. A slow channel (5.0 s): delivered. HTTP 500, HTTP 429 (its `Retry-After: 30` is ignored), a send blocked until the 15.0 s timeout, a refused connection, a name that does not resolve: each time the message stayed queued, then was delivered once when the channel came back. A "New application" event: 83 characters on one line. A 900-character reason arrived cut to 324 characters with no visible mark.
- **Fixed after reading these (this change, tests first, both failing before):** a cut text now ends with an ellipsis (a reason longer than 300 characters was cut silently); the `PermissionError` message of `rpl watch` names the cause. 3 new tests (suite: 474, Python 3.11, 3.12 and 3.13).
- **Not fixed here, written down:** `Retry-After` is ignored; `max_attempts` counted runs, not time, so a timer that ran every minute gave up after about 20 minutes of channel outage (by reading `notify.deliver`, not run): the alert was still printed on every `rpl watch` run but no longer sent. The back-off by elapsed time that fixes this is in the next section; a channel that hangs still holds a run for 15 s per channel and per event (the timeout is not configurable).
- **Still not verified:** a real remote webhook or Telegram; a user unit; a restart of the server with the timer active; a timer that stops; a real group.
### Retry delay by elapsed time (23 November 2026)

Reading `notify.deliver` after the second round of measures: `max_attempts` counted runs, so a timer every minute would stop sending after about 20 minutes of channel outage (the alert stays printed on every `rpl watch` run). Fixed in `rpl/notify.py`: retry after 30 s, doubling up to 1 h, a waiting event is not a try. Tests first (the new ones failed before, 2 on an assertion and 6 on the missing constants), then the code; a sixty-run test with a one-minute timer checks that nothing is given up and that fewer than 20 sends happen. Suite 480, passing on Python 3.11, 3.12 and 3.13. By hand, 7 removals of the new rules (the gate, the future-time guard, the doubling, the ceiling, the cleanup of `next_try`, counting a held event as a try, the stored `next_try`) each fail at least one test.

**Not verified:** a real timer or a real channel outage (the delay is tested with an injected clock only); that 13 hours is the right span (the 20 tries over about 13 hours come from arithmetic on the constants); `Retry-After` (still ignored: the delay does not read it, the headers are not returned by `notify.post`); a channel that hangs (15 s per channel and per event, not configurable); two runs at the same instant.

## What was not measured

- No false-negative rate: nothing shows the score never ranks a dangerous finding low.
- No second host, no other reverse proxy than Traefik, no other registry than Docker Hub and ghcr.io.
- Healthy-but-broken updates: the check proves the container answers, not that the application works.
- The tests use fakes for Docker, Compose, Trivy and the registry. The rollback is proven against a fake host, not on a real failure; parsing of real Compose and registry output is only as good as the fakes' fidelity.
