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

**The automatic rollback has never fired in production.** Every update passed its check. The rollback path is covered by code review and by the dry run, not by a real failure. Treat it as unproven until it has been exercised.

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

## What was not measured

- No false-negative rate: nothing shows the score never ranks a dangerous finding low.
- No second host, no other reverse proxy than Traefik, no other registry than Docker Hub and ghcr.io.
- Healthy-but-broken updates: the check proves the container answers, not that the application works.
- The tests use fakes for Docker, Compose, Trivy and the registry. The rollback is proven against a fake host, not on a real failure; parsing of real Compose and registry output is only as good as the fakes' fidelity.
