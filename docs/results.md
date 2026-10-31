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

## What was not measured

- No false-negative rate: nothing shows the score never ranks a dangerous finding low.
- No second host, no other reverse proxy than Traefik, no other registry than Docker Hub and ghcr.io.
- Healthy-but-broken updates: the check proves the container answers, not that the application works.
