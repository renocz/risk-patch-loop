# A supervised trial of `rpl group` on a disposable test group

`setup-trial-group.sh` builds a small update group that the real commands can patch, so that you can watch `rpl group` work on your own host before trusting it with a group that matters. Nothing here supplies a result: the scan, the score, the fix check and the digest are the tool's own.

This sequence was run on 22 November 2026 in a sandbox (Docker 29.10.0, Compose v5.7.1) and on the author's host (Docker 29.10.0, Compose 5.8.0, Python 3.11.2); see [docs/results.md](../results.md). At each step, "Expect" is what was seen then. If you see something else, stop and keep the output.

The procedure for trying `rpl watch` and `rpl notify` on the same group, with a real webhook and a timer, is in [notify.md](notify.md); it was run once on 23 November 2026, with a local receiver (see docs/results.md).

## What the script builds

- A compose project `rpltrial`: `parent`, `dep-a` and `dep-b`, the last two with `network_mode: service:parent`, on a Docker network marked `internal`, with no published port.
- `parent` and `dep-a` on `alpine:3.18.0` (9 fixable HIGH/CRITICAL findings on 22 November 2026); `dep-b` on `busybox:1.36` (no finding reported: it is only recreated).
- A configuration directory for `dep-a` (a 0600 file, a sub-directory, a symlink) and one for `dep-b`.
- Its own `rpl.json`, state directory, backup directory and Trivy cache, all inside the trial directory. An existing rpl setup is neither read nor written.

## Three things to know before you start

1. **A Traefik label on `parent`.** Without it the trial is impossible: a container with no published port and no route is "internal" (factor 0.2) and cannot score above 22, under the ACT threshold of 45, so the plan would answer "not an updater". The label declares a route `rpl-trial.example.test`, listed in the trial's own `tunnel-hosts.json`. No port is published and the network stays internal. If a Traefik with the Docker provider runs on the host it may log this router; it cannot reach the container.
2. **Two roles declared** for `parent` and `dep-a` in the trial's `roles.json`, so that a fixable HIGH finding reaches 50.
3. **The scan is narrowed by a six-line wrapper** (`scan-trial-only.py`, written by the script), because `rpl scan` has no filter: it reduces the list of images to the `rpltrial` project. It supplies no finding and skips no check.

Two more: the trial has its own state directory, so the pause switch and the shared lock of another rpl setup on the host do not apply to it; and `rpl inventory` lists every container of the host, read-only, into the trial's state directory.

## Step 0. Build the group

```bash
bash docs/trial/setup-trial-group.sh /path/to/a/new/empty/directory /path/to/this/checkout
```

```bash
source /path/to/a/new/empty/directory/env.sh
```

`env.sh` sets `RPL_CONFIG`, `PYTHONPATH`, `F` (the compose file), `T` (the trial directory) and a shell function `rpl`. Source it in every shell you use.

Expect `trial group ready in ...`. Then:

```bash
docker ps --filter label=com.docker.compose.project=rpltrial --format '{{.Names}} {{.Image}} {{.Ports}}'
```

Expect three lines and an empty ports column.

```bash
docker network inspect rpltrial_isolated -f 'internal={{.Internal}}'
```

Expect `internal=true`.

## Step 1. Scan, inventory, score

```bash
python3 "$T/scan-trial-only.py"
```

Expect `2 images: 0 KEV, N fixable HIGH/CRITICAL, ...` with N above 0, no `UNRELIABLE`, exit code 0. The first run downloads the Trivy database. With `UNRELIABLE` (database missing, KEV list unreachable) nothing is written and the rest will refuse: that is intended, fix the cause.

```bash
rpl inventory
```

Expect a summary line with `internet-no-auth` at 3 or more.

```bash
rpl risk
```

Expect `ACT N · PLAN 0 · WATCH 0 (rows)` and a line `ACT 65 · alpine:3.18.0: ... · internet-no-auth`.

## Step 2. The fix proof

```bash
rpl fixcheck
```

Expect one JSON line for `alpine:3.18.0` with `"verdict": "COMPLETE"`, a `"candidate"` (the newest `3.x.y` published; `3.24.4` on 22 November 2026) and a non-null `"candidate_digest"`.

`PARTIAL` means today's candidate keeps one of the findings: the trial stops here, and that is information, not a failure. A null `candidate_digest` means the digest could not be read twice identically: run it again.

## Step 3. The plan (changes nothing)

```bash
rpl group --compose "$F" --parent parent --plan
```

Expect:

- `group rpltrial-parent-1: policy ask (supervised trial group), confirmed`;
- `parent` and `dep-a`: `alpine:3.18.0  ->  alpine:<candidate>@sha256:...`, the digest of step 2;
- `dep-b: busybox:1.36  (no new image: recreated only)`;
- `dep-a` and `dep-b` with `quiesce stop` and their backup directory, `parent` with `quiesce none`;
- `backup proof: 2 item(s) ...`;
- `fingerprint: ................` then `PLAN READY, nothing changed`.

Check that nothing moved: the same `docker ps` as in step 0 shows containers that were not recreated, and `ls "$T/backups"` is empty.

Read the plan yourself before going on. Under policy `ask` the fingerprint is the approval of a human who read this output; if an agent runs the trial for you, have it stop here and give it the fingerprint yourself.

## Step 4. Refused without approval

```bash
rpl group --compose "$F" --parent parent --no-snapshot
```

Expect `REFUSED: policy ask (supervised trial group): a human must approve THIS plan: --approve <fingerprint>`, exit code 1, nothing changed.

## Step 5. Two applies killed, each followed by `--resume`

The apply is killed with SIGTERM, which is what a scheduler or `systemctl stop` sends, and the hardest case: the process dies without running a line of cleanup. Do not use SIGINT from a script: a background job of a non-interactive shell ignores it and the apply simply completes (this happened in the first trial).

Note the IDs first:

```bash
for c in parent dep-a dep-b; do echo "$c $(docker inspect -f '{{.Id}} {{.HostConfig.NetworkMode}}' rpltrial-$c-1 | cut -c1-90)"; done
```

### Run A: killed right after the backup

Replace FINGERPRINT with the one of step 3:

```bash
python3 -u -m rpl group --compose "$F" --parent parent --no-snapshot --approve FINGERPRINT > "$T/run-A.log" 2>&1 & PID=$!
for i in $(seq 1 300); do grep -q "^backup:" "$T/run-A.log" && break; sleep 0.1; done; kill -TERM $PID; wait $PID; echo "exit code $?"
```

Expect exit code 143 and **no** line starting with `ABORTED` in the log (the process is killed outright). Then:

```bash
docker ps -a --filter label=com.docker.compose.project=rpltrial --format '{{.Names}} {{.Image}} {{.State}}'; grep image: "$F"
```

Expect `dep-a` and `dep-b` exited and `parent` running. Depending on when the signal lands, the compose file is either unchanged (the journal then says `backed-up`) or has its first `image:` line already pinned (the journal says `changing`). Both were seen; both are fine.

```bash
rpl group --compose "$F" --parent parent --no-snapshot --approve FINGERPRINT
```

Expect `REFUSED: an earlier group apply never finished: run ... --resume first`.

```bash
rpl group --compose "$F" --parent parent --resume
```

Expect `unfinished apply of group rpltrial-parent-1 (stopped at '...'): rolling back`, then `rollback ok: every member runs its original image again, configuration restored, controls passed`, exit code 0. Then check:

```bash
docker ps -a --filter label=com.docker.compose.project=rpltrial --format '{{.Names}} {{.Image}} {{.State}}'; grep image: "$F"; cat "$T/proj/dep-a/config/settings.json"; stat -c %a "$T/proj/dep-a/config/secret.key"; readlink "$T/proj/dep-a/config/current.json"
```

Expect three containers running on `alpine:3.18.0`, `alpine:3.18.0`, `busybox:1.36`; the three original `image:` lines; `{"version": 1}`, `600`, `settings.json`. The `NetworkMode` of both dependants (the loop above) names the current `parent`.

### Run B: killed right after the parent was recreated

Take the plan again (step 3): the fingerprint must be the same as for run A. Then:

```bash
python3 -u -m rpl group --compose "$F" --parent parent --no-snapshot --approve FINGERPRINT > "$T/run-B.log" 2>&1 & PID=$!
for i in $(seq 1 600); do grep -q "^parent: recreated" "$T/run-B.log" && break; sleep 0.1; done; kill -TERM $PID; wait $PID; echo "exit code $?"
```

Expect exit code 143; `parent` running on the new image, `dep-a` and `dep-b` exited; the compose file pinned by digest for `parent` and `dep-a`. Then the same refused apply, the same `--resume` (it says `stopped at 'changing'`) and the same checks as in run A.

If a kill lands too late and the apply ends with `OK`, you have done step 6: to replay the kill, tear down (step 8) and start again from step 0.

## Step 6. The full apply

Take the plan again; the fingerprint is still the same. Then:

```bash
rpl group --compose "$F" --parent parent --no-snapshot --approve FINGERPRINT
```

Expect, in this order: `backup: .../backups/group-rpltrial-parent-1-<date> (2 item(s), owner-only; ...)`; `parent: recreated, healthy, runs alpine:<candidate>@sha256:...`; the same for `dep-a`; `dep-b: recreated, healthy, runs busybox:1.36`; `OK`; exit code 0.

## Step 7. Checks after the apply

```bash
for c in parent dep-a dep-b; do echo "$c $(docker inspect -f '{{.Id}} {{.HostConfig.NetworkMode}}' rpltrial-$c-1 | cut -c1-90)"; done
```

The `NetworkMode` of `dep-a` and `dep-b` is `container:` followed by the ID of the **new** `parent`. This is the central point: a dependant that is not recreated stays attached to the old network namespace.

```bash
ls -ld "$T"/backups/group-*; docker exec rpltrial-dep-a-1 cat /config/settings.json; grep image: "$F"
```

Expect directories in `drwx------`; `{"version": 1}` read from inside the container; two `image:` lines pinned by digest and `busybox:1.36` unchanged.

```bash
python3 "$T/scan-trial-only.py"; rpl group --compose "$F" --parent parent --plan
```

Expect `0 fixable HIGH/CRITICAL`, then `NOT READY: no member of this group has a proven security fix pending: nothing to apply (rpl is not an updater)`.

## Step 8. Tear down

```bash
docker compose -f "$F" down
```

```bash
rm -rf "$T"
```

The directory holds the backups (a pretend secret here; keep the habit). The `alpine` and `busybox` images stay in the local store.

## What this trial does not show

- A real VPN: no tunnel, hence no `exit_differs` or `no_leak` control (the group uses `members_healthy` only).
- An application that really changes its configuration or an embedded database: the containers run `sleep`.
- A failure at a dependant and a failed restore: only a killed apply followed by `--resume`, and a success, are played here.
- Policy `auto` started by a scheduler.
- File ownership, when the trial runs as root on root-owned files.
- Anything about tomorrow: the candidate and the number of findings depend on the day you run it.
