# A supervised trial of `rpl watch` and `rpl notify` on a real host

Run once on 23 November 2026 (results in [docs/results.md](../results.md)); the procedure below is the corrected one, with the gaps that run found. Run it on the disposable trial group of [README.md](README.md) (Step 0 to Step 2 done, the `rpl` function from `env.sh` sourced), with a real webhook. Keep every output; when something differs from "Expect", stop. Results go to `docs/results.md` with date and versions, and no secret.

Rules for the run: use the trial's own state directory (`$T/state`), never your real one; do not paste the webhook URL or its secret anywhere in the results; the PR stays a draft until this is done and written up.

## 0. Channel and settings

1. A webhook endpoint you control. Its secret goes in a file readable by its owner only (`chmod 600`), and that owner is the account that will run the timer in step 5.
2. In the trial's `rpl.json` add (the URL and the file are yours):

```json
"notifications": {"channels": [{"type": "webhook", "url": "https://YOUR-HOOK", "secret_file": "/path/to/secret"}]},
"group_unfinished_grace_minutes": 1
```

3. Measure first the latency of one delivery to your endpoint, and the quota, if any. `rpl notify` has no test option: send one message by calling `python3 -c 'from rpl import notify, config; print(notify.deliver([{"key": "trial-test", "text": "rpl trial test"}], config.load()))'` (with `RPL_CONFIG` set). A slow or rate-limited channel looks like a failure.
4. A receiver on the same host is refused unless the channel has `"allow_private": true`; the first real remote webhook is a different test (latency, quota, network failure), say which one you ran.
5. If a monitoring tool watches the trial's containers, its alerts for `Exited 143` are not rpl's: do not count them as messages.
6. Keep a copy of the trial's `rpl.json` before editing it, to restore it at the end (the grace goes back to 60).

## 1. The check is quiet when nothing is wrong

```bash
rpl watch; echo "exit $?"
```

Expect `exit 0`, no output, no message received.

## 2. An apply killed by SIGTERM, then reported

Follow README Step 5, run A (kill after `^backup:`), up to and including the kill. Then, **before** doing anything else:

```bash
python3 -c 'import json,os; j=json.load(open(os.environ["T"]+"/state/group-journal.json")); print([(e["id"], e.get("state"), e.get("result")) for e in j])'
rpl watch; echo "exit $?"
```

Expect the entry open (`result` None; note its `state`: it may be `changing` rather than `backed-up`, as on 22 November), and `rpl watch` at `exit 0` if less than a minute passed (the grace). Then wait 70 seconds and run it again.

Expect `exit 1`, a line `ALERT: rpl: the group apply ... never recorded a result`, and one message received. Run it once more: `exit 1`, no second message. Check that the message carries no secret and no path of your home directory.

Then `rpl group ... --resume` as in Step 5, and `rpl watch`: expect `exit 0`. The group apply also sends its own message `the update failed (interrupted at ...) and was rolled back`, on the first resume only: a second apply of the same plan sends none and prints `notification not delivered yet`, a defect of `rpl/groupapply.py` found by this trial (see docs/results.md). Count messages accordingly. Repeat from "run B" (kill after `^parent: recreated`) to see a second instant. Check that after each `--resume` the three containers run their original images.

## 3. A journal that cannot be read

```bash
cp "$T/state/group-journal.json" "$T/journal.keep"; echo '{"result": null}' > "$T/state/group-journal.json"
rpl watch; echo "exit $?"
cp "$T/journal.keep" "$T/state/group-journal.json"
```

Expect `exit 2` and one message about the unreadable journal; not `exit 0`. Restore the file afterwards, as above.

## 4. A new application, and a channel that fails

```bash
rpl inventory
rpl notify; echo "exit $?"
```

Expect `baseline recorded: N containers ...`. Without a `nightly.json` the same run also reports `The nightly run has never completed` (one message): expected, there is no nightly job in the trial state. Anything else is a finding.

Now cut the channel by pointing the URL at a name that does not resolve (change the host in the trial's `rpl.json` to `hook.example.test`), then create the event during the cut:

```bash
docker run -d --name rpltrial-extra alpine:3.18.0 sleep 600
rpl inventory
rpl notify; echo "exit $?"
```

Expect `exit 1`, a line `EVENT: New application: container rpltrial-extra ...`, `1 queued`, nothing received. Look at `$T/state/notifs.json`: `tries` 1, a `last_error`, no URL, no token. Restore the real URL, then:

```bash
rpl notify; echo "exit $?"; rpl notify; echo "exit $?"
```

Expect the first `exit 0` with the message received **once**, the second `exit 0` and no new message. Then `docker rm -f rpltrial-extra`; `rpl inventory`; `rpl notify` says `no event` (a removed container is never reported).

## 5. The timer alone, with the nightly job absent

The point is that a new incident is detected by the timer and by nothing else. Confirm no nightly timer or cron entry exists for the trial (`systemctl --user list-timers`, `crontab -l`). Where `systemctl --user` works (it did not as root in an LXC container: no user bus; use system units there, or `loginctl enable-linger` with `XDG_RUNTIME_DIR`, untested), create the units with the account that owns the secret file, with the same `RPL_CONFIG` and `PYTHONPATH` as `env.sh`:

```ini
# ~/.config/systemd/user/rpl-watch.service
[Service]
Type=oneshot
Environment=RPL_CONFIG=/path/to/trial/rpl.json PYTHONPATH=/path/to/this/checkout
ExecStart=/usr/bin/python3 -m rpl watch
SuccessExitStatus=0 1
```

```ini
# ~/.config/systemd/user/rpl-watch.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
```

`systemctl --user daemon-reload && systemctl --user enable --now rpl-watch.timer`. Then kill a new apply (run A again, a fresh trial group state) and wait: do not run `rpl watch` by hand. Expect a message within about two minutes after the grace, from `journalctl --user -u rpl-watch` an `ALERT:` line, and no message from a second timer tick. If no secret-read error appears under the timer's account, the 0600 file is readable there; if one does, that is a finding. Time the kill, the alert and the message.

A timer that stops running is not detected by anything: after the trial look at `systemctl --user list-timers` and say in the results how you would notice.

## 6. The nightly job records its end, on success and on failure

On a copy of your nightly script, not the real one. The record on failure must not be skipped by `set -e`:

```bash
#!/bin/bash
set -euo pipefail
trap 'rc=$?; if [ "$rc" -ne 0 ]; then python3 -m rpl notify --record failed --reason "nightly exited $rc"; fi' EXIT
python3 -m rpl scan
python3 -m rpl inventory
python3 -m rpl risk
python3 -m rpl notify --record ok
```

Run it once as it is: expect `$T/state/nightly.json` with `"status": "ok"`. Run it once with `python3 -m rpl scan` replaced by `false`: expect `"status": "failed"`, the reason `nightly exited 1`, and, at the next `rpl notify`, one message `The nightly run failed: ...`. Then age the record:

```bash
python3 -c 'import json,os,time; p=os.environ["T"]+"/state/nightly.json"; d=json.load(open(p)); d["ts"]=time.time()-40*3600; d["status"]="ok"; json.dump(d,open(p,"w"))'
rpl notify; echo "exit $?"
```

Expect `The nightly run has not completed for 40 h.` and a message. Run it again: no second message for the same record.

## 7. Tear down

Remove the timer units (`systemctl --user disable --now rpl-watch.timer`), the extra container, put the trial's `rpl.json` back (grace 60), remove the webhook and secret if they were only for this. Backups of the trial group stay until you delete them.

## What this trial does not show

- A remote webhook if yours was local; a timer under a non-root account; a user unit; a server restart with the timer active; a complete, uninterrupted apply (the duration of a normal apply was not measured);
- A real group, a real application or a real VPN; policy `auto`; a nightly job that really runs from cron or a timer for days.
- A webhook other than yours; Telegram; a channel that is slow or rate-limited (measured once in step 0, not stressed).
- Two `rpl watch` or `rpl notify` runs at the same instant (`notifs.json` has no lock), retries exhausted up to `max_attempts`, and an apply that legitimately runs longer than the grace.
- A timer that silently stops.
