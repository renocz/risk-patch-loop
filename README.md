# risk-patch-loop

**English** · [Français](README.fr.md)

**Which container vulnerabilities actually matter on *your* host, is there a fix that really removes them, and can it be applied safely, with a human saying yes?**

On the author's homelab, one night's scan returned 2,297 fixable HIGH/CRITICAL findings. That is not a to-do list. This tool turns it into one, using three things a scanner does not know: how exposed each container really is, whether a newer version really removes the finding, and what a safe update of one service looks like.

```
scan ──► inventory ──► risk score ──► fix check ──► proposals ──► you say yes ──► patch + automatic rollback
```

- **Exposure-aware score.** Severity, "exploited in the wild" (CISA KEV), access to the Docker socket, and the role of the service, all scaled by how reachable the container is: on the Internet without a login, behind a login, on a LAN port, localhost only, internal.
- **A fix is proven before it is proposed.** The candidate version is scanned *from the registry* (nothing is pulled). If the maintainer has not published a rebuilt image, the answer is "no fix", not a version bump that changes nothing.
- **One service at a time.** Snapshot, database dump, pinned image, dry run, recreate, health and route check, and an automatic rollback if the check fails. A VPN container and the services behind it are refused.
- **Nothing happens without a human.** The tool prepares proposals; applying one is a separate, explicit command.

## Status: v0.9, one host, honest numbers

Built and used for one week on one Docker host (65 containers, Traefik, one owner). **Read [docs/results.md](docs/results.md) before trusting it**: the score agrees with its owner's verdicts 14 times out of 20 (a trivial "always defer" answer gets 13), the roles were tuned after seeing those verdicts, and the automatic rollback has never fired in production. It handles Docker Compose + Traefik, Docker Hub and ghcr.io. It is a proof of concept for someone who is comfortable reading 1,000 lines of Python, not a product.

## Known limits

From [docs/results.md](docs/results.md); none of these is hidden, and none is fixed yet.

- **One host.** Everything was measured on one homelab (65 containers, one owner, one week). No second host has run it.
- **Traefik only.** Exposure comes from Traefik labels. Another reverse proxy, or routes defined in a file, will read as "not routed".
- **Docker Hub and ghcr.io only.** Any other registry gives "UNKNOWN", never a guess.
- **The automatic rollback has never fired in production.** Every real update passed its check. The rollback is covered by deterministic tests against a *fake* Docker host (compose file restored, old image recreated, result journaled), not by a real failure on a real host. Treat it as unproven until it has been exercised.
- **The tests do not run real Docker, Compose, Trivy or a real registry.** They prove the sequencing and the refusals; they cannot prove that real Compose output looks the way the parser expects.
- **The score is a ranking, not a verdict.** It agrees with its owner 14 times out of 20 (the trivial "always defer" answer: 13), on twenty cases, with roles chosen after seeing the verdicts. No false-negative rate has been measured.
- **Healthy-but-broken updates pass.** The check proves the container is healthy and one route answers, not that the application works.
- **The rollback restores the image, not the data.** A database migrated by the new version needs the dump or the snapshot.
- **VPN containers are recognised by name** ("gluetun"), not by what they do.

## Roadmap to 1.0

1.0 is released when all three are true, and each has evidence in `docs/results.md`. The numbers are proposed targets, open to argument in an issue.

1. **Rollback exercised in real conditions.** At least 3 automatic rollbacks on a real host, covering a container that never becomes healthy, a route that answers an unexpected status, and a `docker compose up` that fails; each journaled `rollback ok`, with the old image running and its route answering afterwards. Logs published.
2. **A second host.** At least 4 consecutive weeks on a second, independent host (a different owner, or a reverse proxy other than Traefik) with 20 or more containers, reported in the same format as the first host's numbers.
3. **A measured false-negative rate.** A labelled sample of at least 100 findings, with verdicts from at least 2 reviewers, drawn after the roles and thresholds are frozen (not the 20 cases used for tuning). Publish how many "act" verdicts the score ranks below ACT, with a confidence interval. Target: at most 10% of "act" verdicts missed. If the target is not met, the score changes and the measurement is repeated before 1.0.

## Quick start

Python 3.9 or later, no dependencies. Docker with the Compose plugin; Trivy runs as a container.

```bash
git clone https://github.com/renocz/risk-patch-loop && cd risk-patch-loop
cp examples/rpl.json rpl.json            # edit: state_dir, snapshot_command, files below
cp examples/roles.json examples/patch-apps.json .   # describe YOUR services
export RPL_CONFIG=$PWD/rpl.json

python -m rpl scan         # Trivy on running images + CISA KEV  -> findings.json
python -m rpl inventory    # how exposed is each container       -> inventory.json
python -m rpl risk         # score and ACT / PLAN / WATCH
python -m rpl fixcheck     # which candidate versions really fix the ACT rows (read-only)
python -m rpl proposals    # updates ready to approve
python -m rpl proposals --list
python -m rpl proposals --apply myapp --dry      # then without --dry
```

`rpl patch` is the last step on its own (`rpl patch --help`). Run the first five steps nightly (cron or a systemd timer).

## Files you write by hand (see `examples/`)

| File | Purpose |
|---|---|
| `rpl.json` | paths, the snapshot command, the Traefik middleware words that mean "login required" |
| `patch-apps.json` | the services the tool is allowed to *propose*, each with a health route and a database to dump |
| `roles.json` | control-plane services and services that parse untrusted input (they weigh more) |
| `tunnel-hosts.json` | host names published to the Internet (from your tunnel or firewall); without it, Internet exposure is "unknown", never guessed |
| `accepted.json` | findings you reviewed and accepted: `{"image|CVE-...": "reason"}` |

## Safety rules, as code

- A scan that cannot do its job (stale database, KEV list unavailable, an image not analysed) is not "OK", and findings are not rewritten.
- `rpl patch` refuses to start without a snapshot command, unless you say `--no-snapshot`; a failed snapshot or database dump stops everything before any change.
- The dry run must show that only the service to update would be recreated.
- A VPN container, or a service sharing its network, is refused.
- `rpl proposals --apply` takes the parameters from the stored proposal, nothing free-form, and refuses a proposal older than 36 hours, or whose file was modified after it was computed (SHA-256 check: integrity, not authentication).
- `rpl patch` validates service, database and image names before running anything, and refuses a service the Compose file does not define. A failed `docker compose up` or a failed dry run counts as a failed update, not as success.

## With an AI agent

If an agent drives your infrastructure, give it the read-only steps and keep `--apply` behind an approval it cannot grant itself. [agent-ops-guardrails](https://github.com/renocz/agent-ops-guardrails) is the author's attempt at that approval step; this project works without it.

## Documentation

- [SECURITY.md](SECURITY.md): reporting a vulnerability, what the tool does and does not do
- [CONTRIBUTING.md](CONTRIBUTING.md): running the tests and the rules (standard library only, real numbers and written limits)
- [docs/design.md](docs/design.md): the loop, the decisions, the limits
- [docs/results.md](docs/results.md): what was measured, what was not, the defects found by using it

## License

MIT. Use it, fork it, tell me what breaks.
