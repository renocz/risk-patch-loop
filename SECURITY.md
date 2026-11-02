# Security policy

## Reporting a vulnerability

Please report it **privately**, not in a public issue: open a GitHub private security advisory at
<https://github.com/renocz/risk-patch-loop/security/advisories/new> ("Report a vulnerability" in the Security tab).

Include the version (`python -m rpl --version`), what you did, what happened, and what you expected. A failing test is the best report.

This is a one-person, spare-time project. Expect an acknowledgement within about a week and a fix when I can write and test one; there is no
service-level agreement. Only the latest release receives fixes (currently 0.9.x). I will credit you in the changelog unless you prefer not to be named.

## What the tool does, and does not do

`rpl` applies container image updates on a Docker Compose host, **with a human saying yes**. Concretely:

- It reads: `docker ps` / `docker inspect`, Compose files, the CISA KEV feed, and the tag lists and manifests of Docker Hub and ghcr.io (anonymous).
- It runs Trivy as a container (`rpl scan` mounts the Docker socket into it; `rpl fixcheck` does not) and **trusts that image by tag**, not by digest.
- It writes only when you run `rpl patch` (directly, or through `rpl proposals --apply <service>`): one `image:` line of one Compose file (with a backup),
  then `docker compose up` for that one service, and a database dump if you configured one.
- It never applies anything on its own: proposals are prepared by one command and applied by another.

It does **not**: authenticate or sandbox anything, run with reduced privileges (it needs the same rights as the user running `docker`),
patch the host operating system, update stateful data (a rollback restores the previous image, not the data), or protect you from a malicious
`patch-apps.json`, `rpl.json` or `snapshot_command`: those files are code you wrote and they are trusted.

Integrity, not authentication: `proposals.json` carries a SHA-256 of its content so that an edited or truncated file is refused. Anyone who can write
the state directory can recompute it; keep that directory writable only by the user who runs the tool.

## In scope for a report

- A way to make `rpl patch` or `rpl proposals --apply` run something other than the stored, validated proposal (argument or YAML injection, path tricks).
- A refusal that can be bypassed: VPN containers, stale or modified proposals, a missing snapshot.
- A "success" reported when the update did not happen or the scan could not do its job.
- Secrets or private data written to logs, state files or the repository.

## Out of scope

- Vulnerabilities in the images the tool scans, in Trivy, Docker, Compose or your reverse proxy (report those upstream).
- Anything that requires write access to the state directory, the configuration files or the Docker socket: all of them are already full control of the host.
- The score being wrong for your host (it is tuned on one owner's twenty verdicts, see [docs/results.md](docs/results.md)). That is a limit, not a vulnerability; an issue is welcome.
