# Changelog

## Unreleased

Integration tests for the parts 0.9.0 left untested, the defects they exposed, and repository hygiene.

### Tests
- 106 tests added (54 -> 160), standard library only, doubles only: a fake registry on a free local port, a fake Docker host injected into `rpl patch`, mocked Trivy/Docker for `rpl scan`. `tests/__init__.py` fails any test that touches a host other than 127.0.0.1.
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

### Documentation
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
