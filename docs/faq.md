# FAQ

**English** · [Français](fr/faq.md)

- [General](#general)
- [The score and the scan](#the-score-and-the-scan)
- [The update and the rollback](#the-update-and-the-rollback)
- [Running it](#running-it)
- [With an AI agent](#with-an-ai-agent)
- [Trust and limits](#trust-and-limits)

## General

### What is this, in one sentence?
A scanner tells me what is vulnerable. rpl tells me which of those findings matter on my host, whether a newer image really removes them, and then updates one service at a time, with a rollback if the check fails, once I have said yes.

### Why did I build it?
One night's scan of my 65 containers returned 2,297 fixable HIGH or CRITICAL lines. I can't read that. And "fixable" turned out to mean "some tag exists", not "a newer image really removes the finding". I wanted a short list I could act on, and I wanted updates that don't leave me with a broken service at midnight.

### Who is it for?
Someone who runs Docker Compose behind Traefik at home or on a small team, who is fine with reading about 1,300 lines of Python, and who wants to stay the one who decides. It has one user so far, me, on one host. If you have a team with a patching process and a vulnerability platform already, this is not what you need.

### How is it different from Trivy alone?
Trivy finds the vulnerabilities, and rpl uses it for that. What Trivy doesn't know is how exposed a container is on my host, whether the flaw is exploited in the wild right now, or whether the next image really fixes it. rpl adds those three things and ranks the result. It does not replace the scanner.

### How is it different from Renovate, Dependabot or Watchtower?
Those answer "is there a newer version?". rpl answers "does it matter, does the newer image really fix it, and can I apply it safely?".
- **Watchtower** pulls and restarts when a new image appears. There is no ranking, no check that the finding is gone, and no human in the loop.
- **Renovate and Dependabot** open pull requests for new versions. They don't look at what is running on my host or at how it is exposed.

I could use them together with rpl. I don't, because my compose files are on the server, not in a repository with a bot.

### Why not update everything automatically?
Because an update that passes the health check can still break something, and I want to be the one who accepts that. rpl prepares proposals every night and does nothing to a running service. Applying one is a separate command, for one service.

## The score and the scan

### What does the score use?
Four things:
- the severity of the finding;
- whether it is in the CISA KEV list (exploited in the wild);
- whether the container has the Docker socket, and what role the service plays (a control plane, or a service that parses untrusted input, weigh more);
- how reachable the container is: on the Internet without a login, behind a login, on a LAN port, on localhost only, or internal.

The exposure comes from the Traefik labels and the published ports. It doesn't guess: without a list of the host names published to the Internet, the Internet exposure reads "unknown".

### Can I trust the score?
As a ranking, a bit. As a verdict, no. On 20 real findings it agreed with my own verdicts 14 times (answering "defer" every time agrees 13 times). It found 5 of my 7 "act" cases, with 4 false alarms. And I chose the roles after seeing those verdicts, so that table is a replay, not a validation. The numbers and their limits are in [results.md](results.md). There is no measured false-negative rate yet, and that is one of the three conditions for a 1.0.

### What does "a fix is proven" mean?
For each candidate version, rpl scans the image from the registry, without pulling it into Docker, and checks that the "act" findings are gone. On 12 images with "act" rows, 7 had a candidate that removes all of them, 2 had a candidate that removes none, and 3 had no newer version at all. Bumping the tag blindly would have changed nothing for 5 of the 12.

### What if the maintainer hasn't published a fixed image?
Then the answer is "no fix", and rpl says so. The finding stays on the list. A tag bump that changes nothing is worse than no proposal.

### Which registries does it support?
Docker Hub and ghcr.io. For any other registry the answer is UNKNOWN, never a guess.

### Can I accept a finding I have reviewed?
Yes, in `accepted.json`: `{"image|CVE-...": "reason"}`. The text is only there for me: the tool matches on the key and ignores the value, so I write a real reason, to be able to read it again in six months.

## The update and the rollback

### What does `rpl patch` do?
For one service: it asks for a snapshot (you give the command), dumps the database if the service has one, pins the new image in the compose file, runs a dry run that must show exactly one recreation (that of the service itself), recreates, then checks that the container is healthy, that it runs the new image, and that a route answers with the expected status. If any of that fails, it restores the compose file and brings the old image back.

### What can make it refuse to start?
- no snapshot command (unless I pass `--no-snapshot`), or a failed snapshot or dump;
- a service the compose file doesn't define, or one that has `build:` instead of `image:`;
- a service with no running container, because then there is no proof of what the "old" image was;
- a dry run that shows anything other than one recreation of that service;
- a VPN container (recognised by the name "gluetun"), or a service that shares its network;
- a stored proposal older than 36 hours, or whose file was modified after it was computed.

### Has the rollback ever saved a real service?
No. Every real update passed its check. I exercised the rollback three times on purpose, on 2 November 2026, on a disposable service on my real Docker host: a new image that serves nothing, one that never becomes healthy, and a `docker compose up` that fails because the new container can't start. Each time the old image came back with the same image ID, the route answered again, the compose file was restored and the journal said `rollback ok`. That is tested, not proven. I didn't test a real port conflict, a real application, or a rollback with data.

### Does the rollback restore my data?
No, only the image. If the new version ran a database migration, the rollback doesn't undo it. That is what the snapshot and the dump are for.

### What does exit code 4 mean?
`rollback FAILED: CHECK BY HAND`. The tool could not prove that the original image is running again, or the update was interrupted at a bad moment. Look at the service yourself before doing anything else. Code 2 is a verified rollback. I'd rather have a loud 4 than a quiet "ok" I can't back up.

### What if the check passes but the application is broken?
Then rpl won't notice. The check proves the container is healthy, runs the new image, and that one route answers. It doesn't prove that the application works. That is why proposals are one service at a time, with a snapshot, and why I look at the service afterwards.

## Running it

### What do I need?
Python 3.9 or later and nothing to install with pip. Docker with the Compose plugin. Trivy runs as a container. Traefik in front of the services. The files you write by hand are in [examples/](../examples).

### Does it need an AI?
No. It is plain Python with the standard library. There is no model call anywhere.

### What leaves my machine?
Three kinds of requests, as far as I can tell from the code (`grep -rn "https://" rpl/` shows them):
- Trivy downloads its vulnerability database;
- the CISA KEV list is downloaded from cisa.gov;
- the candidate versions are looked up on Docker Hub and ghcr.io, with the usual anonymous token requests.

Nothing about my containers is sent anywhere else, and there is no telemetry. Check it yourself, it is short.

### How long does a scan take, and what does it cost?
It costs nothing but disk and a few minutes of CPU. I run the first five steps every night, from cron or a systemd timer, and they only read.

### Does it work with Podman, Kubernetes, Caddy, nginx?
No. Docker Compose and Traefik only. Another reverse proxy, or routes defined in a file, read as "not routed", which makes the score too low. I haven't tried the rest.

### Does it work on Windows or macOS?
I run it on Linux. CI runs on Linux with Python 3.9 and 3.12. I haven't tried anything else.

## With an AI agent

### Is it made for an AI agent?
It works without one. But I do let an AI agent run my homelab, and that is where the question "who says yes to the update" came from. The read-only steps are safe to hand to an agent. `--apply` is the one that changes something.

### Can the agent apply updates by itself?
It can if you let it, and I wouldn't. Keep `--apply` behind an approval the agent can't grant itself. [agent-ops-guardrails](https://github.com/renocz/agent-ops-guardrails) is my attempt at that approval step, and rpl works fine without it. `proposals --apply` only takes the parameters of the stored proposal, nothing free-form, which makes it easier to gate.

## Trust and limits

### What is the biggest thing missing before I'd call it 1.0?
Three things, each with evidence in `results.md`: at least 3 automatic rollbacks on a real host; 4 weeks on a second, independent host with 20 or more containers; and a measured false-negative rate on 100 labelled findings I haven't tuned on. None of the three is done.

### Are the pulled images verified?
No. The tool trusts the tag and the registry. There is no signature check, and for a moving tag only the digest the registry reports at that moment is pinned. A compromised registry or maintainer is outside what it can see.

### What if I find a bug or a security problem?
For a bug, open an issue. For a vulnerability, follow [SECURITY.md](../SECURITY.md). I'd like to hear what breaks on your setup, especially if it isn't a Traefik homelab.

### Where do I see the numbers behind all this?
[results.md](results.md): what was measured, what wasn't, and the defects the tool had when I first used it on a real host. [design.md](design.md) explains why it works the way it does.
