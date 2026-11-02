# risk-patch-loop, for IT leaders

**English** · [Français](fr/pour-les-dirigeants-it.md)

A short page for someone who runs or manages infrastructure and wants to know whether this is worth a look. Five minutes, no code. The details are in [the README](../README.md), the questions engineers ask are in [the FAQ](faq.md), and the numbers are in [results.md](results.md).

## The 30-second version

A vulnerability scanner gives you a list, and the list is too long to act on. One night's scan of my 65 containers returned 2,297 fixable findings. Nobody reads that.

risk-patch-loop is a small tool I wrote to turn that list into a few things worth doing. It ranks the findings by how exposed each container really is, checks that a newer image really removes the finding, and prepares proposals. Applying one is a separate step that touches one service, keeps a snapshot, and puts the old image back if the check fails. Nothing is applied without a person saying yes.

It is a proof of concept. I built it and used it for a week on one host. Read the limits below before you think about anything bigger.

## What it changes

- **A shorter list, in a better order.** Severity alone puts everything at the top. rpl adds three things the scanner doesn't know: how reachable the container is, whether the flaw is being exploited right now (the CISA list), and what the service does.
- **No update that changes nothing.** Of 12 images with findings worth acting on, 5 would have been "updated" without removing anything: no fixed image had been published. rpl says "no fix" instead of proposing a version bump.
- **A small blast radius.** One service at a time, a snapshot first, a check after, a way back. On my host the updates it prepared cost 5 to 40 seconds of outage each.
- **A person stays in charge.** The tool prepares, a human approves. That also makes it easy to put behind an approval step if an AI agent does the work.

## What it does not do

- It does not decide for you. The score is a ranking: on 20 findings it agreed with my own verdicts 14 times, and answering "defer" every time would have agreed 13 times. I chose its settings after seeing those verdicts, so treat it as a first number, not a result.
- It does not prove an application works after an update. The check proves the container is healthy, runs the new image, and that one route answers.
- It does not restore data. A database migration run by the new version stays; that is what the snapshot and the dump are for.
- It does not verify image signatures. It trusts the tag and the registry.
- It does not cover what I haven't tried: one host, Docker Compose, Traefik, Docker Hub and ghcr.io. Anything else reads as "unknown", never as a guess.

## How far to trust it

| | |
|---|---|
| **Tested** | 203 automated tests against a fake Docker host, run in CI on two Python versions. A few behaviours were checked by hand on a real Docker engine. |
| **Used** | One week on one homelab: 65 containers, one owner. Five real updates went through it and each one passed its check. |
| **The rollback** | Never needed on a real service. I made it fire three times on purpose, on a disposable service of the real host (2 November 2026). The old image came back every time. That is tested, not proven. |
| **Found by using it** | Three real defects in the first week, then eleven more by writing tests and reviewing the code. They are listed in [results.md](results.md), with the tests that now cover them. |

I wrote the numbers down the way they came out, including the ones that don't flatter the tool.

## What it would take to use it in a team

I have set three conditions for calling it 1.0. None is met, and I would want all three before recommending it to anyone for real work:

1. **The rollback exercised in real conditions:** at least 3 times on a real host, each journaled and checked.
2. **A second host:** 4 weeks on an independent one (another owner, or another reverse proxy than Traefik) with 20 or more containers.
3. **A measured miss rate:** a labelled sample of 100 findings, judged by two people who don't see the score, to count how many "act" cases it ranks too low. My target is at most 10%.

If your setup is a Traefik homelab and you are curious, you can try it today in read-only mode: the first steps change nothing. If it is a production environment, wait for these conditions, or help me meet them.

## Likely questions

**Is it a product?**
No. It is one engineer's tool, in Python, with no dependency. There is no support, no roadmap promise and no service behind it.

**Does it send my data anywhere?**
Not that I know of, and the code is short enough to check. It downloads the scanner's database, the CISA list, and looks up versions on the registries. No telemetry, no AI service.

**Does it need an AI agent?**
No. It works from the command line. I do let an AI agent drive my infrastructure, and for that I keep the "apply" step behind an approval the agent can't give itself (see [agent-ops-guardrails](https://github.com/renocz/agent-ops-guardrails)). rpl works without it.

**Why would a manager care?**
Because the cheap answer to a long vulnerability list is either to ignore it or to update everything at once, and both go wrong in ways that cost more later. A ranked, checked, reversible way of doing it is the part I was missing.

---

*This is one engineer's field notes on one project, not a pitch. The numbers behind every claim are in [results.md](results.md).*
