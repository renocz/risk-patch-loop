# Labelling criteria for the false-negative measurement

These are the written criteria of [roadmap criterion 3](../README.md#roadmap-to-10). They are fixed **before** any
labelling: `rpl sample draw` refuses to run without this file and records its SHA-256 in the manifest, so a change after
the draw is visible. If the criteria need to change, change them in a commit, then draw again.

## The question

For each finding on the sheet, would a careful operator of that service have acted on it **now**, that is, taken the
update as the next piece of work rather than planning it or watching it?

## Answer `act` only when all three hold

1. **Exploitable from where the container is exposed.** Use the `exposure` column (it comes from the inventory, do not
   guess another level). A flaw that needs a position the attacker does not have from that exposure (local access,
   an authenticated admin, a network the service is not on) does not count. `kev` = yes means the flaw is exploited in the
   wild, which makes the first point much easier to meet, but does not meet it on its own.
2. **A fix exists.** The `fixed_version` column is not empty and is a version the operator could actually move to.
3. **The vulnerable component is reachable in this service.** The package being present in the image is not enough: the
   service must use it on a path an attacker can drive (for example a parsing library fed by user input, or a TLS library
   on an exposed port). A package only used at build time, or never loaded, does not count.

Answer `defer` when at least one of the three does not hold. Answer `unsure` when you cannot decide without information
you do not have (write what is missing in `notes`). `unsure` is reported separately and the rate is given both ways, so it
does not hide in either side.

## Rules for reviewers

- You do not see the score or the decision, and you do not run `rpl risk` on these findings while labelling.
- You answer alone. You do not discuss a row with the other reviewer before both sheets are in.
- Look the finding up as long as you need, but write the reason in `notes` when you answer `act` or `unsure`.
- You label the whole sheet, in any order. A blank answer is refused.
- A reviewer may be a panel of language models from at least 3 different families. Each model answers alone, in a fresh
  session, on the same redacted sheet (exposure from the inventory, no score, no decision) and these same criteria; the
  panel's majority answer is ONE reviewer's sheet, and its members are treated as correlated, not as several confirmations.
  A model outside the panel is the tie-break. Log model versions and prompts, never secrets. A rate obtained with models is
  published as "1 human + 1 model panel".
- Two reviewers label every row. When they differ, a third reviewer, who has not seen the other two sheets, answers the
  rows they differ on (the whole sheet is fine). Disagreements are counted and published, not hidden.

## What is computed (and what it is not)

`rpl sample result` takes the final answer of each finding (the two reviewers' answer when they agree, the third
reviewer's when they differ) and reports: the number of `act` verdicts, how many of them the score ranked below ACT, the
rate with a 95% Wilson interval, the number of disagreements and a kappa between the first two reviewers. The sample is
stratified (as many ACT findings as PLAN plus WATCH findings), so the rate is the one defined in the README, not the
prevalence of missed findings in a typical scan. Findings with no known fix are not sampled: the second criterion makes
them impossible to `act` on, so they cannot change the rate.
