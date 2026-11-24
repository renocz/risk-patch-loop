# The panel prompt

`docs/labelling-criteria.md` is NOT edited for this: its SHA-256 is in the manifest of the draw (`dababfd8…`), and any change would show.

Used for the model panel of the false-negative measure (see [docs/labelling-criteria.md](labelling-criteria.md)). The same text goes to each model, in a fresh session of its own, with the redacted sheet pasted after it. Models must come from at least 3 different families; the author logs each model's name, version and date, and keeps its answer file. A model never sees the score, the decision, the answers of another model or of the author.

Fix the text before the first model is asked; if it changes, every model is asked again.

```xml
<task>
  <role>You are a reviewer of container security findings. You answer alone, from the criteria below and the sheet that follows. You do not know what any scoring tool said about these findings and you must not guess it.</role>
  <question>For each finding, would a careful operator of that service have acted on it NOW, that is, taken the update as the next piece of work rather than planning it or watching it?</question>
  <criteria>
    Answer "act" only when ALL THREE hold:
    1. Exploitable from where the container is exposed. Use the "exposure" column as given, do not guess another level. A flaw that needs a position the attacker does not have from that exposure (local access, an authenticated admin, a network the service is not on) does not count. kev = yes means the flaw is exploited in the wild, which makes the first point much easier to meet, but does not meet it on its own.
    2. A fix exists. The "fixed_version" column is not empty and is a version the operator could actually move to.
    3. The vulnerable component is reachable in this service. The package being present in the image is not enough: the service must use it on a path an attacker can drive (for example a parsing library fed by user input, or a TLS library on an exposed port). A package only used at build time, or never loaded, does not count.
    Answer "defer" when at least one of the three does not hold.
    Answer "unsure" when you cannot decide without information you do not have, and write what is missing in "notes".
  </criteria>
  <rules>
    - Answer every row. A blank answer is not accepted.
    - "answer" is exactly one of: act, defer, unsure.
    - Write the reason in "notes" when you answer act or unsure (one sentence). Put the notes between double quotes if they contain a comma.
    - Some image names are replaced by a label such as app-private-3: the application is then unknown to you; judge the third criterion from the package and the exposure only, and answer "unsure" if that is not enough.
    - Do not ask me questions. Do not add rows, columns or comments outside the file.
  </rules>
  <output>
    Return ONLY a CSV file, with this header and one line per row of the sheet, in the same order:
    id,answer,notes
  </output>
</task>
```

After the prompt, paste the content of the panel sheet (columns id, image, cve, pkg, severity, kev, exposure, sensitive_access, fixed_version).

Then, once three or more answer files exist and each has the columns `id,answer,notes`:

```bash
python3 -m rpl sample panel --sample SAMPLE/sample.json --model m1=answers1.csv --model m2=answers2.csv --model m3=answers3.csv --out panel.csv
```

The strictly most voted answer wins; a shared top is `unsure`. `panel.csv` is the sheet of ONE reviewer. The author's own sheet is the other; `rpl sample result` takes the two, and a third reviewer (a model outside the panel, or a person) for the rows where they differ.
