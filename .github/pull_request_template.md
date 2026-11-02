## What and why

<!-- One idea per pull request. Link the issue if there is one. -->

## What is tested

<!-- The tests added or changed, and what they prove. For a bug fix: the test failed before the fix (say how you checked). -->

## What is not tested, and known limits

<!-- Be specific: which behaviour only a real Docker / registry / host would show. "Nothing" is rarely true. -->

## Defects found

<!-- In the existing code, while doing this. "None" is an answer. -->

## Checklist

- [ ] `python -m unittest discover -s tests -t . -v` passes (CI covers Python 3.9 and 3.12)
- [ ] Standard library only (no new dependency, no pytest)
- [ ] Tests use doubles: no network, no real Docker or Trivy
- [ ] No name, address, domain or identifier from a real infrastructure (use `example.test`, `registry.example.test`, `app-1`)
- [ ] Numbers in docs come from something I ran; unverified claims are labelled as such
- [ ] CHANGELOG "Unreleased" updated; `README.fr.md` updated if `README.md` changed
