# Contributing

Bug reports, corrections and second opinions on the score are welcome. For a larger change, open an issue first so we can agree on the idea before you write it.

## Run the tests

```bash
python -m unittest discover -s tests -t . -v
```

Python 3.9 or later. CI runs 3.9 and 3.12; please do not use syntax or library features newer than 3.9.

## Rules

**Standard library only.** No runtime dependency, and no test dependency either: tests use `unittest`, not pytest. A dependency needs a very good reason and an issue first.

**Real numbers and written limits.** This project's value is that it says what was measured and what was not. A claim in the README, the docs or a commit message must be backed
by something you ran, with the number, the sample size and the date; anything you did not verify says so. A new feature that has a limit documents the limit in the same change
(`README.md` "Known limits", `docs/results.md`).

**Tests use doubles, never the real thing.** No network (beyond the `127.0.0.1` fake registry in `tests/fakes.py`), no real Docker, no real Trivy: `tests/__init__.py` fails any test
that resolves or connects to another host. Inject a fake (`FakeHost`, `FakeRegistry`, `mock.patch`) instead. Use `example.test`, `registry.example.test`, `app-1` for names;
never put a real host name, address, domain or container name from your own infrastructure in the repository, tests or fixtures.

**A bug fix comes with a test that fails before the fix.** Show it failing on the parent commit; say so in the pull request.

**Safety-relevant behaviour is conservative.** When the tool cannot tell (unreadable registry, scan that could not run, compose file that will not load), it refuses or says UNKNOWN. It never answers "OK".

## Pull requests

- English for code, comments, docs and commit messages. `README.fr.md` mirrors `README.md`; update it when the English README changes.
- Keep a pull request to one idea, with a CHANGELOG entry under "Unreleased".
- Fill in the pull request template: what is tested, what is not, any defect found.
