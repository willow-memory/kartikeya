# Contributing

## Set up

The same steps CI runs (`.github/workflows/tests.yml`), on Python 3.11 or newer:

```sh
pip install -e . pytest pyyaml
```

`pyyaml` is only for `tests/test_release_wiring.py`, which reads the release
workflows; without it those checks skip instead of failing, so install it. CI
also installs bubblewrap; see the workflow for the exact steps.

## Run the tests

```sh
python -m pytest tests/ -q
```

That is the command CI runs, verbatim. Quote it and its result (the
`N passed` line) in the pull request, so the PR carries a receipt rather than
a claim.

## Commits and releases

Commit subjects follow Conventional Commits. `docs:`, `test:`, `ci:` and
`chore:` are hidden: they cut no release and do not appear in `CHANGELOG.md`.
Every other type releases on its own once its PR merges, because
`release-please.yml` arms auto-merge on the release PR. The reasoning for
both sets lives beside the setting in `release-please-config.json`
(`$comment-hidden-rule`, `$comment-what-cuts-a-release`); read it before
changing either. `pr-title.yml` checks a PR title against what the PR
touches, in both directions.

These rules are the fleet's, published by `reconciler conventions --json`
(willow-reconciler) and held here by `tests/test_fleet_conventions.py`.
