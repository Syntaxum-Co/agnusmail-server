# Maintaining

How the repository is configured so that only reviewed, tested changes reach `main`. The
files live in the repository; the settings below are applied by an administrator on
GitHub, once.

## Branch and tag protection

Import the rulesets in **Settings → Rules → Rulesets → New ruleset → Import a ruleset**:

- [`.github/rulesets/main.json`](../.github/rulesets/main.json) — `main` only changes
  through pull requests: one approval from a code owner
  ([`.github/CODEOWNERS`](../.github/CODEOWNERS)), approvals dismissed by new commits,
  conversations resolved, every CI job green on the latest `main`, squash merge, linear
  history, no force push, no deletion. Administrators may merge their own pull request
  without a second reviewer (bypass "pull request only"); they can never push directly.
- [`.github/rulesets/release-tags.json`](../.github/rulesets/release-tags.json) — only
  administrators create, move or delete `v*` tags.

When the project has a second maintainer, remove the administrator bypass from
`main.json` so every change gets a second pair of eyes.

## Settings

- **Actions → General:** workflow permissions "Read repository contents"; do not allow
  GitHub Actions to create or approve pull requests; "Require approval for all external
  contributors" for fork pull request workflows.
- **Code security:** private vulnerability reporting (see [SECURITY.md](../SECURITY.md)),
  Dependabot alerts and security updates, secret scanning with push protection, CodeQL
  (the workflow in `.github/workflows/codeql.yml` starts once the repository is public).
- **General:** allow squash merging only; automatically delete head branches.

## Releasing

1. Update [CHANGELOG.md](../CHANGELOG.md) and the version in `pyproject.toml` in a pull
   request.
2. After it merges, tag the merge commit and push the tag:

   ```sh
   git tag -s vX.Y.Z -m "Agnusmail server vX.Y.Z"   # -s signs it; -a if you have no key
   git push origin vX.Y.Z
   ```

3. Create a GitHub release from the tag, with the changelog entry.
