# Contributing

Thanks for helping. A few rules keep the project safe to use.

## Ground rules

1. **The backend must never be able to decrypt user content.** No decryption function,
   no endpoint that returns decrypted data, no private keys or passphrases sent to the
   server — not even for debugging. The outbound SMTP queue is the only, documented
   exception (see [SECURITY.md](SECURITY.md)).
2. **No home-made cryptography.** Changes to keys, envelopes, recovery or SMTP follow
   [docs/specs/protocol-v1.md](docs/specs/protocol-v1.md); change the spec first, with
   test vectors.
3. **Never log content, tokens, passwords, keys or secrets.**
4. **Every database change is a new Alembic migration**, plus a privilege decision in
   `src/agnusmail/infrastructure/database/roles.py` for new tables.
5. **Every change comes with tests**, including negative and cross-account tests for new
   endpoints. Never weaken a security check to make a test pass.
6. **Dependencies are a cost.** Justify new ones, pin them in `uv.lock`, keep `pip-audit`
   clean.

Security vulnerabilities go through private reporting, not issues: see
[SECURITY.md](SECURITY.md).

## How a change reaches main

Nobody pushes to `main`, maintainers included:

1. Fork the repository (or, for maintainers, create a branch `feat/<name>`,
   `fix/<name>`, ...).
2. Open a pull request against `main`, following the template.
3. CI runs on it: lint, types, unit and integration tests, the container image, the
   OpenPGP.js interoperability test and the dependency audit. It uses no secret, so it
   runs the same on forks. A maintainer may need to approve the first run of a new
   contributor's workflows.
4. A code owner reviews it. New commits dismiss earlier approvals.
5. It is squash-merged once every check passes, so `main` stays a linear history of
   reviewed changes. Releases are signed tags `vX.Y.Z` that only maintainers create.

## Workflow

```sh
uv sync --locked
uv run ruff check . && uv run ruff format --check .
uv run mypy .
uv run pytest                    # unit tests
uv run pytest -m integration     # with the compose services (see README.md)
```

- Python 3.13, fully typed (`mypy --strict`), formatted with Ruff.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `security:`), in English,
  imperative and concise.
- Keep pull requests focused on one change and describe how you tested it.

By contributing, you agree that your contributions are licensed under the
[Apache-2.0](LICENSE) license of the project.
