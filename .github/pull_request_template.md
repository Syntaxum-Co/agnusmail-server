## What and why

<!-- What this changes and the reason for it. -->

## How it was tested

<!-- Commands run, new tests, manual checks. -->

## Checklist

- [ ] Tests added or updated (negative and cross-account cases for new endpoints)
- [ ] `ruff`, `mypy` and `pytest` pass locally
- [ ] Database changes come with a new migration and a privilege decision in `roles.py`
- [ ] Nothing new is logged that could contain content, tokens, keys or secrets
- [ ] The server still cannot decrypt user content
