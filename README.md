# Agnusmail

Open-source, end-to-end encrypted e-mail backend with Ethereum wallet identity.

- **The server cannot read your mail.** Messages, attachments and key backups are
  encrypted on the user's devices (OpenPGP, RFC 9580) with post-quantum hybrid encryption
  (ML-KEM-768 + X25519, RFC 9980). The backend stores and moves ciphertext only.
- **Your wallet is your account.** Sign-In with Ethereum (EIP-4361) for login; the wallet
  signs every device key (EIP-712), so the server cannot swap a key without it. Passkeys
  are an optional, wallet-approved login.
- **It still talks to the rest of the world.** An inbound SMTP gateway encrypts external
  mail on arrival, an outbound service delivers to regular mailboxes (clearly labeled as
  not end-to-end encrypted), and a secure portal sends password-protected messages to
  people without Agnusmail.

This repository is the backend: an HTTP API, a background worker and the SMTP services.
You can run it yourself; a web client talks to it over the `/v1` API.

> **Status:** early and unaudited. The protocol is a draft that has not been externally
> reviewed yet. Do not rely on it for high-risk use until it has been.

## Contents

- [Quick start](#quick-start)
- [Development](#development)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Quick start

Requirements: Docker with Compose v2.

```sh
git clone https://github.com/Syntaxum-Co/agnusmail-server.git
cd agnusmail-server
cp .env.example .env                        # then change AGNUSMAIL_DB_PASSWORD
docker compose --profile app up -d --build  # PostgreSQL, Redis, S3, Rspamd, API, worker, SMTP
curl http://127.0.0.1:8000/readyz           # {"status":"ready"}
```

What you get, all bound to `127.0.0.1`:

| Service | Address | Notes |
|---|---|---|
| API | `http://127.0.0.1:8000` | `/healthz`, `/readyz`, everything else under `/v1` |
| Inbound SMTP | `127.0.0.1:2525` | no TLS; mail to `name@<AGNUSMAIL_MAIL_DOMAIN>` arrives encrypted |
| S3 storage (SeaweedFS) | `http://s3.localhost:8333` | bucket `agnusmail-dev`, for encrypted attachments |
| PostgreSQL / Redis | `5432` / `6379` | development credentials from `.env` |

Outbound mail never leaves your machine in this setup: the outbound service delivers
everything to a local sink that discards it.

**Using a web client.** SIWE and passkeys are bound to the page the user is on. By
default the API expects a client served at `http://127.0.0.1:5173` that proxies `/v1` to
the API (same origin, so cookies and CSRF work as in production). Point it elsewhere with
`DEV_FRONTEND_ORIGIN` and `DEV_FRONTEND_HOST` when you start the stack. Passkeys need a
host name, not an IP address (a WebAuthn rule): use
`DEV_FRONTEND_ORIGIN=http://localhost:5173 DEV_FRONTEND_HOST=localhost:5173`.

Stop everything with `docker compose --profile app down` (add `-v` to delete the data).

## Development

Requirements: Python 3.13 and [uv](https://docs.astral.sh/uv/).

```sh
uv sync --locked
cp .env.example .env
docker compose up -d              # PostgreSQL, Redis, S3 and Rspamd only
uv run alembic upgrade head
uv run uvicorn agnusmail.apps.api.main:create_app --factory --reload
```

Checks (the same as CI):

```sh
uv run ruff check . && uv run ruff format --check .
uv run mypy .
uv run pytest                       # unit tests, no services needed
```

Integration tests run against the compose services and read the connection URLs from the
environment:

```sh
docker compose up -d && uv run alembic upgrade head
set -a && . ./.env && set +a
export AGNUSMAIL_TEST_S3_ENDPOINT=http://127.0.0.1:8333   # attachment tests (optional)
uv run pytest -m integration
```

Rspamd tests also need `AGNUSMAIL_TEST_RSPAMD_URL` and a published Rspamd port (see
`.github/workflows/ci.yml`); without them they are skipped.

Other processes:

```sh
uv run python -m agnusmail.apps.worker          # background jobs
uv run python -m agnusmail.apps.smtp_inbound    # inbound SMTP gateway
uv run python -m agnusmail.apps.smtp_outbound   # outbound SMTP delivery
uv run python -m agnusmail.apps.admin --help    # administration CLI (two-operator approval)
```

Every setting is an environment variable with the `AGNUSMAIL_` prefix; see
[docs/configuration.md](docs/configuration.md).

## Architecture

```text
              web client (decrypts and encrypts locally)
                         │ HTTPS /v1
                         ▼
 ┌──────────────┐   ┌─────────┐   ┌────────┐   ┌────────────────────┐
 │ SMTP inbound │──▶│   API   │──▶│ Redis  │   │ S3 object storage  │
 │ (encrypts on │   │(FastAPI)│   └────────┘   │ (encrypted         │
 │  arrival)    │   └────┬────┘                │  attachments)      │
 └──────┬───────┘        │                     └────────────────────┘
        │           ┌────▼─────┐   ┌──────────────┐
        └──────────▶│PostgreSQL│◀──│    worker    │
                    └────▲─────┘   └──────────────┘
                         │
                  ┌──────┴────────┐
                  │ SMTP outbound │──▶ recipients' mail servers (not E2EE)
                  └───────────────┘
```

Each process uses its own PostgreSQL role with only the privileges it needs. See
[ARCHITECTURE.md](ARCHITECTURE.md) for components, data model and flows.

```text
src/agnusmail/
  apps/            process entry points (api, worker, smtp_inbound, smtp_outbound, admin)
  core/            settings, logging, errors, security helpers
  infrastructure/  PostgreSQL, Redis, S3, OpenPGP (Sequoia), metrics
  modules/         one folder per feature: models, service, router
  migrations/      Alembic migrations
  extensions.py    extension points (see docs/extensions.md)
tests/             unit (in-memory) and integration (real PostgreSQL/Redis/S3) tests
docs/              protocol specification, configuration, self-hosting
docker/            container image and development configuration
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — components, data model and main flows
- [SECURITY.md](SECURITY.md) — security model and how to report a vulnerability
- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, adversaries and known limitations
- [docs/specs/protocol-v1.md](docs/specs/protocol-v1.md) — the cryptographic protocol
- [docs/specs/audit-chain-v1.md](docs/specs/audit-chain-v1.md) — the per-user audit chain
- [docs/configuration.md](docs/configuration.md) — every setting
- [docs/self-hosting.md](docs/self-hosting.md) — running it beyond your laptop
- [docs/extensions.md](docs/extensions.md) — adding features without forking

## Security

Please **do not open public issues for vulnerabilities**. See [SECURITY.md](SECURITY.md)
for how to report one privately.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

[Apache License 2.0](LICENSE) (`Apache-2.0`). Copyright 2026 Natan Dias; see [NOTICE](NOTICE).
