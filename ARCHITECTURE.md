# Architecture

Agnusmail's backend is **cryptographically blind**: it stores and moves ciphertext and has
no way to decrypt messages, attachments or key backups. Clients do all the cryptography
(see [docs/specs/protocol-v1.md](docs/specs/protocol-v1.md)).

## Components

Every process runs from the same image and code base, with its own configuration and
its own PostgreSQL role.

| Process | Command | Responsibility |
|---|---|---|
| API | `uvicorn agnusmail.apps.api.main:create_app --factory` | HTTP API under `/v1`: identity, sessions, devices, keys, messages, attachments, recovery, addresses, domains, portal, usage |
| Worker | `python -m agnusmail.apps.worker` | Background jobs from a PostgreSQL queue (`jobs`): audit verification and purge, cleanup, queue and portal expiry, account migrations, usage recomputation, abuse evaluation |
| Inbound SMTP | `python -m agnusmail.apps.smtp_inbound` | Receives external mail, runs antispam, encrypts it to the recipients' public keys and stores only ciphertext |
| Outbound SMTP | `python -m agnusmail.apps.smtp_outbound` | Delivers mail to external servers (not end-to-end encrypted), signs it with DKIM |
| Admin CLI | `python -m agnusmail.apps.admin` | Operator actions on account metadata, each change approved by a second operator |

Backing services: **PostgreSQL** (all durable state), **Redis** (sessions, nonces,
challenges, rate limits — nothing durable), **S3-compatible storage** (encrypted
attachments) and **Rspamd** (antispam for the inbound gateway).

Extensions ([docs/extensions.md](docs/extensions.md)) add routes, jobs, admin actions,
tables and a quota policy to these same processes, without changing their code.

## Code layout

```text
src/agnusmail/
  apps/                   process entry points
    api/                  FastAPI app factory, middleware, health routes
  core/                   settings, logging (with redaction), errors, security helpers
  infrastructure/         database (sessions, roles), Redis, object storage, OpenPGP, metrics
  modules/<feature>/      models.py (tables), service.py (use cases), router.py (HTTP)
  migrations/versions/    Alembic migrations, applied in order
tests/unit/               fast tests (SQLite in memory, fake Redis and storage)
tests/integration/        tests against real PostgreSQL, Redis, S3 and Rspamd
```

Feature modules: `identity` (accounts, SIWE), `authentication` (sessions, CSRF, device
binding), `passkeys`, `devices`, `keys` (public key directory), `audit` (hash chain),
`messages`, `attachments`, `folders`, `quotas`, `recovery`, `addresses`, `domains`,
`inbound`, `outbound`, `portal`, `abuse`, `admin`, `jobs`.

## Data model

| Area | Tables |
|---|---|
| Accounts | `users`, `mail_addresses`, `mail_domains`, `passkey_credentials` |
| Devices and keys | `devices`, `public_keys` |
| Audit | `audit_events` (append-only), `audit_chain_heads` |
| Messages | `messages` (encrypted body, stored once), `message_keys` (one PKESK per device key), `mailbox_entries` (each participant's folder and read state), `mail_folders` (encrypted names) |
| Attachments | `attachments` (metadata; the ciphertext is in object storage) |
| Recovery | `recovery_keys`, `recovery_backups` (encrypted), `account_migrations` |
| SMTP | `gateway_keys` (public), `outbound_keys` (public), `outbound_messages` (encrypted queue, ≤ 72 h), `outbound_recipients` |
| Portal | `portal_messages` (encrypted envelopes, ≤ 30 days), `portal_links` (hashed tokens) |
| Quotas and abuse | `account_usage`, `abuse_reports`, `account_restrictions` |
| Operations | `jobs`, `operators`, `admin_actions`, `admin_signatures` |

Hard rules: no table stores message content in clear, private keys, passphrases or
recovery secrets. Sessions live in Redis, not in a table.

## Main flows

### Login

1. `POST /v1/auth/siwe/nonce` → a single-use nonce.
2. The wallet signs a SIWE message; `POST /v1/auth/siwe/verify` checks it and opens an
   opaque session (cookie). The first login creates the account.
3. To use mail, the client binds the session to one of its active devices with a signed
   challenge (`/v1/auth/device/challenge` and `/bind`).

### New device

1. The device generates an OpenPGP v6 certificate locally and uploads the **public** part
   with a proof of possession (`POST /v1/devices`, then `/keys`).
2. The wallet signs an EIP-712 `DeviceCertificate` over its fingerprint
   (`POST /v1/devices/{id}/authorize`); the device becomes active and appears in the
   directory.

### Message between Agnusmail users (E2EE)

1. The sender fetches the recipients' keys (`GET /v1/keys/{address}`) and verifies their
   wallet certificates.
2. It encrypts locally — one PKESK per recipient device, per own device and per recovery
   key — and sends the envelope (`POST /v1/messages`).
3. The API checks the structure and completeness and stores ciphertext only.
4. Recipients fetch the body and their own PKESK and decrypt on their devices.

### External mail in

1. The inbound gateway receives a message (STARTTLS), checks the recipient and runs
   Rspamd.
2. It encrypts the message to the recipient's published keys, signs it with the gateway
   key, stores the ciphertext and only then answers `250`. Nothing in clear is written.

### External mail out (not E2EE)

1. The client decrypts locally, builds the MIME message and encrypts it to the outbound
   queue key (`POST /v1/outbound/messages`).
2. The outbound service decrypts it in memory, checks it, signs it with DKIM and delivers
   it to the recipient's MX. The queued ciphertext is deleted when delivery ends, and
   after 72 hours at most.

## API conventions

- Versioned by URL: `/v1/...`. Probes (`/healthz`, `/readyz`) are not versioned.
- JSON bodies only (`415` otherwise); errors are `{"error": {"code", "detail"}}`.
- Another user's resource answers `404`.
- Cookie sessions with CSRF protection on state-changing requests.
