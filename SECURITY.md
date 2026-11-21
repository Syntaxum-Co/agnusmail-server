# Security

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub: on this repository, open the **Security** tab and
choose **Report a vulnerability**. Include what you found, how to reproduce it and the
impact you expect. We will acknowledge the report, keep you informed while we fix it, and
credit you in the release notes if you wish.

In scope: this repository's code, its default configuration and its documentation (for
example, a protocol flaw in `docs/specs/`). Out of scope: denial of service by sheer
volume, findings that need a compromised user device, and issues in third-party
dependencies that are already public (please still tell us if we are affected).

## Supported versions

The project is pre-1.0. Only the latest commit on the default branch receives security
fixes.

## Security model

### The central guarantee

**The backend cannot decrypt users' messages.** This is a property of the architecture
and it is checked by tests:

- There is no decryption function in the backend, not even for support, administration
  or debugging.
- The backend receives **public** keys only; private keys and their passphrases never
  reach the server.
- Attachments and recovery backups are stored **already encrypted**.
- **Inbound SMTP** is an operational exception: the gateway receives plaintext from the
  external sender and turns it into ciphertext with the recipients' public keys. It never
  decrypts anything; its own key can sign but cannot decrypt.
- **The one exception: outbound SMTP**, which is labeled not end-to-end encrypted. The
  outbound queue holds content the user handed over for delivery to a regular mailbox,
  encrypted to a key that only the outbound service holds; the service decrypts it in
  memory to deliver it and deletes it within 72 hours. That key never applies to E2EE
  messages, attachments, backups or user keys. A test makes sure no other module
  decrypts (`tests/unit/test_outbound_service.py`).

What the server does see is routing metadata: sender and recipient accounts, device
fingerprints, times, sizes and delivery state. See [THREAT_MODEL.md](THREAT_MODEL.md).

### Authentication and sessions

- Sign-In with Ethereum (EIP-4361): single-use nonces with expiry; domain, URI, chain id
  and time checks; replay protection.
- Opaque server-side sessions in Redis; `HttpOnly`, `Secure` (in production) and
  `SameSite` cookies; idle and absolute lifetimes; a session limit per user; logout and
  revocation.
- Suspicious-session detection: a session presented with another User-Agent than the
  one that logged in is revoked.
- Suspending an account (admin CLI, two operators) refuses its logins and ends its open
  sessions on their next request.
- Optional passkey login (WebAuthn): phishing-resistant, user verification required,
  signature counter checked. Each passkey is approved by the wallet (EIP-712); the wallet
  is still required to authorize devices.
- Sessions are bound to a device by a challenge signed with the device's signing subkey.
  Revoking a device ends its sessions, and sensitive routes re-check in the database that
  the device is still active.

### HTTP

- HTTPS enforced outside local development; HSTS; security headers.
- CORS with an allowlist (a wildcard is refused at startup); CSRF protection for
  cookie-authenticated requests; JSON-only request bodies.
- Limits on body size, request time, concurrency and page size.
- Strict validation of every input (Pydantic v2); validation errors never echo the
  submitted values.
- Forwarded headers are trusted only from configured proxies.

### Authorization and isolation

- Deny by default; every resource is checked against its owner. Another user's resource
  answers 404 (no existence oracle).
- No mass assignment: request models list exactly the accepted fields.
- Cross-account access tests for every resource type.

### Devices and the public key directory

- Only public OpenPGP v6 certificates of the protocol's profile are accepted, validated
  on upload (structure, post-quantum subkey, expiry, bindings) with a proof of possession
  bound to the account and the service. Secret key packets and textual private key
  encodings are refused.
- A device becomes active only with an EIP-712 certificate signed by the account's
  wallet over the device's fingerprint; the directory publishes it so senders can verify
  it without trusting the server.
- The directory publishes only active keys of active devices of active accounts; an
  unknown address returns an empty list (no enumeration).

### Audit trail

- Every security-relevant change writes an event to `audit_events` in the same
  transaction. The table is append-only in PostgreSQL (triggers).
- Each user's events form a SHA-256 hash chain ([spec](docs/specs/audit-chain-v1.md))
  that the user's own client can verify through `GET /v1/audit/*`.
- Deletion happens only through the retention purge: events older than 365 days by the
  database clock, after a checkpoint is recorded. A broken chain is never purged.

### Database roles

- The API, the worker, the inbound gateway, the outbound service and the admin CLI each
  connect with their own PostgreSQL role, holding only the table privileges they need
  (`src/agnusmail/infrastructure/database/roles.py`). None of them owns a table, so none
  can disable the triggers.
- Outside local development, every process refuses to start as a superuser or as a table
  owner; the SMTP services and the admin CLI also refuse any privilege beyond their map.

### Messages, attachments and recovery

- The server stores the SEIPDv2 body and one v6 PKESK per device key, and checks their
  structure by reading fixed-size headers, without decrypting anything.
- Attachments go straight from the client to S3-compatible storage through presigned
  URLs; the server keeps only size, declared digest, owner and message. Downloads use
  60-second URLs, for the owner and the participants only.
- The server stores the **public** recovery certificate and the **encrypted** backup of
  its secret key; it checks only the backup's structure and never receives the 24 words.
  The unauthenticated backup fetch returns a stable decoy for unknown accounts, so it does
  not reveal which accounts exist.
- There is no operator-assisted recovery: without devices and without the 24 words, old
  messages are unrecoverable by design.

### SMTP

- Inbound gateway: a separate, non-dumpable process in a read-only container without
  swap; its own narrow database role; antispam (Rspamd) runs before encryption and keeps
  nothing; nothing in clear is ever written. Proven by
  `tests/integration/test_inbound_no_plaintext.py` and `scripts/inbound-no-persistence.sh`.
- Outbound service: the same process hardening; it checks `From` after decrypting (nobody
  sends as another address), connects only to public addresses on port 25 (an MX pointing
  at an internal network is refused) and signs with DKIM. Per-account sending limits fail
  closed.
- Secure portal: shared-secret E2EE. The server stores only the OpenPGP envelope and checks
  its parameters (Argon2 t ≥ 3, p ≥ 4, m ≥ 2^16 KiB; AES-256/OCB). Link tokens are 256-bit,
  stored only as SHA-256, and travel in the URL fragment and `POST` bodies (never in access
  logs). Public routes are rate-limited per IP.

### Abuse controls

- Metadata only: reports (message, category, reporter — never content), outbound
  bounces and counters in Redis. A test keeps the abuse module away from message bodies.
- Automatic, temporary restriction (no external sending or portal, a small internal
  quota), audited and visible to the owner; nothing is ever deleted.
- Limits against mass sign-up: new accounts per IP and day, device registrations per
  account and day.

### Extensions

- Extensions ([docs/extensions.md](docs/extensions.md)) are loaded only from the explicit
  `AGNUSMAIL_EXTENSIONS` list, never discovered automatically. They run with each
  process's privileges, so only list code you trust.
- An extension can add tables, routes, jobs and admin actions, but it cannot change the
  privileges of a built-in table, replace a built-in admin action or field, or bypass the
  database roles: Agnusmail refuses to start if it tries.

### Secrets and logs

- No secret in the code or in the image; configuration comes from the environment at
  runtime.
- Structured logs with mandatory redaction: message content, tokens, passwords, keys and
  secrets are never logged. Tests cover the redaction.

### Cryptography

- Only maintained libraries: Sequoia (`pysequoia`) for OpenPGP, `eth-account` for
  EIP-712/SIWE, `webauthn` for passkeys, `cryptography` for infrastructure (DKIM, TLS).
- No home-made cryptographic protocol: the protocol is a profile of existing standards
  ([spec](docs/specs/protocol-v1.md)), with public test vectors and interoperability tests
  against OpenPGP.js.

## Before you run it for real users

This is a young project. Before serving real users, at least: deploy with separate
database roles and TLS everywhere (see [docs/self-hosting.md](docs/self-hosting.md)),
back up the database and your key files, set up monitoring, and get an independent
security review. The protocol has not been externally audited.
