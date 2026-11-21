# Configuration

Every setting is an environment variable with the `AGNUSMAIL_` prefix. A `.env` file in
the working directory is also read. The source of truth, with validation rules, is
[`src/agnusmail/core/config.py`](../src/agnusmail/core/config.py); invalid values stop the
process at startup.

Lists are JSON (`AGNUSMAIL_CORS_ALLOWED_ORIGINS='["https://app.example.com"]'`). Sizes are
bytes, durations are seconds unless the name says otherwise.

## Environment and hardening

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `production` | `local`, `staging` or `production`. Anything but `local` turns on the checks below; development opts into `local` explicitly (`.env.example`). |

Outside `local`, the processes refuse to start unless:

- `DATABASE_URL` sets `sslmode=require`, `verify-ca` or `verify-full`;
- `FORCE_HTTPS=true`;
- `SIWE_DOMAIN`, `SIWE_URI` (https) and `MAIL_DOMAIN` are set explicitly;
- `PORTAL_BASE_URL`, if set, uses https;
- `RECOVERY_DECOY_SECRET` is set (32+ characters);
- `OUTBOUND_RELAY` is unset (production only);
- the database role is not a superuser or a table owner (see
  [self-hosting](self-hosting.md#database-roles));
- the SMTP services also have their keys, TLS files, Rspamd and process hardening (see
  below).

## Required

| Variable | Notes |
|---|---|
| `DATABASE_URL` | `postgresql+psycopg://user:password@host:5432/db`. Never logged. |
| `REDIS_URL` | `redis://[:password@]host:6379/0`. Never logged. |

## Identity and sessions

| Variable | Default | Notes |
|---|---|---|
| `SIWE_DOMAIN` | `app.agnusmail` | Host (and port) of the web client; also the WebAuthn relying party and the protocol's `service`. |
| `SIWE_URI` | `https://app.agnusmail/login` | Expected SIWE URI. |
| `SIWE_CHAIN_ID` | `1` | Signing a SIWE message costs no gas on any chain. |
| `SIWE_CLOCK_SKEW_SECONDS` | `60` | |
| `SESSION_COOKIE_MAX_AGE_SECONDS` | `86400` | Idle (sliding) lifetime. |
| `SESSION_ABSOLUTE_TTL_SECONDS` | `604800` | Hard cap, renewals included. |
| `SESSION_COOKIE_SAMESITE` | `lax` | `none` requires `FORCE_HTTPS=true`. |
| `MAX_SESSIONS_PER_USER` | `10` | |
| `SESSION_BIND_USER_AGENT` | `true` | Revoke a session presented with another User-Agent. |
| `STEP_UP_MAX_AUTH_AGE_SECONDS` | `600` | Sensitive changes need a login this recent. |
| `MAX_DEVICES_PER_USER` | `10` | Pending + active. |
| `MAX_PASSKEYS_PER_USER` | `10` | |
| `MAX_KEYS_PER_DEVICE` | `100` | |
| `MAX_PUBLIC_KEY_BYTES` | `8192` | |

## HTTP

| Variable | Default | Notes |
|---|---|---|
| `FORCE_HTTPS` | `false` | Refuse plain HTTP (400), send HSTS, mark cookies `Secure`. |
| `CORS_ALLOWED_ORIGINS` | `[]` | Exact origins; `*` is refused. Not needed when the client is served from the same origin. |
| `TRUSTED_PROXIES` | `[]` | IPs/CIDRs allowed to set `X-Forwarded-For`/`-Proto`. Empty: the socket peer is used. |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | |
| `REQUEST_TIMEOUT_SECONDS` | `30` | |
| `MAX_CONCURRENT_REQUESTS` | `100` | |
| `READINESS_TIMEOUT_SECONDS` | `2.0` | |
| `RATE_LIMIT_PER_IP` | `120` | Every route, per window. |
| `RATE_LIMIT_AUTH_PER_IP` | `20` | Login routes. |
| `RATE_LIMIT_PER_USER` | `300` | Authenticated routes. |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | |

## Database and Redis tuning

| Variable | Default |
|---|---|
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `10` / `5` |
| `DB_POOL_TIMEOUT_SECONDS` | `30` |
| `DB_STATEMENT_TIMEOUT_MS` | `30000` |
| `DB_CONNECT_TIMEOUT_SECONDS` | `5` |
| `REDIS_POOL_MAX_CONNECTIONS` | `10` |
| `REDIS_SOCKET_TIMEOUT_SECONDS` / `REDIS_CONNECT_TIMEOUT_SECONDS` | `1.0` / `1.0` |
| `REDIS_HEALTH_CHECK_INTERVAL_SECONDS` | `30` |

## Mail

| Variable | Default | Notes |
|---|---|---|
| `MAIL_DOMAIN` | `mail.agnusmail.localhost` | Domain of users' addresses (`name@MAIL_DOMAIN`). |
| `STORAGE_QUOTA_BYTES` | `5368709120` (5 GiB) | Per account: messages it holds, its attachments and portal messages. |
| `MAX_MESSAGE_BYTES` | `524288` | Encrypted body; larger content goes in attachments. |
| `MAX_MESSAGE_RECIPIENTS` | `20` | |

## Attachments (S3-compatible storage)

Unset `OBJECT_STORAGE_ENDPOINT` disables attachments (the routes answer 503).

| Variable | Default | Notes |
|---|---|---|
| `OBJECT_STORAGE_ENDPOINT` | — | e.g. `https://s3.us-west-000.example.com` |
| `OBJECT_STORAGE_REGION` | `us-east-1` | |
| `OBJECT_STORAGE_BUCKET` | — | A private bucket used only for attachments. |
| `OBJECT_STORAGE_ACCESS_KEY` / `OBJECT_STORAGE_SECRET_KEY` | — | Credentials restricted to that bucket. |
| `MAX_ATTACHMENT_BYTES` | `26214400` | |
| `MAX_ATTACHMENTS_PER_MESSAGE` | `10` | |
| `ATTACHMENT_UPLOAD_URL_TTL_SECONDS` | `900` | |
| `ATTACHMENT_DOWNLOAD_URL_TTL_SECONDS` | `60` | |
| `ATTACHMENT_ORPHAN_HOURS` | `24` | Uploads never attached are deleted after this. |

The bucket needs a CORS rule for the web client's origin (`PUT`, `GET`, `HEAD`), since
browsers upload and download directly.

## Recovery

| Variable | Default | Notes |
|---|---|---|
| `RECOVERY_DECOY_SECRET` | — | Key of the decoy backups returned for unknown accounts. 32+ random characters. **Never change it** once in use: that would change every decoy at once and reveal which accounts are real. |

## Inbound SMTP gateway

| Variable | Default | Notes |
|---|---|---|
| `INBOUND_SMTP_HOST` / `INBOUND_SMTP_PORT` | `127.0.0.1` / `2525` | |
| `INBOUND_SMTP_HOSTNAME` | — | The MX name (greeting, `Received`). |
| `INBOUND_SIGNING_KEY_FILE` | — | Created by `python -m apps.smtp_inbound generate-key <path>`; mode 0600. Required. |
| `INBOUND_TLS_CERT_FILE` / `INBOUND_TLS_KEY_FILE` | — | PEM; required outside `local`. |
| `INBOUND_RSPAMD_URL` | — | `http://host:11333`, internal network; required outside `local`. |
| `INBOUND_RSPAMD_TIMEOUT_SECONDS` | `30` | |
| `INBOUND_MAX_UNKNOWN_RECIPIENTS` | `5` | Per connection, then it closes. |
| `INBOUND_IDLE_TIMEOUT_SECONDS` / `INBOUND_MAX_CONNECTION_SECONDS` | `120` / `600` | |
| `INBOUND_MAX_CONNECTIONS` / `INBOUND_MAX_CONNECTIONS_PER_IP` | `200` / `10` | |
| `INBOUND_PROXY_PROTOCOL` / `INBOUND_TRUSTED_PROXIES` | `false` / `[]` | PROXY protocol v1/v2 from these peers only. |
| `INBOUND_PROXY_TIMEOUT_SECONDS` | `10` | |
| `INBOUND_UNKNOWN_RECIPIENTS_PER_IP_PER_HOUR` | `30` | |
| `INBOUND_MESSAGES_PER_IP_PER_HOUR` | `300` | |

## Outbound SMTP (not end-to-end encrypted)

| Variable | Default | Notes |
|---|---|---|
| `OUTBOUND_KEY_FILE` | — | Queue key, created by `python -m apps.smtp_outbound generate-key <path>`; mode 0600. |
| `OUTBOUND_PREVIOUS_KEY_FILES` | `[]` | Old queue keys, kept 72 h after a rotation. |
| `OUTBOUND_DKIM_KEY_FILE` | — | Created by `python -m apps.smtp_outbound generate-dkim-key <path>`. |
| `OUTBOUND_DKIM_SELECTOR` | `agnus1` | |
| `OUTBOUND_HOSTNAME` | — | EHLO name, with matching A/AAAA and PTR. Required outside `local`. |
| `OUTBOUND_SMTP_PORT` | `25` | |
| `OUTBOUND_RELAY` | — | `host:port` to send everything to (development and tests only). |
| `OUTBOUND_REQUIRE_TLS` | `false` | Refuse servers without STARTTLS. |
| `OUTBOUND_MAX_MESSAGE_BYTES` / `OUTBOUND_MAX_RECIPIENTS` | `524288` / `50` | |
| `OUTBOUND_MESSAGES_PER_HOUR` / `OUTBOUND_RECIPIENTS_PER_DAY` | `30` / `300` | Per account; fail closed without Redis. |
| `OUTBOUND_PER_DOMAIN_PER_HOUR` | `100` | Recipients per destination domain. |
| `OUTBOUND_POLL_SECONDS` / `OUTBOUND_BATCH_SIZE` / `OUTBOUND_LEASE_SECONDS` | `5` / `10` / `600` | |
| `OUTBOUND_SMTP_TIMEOUT_SECONDS` | `60` | |

## Secure portal

Unset `PORTAL_BASE_URL` disables the portal (503).

| Variable | Default | Notes |
|---|---|---|
| `PORTAL_BASE_URL` | — | The web client's portal page; links are `{PORTAL_BASE_URL}#{token}`. |
| `PORTAL_MAX_RECIPIENTS` | `20` | |
| `PORTAL_MAX_MESSAGE_BYTES` | `524288` | |
| `PORTAL_MAX_DAYS` | `30` | |
| `PORTAL_MAX_REPLIES_PER_LINK` | `5` | |
| `PORTAL_ACCESS_PER_IP_PER_MINUTE` / `PORTAL_REPLIES_PER_IP_PER_HOUR` | `30` / `20` | |

## Abuse limits

| Variable | Default | Notes |
|---|---|---|
| `INTERNAL_MESSAGES_PER_HOUR` / `INTERNAL_RECIPIENTS_PER_DAY` | `200` / `2000` | E2EE mail, per account. |
| `ABUSE_RESTRICTED_MESSAGES_PER_DAY` | `20` | What a restricted account may still send internally. |
| `DEVICE_REGISTRATIONS_PER_DAY` | `10` | Per account. |
| `NEW_ACCOUNTS_PER_IP_PER_DAY` | `10` | |
| `ABUSE_REPORT_THRESHOLD` / `ABUSE_REPORT_WINDOW_DAYS` | `5` / `7` | Distinct reporters that trigger a restriction. |
| `ABUSE_BOUNCE_RATIO` / `ABUSE_BOUNCE_MINIMUM` | `0.3` / `20` | Outbound bounce rate that triggers a restriction. |
| `ABUSE_RESTRICTION_DAYS` | `7` | |

## Background worker and audit

| Variable | Default | Notes |
|---|---|---|
| `WORKER_POLL_SECONDS` / `WORKER_LEASE_SECONDS` / `WORKER_BATCH_SIZE` | `5` / `900` / `10` | |
| `AUDIT_RETENTION_DAYS` | `365` | Can only be made longer; the database refuses to delete younger events. |

## Metrics

| Variable | Default | Notes |
|---|---|---|
| `METRICS_PORT` | — | Each process serves Prometheus `/metrics` on this port when set. Keep it on an internal network. |
| `METRICS_HOST` | `0.0.0.0` | |
