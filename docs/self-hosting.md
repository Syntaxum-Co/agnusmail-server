# Self-hosting

`docker-compose.yml` is for development and testing only: it runs everything with the
database owner, no TLS and development credentials. This guide lists what a real
deployment needs. It does not prescribe a platform; any container runtime works.

> The project is young and the protocol has not been externally audited. Read
> [SECURITY.md](../SECURITY.md) and [THREAT_MODEL.md](../THREAT_MODEL.md) first.

## 1. Build the image

```sh
docker build -f docker/Dockerfile -t agnusmail .
```

The image runs as a non-root user (UID/GID `10001`) and contains no configuration or
secret. Every process below runs from this image with a different command.

## 2. PostgreSQL and its roles

Use PostgreSQL 17 with TLS. Create a database and an **owner** role that owns it. The owner
only runs migrations; no long-running process uses it.

```sh
# as the owner (AGNUSMAIL_DATABASE_URL points to the owner role, with sslmode=require)
alembic upgrade head

# then create or update the roles of each process, with their passwords
AGNUSMAIL_DB_APP_PASSWORD=...       \
AGNUSMAIL_DB_GATEWAY_PASSWORD=...   \
AGNUSMAIL_DB_OUTBOUND_PASSWORD=...  \
AGNUSMAIL_DB_ADMIN_PASSWORD=...     \
python -m agnusmail.infrastructure.database.roles
```

Run both commands again after every upgrade: the role command re-applies the grants, and
it refuses to run if a new table has no privilege decision.

| Role (default name) | Used by | Privileges |
|---|---|---|
| `agnusmail_app` | API, worker | the minimum DML per table (`RUNTIME_TABLE_PRIVILEGES`) |
| `agnusmail_gateway` | inbound SMTP | read recipients and keys, insert messages (`GATEWAY_TABLE_PRIVILEGES`) |
| `agnusmail_outbound` | outbound SMTP | the queue tables only (`OUTBOUND_TABLE_PRIVILEGES`) |
| `agnusmail_admin` | admin CLI | account metadata and admin tables (`ADMIN_TABLE_PRIVILEGES`) |

The maps are in `src/agnusmail/infrastructure/database/roles.py`. Role names can be changed
with `AGNUSMAIL_DB_<ROLE>_USER`. Outside `local`, every process refuses to start as a
superuser or a table owner.

## 3. Redis

Redis 7 with a password (`requirepass`), reachable only from the application network.
It holds sessions and rate-limit counters, nothing that needs a backup.

## 4. Secrets and keys

Generate them once and keep them out of the repository and the image. Key files must be
owned by UID `10001` and readable only by it (mode `0400` or `0600`); the services refuse
key files that group or others can read.

```sh
# 32+ random characters; never change it after the first user exists
python -c "import secrets; print(secrets.token_hex(32))"   # AGNUSMAIL_RECOVERY_DECOY_SECRET

python -m agnusmail.apps.smtp_inbound generate-key /keys/inbound-signing-key.pgp
python -m agnusmail.apps.smtp_outbound generate-key /keys/outbound-queue-key.pgp
python -m agnusmail.apps.smtp_outbound generate-dkim-key /keys/outbound-dkim.pem
```

The inbound gateway also needs a TLS certificate and key for its MX name (a certificate
from a public CA, or self-signed for opportunistic STARTTLS).

Pass secrets to the containers through your platform's secret mechanism where possible,
rather than plain environment variables.

## 5. Configuration

See [configuration.md](configuration.md) for every variable. A minimal production set for
the API and the worker:

```sh
AGNUSMAIL_ENVIRONMENT=production
AGNUSMAIL_DATABASE_URL=postgresql+psycopg://agnusmail_app:<password>@db:5432/agnusmail?sslmode=verify-full
AGNUSMAIL_REDIS_URL=redis://:<password>@redis:6379/0
AGNUSMAIL_FORCE_HTTPS=true
AGNUSMAIL_TRUSTED_PROXIES=["10.0.0.0/24"]        # your reverse proxy's network
AGNUSMAIL_MAIL_DOMAIN=example.com
AGNUSMAIL_SIWE_DOMAIN=app.example.com
AGNUSMAIL_SIWE_URI=https://app.example.com/login
AGNUSMAIL_RECOVERY_DECOY_SECRET=<secret>
# optional features
AGNUSMAIL_OBJECT_STORAGE_ENDPOINT=...            # attachments
AGNUSMAIL_PORTAL_BASE_URL=https://app.example.com/portal
```

## 6. Processes

| Process | Command | Notes |
|---|---|---|
| API | default command (`uvicorn agnusmail.apps.api.main:create_app --factory ...`) | port 8000, behind the reverse proxy |
| Worker | `python -m agnusmail.apps.worker` | one or more instances; jobs are leased |
| Inbound SMTP | `python -m agnusmail.apps.smtp_inbound` | publish port 25 → 2525 preserving the client IP |
| Outbound SMTP | `python -m agnusmail.apps.smtp_outbound` | outbound port 25 must be open |
| Rspamd | `rspamd/rspamd` with `docker/rspamd/` mounted | internal network only |

**Hardening for both SMTP services:** read-only root filesystem, no swap (memory limit
equal to memory + swap limit), all capabilities dropped, `no-new-privileges`, and an init
process as PID 1. The processes disable core dumps themselves and refuse to start if they
cannot; the container settings are your platform's job. The `smtp-inbound` and
`smtp-outbound` services in `docker-compose.yml` show the exact settings.

The audit chain is verified and purged daily by the worker. To run it by hand:
`python -m agnusmail.modules.audit verify` (or `purge --dry-run`).

## 7. Reverse proxy and the web client

Terminate TLS (1.2+) at a reverse proxy and forward to the API on port 8000. Serve the web
client from the same origin and route `/v1` to the API: the session cookie, CSRF checks,
SIWE and passkeys then work without CORS. Set `AGNUSMAIL_TRUSTED_PROXIES` to the proxy's
address only; a wrong value either makes every user look like the same IP or lets
clients forge theirs.

## 8. DNS

- `MX` for `MAIL_DOMAIN` → the inbound gateway's host name (`INBOUND_SMTP_HOSTNAME`), with
  `A`/`AAAA` records.
- `PTR` of the outbound IP → `OUTBOUND_HOSTNAME`, which must resolve back to that IP.
- SPF, DKIM and DMARC: print them with `python -m agnusmail.apps.smtp_outbound dns-records`.

## 9. Operators

Administrative changes (suspending an account, lifting a restriction, adding an operator)
need two operators, each signing with their own wallet. Add the first two on the server,
with the admin role:

```sh
python -m agnusmail.apps.admin bootstrap-operator 0x...first
python -m agnusmail.apps.admin bootstrap-operator 0x...second
```

## 10. Backups

- The database: `pg_dump` as the owner, encrypted, stored off the server, and restored
  regularly as a test.
- The key files and `RECOVERY_DECOY_SECRET`: losing the queue key loses queued outbound
  mail; losing the inbound signing key only requires a new one (old certificates stay
  published).
- Object storage: use the provider's versioning or replication.

Redis needs no backup.

## Checklist

- [ ] `AGNUSMAIL_ENVIRONMENT=production` on every process
- [ ] separate database roles; TLS to PostgreSQL; Redis with a password; neither public
- [ ] HTTPS at the proxy; `FORCE_HTTPS=true`; `TRUSTED_PROXIES` set to the proxy only
- [ ] key files owned by UID 10001, mode 0400/0600, and backed up
- [ ] SMTP containers hardened (read-only, no swap, no capabilities, init)
- [ ] DNS: MX, PTR, SPF, DKIM, DMARC
- [ ] two operators bootstrapped
- [ ] database backups tested; monitoring of `/readyz` and, optionally, `/metrics`
