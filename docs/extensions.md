# Extensions

An extension adds features to Agnusmail without changing its code: for example, plans
and payments for a hosted service, or an integration with your company's systems. It is
a normal Python package that depends on `agnusmail` and exposes one `Extension` object.

> An extension runs inside every Agnusmail process with their full privileges. Only
> install extensions you trust as much as Agnusmail itself, and keep the protocol's
> rule: nothing may make the server able to read users' mail.

## What an extension can add

Everything is declared on `agnusmail.extensions.Extension`:

| Field | What it does |
|---|---|
| `routers` | FastAPI routers, mounted under `/v1` |
| `raw_body_paths` | exact paths (e.g. `/v1/billing/webhook`) that accept non-JSON bodies; the route must authenticate the body itself |
| `quota_policy` | builds a `QuotaPolicy` subclass: a storage limit per account (`quota_bytes_for`) and a reason an account may not grow (`growth_refusal`) |
| `on_account_created` | called once, in the transaction that creates an account |
| `jobs`, `schedule` | background jobs (`JobSpec`) and how often they run (`Periodic`) |
| `admin_actions` | changes operators can request (two signatures, like the built-in ones) |
| `admin_credentials` | credential names whose rotation operators may record |
| `admin_account_details` | extra fields for `admin show <account>` |
| `table_privileges` | per role (`runtime`, `gateway`, `outbound`, `admin`), the privileges on the extension's **own** tables |

What it cannot do, by design: change the privileges of a table Agnusmail decides, replace
a built-in admin action or account field, or provide a second quota policy next to
another extension's. Agnusmail refuses to start in those cases.

## A minimal extension

```python
# my_extension/plugin.py
from fastapi import APIRouter

from agnusmail.extensions import Extension
from agnusmail.modules.authentication.dependencies import CurrentSession

router = APIRouter(tags=["hello"])


@router.get("/hello")
async def hello(session: CurrentSession) -> dict[str, str]:
    return {"user": session.user_id}


extension = Extension(name="hello", routers=(router,))
```

Install it next to Agnusmail and list it:

```sh
AGNUSMAIL_EXTENSIONS='["my_extension.plugin:extension"]'
```

Every process reads the same variable: the API, the worker, the SMTP services, the admin
CLI, the database role provisioning and the migrations.

## Tables and migrations

An extension keeps its tables in the same database, with its own Alembic migrations in a
second version location:

1. Define the models on `agnusmail.infrastructure.database.base.Base`, in a module the
   extension imports (importing the extension registers them).
2. Start the extension's migration history on Agnusmail's head, with its own branch label:

   ```python
   revision = "myext_0001"
   down_revision = None
   branch_labels = ("myext",)
   depends_on = "20261121_0027"  # the Agnusmail revision the tables need
   ```

3. Point Alembic at both locations, in the extension's `alembic.ini`:

   ```ini
   [alembic]
   script_location = agnusmail:migrations
   version_locations = agnusmail:migrations/versions %(here)s/migrations/versions
   path_separator = space
   ```

4. Migrate with `alembic upgrade heads` (plural: both histories), then provision the roles
   again with `python -m agnusmail.infrastructure.database.roles`. Provisioning refuses to
   run while a table has no privilege decision, so declare every new table in
   `table_privileges["runtime"]`.

New audit event types are rows of `audit_event_types`; add them in a migration:

```python
op.execute("INSERT INTO audit_event_types (name) VALUES ('myext.something_happened')")
```

and record them with `agnusmail.modules.audit.service.record_event(session, actor,
"myext.something_happened", owner_id=...)`.

## A different quota

```python
from agnusmail.core.exceptions import AgnusmailError
from agnusmail.modules.quotas.policy import QuotaPolicy


class PlanQuota(QuotaPolicy):
    def quota_bytes_for(self, session, user_id, now) -> int:
        return limit_of_the_users_plan(session, user_id, now)

    def growth_refusal(self, session, user_id, now) -> AgnusmailError | None:
        return None if has_a_paid_period(session, user_id, now) else PaymentRequiredError()


extension = Extension(name="plans", quota_policy=lambda settings: PlanQuota(quota_bytes=0))
```

The policy is used wherever storage grows: sending, uploads, the secure portal and the
inbound SMTP gateway (which answers `452` to an account that cannot receive). Reading,
moving and deleting never depend on it.

## Checklist

- [ ] Every new route checks the session (`CurrentSession` or `DeviceSession`) unless it
      is meant to be public, and checks ownership of every resource it returns.
- [ ] Webhooks in `raw_body_paths` authenticate the sender (signature, or a call back to
      the provider) before trusting anything in the body.
- [ ] Every new table is in `table_privileges`, with the least privileges that work.
- [ ] Nothing new is logged that could contain content, tokens, keys or secrets.
- [ ] Tests, including cross-account ones.
