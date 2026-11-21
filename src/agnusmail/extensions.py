"""Extension points: add features to Agnusmail without changing its code.

An extension is a Python package that exposes an ``Extension`` object. The operator
lists it in ``AGNUSMAIL_EXTENSIONS`` (``"package.module:attribute"``), and every process
loads the same list: the API, the worker, the SMTP services, the admin CLI, the database
role provisioning and the migrations. See ``docs/extensions.md``.

An extension runs inside those processes with their full privileges. Only list code you
trust as much as Agnusmail itself.

What an extension can add, and nothing else:

- HTTP routers (mounted under ``/v1``), and exact paths that take non-JSON bodies
  (webhooks from third parties);
- its own storage quota policy (a subclass of ``QuotaPolicy``);
- a hook called in the transaction that creates an account;
- background jobs and their schedule;
- administrative actions (two operators) and fields in ``admin show``;
- database privileges for its own tables, per role. It can never change the privileges
  of a table that Agnusmail already decides.

Its tables and audit event types come from its own Alembic migrations (a second version
location, see ``docs/extensions.md``).
"""

import importlib
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import APIRouter
    from sqlalchemy.orm import Session

    from agnusmail.core.config import Settings
    from agnusmail.modules.admin.service import Kind
    from agnusmail.modules.identity.models import User
    from agnusmail.modules.jobs.handlers import Periodic
    from agnusmail.modules.jobs.queue import JobSpec
    from agnusmail.modules.quotas.policy import QuotaPolicy

# "package.module:attribute", Python identifiers only.
REFERENCE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$"
)
# Database roles an extension can grant privileges to (infrastructure/database/roles.py).
ROLES = ("runtime", "gateway", "outbound", "admin")
PRIVILEGES = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})

AccountCreatedHook = Callable[["Session", "User", datetime], None]
AccountDetails = Callable[["Session", "User", datetime], dict[str, Any]]


class ExtensionError(RuntimeError):
    """A configured extension cannot be loaded or is inconsistent: the process stops."""


@dataclass(frozen=True)
class Extension:
    name: str
    routers: Sequence["APIRouter"] = ()
    # Exact request paths (e.g. "/v1/billing/webhook") that accept non-JSON bodies.
    raw_body_paths: frozenset[str] = frozenset()
    # Builds the storage quota policy used everywhere (API, SMTP gateway, admin).
    quota_policy: Callable[["Settings"], "QuotaPolicy"] | None = None
    # Called once, in the transaction that creates the account (first SIWE login).
    on_account_created: AccountCreatedHook | None = None
    jobs: Sequence["JobSpec"] = ()
    schedule: Sequence["Periodic"] = ()
    admin_actions: Mapping[str, "Kind"] = field(default_factory=dict)
    # Credential names whose rotation operators may record (names only, never values).
    admin_credentials: frozenset[str] = frozenset()
    # Extra fields shown by ``python -m agnusmail.apps.admin show <account>``.
    admin_account_details: AccountDetails | None = None
    # role -> table -> privileges, for the extension's own tables only.
    table_privileges: Mapping[str, Mapping[str, tuple[str, ...]]] = field(default_factory=dict)


@dataclass(frozen=True)
class Extensions:
    """The loaded extensions, and their contributions merged."""

    items: tuple[Extension, ...] = ()

    def routers(self) -> list["APIRouter"]:
        return [router for extension in self.items for router in extension.routers]

    def raw_body_paths(self) -> frozenset[str]:
        return frozenset(path for extension in self.items for path in extension.raw_body_paths)

    def quota_policy(self, settings: "Settings") -> "QuotaPolicy":
        from agnusmail.modules.quotas.policy import QuotaPolicy

        builders = [e.quota_policy for e in self.items if e.quota_policy is not None]
        if len(builders) > 1:
            raise ExtensionError("only one extension may provide the quota policy")
        if builders:
            return builders[0](settings)
        return QuotaPolicy.from_settings(settings)

    def account_created_hooks(self) -> list[AccountCreatedHook]:
        return [e.on_account_created for e in self.items if e.on_account_created is not None]

    def jobs(self, base: Iterable["JobSpec"]) -> list["JobSpec"]:
        return [*base, *(spec for extension in self.items for spec in extension.jobs)]

    def schedule(self, base: Iterable["Periodic"]) -> tuple["Periodic", ...]:
        extra = (periodic for extension in self.items for periodic in extension.schedule)
        return (*base, *extra)

    def admin_actions(self, base: Mapping[str, "Kind"]) -> dict[str, "Kind"]:
        merged = dict(base)
        for extension in self.items:
            for kind, spec in extension.admin_actions.items():
                if kind in merged:
                    raise ExtensionError(f"{extension.name}: admin action {kind!r} exists")
                merged[kind] = spec
        return merged

    def admin_credentials(self, base: frozenset[str]) -> frozenset[str]:
        return base.union(*(extension.admin_credentials for extension in self.items))

    def admin_account_details(self) -> list[AccountDetails]:
        return [e.admin_account_details for e in self.items if e.admin_account_details]

    def privileges(
        self, role: str, base: Mapping[str, tuple[str, ...]]
    ) -> dict[str, tuple[str, ...]]:
        """``base`` plus the extensions' tables for ``role``. Extensions may only add
        tables: one that touches a table Agnusmail decides is refused."""
        if role not in ROLES:
            raise ExtensionError(f"unknown role {role!r}")
        merged = dict(base)
        for extension in self.items:
            for table, privileges in extension.table_privileges.get(role, {}).items():
                if table in merged:
                    raise ExtensionError(
                        f"{extension.name}: privileges on {table!r} are already decided"
                    )
                if not privileges or not set(privileges) <= PRIVILEGES:
                    raise ExtensionError(f"{extension.name}: invalid privileges on {table!r}")
                merged[table] = tuple(privileges)
        return merged


def load(references: Sequence[str]) -> Extensions:
    """Import each ``"package.module:attribute"`` and check it is an ``Extension``."""
    items: list[Extension] = []
    for reference in references:
        if not REFERENCE.fullmatch(reference):
            raise ExtensionError(f"invalid extension reference {reference!r}")
        module_name, _, attribute = reference.partition(":")
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise ExtensionError(f"cannot import extension module {module_name!r}") from exc
        extension = getattr(module, attribute, None)
        if not isinstance(extension, Extension):
            raise ExtensionError(f"{reference!r} is not an agnusmail Extension")
        if any(other.name == extension.name for other in items):
            raise ExtensionError(f"extension {extension.name!r} is listed twice")
        unknown = set(extension.table_privileges) - set(ROLES)
        if unknown:
            raise ExtensionError(f"{extension.name}: unknown roles {sorted(unknown)}")
        items.append(extension)
    return Extensions(tuple(items))


def from_settings(settings: "Settings") -> Extensions:
    return load(settings.extensions)


def from_environment(environ: Mapping[str, str] = os.environ) -> Extensions:
    """For the tools that run without the full settings (role provisioning, migrations):
    ``AGNUSMAIL_EXTENSIONS`` as a JSON list, like the settings read it."""
    raw = environ.get("AGNUSMAIL_EXTENSIONS", "").strip() or "[]"
    try:
        references = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExtensionError("AGNUSMAIL_EXTENSIONS must be a JSON list of strings") from exc
    if not isinstance(references, list) or not all(isinstance(r, str) for r in references):
        raise ExtensionError("AGNUSMAIL_EXTENSIONS must be a JSON list of strings")
    return load(references)
