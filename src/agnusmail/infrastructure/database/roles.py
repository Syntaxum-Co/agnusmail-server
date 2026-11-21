"""PostgreSQL roles: the owner migrates, the API runs as a runtime role, and
the inbound SMTP gateway runs as its own, narrower role.

The owner (the role that runs Alembic) owns every table and trigger. The runtime role
gets only the table privileges below. It owns nothing, so it cannot ``ALTER TABLE``,
drop or disable triggers, or truncate. It is not a superuser, so it cannot set
``session_replication_role`` to skip triggers.

    python -m agnusmail.infrastructure.database.roles

runs as the owner after every migration. It creates or
updates the runtime role, sets its password from a SCRAM verifier computed on the
client (the password itself never reaches the server or its logs), and re-applies the
grants. A table missing from ``RUNTIME_TABLE_PRIVILEGES`` stops provisioning: every new
table needs an explicit decision. With ``AGNUSMAIL_DB_GATEWAY_PASSWORD`` set it also
provisions the gateway role (``GATEWAY_TABLE_PRIVILEGES``; every other table: nothing),
and with ``AGNUSMAIL_DB_OUTBOUND_PASSWORD`` the outbound service's role
(``OUTBOUND_TABLE_PRIVILEGES``).
"""

import json
import os
import re
import sys
from typing import Any

from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from agnusmail.core.logging import get_logger

log = get_logger(__name__)

# Least privilege per table. Nothing in the application deletes users, devices or keys
# (they change status). audit_events: no UPDATE (append-only); DELETE only through the
# guarded retention purge. audit_chain_heads: rows are never deleted.
RUNTIME_TABLE_PRIVILEGES: dict[str, tuple[str, ...]] = {
    "users": ("SELECT", "INSERT", "UPDATE"),
    "devices": ("SELECT", "INSERT", "UPDATE"),
    "public_keys": ("SELECT", "INSERT", "UPDATE"),
    "audit_events": ("SELECT", "INSERT", "DELETE"),
    "audit_chain_heads": ("SELECT", "INSERT", "UPDATE"),
    # Never deleted, except addresses on a custom domain that is removed or
    # changes hands; a trigger refuses deleting any other kind.
    "mail_addresses": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "mail_domains": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "jobs": ("SELECT", "INSERT", "UPDATE", "DELETE"),  # finished jobs are cleaned up
    "passkey_credentials": ("SELECT", "INSERT", "UPDATE"),  # revoked, never deleted
    # Messages: ciphertext is never rewritten; only the mailbox state changes.
    "messages": ("SELECT", "INSERT", "DELETE"),  # deleted from the trash
    "message_keys": ("SELECT", "INSERT", "DELETE"),
    "mailbox_entries": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "account_usage": ("SELECT", "INSERT", "UPDATE"),
    "attachments": ("SELECT", "INSERT", "UPDATE"),  # deleted = status, row kept
    "recovery_keys": ("SELECT", "INSERT", "UPDATE"),  # replaced, never deleted
    "recovery_backups": ("SELECT", "INSERT"),  # versions are immutable
    "account_migrations": ("SELECT", "INSERT", "UPDATE"),
    "gateway_keys": ("SELECT", "INSERT"),  # public history, never changed
    # Outbound queue (spec §10): the API queues, the worker purges at 72 h and deletes
    # old delivery records; it never reads the payload back.
    "outbound_keys": ("SELECT",),
    "outbound_messages": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "outbound_recipients": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    # Secure portal (spec §11): envelopes are never rewritten; deleted at expiry.
    "portal_messages": ("SELECT", "INSERT", "DELETE"),
    "portal_links": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "mail_folders": ("SELECT", "INSERT", "UPDATE", "DELETE"),  # names: ciphertext only
    "abuse_reports": ("SELECT", "INSERT"),  # metadata only, never changed
    "account_restrictions": ("SELECT", "INSERT", "UPDATE"),
}
# The inbound gateway (spec §9) resolves recipients, re-checks wallet attestations and
# writes ciphertext. It reads no message, mailbox, audit, session or job data and
# changes no existing row.
GATEWAY_TABLE_PRIVILEGES: dict[str, tuple[str, ...]] = {
    "users": ("SELECT",),
    "mail_addresses": ("SELECT",),
    "mail_domains": ("SELECT",),  # custom domains
    "devices": ("SELECT",),
    "public_keys": ("SELECT",),
    "recovery_keys": ("SELECT",),
    "account_migrations": ("SELECT",),
    "messages": ("INSERT",),
    "message_keys": ("INSERT",),
    "mailbox_entries": ("INSERT",),
    "account_usage": ("SELECT", "INSERT", "UPDATE"),  # counts what it delivers
    "gateway_keys": ("SELECT", "INSERT"),
}
DEFAULT_GATEWAY_ROLE = "agnusmail_gateway"
# The outbound service (spec §10) reads and settles its queue and publishes its queue
# key. It reads no user, key, message or audit data, inserts no message and deletes
# nothing (expired rows are cleaned up by the worker).
OUTBOUND_TABLE_PRIVILEGES: dict[str, tuple[str, ...]] = {
    "outbound_keys": ("SELECT", "INSERT"),
    "outbound_messages": ("SELECT", "UPDATE"),
    "outbound_recipients": ("SELECT", "UPDATE"),
}
DEFAULT_OUTBOUND_ROLE = "agnusmail_outbound"
TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
# Tables the runtime role must not touch at all.
OWNER_ONLY_TABLES = frozenset({"alembic_version"})
# Administration: only the admin role touches these; the API's
# runtime role gets nothing on them, so a compromised API cannot add operators.
ADMIN_ONLY_TABLES = frozenset({"operators", "admin_actions", "admin_signatures"})
ADMIN_TABLE_PRIVILEGES: dict[str, tuple[str, ...]] = {
    "users": ("SELECT", "UPDATE"),  # suspend and reinstate (users.status)
    "mail_addresses": ("SELECT",),
    "mail_domains": ("SELECT",),
    "devices": ("SELECT",),
    "account_usage": ("SELECT",),
    "account_restrictions": ("SELECT", "UPDATE"),
    "abuse_reports": ("SELECT",),
    "audit_events": ("SELECT", "INSERT"),
    "audit_chain_heads": ("SELECT", "INSERT", "UPDATE"),
    "operators": ("SELECT", "INSERT", "UPDATE"),
    "admin_actions": ("SELECT", "INSERT", "UPDATE"),
    "admin_signatures": ("SELECT", "INSERT"),
}
DEFAULT_ADMIN_ROLE = "agnusmail_admin"

ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
DEFAULT_RUNTIME_ROLE = "agnusmail_app"
ROLE_ATTRIBUTES = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"


class RoleProvisioningError(RuntimeError):
    pass


def _quote(connection: Connection, identifier: str) -> str:
    return connection.dialect.identifier_preparer.quote_identifier(identifier)


def _scram_verifier(connection: Connection, role: str, password: str) -> str:
    """SCRAM-SHA-256 verifier computed by libpq on the client (like psql's \\password)."""
    raw: Any = connection.connection.driver_connection
    verifier: bytes = raw.pgconn.encrypt_password(
        password.encode(), role.encode(), b"scram-sha-256"
    )
    value = verifier.decode("ascii")
    if not value.startswith("SCRAM-SHA-256$") or "'" in value:
        raise RoleProvisioningError("unexpected password verifier format")
    return value


def _public_tables(connection: Connection) -> set[str]:
    rows = connection.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))
    return set(rows.scalars())


def provision_runtime_role(connection: Connection, role: str, password: str | None) -> bool:
    """Create/update the API's ``role`` and re-apply its grants. True if it was created."""
    tables = _public_tables(connection) if connection.dialect.name == "postgresql" else set()
    undecided = tables - set(RUNTIME_TABLE_PRIVILEGES) - OWNER_ONLY_TABLES - ADMIN_ONLY_TABLES
    missing = set(RUNTIME_TABLE_PRIVILEGES) - tables
    if connection.dialect.name == "postgresql" and (undecided or missing):
        raise RoleProvisioningError(
            f"privilege map out of date: undecided={sorted(undecided)} missing={sorted(missing)}"
        )
    return _provision(connection, role, password, RUNTIME_TABLE_PRIVILEGES, sequences=True)


def _provision_service(
    connection: Connection,
    role: str,
    password: str | None,
    privileges: dict[str, tuple[str, ...]],
    label: str,
) -> bool:
    if connection.dialect.name == "postgresql":
        missing = set(privileges) - _public_tables(connection)
        if missing:
            raise RoleProvisioningError(f"{label} privilege map out of date: {sorted(missing)}")
    return _provision(connection, role, password, privileges, sequences=False)


def provision_gateway_role(connection: Connection, role: str, password: str | None) -> bool:
    """Create/update the gateway's ``role``: only ``GATEWAY_TABLE_PRIVILEGES``."""
    return _provision_service(connection, role, password, GATEWAY_TABLE_PRIVILEGES, "gateway")


def provision_admin_role(connection: Connection, role: str, password: str | None) -> bool:
    """Create/update the admin CLI's ``role``: only ``ADMIN_TABLE_PRIVILEGES`` (plus the
    audit sequence, to append events)."""
    if connection.dialect.name == "postgresql":
        missing = set(ADMIN_TABLE_PRIVILEGES) - _public_tables(connection)
        if missing:
            raise RoleProvisioningError(f"admin privilege map out of date: {sorted(missing)}")
    return _provision(connection, role, password, ADMIN_TABLE_PRIVILEGES, sequences=True)


def provision_outbound_role(connection: Connection, role: str, password: str | None) -> bool:
    """Create/update the outbound service's ``role``: only ``OUTBOUND_TABLE_PRIVILEGES``."""
    return _provision_service(connection, role, password, OUTBOUND_TABLE_PRIVILEGES, "outbound")


def _provision(
    connection: Connection,
    role: str,
    password: str | None,
    privileges_by_table: dict[str, tuple[str, ...]],
    *,
    sequences: bool,
) -> bool:
    if not ROLE_NAME.fullmatch(role):
        raise RoleProvisioningError("invalid role name")
    if connection.dialect.name != "postgresql":
        raise RoleProvisioningError("roles exist only in PostgreSQL")
    current = connection.execute(text("SELECT current_user")).scalar_one()
    if current == role:
        raise RoleProvisioningError("run provisioning as the owner, not as the runtime role")

    name = _quote(connection, role)
    exists = connection.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role}
    ).scalar()
    # exec_driver_sql: no bind-parameter parsing of DDL (verifiers contain ':' and '$').
    keyword = "ALTER" if exists else "CREATE"
    connection.exec_driver_sql(f"{keyword} ROLE {name} WITH {ROLE_ATTRIBUTES}")
    if password:
        verifier = _scram_verifier(connection, role, password)
        connection.exec_driver_sql(f"ALTER ROLE {name} WITH PASSWORD '{verifier}'")

    database_name = connection.execute(text("SELECT current_database()")).scalar_one()
    database = _quote(connection, database_name)
    connection.exec_driver_sql(f"GRANT CONNECT ON DATABASE {database} TO {name}")
    connection.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {name}")
    connection.exec_driver_sql(f"REVOKE CREATE ON SCHEMA public FROM {name}")
    connection.exec_driver_sql(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {name}")
    connection.exec_driver_sql(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {name}")
    for table, privileges in sorted(privileges_by_table.items()):
        connection.exec_driver_sql(
            f"GRANT {', '.join(privileges)} ON {_quote(connection, table)} TO {name}"
        )
    if sequences:  # nextval() for BIGSERIAL/IDENTITY-style ids (e.g. audit_events.id)
        connection.exec_driver_sql(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {name}")
    return not exists


def excess_privileges(connection: Connection, allowed: dict[str, tuple[str, ...]]) -> list[str]:
    """Table privileges the current role holds beyond ``allowed`` (empty list = fine)."""
    if connection.dialect.name != "postgresql":
        return []
    excess: list[str] = []
    for table in sorted(_public_tables(connection)):
        for privilege in TABLE_PRIVILEGES:
            held = connection.execute(
                text("SELECT has_table_privilege(current_user, :table, :privilege)"),
                {"table": f"public.{table}", "privilege": privilege},
            ).scalar_one()
            if held and privilege not in allowed.get(table, ()):
                excess.append(f"can {privilege} {table}")
    return excess


def runtime_role_problems(connection: Connection) -> list[str]:
    """Why the current role is too powerful to serve the API (empty list = fine)."""
    if connection.dialect.name != "postgresql":
        return []
    attrs = connection.execute(
        text(
            "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb "
            "FROM pg_roles WHERE rolname = current_user"
        )
    ).one()
    problems = [
        label
        for label, flag in zip(
            ("superuser", "bypassrls", "createrole", "createdb"), attrs, strict=True
        )
        if flag
    ]
    owned = connection.execute(
        text(
            "SELECT tablename FROM pg_tables "
            "WHERE schemaname = 'public' AND tableowner = current_user ORDER BY tablename"
        )
    ).scalars()
    problems += [f"owns table {table}" for table in owned]
    memberships = connection.execute(
        text(
            "SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid "
            "WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "ORDER BY r.rolname"
        )
    ).scalars()
    problems += [f"member of role {name}" for name in memberships]
    forbidden = connection.execute(
        text(
            "SELECT has_table_privilege(current_user, 'audit_events', 'UPDATE'), "
            "has_table_privilege(current_user, 'audit_chain_heads', 'DELETE')"
        )
    ).one()
    if forbidden[0]:
        problems.append("can UPDATE audit_events")
    if forbidden[1]:
        problems.append("can DELETE audit_chain_heads")
    return problems


def check_runtime_role(
    engine: Engine, *, strict: bool, allowed: dict[str, tuple[str, ...]] | None = None
) -> list[str]:
    """Startup guard. ``strict`` (deployed environments): refuse a privileged role.
    ``allowed``: also refuse any table privilege beyond this map (the gateway).

    An unreachable database only skips the check (the API already answers 503 then).
    """
    try:
        with engine.connect() as connection:
            problems = runtime_role_problems(connection)
            if allowed is not None:
                problems += excess_privileges(connection, allowed)
    except SQLAlchemyError as exc:
        log.warning("db_role_check_skipped", error_type=type(exc).__name__)
        return []
    if problems and strict:
        raise RoleProvisioningError(
            "refusing to start: the database role is too privileged ("
            + "; ".join(problems)
            + "); run the API as the runtime role"
        )
    if problems:
        log.warning("db_role_privileged", problems=problems)
    return problems


def main() -> int:
    """Provision from the environment; prints a JSON summary, never the password."""
    url = os.environ.get("AGNUSMAIL_DATABASE_URL")
    role = os.environ.get("AGNUSMAIL_DB_APP_USER", DEFAULT_RUNTIME_ROLE)
    password = os.environ.get("AGNUSMAIL_DB_APP_PASSWORD")
    if not url or not password:
        message = "AGNUSMAIL_DATABASE_URL (owner) and AGNUSMAIL_DB_APP_PASSWORD are required"
        print(message, file=sys.stderr)
        return 2
    engine = create_engine(url, connect_args={"connect_timeout": 10})
    gateway_role = os.environ.get("AGNUSMAIL_DB_GATEWAY_USER", DEFAULT_GATEWAY_ROLE)
    gateway_password = os.environ.get("AGNUSMAIL_DB_GATEWAY_PASSWORD")
    admin_role = os.environ.get("AGNUSMAIL_DB_ADMIN_USER", DEFAULT_ADMIN_ROLE)
    admin_password = os.environ.get("AGNUSMAIL_DB_ADMIN_PASSWORD")
    outbound_role = os.environ.get("AGNUSMAIL_DB_OUTBOUND_USER", DEFAULT_OUTBOUND_ROLE)
    outbound_password = os.environ.get("AGNUSMAIL_DB_OUTBOUND_PASSWORD")
    try:
        with engine.begin() as connection:
            created = provision_runtime_role(connection, role, password)
            gateway_created = None
            if gateway_password:
                gateway_created = provision_gateway_role(connection, gateway_role, gateway_password)
            admin_created = None
            if admin_password:
                admin_created = provision_admin_role(connection, admin_role, admin_password)
            outbound_created = None
            if outbound_password:
                outbound_created = provision_outbound_role(
                    connection, outbound_role, outbound_password
                )
    finally:
        engine.dispose()
    summary: dict[str, Any] = {
        "role": role,
        "created": created,
        "tables": len(RUNTIME_TABLE_PRIVILEGES),
    }
    if gateway_created is not None:
        summary["gateway_role"] = gateway_role
        summary["gateway_created"] = gateway_created
    if admin_created is not None:
        summary["admin_role"] = admin_role
        summary["admin_created"] = admin_created
    if outbound_created is not None:
        summary["outbound_role"] = outbound_role
        summary["outbound_created"] = outbound_created
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
