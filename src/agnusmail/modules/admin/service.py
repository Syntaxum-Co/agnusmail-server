"""Administrative actions.

Every change is requested by one operator and executed only when a different operator
approves (two signatures). Queries need one signature. All of it is recorded in
``admin_actions``; changes to an account also go to that account's own audit chain.
Nothing here can read message content: the actions work on account metadata only.
"""

import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import AgnusmailError, InvalidStateError, ResourceNotFoundError
from agnusmail.extensions import AccountDetails, Extensions
from agnusmail.modules.abuse.models import AbuseReport, AccountRestriction
from agnusmail.modules.addresses.models import MailAddress
from agnusmail.modules.addresses.service import resolve
from agnusmail.modules.admin.models import (
    ActionStatus,
    AdminAction,
    Operator,
    OperatorStatus,
)
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import record_event
from agnusmail.modules.devices.models import Device, DeviceStatus
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.modules.identity.repository import get_by_address
from agnusmail.modules.quotas.policy import QuotaPolicy

APPROVAL_WINDOW = timedelta(hours=24)
ETH_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
# Credentials whose rotation is recorded (names only: never a value or a free note).
CREDENTIALS = frozenset(
    {
        "db_owner_password",
        "db_app_password",
        "db_gateway_password",
        "db_outbound_password",
        "db_admin_password",
        "redis_password",
        "s3_credentials",
        "gateway_signing_key",
        "outbound_queue_key",
        "dkim_key",
        "tls_certificates",
    }
)


class ActionInvalidError(AgnusmailError):
    status_code = 422
    message = "invalid administrative action"
    code = "ADMIN_ACTION_INVALID"


@dataclass(frozen=True)
class Context:
    policy: QuotaPolicy
    mail_domain: str
    # The change kinds operators may request: the built-in ones plus the extensions'.
    changes: Mapping[str, "Kind"] = field(default_factory=lambda: CHANGES)
    # Extra fields of ``show_account``, from extensions.
    account_details: Sequence[AccountDetails] = ()


def find_account(session: Session, value: Any, ctx: Context, *, lock: bool = False) -> User:
    """The account named by a wallet address or an e-mail address. ``lock`` holds its
    row until the transaction ends (changes of its status)."""
    if not isinstance(value, str):
        raise ActionInvalidError("account must be a wallet address or an e-mail address")
    if ETH_ADDRESS.fullmatch(value):
        found = get_by_address(session, value)
        if found is None:
            raise ResourceNotFoundError("no such account")
        user = found
    else:
        try:
            user = resolve(session, value, ctx.mail_domain)[1]
        except ResourceNotFoundError as exc:
            raise ResourceNotFoundError("no such account") from exc
    if lock:
        locked = session.get(User, user.id, with_for_update=True, populate_existing=True)
        assert locked is not None
        user = locked
    return user


def record_admin_event(
    session: Session, user: User, kind: AuditEventType | str, action: AdminAction, now: datetime
) -> None:
    """Record an approved change in the account's audit chain, with both operators."""
    record_event(
        session,
        None,
        kind,
        owner_id=user.id,
        details={
            "admin_action": str(action.id),
            "requested_by": action.requested_by,
            "approved_by": action.approved_by,
        },
        now=now,
    )


# --- changes (two operators) ----------------------------------------------------------


def _suspend(session: Session, action: AdminAction, ctx: Context, now: datetime) -> dict[str, Any]:
    user = find_account(session, action.params["account"], ctx, lock=True)
    if user.status == UserStatus.SUSPENDED:
        raise InvalidStateError("the account is already suspended")
    user.status = UserStatus.SUSPENDED
    record_admin_event(session, user, AuditEventType.ADMIN_SUSPENDED, action, now)
    return {"account": user.ethereum_address, "status": "suspended"}


def _reinstate(
    session: Session, action: AdminAction, ctx: Context, now: datetime
) -> dict[str, Any]:
    user = find_account(session, action.params["account"], ctx, lock=True)
    if user.status != UserStatus.SUSPENDED:
        raise InvalidStateError("the account is not suspended")
    user.status = UserStatus.ACTIVE
    record_admin_event(session, user, AuditEventType.ADMIN_REINSTATED, action, now)
    return {"account": user.ethereum_address, "status": "active"}


def _lift(session: Session, action: AdminAction, ctx: Context, now: datetime) -> dict[str, Any]:
    user = find_account(session, action.params["account"], ctx)
    row = session.get(AccountRestriction, user.id, with_for_update=True)
    if (
        row is None
        or row.restricted_until.replace(tzinfo=row.restricted_until.tzinfo or UTC) <= now
    ):
        raise InvalidStateError("the account is not restricted")
    row.restricted_until = now
    row.updated_at = now
    record_admin_event(session, user, AuditEventType.ADMIN_RESTRICTION_LIFTED, action, now)
    return {"account": user.ethereum_address, "restricted": False}


def _add_operator(
    session: Session, action: AdminAction, _ctx: Context, now: datetime
) -> dict[str, Any]:
    address = str(action.params["address"]).lower()
    row = session.scalars(select(Operator).where(Operator.address == address)).one_or_none()
    if row is None:
        session.add(Operator(address=address, status=OperatorStatus.ACTIVE, added_at=now))
    elif row.status == OperatorStatus.ACTIVE:
        raise InvalidStateError("already an operator")
    else:
        row.status, row.removed_at = OperatorStatus.ACTIVE, None
    return {"operator": address, "status": "active"}


def _remove_operator(
    session: Session, action: AdminAction, _ctx: Context, now: datetime
) -> dict[str, Any]:
    address = str(action.params["address"]).lower()
    row = session.scalars(select(Operator).where(Operator.address == address)).one_or_none()
    if row is None or row.status != OperatorStatus.ACTIVE:
        raise InvalidStateError("not an active operator")
    remaining = session.scalar(
        select(func.count())
        .select_from(Operator)
        .where(Operator.status == OperatorStatus.ACTIVE, Operator.address != address)
    )
    if (remaining or 0) < 2:  # two operators must always be able to approve
        raise InvalidStateError("at least two operators must remain")
    row.status, row.removed_at = OperatorStatus.REMOVED, now
    return {"operator": address, "status": "removed"}


def _rotation(
    _session: Session, action: AdminAction, _ctx: Context, now: datetime
) -> dict[str, Any]:
    return {"credential": action.params["credential"], "rotated_at": now.isoformat()}


@dataclass(frozen=True)
class Kind:
    params: dict[str, Callable[[Any], bool]]
    execute: Callable[[Session, AdminAction, Context, datetime], dict[str, Any]]


def _text(value: Any) -> bool:
    return isinstance(value, str) and 3 <= len(value) <= 320


def _address(value: Any) -> bool:
    return isinstance(value, str) and bool(ETH_ADDRESS.fullmatch(value))


CHANGES: dict[str, Kind] = {
    "suspend_account": Kind({"account": _text}, _suspend),
    "reinstate_account": Kind({"account": _text}, _reinstate),
    "lift_restriction": Kind({"account": _text}, _lift),
    "add_operator": Kind({"address": _address}, _add_operator),
    "remove_operator": Kind({"address": _address}, _remove_operator),
    "record_rotation": Kind({"credential": lambda v: v in CREDENTIALS}, _rotation),
}


def changes_for(extensions: Extensions) -> dict[str, Kind]:
    """The built-in changes plus the extensions' (which may also name more credentials)."""
    credentials = extensions.admin_credentials(CREDENTIALS)
    rotation = Kind({"credential": lambda v: v in credentials}, _rotation)
    return extensions.admin_actions({**CHANGES, "record_rotation": rotation})


def validate(kind: str, params: dict[str, Any], ctx: Context) -> dict[str, Any]:
    spec = ctx.changes.get(kind)
    if spec is None:
        raise ActionInvalidError(f"unknown action; one of {sorted(ctx.changes)}")
    if set(params) != set(spec.params) or not all(
        check(params[name]) for name, check in spec.params.items()
    ):
        raise ActionInvalidError(f"{kind} takes {sorted(spec.params)}")
    normalized = dict(params)
    if "address" in normalized:
        normalized["address"] = normalized["address"].lower()
    return normalized


def request(
    session: Session, operator: str, kind: str, params: dict[str, Any], ctx: Context, now: datetime
) -> AdminAction:
    action = AdminAction(
        kind=kind,
        params=validate(kind, params, ctx),
        status=ActionStatus.PENDING,
        requested_by=operator,
        requested_at=now,
        expires_at=now + APPROVAL_WINDOW,
    )
    session.add(action)
    session.flush()
    return action


def pending_action(session: Session, action_id: uuid.UUID, now: datetime) -> AdminAction:
    action = session.get(AdminAction, action_id, with_for_update=True)
    if action is None:
        raise ResourceNotFoundError("no such action")
    expires = action.expires_at.replace(tzinfo=action.expires_at.tzinfo or UTC)
    if action.status == ActionStatus.PENDING and expires <= now:
        action.status = ActionStatus.EXPIRED
        session.flush()
    if action.status != ActionStatus.PENDING:
        raise InvalidStateError(f"the action is {action.status}")
    return action


def approve(
    session: Session, operator: str, action: AdminAction, ctx: Context, now: datetime
) -> AdminAction:
    """Execute ``action`` with a second operator's approval, in the caller's transaction.
    A change that cannot apply is recorded as failed (with the reason), not retried."""
    if operator == action.requested_by:
        raise InvalidStateError("a different operator must approve")
    action.approved_by, action.approved_at = operator, now
    try:
        with session.begin_nested():
            action.result = ctx.changes[action.kind].execute(session, action, ctx, now)
            action.status = ActionStatus.EXECUTED
    except AgnusmailError as exc:
        action.status = ActionStatus.FAILED
        action.result = {"error": exc.error_code, "detail": exc.detail}
    session.flush()
    return action


def bootstrap(session: Session, address: str, now: datetime) -> Operator:
    """The first two operators, added on the server by whoever runs the CLI with the
    admin database role (later operators need two approvals)."""
    if not ETH_ADDRESS.fullmatch(address):
        raise ActionInvalidError("not a wallet address")
    active = session.scalar(
        select(func.count()).select_from(Operator).where(Operator.status == OperatorStatus.ACTIVE)
    )
    if (active or 0) >= 2:
        raise InvalidStateError("operators exist: add more with add_operator (two approvals)")
    if session.scalar(select(Operator.id).where(Operator.address == address.lower())):
        raise InvalidStateError("already an operator")
    operator = Operator(address=address.lower(), status=OperatorStatus.ACTIVE, added_at=now)
    session.add(operator)
    session.add(
        AdminAction(
            kind="add_operator",
            params={"address": address.lower()},
            status=ActionStatus.EXECUTED,
            requested_by="bootstrap",
            requested_at=now,
            expires_at=now,
            result={"operator": address.lower(), "status": "active", "bootstrap": True},
        )
    )
    session.flush()
    return operator


# --- queries (one operator) -----------------------------------------------------------


def show_account(session: Session, account: str, ctx: Context, now: datetime) -> dict[str, Any]:
    """Account metadata for support: never content, keys or message lists."""
    user = find_account(session, account, ctx)
    standing = ctx.policy.standing(session, user.id, now)
    restriction = session.get(AccountRestriction, user.id)
    reports = session.scalar(
        select(func.count(func.distinct(AbuseReport.reporter_id))).where(
            AbuseReport.reported_id == user.id, AbuseReport.created_at > now - timedelta(days=30)
        )
    )
    devices = session.scalar(
        select(func.count())
        .select_from(Device)
        .where(Device.user_id == user.id, Device.status == DeviceStatus.ACTIVE)
    )
    details: dict[str, Any] = {
        "account": user.ethereum_address,
        "user_status": user.status,
        "created_at": user.created_at.isoformat(),
        "addresses": [
            f"{a.email} ({a.kind}, {a.status})"
            for a in session.scalars(select(MailAddress).where(MailAddress.user_id == user.id))
        ],
        "storage": {"stored_bytes": standing.stored_bytes, "quota_bytes": standing.quota_bytes},
        "restricted_until": None
        if restriction is None
        else restriction.restricted_until.isoformat(),
        "reporters_last_30_days": int(reports or 0),
        "active_devices": int(devices or 0),
    }
    for extra in ctx.account_details:
        added = extra(session, user, now)
        if set(added) & set(details):  # an extension never hides or replaces a field
            raise ActionInvalidError("an extension reused a built-in account field")
        details.update(added)
    return details


def list_pending(session: Session, now: datetime) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(AdminAction)
        .where(AdminAction.status == ActionStatus.PENDING, AdminAction.expires_at > now)
        .order_by(AdminAction.requested_at)
    )
    return [
        {
            "id": str(a.id),
            "kind": a.kind,
            "params": a.params,
            "requested_by": a.requested_by,
            "expires_at": a.expires_at.isoformat(),
        }
        for a in rows
    ]
