"""Operator signatures: a readable message, signed in the operator's own
wallet with EIP-191 ``personal_sign`` and pasted into the CLI.

The message states exactly what is authorized (operation, action, parameters, action
id), for which service, with a single-use nonce and a 10-minute validity. A signature
for one action cannot authorize another, and cannot be replayed.
"""

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from eth_account import Account
from eth_account.messages import encode_defunct
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import AgnusmailError
from agnusmail.modules.admin.models import AdminSignature, Operator, OperatorStatus

VALIDITY = timedelta(minutes=10)


class SignatureRejectedError(AgnusmailError):
    status_code = 403
    message = "signature rejected"
    code = "ADMIN_SIGNATURE_REJECTED"


@dataclass(frozen=True)
class Statement:
    service: str
    operation: str  # "request", "approve" or "query"
    action: str
    params: dict[str, Any]
    action_id: str  # "-" when the action does not exist yet
    nonce: str
    issued_at: datetime

    @classmethod
    def new(
        cls,
        service: str,
        operation: str,
        action: str,
        params: dict[str, Any],
        now: datetime,
        action_id: str = "-",
    ) -> "Statement":
        return cls(service, operation, action, params, action_id, secrets.token_hex(16), now)

    def text(self) -> str:
        return "\n".join(
            [
                "Agnusmail administration",
                f"Service: {self.service}",
                f"Operation: {self.operation}",
                f"Action: {self.action}",
                f"Parameters: {json.dumps(self.params, sort_keys=True, separators=(',', ':'))}",
                f"Action ID: {self.action_id}",
                f"Nonce: {self.nonce}",
                f"Issued At: {self.issued_at.isoformat()}",
            ]
        )


def signer_of(statement: Statement, signature: str) -> str:
    try:
        address: str = Account.recover_message(
            encode_defunct(text=statement.text()), signature=signature
        )
    except Exception as exc:  # malformed signature of any kind
        raise SignatureRejectedError("malformed signature") from exc
    return address.lower()


def authenticate(session: Session, statement: Statement, signature: str, now: datetime) -> str:
    """The active operator who signed ``statement``; consumes its nonce."""
    if not now - VALIDITY <= statement.issued_at <= now + timedelta(seconds=30):
        raise SignatureRejectedError("the signed message is too old; start again")
    address = signer_of(statement, signature)
    active = session.scalar(
        select(Operator.id).where(
            Operator.address == address, Operator.status == OperatorStatus.ACTIVE
        )
    )
    if active is None:
        raise SignatureRejectedError("not an active operator")
    try:
        with session.begin_nested():
            session.add(AdminSignature(nonce=statement.nonce, operator=address, used_at=now))
    except IntegrityError as exc:
        raise SignatureRejectedError("this signature was already used") from exc
    return address
