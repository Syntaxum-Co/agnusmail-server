"""Encryption on arrival of external mail (protocol v1 §9).

The gateway receives a conventional message in clear and never writes it anywhere: it
encrypts it in memory to the recipient's published keys — each active device and the
recovery key, exactly the directory a sender would use (§6.2) — and stores only the
SEIPDv2 body and the PKESKs, in the same tables as E2EE messages (``origin = external``).

Like any sender, the gateway re-checks the wallet attestations of the keys it encrypts
to (§4): a key written straight into the database, without the wallet, is skipped. The
gateway has no decryption key for anything.
"""

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import format_datetime

from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import ResourceNotFoundError
from agnusmail.core.logging import get_logger
from agnusmail.infrastructure.openpgp import GatewayKey as GatewaySigningKey
from agnusmail.infrastructure.openpgp import encrypt_to_certificates
from agnusmail.modules.addresses.service import resolve
from agnusmail.modules.devices.attestation import (
    AttestationError,
    DeviceCertificateClaim,
    RecoveryKeyClaim,
    verify_device_certificate,
    verify_recovery_key,
)
from agnusmail.modules.devices.models import Device
from agnusmail.modules.identity.models import User
from agnusmail.modules.inbound.antispam import strip_header_fields
from agnusmail.modules.keys.models import PublicKey
from agnusmail.modules.messages.models import (
    Folder,
    MailboxEntry,
    Message,
    MessageKey,
    MessageOrigin,
)
from agnusmail.modules.messages.service import PublishedKey, published_keys
from agnusmail.modules.quotas.policy import QuotaPolicy
from agnusmail.modules.quotas.usage import add_usage
from agnusmail.modules.recovery.migration import completed_migrations
from agnusmail.modules.recovery.models import RecoveryKey

log = get_logger(__name__)


@dataclass(frozen=True)
class GatewayContext:
    mail_domain: str
    service: str  # EIP-712 service (the SIWE domain)
    chain_id: int
    max_message_bytes: int  # limit on the stored SEIPDv2 body
    signing_key: GatewaySigningKey  # signs every message it encrypts (spec §9)
    quota: QuotaPolicy | None = None  # suspended or full mailboxes get 452

    @classmethod
    def from_settings(cls, settings: Settings, signing_key: GatewaySigningKey) -> "GatewayContext":
        return cls(
            mail_domain=settings.mail_domain,
            service=settings.siwe_domain,
            chain_id=settings.siwe_chain_id,
            max_message_bytes=settings.max_message_bytes,
            signing_key=signing_key,
            quota=QuotaPolicy.from_settings(settings),
        )


class RecipientUnknownError(Exception):
    """No active address/account (anymore): permanent for this recipient."""


class RecipientUnavailableError(Exception):
    """The account exists but has no usable device key yet: temporary."""


class MessageTooLargeError(Exception):
    pass


class MailboxFullError(RecipientUnavailableError):
    """No active period, or storage full: temporary, the sender retries."""


@dataclass(frozen=True)
class RecipientKey:
    fingerprint: str  # encryption subkey (what the PKESK names)
    material: bytes  # the published certificate
    target: PublishedKey


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def resolve_recipient(session: Session, address: str, ctx: GatewayContext) -> User | None:
    try:
        return resolve(session, address, ctx.mail_domain)[1]
    except ResourceNotFoundError:
        return None


def _wallet_chain(session: Session, user: User) -> list[tuple[str, datetime | None]]:
    """Wallets that controlled the account, with the end of their control (§8.5 step 4):
    an attestation by an older wallet counts only if issued before its migration."""
    chain: list[tuple[str, datetime | None]] = [(user.ethereum_address.lower(), None)]
    for migration in completed_migrations(session, user.id):
        assert migration.finished_at is not None
        chain.append((migration.old_account.lower(), _utc(migration.finished_at)))
    return chain


def _wallets_at(chain: list[tuple[str, datetime | None]], issued: datetime) -> list[str]:
    return [wallet for wallet, until in chain if until is None or issued < until]


def _device_attested(
    device: Device, chain: list[tuple[str, datetime | None]], ctx: GatewayContext, now: datetime
) -> bool:
    if not (
        device.fingerprint
        and device.certificate_signature
        and device.certificate_issued_at
        and device.certificate_expires_at
    ):
        return False
    issued = _utc(device.certificate_issued_at)
    signature = bytes.fromhex(device.certificate_signature.removeprefix("0x"))
    for wallet in _wallets_at(chain, issued):
        claim = DeviceCertificateClaim(
            account=wallet,
            device_fingerprint=device.fingerprint,
            service=ctx.service,
            issued_at=int(issued.timestamp()),
            expires_at=int(_utc(device.certificate_expires_at).timestamp()),
        )
        try:
            verify_device_certificate(claim, signature, chain_id=ctx.chain_id, now=now)
        except AttestationError:
            continue
        return True
    return False


def _recovery_attested(
    key: RecoveryKey, chain: list[tuple[str, datetime | None]], ctx: GatewayContext, now: datetime
) -> bool:
    issued = _utc(key.wallet_issued_at)
    if key.wallet_account.lower() not in _wallets_at(chain, issued):
        return False
    claim = RecoveryKeyClaim(
        account=key.wallet_account,
        recovery_fingerprint=key.fingerprint,
        service=ctx.service,
        issued_at=int(issued.timestamp()),
    )
    try:
        verify_recovery_key(
            claim,
            bytes.fromhex(key.wallet_signature.removeprefix("0x")),
            chain_id=ctx.chain_id,
            now=now,
        )
    except AttestationError:
        return False
    return True


def recipient_keys(
    session: Session, user: User, ctx: GatewayContext, now: datetime
) -> list[RecipientKey]:
    """The published keys of ``user`` whose wallet attestation verifies."""
    chain = _wallet_chain(session, user)
    keys: list[RecipientKey] = []
    for fingerprint, target in published_keys(session, user.id, now).items():
        if target.recovery_key_id is not None:
            recovery = session.get(RecoveryKey, target.recovery_key_id)
            assert recovery is not None
            attested, material = _recovery_attested(recovery, chain, ctx, now), recovery.material
        else:
            device = session.get(Device, target.device_id)
            public_key = session.get(PublicKey, target.public_key_id)
            assert device is not None and public_key is not None
            attested, material = _device_attested(device, chain, ctx, now), public_key.material
        if attested:
            keys.append(RecipientKey(fingerprint, material, target))
        else:  # never expected: the API verifies before publishing
            log.warning(
                "inbound_key_unattested",
                device_id=str(target.device_id) if target.device_id else None,
                recovery=target.recovery_key_id is not None,
            )
    return keys


def has_device_key(session: Session, user: User, now: datetime) -> bool:
    """Cheap check at RCPT time; the full verification runs at delivery."""
    return any(k.device_id for k in published_keys(session, user.id, now).values())


# Fields only this gateway may write: copies arriving from outside are forged (RFC 8601
# §5) and always removed before ours are added.
GATEWAY_FIELDS = frozenset({"authentication-results", "x-spam", "x-spam-score"})


def header_safe(value: str, limit: int = 255) -> str:
    """Printable ASCII only, bounded: values come from the SMTP client."""
    cleaned = "".join(ch if 32 < ord(ch) < 127 else "?" for ch in value)
    return cleaned[:limit] or "unknown"


@dataclass(frozen=True)
class Arrival:
    """One received SMTP transaction, in memory only."""

    content: bytes  # the message as received (DATA)
    mail_from: str
    helo: str
    peer: str  # client IP
    hostname: str  # this gateway
    esmtp: bool
    received_at: datetime
    tls: bool = False  # STARTTLS was negotiated (RFC 3848: ESMTPS)
    # Fields added by the gateway (antispam verdict, Authentication-Results), each a full
    # "Name: value" line already folded; and field names to drop from the message.
    annotations: tuple[bytes, ...] = ()
    strip: frozenset[str] = frozenset()

    def for_recipient(self, address: str) -> bytes:
        """Trace headers (RFC 5321 §4.4), the gateway's fields, then the message. All of
        it is encrypted, so the client IP and envelope are not stored outside the
        ciphertext."""
        date = format_datetime(self.received_at)
        protocol = ("ESMTPS" if self.tls else "ESMTP") if self.esmtp else "SMTP"
        lines = [
            f"Return-Path: <{header_safe(self.mail_from)}>",
            f"Received: from {header_safe(self.helo)} ([{header_safe(self.peer, 45)}])",
            f"\tby {header_safe(self.hostname)} (Agnusmail) with {protocol}",
            f"\tfor <{header_safe(address)}>; {date}",
        ]
        trace = [line.encode("ascii") + b"\r\n" for line in lines]
        added = [field + b"\r\n" for field in self.annotations]
        body = strip_header_fields(self.content, self.strip | GATEWAY_FIELDS)
        return b"".join(trace[:1] + added + trace[1:]) + body


def deliver(
    session: Session,
    recipients: list[str],
    arrival: Arrival,
    ctx: GatewayContext,
    now: datetime,
) -> list[Message]:
    """One encrypted message per recipient account, all in the caller's transaction.

    Each recipient gets its own message (trace headers name them, as for Bcc, §6.1).
    Any failure raises, and nothing is written: the SMTP reply is then a temporary
    error and the sending server retries (there is no spool).
    """
    targets: list[tuple[str, User]] = []
    seen: set[uuid.UUID] = set()
    for address in recipients:
        user = resolve_recipient(session, address, ctx)
        if user is None:
            raise RecipientUnknownError()
        if user.id not in seen:
            seen.add(user.id)
            targets.append((address, user))

    delivered: list[Message] = []
    for address, user in targets:
        keys = recipient_keys(session, user, ctx, now)
        if not any(key.target.device_id for key in keys):
            raise RecipientUnavailableError()
        plaintext = arrival.for_recipient(address)
        encrypted = encrypt_to_certificates(
            plaintext, [key.material for key in keys], ctx.signing_key
        )
        del plaintext
        if len(encrypted.body) > ctx.max_message_bytes:
            raise MessageTooLargeError()
        if ctx.quota is not None and not ctx.quota.accepts(
            session, user.id, len(encrypted.body), now
        ):
            raise MailboxFullError()
        if any(key.fingerprint not in encrypted.pkesks for key in keys):
            raise RuntimeError("a published certificate was not usable for encryption")
        message = Message(
            sender_id=None,
            origin=MessageOrigin.EXTERNAL,
            client_message_id=secrets.token_hex(16),
            body=encrypted.body,
            size=len(encrypted.body),
        )
        session.add(message)
        session.flush()
        for key in keys:  # extra PKESKs (unpublished subkeys of a certificate) are dropped
            session.add(
                MessageKey(
                    message_id=message.id,
                    user_id=user.id,
                    device_id=key.target.device_id,
                    public_key_id=key.target.public_key_id,
                    recovery_key_id=key.target.recovery_key_id,
                    pkesk=encrypted.pkesks[key.fingerprint],
                )
            )
        session.add(MailboxEntry(message_id=message.id, user_id=user.id, folder=Folder.INBOX))
        add_usage(session, user.id, len(encrypted.body))
        session.flush()
        delivered.append(message)
    return delivered


def register_gateway_key(session: Session, key: GatewaySigningKey) -> bool:
    """Publish the gateway's certificate (idempotent). True when it was new."""
    from sqlalchemy import select

    from agnusmail.modules.inbound.models import GatewayKey

    exists = session.scalar(select(GatewayKey.id).where(GatewayKey.fingerprint == key.fingerprint))
    if exists is not None:
        return False
    session.add(
        GatewayKey(fingerprint=key.fingerprint, material=key.certificate, expires_at=key.expires_at)
    )
    session.flush()
    return True
