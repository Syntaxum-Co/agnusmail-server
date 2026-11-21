"""Message use cases (protocol v1 §6). Synchronous; run inside ``run_in_transaction``.

The server validates structure and completeness, stores ciphertext and routes it. It
never decrypts: it reads only the recipient fingerprint in each v6 PKESK header and the
algorithm parameters of the SEIPDv2 header (``infrastructure/openpgp.py``).

Completeness (spec §6.5): every published key (directory rules: active, unexpired key of
an active device with a valid wallet certificate) of every recipient — and of the
sender, for the Sent folder — gets exactly one PKESK. If the client used an outdated
directory the server answers 409 and the client fetches the directory again.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import (
    AgnusmailError,
    ConflictError,
    InvalidStateError,
    ResourceNotFoundError,
)
from agnusmail.infrastructure.openpgp import (
    EnvelopeRejectedError,
    check_seipd_v2,
    pkesk_recipient,
)
from agnusmail.modules.devices.models import Device, DeviceStatus
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.modules.identity.repository import InvalidAddressError, get_by_address
from agnusmail.modules.keys.models import PublicKey, PublicKeyStatus
from agnusmail.modules.messages.models import (
    Folder,
    MailboxEntry,
    Message,
    MessageKey,
    MessageOrigin,
)
from agnusmail.modules.quotas.usage import add_usage
from agnusmail.modules.recovery.models import RecoveryKey, RecoveryKeyStatus

if TYPE_CHECKING:
    from agnusmail.modules.attachments.service import AttachmentLimits
    from agnusmail.modules.quotas.policy import QuotaPolicy


class EnvelopeInvalidError(AgnusmailError):
    status_code = 422
    message = "invalid message envelope"
    code = "ENVELOPE_INVALID"


class RecipientInvalidError(AgnusmailError):
    status_code = 422
    message = "invalid recipient"
    code = "RECIPIENT_INVALID"


class RecipientKeysChangedError(AgnusmailError):
    """The PKESKs do not match the published keys: refetch the directory and re-encrypt."""

    status_code = 409
    message = "recipient keys changed; fetch the directory again"
    code = "RECIPIENT_KEYS_CHANGED"


@dataclass(frozen=True)
class MessageLimits:
    max_bytes: int
    max_recipients: int


@dataclass(frozen=True)
class RecipientInput:
    account: str
    pkesks: list[bytes]


@dataclass(frozen=True)
class PublishedKey:
    """A device key, or (``recovery_key_id``) the account's recovery key."""

    device_id: uuid.UUID | None = None
    public_key_id: uuid.UUID | None = None
    recovery_key_id: uuid.UUID | None = None


def published_keys(session: Session, user_id: uuid.UUID, now: datetime) -> dict[str, PublishedKey]:
    """Encryption-subkey fingerprint → device/key, exactly what the directory publishes."""
    rows = session.execute(
        select(PublicKey.encryption_fingerprint, PublicKey.device_id, PublicKey.id)
        .join(Device, Device.id == PublicKey.device_id)
        .where(
            PublicKey.user_id == user_id,
            PublicKey.status == PublicKeyStatus.ACTIVE,
            PublicKey.expires_at > now,
            Device.status == DeviceStatus.ACTIVE,
            Device.certificate_expires_at > now,
        )
    ).all()
    published = {
        str(fpr): PublishedKey(device_id, key_id) for fpr, device_id, key_id in rows if fpr
    }
    recovery = session.execute(
        select(RecoveryKey.encryption_fingerprint, RecoveryKey.id).where(
            RecoveryKey.user_id == user_id,
            RecoveryKey.status == RecoveryKeyStatus.ACTIVE,
            RecoveryKey.expires_at > now,
        )
    ).one_or_none()
    if recovery is not None:
        published[str(recovery[0])] = PublishedKey(recovery_key_id=recovery[1])
    return published


def _route(pkesks: list[bytes], required: dict[str, PublishedKey], who: str) -> dict[str, bytes]:
    routed: dict[str, bytes] = {}
    for pkesk in pkesks:
        try:
            fingerprint = pkesk_recipient(pkesk)
        except EnvelopeRejectedError as exc:
            raise EnvelopeInvalidError(f"{who}: {exc.reason}") from exc
        if fingerprint in routed:
            raise EnvelopeInvalidError(f"{who}: duplicate PKESK")
        routed[fingerprint] = pkesk
    if not required:
        raise RecipientKeysChangedError(f"{who} has no published device keys")
    if set(routed) != set(required):
        raise RecipientKeysChangedError()
    return routed


def check_owner_pkesks(
    session: Session, owner_id: uuid.UUID, pkesks: list[bytes], now: datetime
) -> None:
    """Exactly one PKESK per published key of ``owner_id`` (§6.5), or 409/422."""
    _route(pkesks, published_keys(session, owner_id, now), "owner")


def send_message(
    session: Session,
    sender_id: uuid.UUID,
    client_message_id: str,
    recipients: list[RecipientInput],
    self_pkesks: list[bytes],
    body: bytes,
    limits: MessageLimits,
    now: datetime,
    attachment_ids: list[uuid.UUID] | None = None,
    attachment_limits: "AttachmentLimits | None" = None,
    quota: "QuotaPolicy | None" = None,
) -> Message:
    if len(body) > limits.max_bytes:
        raise EnvelopeInvalidError(f"message body exceeds {limits.max_bytes} bytes")
    try:
        check_seipd_v2(body)
    except EnvelopeRejectedError as exc:
        raise EnvelopeInvalidError(f"body: {exc.reason}") from exc
    if not 1 <= len(recipients) <= limits.max_recipients:
        raise RecipientInvalidError(f"between 1 and {limits.max_recipients} recipients")

    sender = session.get(User, sender_id)
    assert sender is not None
    targets: list[tuple[User, list[bytes]]] = []
    seen: set[uuid.UUID] = set()
    for recipient in recipients:
        try:
            user = get_by_address(session, recipient.account)
        except InvalidAddressError as exc:
            raise RecipientInvalidError("malformed recipient address") from exc
        if user is None or user.status != UserStatus.ACTIVE:
            raise RecipientInvalidError("unknown recipient")
        if user.id == sender_id:
            raise RecipientInvalidError("the sender's own devices go in self_pkesks")
        if user.id in seen:
            raise RecipientInvalidError("duplicate recipient")
        seen.add(user.id)
        targets.append((user, recipient.pkesks))

    duplicate = session.scalar(
        select(Message.id).where(
            Message.sender_id == sender_id, Message.client_message_id == client_message_id
        )
    )
    if duplicate is not None:
        raise ConflictError("message_id already used by this sender")

    if quota is not None:  # the sender grows (Sent), so do the recipients
        quota.require_space(session, sender_id, len(body), now)
        for user, _ in targets:
            quota.require_recipient(session, user.id, len(body), now)

    # Validate every recipient's PKESKs before writing anything.
    plan: list[tuple[User, dict[str, bytes], dict[str, PublishedKey]]] = []
    for user, pkesks in targets:
        required = published_keys(session, user.id, now)
        plan.append((user, _route(pkesks, required, "recipient"), required))
    own_required = published_keys(session, sender_id, now)
    plan.append((sender, _route(self_pkesks, own_required, "sender"), own_required))

    message = Message(
        sender_id=sender_id, client_message_id=client_message_id, body=body, size=len(body)
    )
    session.add(message)
    session.flush()
    for user, routed, required in plan:
        for fingerprint, pkesk in routed.items():
            key = required[fingerprint]
            session.add(
                MessageKey(
                    message_id=message.id,
                    user_id=user.id,
                    device_id=key.device_id,
                    public_key_id=key.public_key_id,
                    recovery_key_id=key.recovery_key_id,
                    pkesk=pkesk,
                )
            )
        folder = Folder.SENT if user.id == sender_id else Folder.INBOX
        session.add(MailboxEntry(message_id=message.id, user_id=user.id, folder=folder))
        add_usage(session, user.id, len(body))
    session.flush()
    if attachment_ids:
        assert attachment_limits is not None
        from agnusmail.modules.attachments.service import attach_to_message

        attach_to_message(session, sender_id, message.id, attachment_ids, attachment_limits)
    return message


def store_for_owner(
    session: Session,
    owner_id: uuid.UUID,
    *,
    sender_id: uuid.UUID | None,
    origin: MessageOrigin,
    client_message_id: str,
    pkesks: list[bytes],
    body: bytes,
    max_bytes: int,
    now: datetime,
) -> Message:
    """A message only ``owner_id`` holds, encrypted to exactly their published keys:
    the sender's own copy of an outbound message (Sent, spec §10) or a portal reply
    (Inbox, spec §11). Same completeness rule as §6.5."""
    if len(body) > max_bytes:
        raise EnvelopeInvalidError(f"message body exceeds {max_bytes} bytes")
    try:
        check_seipd_v2(body)
    except EnvelopeRejectedError as exc:
        raise EnvelopeInvalidError(f"body: {exc.reason}") from exc
    required = published_keys(session, owner_id, now)
    routed = _route(pkesks, required, "owner")
    if sender_id is not None and session.scalar(
        select(Message.id).where(
            Message.sender_id == sender_id, Message.client_message_id == client_message_id
        )
    ):
        raise ConflictError("message_id already used by this sender")
    message = Message(
        sender_id=sender_id,
        origin=origin,
        client_message_id=client_message_id,
        body=body,
        size=len(body),
    )
    session.add(message)
    session.flush()
    for fingerprint, pkesk in routed.items():
        key = required[fingerprint]
        session.add(
            MessageKey(
                message_id=message.id,
                user_id=owner_id,
                device_id=key.device_id,
                public_key_id=key.public_key_id,
                recovery_key_id=key.recovery_key_id,
                pkesk=pkesk,
            )
        )
    folder = Folder.SENT if sender_id == owner_id else Folder.INBOX
    session.add(MailboxEntry(message_id=message.id, user_id=owner_id, folder=folder))
    add_usage(session, owner_id, len(body))
    session.flush()
    return message


def _entry(session: Session, owner_id: uuid.UUID, message_id: uuid.UUID) -> MailboxEntry:
    entry = session.scalars(
        select(MailboxEntry).where(
            MailboxEntry.message_id == message_id, MailboxEntry.user_id == owner_id
        )
    ).one_or_none()
    if entry is None:
        raise ResourceNotFoundError("message not found")
    return entry


@dataclass(frozen=True)
class MailboxItem:
    entry: MailboxEntry
    message: Message
    sender_address: str | None  # None for external messages (no sender account)


def list_folder(
    session: Session,
    owner_id: uuid.UUID,
    folder: Folder,
    *,
    limit: int,
    offset: int,
    folder_id: uuid.UUID | None = None,
) -> tuple[list[MailboxItem], int]:
    condition = (MailboxEntry.user_id == owner_id) & (MailboxEntry.folder == folder)
    if folder is Folder.CUSTOM:
        if folder_id is None:
            raise InvalidStateError("folder_id is required for custom folders")
        condition = condition & (MailboxEntry.folder_id == folder_id)
    total = session.scalar(select(func.count()).select_from(MailboxEntry).where(condition))
    rows = session.execute(
        select(MailboxEntry, Message, User.ethereum_address)
        .join(Message, Message.id == MailboxEntry.message_id)
        .outerjoin(User, User.id == Message.sender_id)
        .where(condition)
        .order_by(MailboxEntry.created_at.desc(), MailboxEntry.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return [MailboxItem(e, m, a) for e, m, a in rows], int(total or 0)


@dataclass(frozen=True)
class MessageForDevice:
    item: MailboxItem
    pkesks: list[bytes]  # PKESKs for the session's device (empty: not shared with it yet)
    recovery_pkesks: list[bytes]  # for the owner's recovery key (restore, spec §8.4)


def read_message(
    session: Session, owner_id: uuid.UUID, device_id: uuid.UUID, message_id: uuid.UUID
) -> MessageForDevice:
    entry = _entry(session, owner_id, message_id)
    message = session.get(Message, message_id)
    assert message is not None
    sender = None if message.sender_id is None else session.get(User, message.sender_id)
    pkesks = session.scalars(
        select(MessageKey.pkesk)
        .where(
            MessageKey.message_id == message_id,
            MessageKey.user_id == owner_id,
            MessageKey.device_id == device_id,
        )
        .order_by(MessageKey.created_at)
    ).all()
    recovery_pkesks = session.scalars(
        select(MessageKey.pkesk)
        .where(
            MessageKey.message_id == message_id,
            MessageKey.user_id == owner_id,
            MessageKey.recovery_key_id.is_not(None),
        )
        .order_by(MessageKey.created_at)
    ).all()
    return MessageForDevice(
        MailboxItem(entry, message, sender.ethereum_address if sender else None),
        list(pkesks),
        list(recovery_pkesks),
    )


def move(
    session: Session,
    owner_id: uuid.UUID,
    message_id: uuid.UUID,
    folder: Folder,
    folder_id: uuid.UUID | None = None,
) -> MailboxEntry:
    """Fixed folders: recipients use inbox/trash, the sender sent/trash. Any
    message may also go to one of the owner's folders."""
    entry = _entry(session, owner_id, message_id)
    message = session.get(Message, message_id)
    assert message is not None
    home = Folder.SENT if message.sender_id == owner_id else Folder.INBOX
    if folder is Folder.CUSTOM:
        from agnusmail.modules.folders.service import own_folder

        if folder_id is None:
            raise InvalidStateError("folder_id is required for custom folders")
        own_folder(session, owner_id, folder_id)
    elif folder_id is not None:
        raise InvalidStateError("folder_id is only for custom folders")
    elif folder not in (home, Folder.TRASH):
        raise InvalidStateError(f"this message can only be in {home}, trash or a folder")
    entry.folder = folder
    entry.folder_id = folder_id
    session.flush()
    return entry


def delete_permanently(session: Session, owner_id: uuid.UUID, message_id: uuid.UUID) -> list[str]:
    """Delete a message from the owner's trash: their entry and their
    PKESKs go; when no one holds the message any more, it and its attachments go too.
    Returns the object keys to delete from storage after the commit."""
    from agnusmail.modules.attachments.models import Attachment, AttachmentStatus

    entry = _entry(session, owner_id, message_id)
    if entry.folder != Folder.TRASH:
        raise InvalidStateError("only messages in the trash can be deleted")
    message = session.get(Message, message_id)
    assert message is not None
    session.execute(
        delete(MessageKey).where(
            MessageKey.message_id == message_id, MessageKey.user_id == owner_id
        )
    )
    session.delete(entry)
    session.flush()
    add_usage(session, owner_id, -message.size)
    remaining = session.scalar(
        select(func.count()).select_from(MailboxEntry).where(MailboxEntry.message_id == message_id)
    )
    if remaining:
        return []
    objects: list[str] = []
    now = datetime.now(UTC)
    for attachment in session.scalars(
        select(Attachment).where(Attachment.message_id == message_id).with_for_update()
    ):
        objects.append(attachment.object_key)
        add_usage(session, attachment.owner_id, -attachment.size)
        attachment.status = AttachmentStatus.DELETED
        attachment.message_id = None
        attachment.deleted_at = now
    session.flush()
    session.execute(delete(MessageKey).where(MessageKey.message_id == message_id))
    session.delete(message)
    session.flush()
    return objects


def mark_read(
    session: Session, owner_id: uuid.UUID, message_id: uuid.UUID, now: datetime
) -> MailboxEntry:
    entry = _entry(session, owner_id, message_id)
    if entry.read_at is None:
        entry.read_at = now
        session.flush()
    return entry


def share_with_devices(
    session: Session, owner_id: uuid.UUID, message_id: uuid.UUID, pkesks: list[bytes], now: datetime
) -> int:
    """§6.4: a device that holds the session key re-wraps it for the owner's other
    devices. Only the owner's published keys are accepted; nothing is rewritten."""
    _entry(session, owner_id, message_id)
    mine = published_keys(session, owner_id, now)
    existing = set(
        session.scalars(select(MessageKey.public_key_id).where(MessageKey.message_id == message_id))
    )
    added = 0
    for pkesk in pkesks:
        try:
            fingerprint = pkesk_recipient(pkesk)
        except EnvelopeRejectedError as exc:
            raise EnvelopeInvalidError(exc.reason) from exc
        key = mine.get(fingerprint)
        if key is None or key.public_key_id is None:  # devices only (not the recovery key)
            raise RecipientKeysChangedError("PKESK is not for one of your published device keys")
        if key.public_key_id in existing:
            raise ConflictError("this device already has a key for the message")
        session.add(
            MessageKey(
                message_id=message_id,
                user_id=owner_id,
                device_id=key.device_id,
                public_key_id=key.public_key_id,
                pkesk=pkesk,
            )
        )
        existing.add(key.public_key_id)
        added += 1
    session.flush()
    return added
