"""The outbound queue worker (protocol v1 §10).

Each round: expire what passed 72 h, reserve due messages (``FOR UPDATE SKIP LOCKED``
and a lease, so several service instances never send the same message at once), then,
per message and outside any transaction: decrypt in memory, apply the policy, sign with
DKIM and deliver per recipient domain. The plaintext is never written anywhere; when a
message is finished (every recipient delivered or failed for good) its ciphertext is
erased in the same transaction that records the results.

Retries: temporary failures wait 5 min, doubling, capped at 3 h, until the 72 h limit.
"""

import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Protocol

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.logging import get_logger
from agnusmail.infrastructure.metrics import OUTBOUND_RECIPIENTS
from agnusmail.modules.outbound.delivery import Outcome, Result
from agnusmail.modules.outbound.dkim import DkimSigner
from agnusmail.modules.outbound.models import (
    OutboundMessage,
    OutboundRecipient,
    OutboundStatus,
    RecipientStatus,
)
from agnusmail.modules.outbound.policy import PolicyError, prepare
from agnusmail.modules.outbound.queue_key import QueueDecryptionError, QueueKey
from agnusmail.modules.outbound.recipients import domain_of

log = get_logger(__name__)

FIRST_RETRY = timedelta(minutes=5)
MAX_RETRY = timedelta(hours=3)


class Transport(Protocol):
    def deliver(
        self, domain: str, sender: str, recipients: list[str], data: bytes
    ) -> dict[str, Result]: ...


def retry_delay(attempts: int) -> timedelta:
    """Wait after the ``attempts``-th failed attempt (1-based)."""
    return min(FIRST_RETRY * (1 << min(max(attempts - 1, 0), 16)), MAX_RETRY)


def expire_due(session: Session, now: datetime) -> int:
    """Erase the ciphertext of everything past 72 h. Also run by the worker
    (``outbound.purge``) so the limit holds with the outbound service stopped."""
    due = list(
        session.scalars(
            select(OutboundMessage.id)
            .where(
                OutboundMessage.status == OutboundStatus.QUEUED, OutboundMessage.expires_at <= now
            )
            .with_for_update(skip_locked=True)
        )
    )
    if not due:
        return 0
    session.execute(
        update(OutboundRecipient)
        .where(
            OutboundRecipient.outbound_message_id.in_(due),
            OutboundRecipient.status == RecipientStatus.PENDING,
        )
        .values(status=RecipientStatus.FAILED, smtp_status="expired", updated_at=now)
    )
    session.execute(
        update(OutboundMessage)
        .where(OutboundMessage.id.in_(due))
        .values(
            status=OutboundStatus.EXPIRED,
            payload=None,
            finished_at=now,
            locked_until=None,
        )
    )
    return len(due)


@dataclass(frozen=True)
class _Work:
    id: uuid.UUID
    client_message_id: str
    sender: str
    key_fingerprint: str
    payload: bytes
    attempts: int
    pending: list[str]


class OutboundSender:
    def __init__(
        self,
        factory: "sessionmaker[Session]",
        *,
        keys: Iterable[QueueKey],
        signer: DkimSigner,
        transport: Transport,
        mail_domain: str,
        batch_size: int = 10,
        lease: timedelta = timedelta(minutes=10),
    ) -> None:
        self._factory = factory
        self._keys = {key.encryption_fingerprint: key for key in keys}
        self._signer = signer
        self._transport = transport
        self._mail_domain = mail_domain
        self._batch = batch_size
        self._lease = lease

    def run_once(self, now: datetime) -> int:
        """One round; returns how many messages were attempted."""
        with self._factory() as session, session.begin():
            expired = expire_due(session, now)
        if expired:
            log.info("outbound_expired", count=expired)
        claimed = self._claim(now)
        for work in claimed:
            self._process(work, now)
        return len(claimed)

    def _claim(self, now: datetime) -> list[_Work]:
        with self._factory() as session, session.begin():
            rows = list(
                session.scalars(
                    select(OutboundMessage)
                    .where(
                        OutboundMessage.status == OutboundStatus.QUEUED,
                        # Only what this instance can open: during a rotation, or with a
                        # misconfigured instance, others' messages are left to them.
                        OutboundMessage.key_fingerprint.in_(list(self._keys)),
                        OutboundMessage.next_attempt_at <= now,
                        OutboundMessage.expires_at > now,
                        (OutboundMessage.locked_until.is_(None))
                        | (OutboundMessage.locked_until < now),
                    )
                    .order_by(OutboundMessage.next_attempt_at)
                    .limit(self._batch)
                    .with_for_update(skip_locked=True)
                )
            )
            work: list[_Work] = []
            for row in rows:
                assert row.payload is not None  # CHECK: queued rows keep the payload
                row.locked_until = now + self._lease
                pending = session.scalars(
                    select(OutboundRecipient.address).where(
                        OutboundRecipient.outbound_message_id == row.id,
                        OutboundRecipient.status == RecipientStatus.PENDING,
                    )
                ).all()
                work.append(
                    _Work(
                        row.id,
                        row.client_message_id,
                        row.sender_address,
                        row.key_fingerprint,
                        row.payload,
                        row.attempts,
                        list(pending),
                    )
                )
        return work

    def _process(self, work: _Work, now: datetime) -> None:
        results = self._attempt(work, now)
        self._record(work, results, now)

    def _attempt(self, work: _Work, now: datetime) -> dict[str, Result]:
        key = self._keys[work.key_fingerprint]  # claimed only for keys we hold
        try:
            plaintext = key.open(work.payload)
        except QueueDecryptionError:
            log.error("outbound_payload_unreadable", outbound_id=str(work.id))
            return dict.fromkeys(work.pending, Result(Outcome.FAILED, None, "unreadable"))
        try:
            prepared = prepare(
                plaintext,
                sender=work.sender,
                message_id=work.client_message_id,
                mail_domain=self._mail_domain,
                now=now,
            )
        except PolicyError as exc:
            return dict.fromkeys(work.pending, Result(Outcome.FAILED, None, f"policy_{exc.reason}"))
        finally:
            del plaintext
        # d= is the sender's domain: the service's, or a custom domain whose DKIM
        # selector is a CNAME to ours.
        signer = replace(self._signer, domain=domain_of(work.sender))
        data = signer.signature(prepared) + prepared
        del prepared
        by_domain: dict[str, list[str]] = defaultdict(list)
        for address in work.pending:
            by_domain[domain_of(address)].append(address)
        results: dict[str, Result] = {}
        for domain, addresses in sorted(by_domain.items()):
            try:
                results.update(self._transport.deliver(domain, work.sender, addresses, data))
            except Exception:  # a bug in one domain's delivery must not lose the others
                log.exception("outbound_delivery_error", outbound_id=str(work.id))
                results.update(
                    dict.fromkeys(addresses, Result(Outcome.RETRY, None, "internal_error"))
                )
        del data
        return results

    def _record(self, work: _Work, results: dict[str, Result], now: datetime) -> None:
        with self._factory() as session, session.begin():
            row = session.get(OutboundMessage, work.id, with_for_update=True)
            if row is None or row.status != OutboundStatus.QUEUED:
                return  # expired meanwhile: the purge already settled it
            recipients = session.scalars(
                select(OutboundRecipient).where(
                    OutboundRecipient.outbound_message_id == work.id,
                    OutboundRecipient.status == RecipientStatus.PENDING,
                )
            ).all()
            still_pending = 0
            for recipient in recipients:
                result = results.get(recipient.address)
                if result is None:
                    still_pending += 1
                    continue
                recipient.smtp_code = result.code
                recipient.smtp_status = result.status
                recipient.updated_at = now
                if result.outcome is Outcome.DELIVERED:
                    recipient.status = RecipientStatus.DELIVERED
                elif result.outcome is Outcome.FAILED:
                    recipient.status = RecipientStatus.FAILED
                else:
                    still_pending += 1
            row.attempts = work.attempts + 1
            row.locked_until = None
            if still_pending:
                row.next_attempt_at = now + retry_delay(row.attempts)
            else:
                row.status = OutboundStatus.DONE
                row.payload = None
                row.finished_at = now
        for result in results.values():
            OUTBOUND_RECIPIENTS.labels(outcome=str(result.outcome)).inc()
        log.info(
            "outbound_attempt",
            outbound_id=str(work.id),
            delivered=sum(r.outcome is Outcome.DELIVERED for r in results.values()),
            failed=sum(r.outcome is Outcome.FAILED for r in results.values()),
            retry=sum(r.outcome is Outcome.RETRY for r in results.values()),
        )
