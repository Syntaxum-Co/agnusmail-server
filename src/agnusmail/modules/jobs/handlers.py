"""Job kinds and the periodic schedule of the worker.

Every handler is idempotent: a job can run again after a lease expires.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from agnusmail.core.logging import get_logger
from agnusmail.modules.audit.integrity import chain_owners, purge_expired, verify_user_chain
from agnusmail.modules.jobs.queue import JobContext, JobRegistry, JobSpec, delete_finished
from agnusmail.modules.outbound.models import PURGE_INTERVAL

log = get_logger(__name__)

FINISHED_JOB_RETENTION = timedelta(days=30)


class AuditVerificationFailedError(Exception):
    """A chain failed verification: the job fails so it shows up as ``dead`` (alert)."""


class AuditPurgeIncompleteError(Exception):
    """Some users could not be purged; the job is retried."""


def verify_audit_chains(ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    with ctx.factory() as session:
        reports = [verify_user_chain(session, owner) for owner in chain_owners(session)]
    broken = [r for r in reports if not r.ok]
    for report in broken:
        log.error(
            "audit_chain_broken",
            user_id=str(report.user_id),
            reason=report.reason,
            failed_seq=report.failed_seq,
        )
    log.info("audit_chains_verified", chains=len(reports), broken=len(broken))
    if broken:
        raise AuditVerificationFailedError()


def purge_audit(ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    report = purge_expired(ctx.factory, retention_days=ctx.settings.audit_retention_days)
    log.info(
        "audit_purged",
        users=len(report.purged),
        events=sum(p.deleted for p in report.purged),
        broken=len(report.broken),
        failed=len(report.failed),
    )
    if not report.ok:
        raise AuditPurgeIncompleteError()


def clean_jobs(ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    with ctx.factory() as session, session.begin():
        removed = delete_finished(session, datetime.now(UTC) - FINISHED_JOB_RETENTION)
    log.info("jobs_cleaned", removed=removed)


def clean_attachments(ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    from agnusmail.infrastructure.object_storage import build_object_storage
    from agnusmail.modules.attachments.service import cleanup_orphans

    storage = build_object_storage(ctx.settings)
    if storage is None:  # attachments not configured on this deployment
        return
    removed = cleanup_orphans(
        ctx.factory, storage, older_than_hours=ctx.settings.attachment_orphan_hours
    )
    log.info("attachments_cleaned", removed=removed)


def complete_migrations(ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    import redis

    from agnusmail.modules.authentication.stores import revoke_owner_sessions_sync
    from agnusmail.modules.recovery.migration import complete_due_migrations

    with ctx.factory() as session, session.begin():
        done = complete_due_migrations(session, datetime.now(UTC))
        moved = [str(m.user_id) for m in done]
    if moved:
        client = redis.Redis.from_url(ctx.settings.redis_url)
        try:
            for owner in moved:  # sessions opened with the old wallet end now
                revoke_owner_sessions_sync(client, owner)
        finally:
            client.close()
    log.info("migrations_completed", count=len(moved))


# Delivery state of finished outbound messages (recipient addresses, SMTP codes): kept for
# the sender to see, then deleted. The ciphertext is already gone (72 h at most).
OUTBOUND_RECORD_RETENTION = timedelta(days=30)


def purge_outbound(ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    from sqlalchemy import CursorResult, delete

    from agnusmail.modules.outbound.models import OutboundMessage
    from agnusmail.modules.outbound.sender import expire_due

    now = datetime.now(UTC)
    with ctx.factory() as session, session.begin():
        expired = expire_due(session, now)
        result: CursorResult[Any] = session.execute(  # type: ignore[assignment]
            delete(OutboundMessage).where(
                OutboundMessage.finished_at.is_not(None),
                OutboundMessage.finished_at < now - OUTBOUND_RECORD_RETENTION,
            )
        )
        removed = int(result.rowcount or 0)
    log.info("outbound_purged", expired=expired, removed=removed)


def purge_portal(ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    from agnusmail.modules.portal.service import purge_expired

    with ctx.factory() as session, session.begin():
        removed = purge_expired(session, datetime.now(UTC))
    log.info("portal_purged", removed=removed)


def recompute_usage(ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    from sqlalchemy import select

    from agnusmail.modules.identity.models import User
    from agnusmail.modules.quotas.usage import recompute

    corrected = 0
    with ctx.factory() as session:
        owners = list(session.scalars(select(User.id)))
    for owner in owners:  # one short transaction per account
        with ctx.factory() as session, session.begin():
            if recompute(session, owner):
                corrected += 1
    log.info("usage_recomputed", accounts=len(owners), corrected=corrected)


def evaluate_abuse(ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    """Re-evaluate accounts with recently settled outbound mail (bounce rate)."""
    from agnusmail.modules.abuse.service import Thresholds, evaluate, recent_outbound_senders

    thresholds = Thresholds.from_settings(ctx.settings)
    now = datetime.now(UTC)
    with ctx.factory() as session:
        senders = recent_outbound_senders(session, now - timedelta(days=1))
    restricted = 0
    for sender in senders:
        with ctx.factory() as session, session.begin():
            if evaluate(session, sender, thresholds, now) is not None:
                restricted += 1
    log.info("abuse_evaluated", accounts=len(senders), restricted=restricted)


REGISTRY = JobRegistry(
    [
        # A broken chain needs a human, not retries.
        JobSpec("audit.verify", verify_audit_chains, max_attempts=1),
        JobSpec("audit.purge", purge_audit, max_attempts=3),
        JobSpec("jobs.cleanup", clean_jobs, max_attempts=3),
        JobSpec("attachments.cleanup", clean_attachments, max_attempts=3),
        JobSpec("recovery.migrations", complete_migrations, max_attempts=5),
        JobSpec("outbound.purge", purge_outbound, max_attempts=3),
        JobSpec("portal.purge", purge_portal, max_attempts=3),
        JobSpec("usage.recompute", recompute_usage, max_attempts=3),
        JobSpec("abuse.evaluate", evaluate_abuse, max_attempts=3),
    ]
)


@dataclass(frozen=True)
class Periodic:
    kind: str
    every: timedelta


SCHEDULE = (
    Periodic("audit.verify", timedelta(days=1)),
    Periodic("audit.purge", timedelta(days=1)),
    Periodic("jobs.cleanup", timedelta(days=1)),
    Periodic("attachments.cleanup", timedelta(hours=1)),
    Periodic("recovery.migrations", timedelta(hours=1)),
    Periodic("outbound.purge", PURGE_INTERVAL),
    Periodic("portal.purge", PURGE_INTERVAL),
    Periodic("usage.recompute", timedelta(days=1)),
    Periodic("abuse.evaluate", PURGE_INTERVAL),
)
