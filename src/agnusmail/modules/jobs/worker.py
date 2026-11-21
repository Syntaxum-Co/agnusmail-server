"""Worker loop: schedule periodic jobs, reap expired leases, claim and run jobs.

Several worker processes can run at once: claims never overlap (SKIP LOCKED) and
periodic jobs are deduplicated per period. Logs carry job id, kind, attempt and the
exception class only — never payload values or exception messages.
"""

import os
import socket
import threading
from datetime import UTC, datetime

from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.core.logging import get_logger
from agnusmail.infrastructure.metrics import JOBS
from agnusmail.modules.jobs.handlers import REGISTRY, SCHEDULE, Periodic
from agnusmail.modules.jobs.queue import (
    ClaimedJob,
    JobContext,
    JobRegistry,
    claim,
    complete,
    enqueue,
    fail,
    reap_expired,
)

log = get_logger(__name__)


def default_worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"[:128]


class Worker:
    def __init__(
        self,
        factory: sessionmaker[Session],
        settings: Settings,
        *,
        registry: JobRegistry = REGISTRY,
        schedule: tuple[Periodic, ...] = SCHEDULE,
        worker_id: str | None = None,
    ) -> None:
        self.factory = factory
        self.settings = settings
        self.registry = registry
        self.schedule = schedule
        self.worker_id = worker_id or default_worker_id()
        self.context = JobContext(factory=factory, settings=settings)

    def schedule_periodic(self, now: datetime) -> int:
        """Enqueue each periodic job once per period, however many workers run."""
        created = 0
        for periodic in self.schedule:
            period = int(now.timestamp() // periodic.every.total_seconds())
            with self.factory() as session, session.begin():
                created += enqueue(
                    session,
                    self.registry,
                    periodic.kind,
                    now=now,
                    dedupe_key=f"periodic:{periodic.kind}:{period}",
                )
        return created

    def execute(self, job: ClaimedJob) -> None:
        try:
            spec = self.registry.get(job.kind)
            spec.handler(self.context, job.payload)
        except Exception as exc:  # any handler failure is recorded, never fatal to the loop
            error_type = type(exc).__name__
            status = fail(self.factory, job, self.worker_id, error_type, datetime.now(UTC))
            JOBS.labels(job.kind, "dead" if status == "dead" else "failed").inc()
            log.error(
                "job_failed",
                job_id=job.id,
                kind=job.kind,
                attempt=job.attempts,
                error_type=error_type,
                outcome=None if status is None else str(status),
            )
            return
        if not complete(self.factory, job, self.worker_id, datetime.now(UTC)):
            log.warning("job_lease_lost", job_id=job.id, kind=job.kind)
            return
        JOBS.labels(job.kind, "succeeded").inc()
        log.info("job_succeeded", job_id=job.id, kind=job.kind, attempt=job.attempts)

    def run_once(self, now: datetime | None = None) -> int:
        """One iteration; returns how many jobs ran."""
        now = now or datetime.now(UTC)
        self.schedule_periodic(now)
        reaped = reap_expired(self.factory, now)
        if reaped:
            log.warning("job_leases_expired", count=reaped)
        ran = 0
        while ran < self.settings.worker_batch_size:
            job = claim(
                self.factory,
                self.worker_id,
                now=now,
                lease_seconds=self.settings.worker_lease_seconds,
            )
            if job is None:
                break
            self.execute(job)
            ran += 1
        return ran

    def run_forever(self, stop: threading.Event) -> None:
        log.info("worker_started", worker_id=self.worker_id, kinds=self.registry.kinds())
        while not stop.is_set():
            try:
                ran = self.run_once()
            except Exception as exc:  # e.g. database down: back off, keep the process alive
                log.error("worker_iteration_failed", error_type=type(exc).__name__)
                ran = 0
            if ran == 0:
                stop.wait(self.settings.worker_poll_seconds)
        log.info("worker_stopped", worker_id=self.worker_id)
