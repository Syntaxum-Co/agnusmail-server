"""Prometheus metrics.

Privacy rule: labels only take values from small fixed sets (HTTP method, the route
*template* such as ``/v1/messages/{message_id}``, status code, outcome, job kind).
Never an id, address, e-mail, token, key, IP or anything from a message. A test scrapes
the exposition after real traffic and looks for such values.

Each process serves its own ``/metrics`` on ``AGNUSMAIL_METRICS_PORT`` (unset: off),
reachable only on the internal network (the port is not published).
"""

import threading
from typing import Any

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    Counter,
    Histogram,
    start_http_server,
)
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector

from agnusmail.core.config import Settings
from agnusmail.core.logging import get_logger

log = get_logger(__name__)

HTTP_REQUESTS = Counter(
    "agnusmail_http_requests_total", "API requests", ["method", "route", "status"]
)
HTTP_LATENCY = Histogram(
    "agnusmail_http_request_duration_seconds",
    "API request duration",
    ["method", "route"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
MESSAGES_SENT = Counter("agnusmail_messages_sent_total", "E2EE messages sent between users")
INBOUND = Counter(
    "agnusmail_inbound_messages_total", "Inbound SMTP transactions by outcome", ["outcome"]
)
OUTBOUND_RECIPIENTS = Counter(
    "agnusmail_outbound_recipients_total", "Outbound delivery attempts by outcome", ["outcome"]
)
JOBS = Counter("agnusmail_jobs_total", "Worker jobs by kind and outcome", ["kind", "outcome"])
ABUSE_LIMIT_HITS = Counter("agnusmail_abuse_limit_hits_total", "Abuse limits reached", ["kind"])

_started: set[int] = set()
_lock = threading.Lock()


def start_metrics(settings: Settings, registry: CollectorRegistry = REGISTRY) -> bool:
    """Serve /metrics for this process if configured (idempotent). True when serving."""
    port = settings.metrics_port
    if port is None:
        return False
    with _lock:
        if port in _started:
            return True
        start_http_server(port, addr=settings.metrics_host, registry=registry)
        _started.add(port)
    log.info("metrics_listening", port=port)
    return True


class DatabaseGauges(Collector):
    """Queue and health gauges read from the database at scrape time (worker process).

    Counts only — never rows' contents. A failing query yields no samples instead of
    breaking the scrape (``up`` stays 1, the alert on missing series catches it)."""

    def __init__(self, factory: Any) -> None:
        self._factory = factory

    def collect(self) -> Any:
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import func, select

        from agnusmail.modules.abuse.models import AccountRestriction
        from agnusmail.modules.jobs.models import Job, JobStatus
        from agnusmail.modules.outbound.models import OutboundMessage, OutboundStatus

        now = datetime.now(UTC)
        try:
            with self._factory() as session:
                queued, oldest = session.execute(
                    select(func.count(), func.min(OutboundMessage.created_at)).where(
                        OutboundMessage.status == OutboundStatus.QUEUED
                    )
                ).one()
                dead = session.scalar(
                    select(func.count()).select_from(Job).where(Job.status == JobStatus.DEAD)
                )
                broken = session.scalar(
                    select(func.count())
                    .select_from(Job)
                    .where(
                        Job.kind == "audit.verify",
                        Job.status == JobStatus.DEAD,
                        Job.created_at > now - timedelta(days=2),
                    )
                )
                restricted = session.scalar(
                    select(func.count())
                    .select_from(AccountRestriction)
                    .where(AccountRestriction.restricted_until > now)
                )
        except Exception as exc:
            log.warning("metrics_database_unavailable", error_type=type(exc).__name__)
            return
        oldest_age = 0.0
        if oldest is not None:
            moment = oldest if oldest.tzinfo else oldest.replace(tzinfo=UTC)
            oldest_age = max((now - moment).total_seconds(), 0.0)
        for name, help_text, value in (
            ("agnusmail_outbound_queued", "Outbound messages waiting", queued),
            ("agnusmail_outbound_oldest_queued_seconds", "Age of the oldest", oldest_age),
            ("agnusmail_jobs_dead", "Jobs that exhausted their attempts", dead),
            ("agnusmail_audit_chain_broken", "Failed audit verifications (2 days)", broken),
            ("agnusmail_accounts_restricted", "Accounts under abuse restriction", restricted),
        ):
            gauge = GaugeMetricFamily(name, help_text)
            gauge.add_metric([], float(value or 0))
            yield gauge
