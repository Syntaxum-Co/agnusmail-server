"""Metrics: useful, and free of personal data.

Real traffic goes through the API (login, devices, addresses, messages, an abuse limit),
then the whole exposition is scanned for anything that identifies a person or a
resource: wallet addresses, e-mail addresses, UUIDs, long hex (tokens, keys, ids).
"""

import re
import uuid
from typing import Any

from prometheus_client import REGISTRY, CollectorRegistry, generate_latest

from agnusmail.infrastructure.metrics import DatabaseGauges, start_metrics
from tests.unit.fakes import make_app, make_session_factory, make_settings
from tests.unit.test_messages import compose, person, send

FORBIDDEN = {
    "wallet address": re.compile(r"0x[0-9a-fA-F]{40}"),
    "e-mail address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "uuid": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "long hex": re.compile(r"[0-9a-f]{32,}"),
}


def exposition() -> str:
    return generate_latest(REGISTRY).decode()


def test_metrics_after_real_traffic_hold_no_personal_data() -> None:
    factory = make_session_factory()
    app = make_app(make_settings(internal_messages_per_hour=2), factory)[0]
    alice, bob = person(app), person(app)
    alice.client.post("/v1/addresses", json={"local_part": "metrics" + uuid.uuid4().hex[:6]})
    message_id = send(alice, compose(alice, [bob])).json()["id"]
    bob.client.get(f"/v1/messages/{message_id}")
    bob.client.get(f"/v1/messages/{uuid.uuid4()}")  # 404 on an id route
    send(alice, compose(alice, [bob]))
    assert send(alice, compose(alice, [bob])).status_code == 429  # abuse limit hit
    alice.client.get("/v1/no-such-route/" + alice.user.address)

    text = exposition()
    assert 'route="/messages/{message_id}"' in text  # templates, not raw paths
    assert 'route="unmatched"' in text
    assert "agnusmail_messages_sent_total" in text
    assert 'agnusmail_abuse_limit_hits_total{kind="internal_messages"}' in text
    samples = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    for name, pattern in FORBIDDEN.items():
        found = pattern.search(samples)
        assert found is None, f"{name} in metrics: {found.group(0) if found else ''}"


def test_database_gauges_are_counts_and_never_break_the_scrape() -> None:
    registry = CollectorRegistry()
    registry.register(DatabaseGauges(make_session_factory()))
    text = generate_latest(registry).decode()
    for name in (
        "agnusmail_outbound_queued",
        "agnusmail_outbound_oldest_queued_seconds",
        "agnusmail_jobs_dead",
        "agnusmail_audit_chain_broken",
        "agnusmail_accounts_restricted",
    ):
        assert f"{name} 0.0" in text

    def broken() -> Any:
        raise RuntimeError("database down")

    failing = CollectorRegistry()
    failing.register(DatabaseGauges(broken))
    assert generate_latest(failing) == b""  # no samples, no exception


def test_metrics_are_off_unless_configured() -> None:
    assert start_metrics(make_settings()) is False
