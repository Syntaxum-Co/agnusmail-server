"""Driver for scripts/inbound-no-persistence.sh. Runs on the compose network.

    python scripts/inbound_persistence_driver.py send <marker>
    python scripts/inbound_persistence_driver.py scan <marker> <address>

``send`` creates a recipient (account, device, address) through the API code against
the shared database, then sends to the real gateway container (``smtp-inbound:2525``):
an ordinary message, a GTUBE spam test message (Rspamd rejects it) and an oversized one
(552), all carrying the marker in envelope, headers and body. Prints the address.
``scan`` searches every table and every Redis key/value for the marker, with controls.
"""

import smtplib
import sys

from sqlalchemy.orm import sessionmaker
from tests.integration.test_inbound_no_plaintext import found_in_database, found_in_redis
from tests.integration.test_messages_postgres import live_person

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine

GATEWAY = ("smtp-inbound", 2525)
GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"


def message(marker: str, address: str, body: str) -> bytes:
    return (
        f"From: Someone <{marker}@example.org>\r\nTo: {address}\r\n"
        f"Subject: {marker} subject\r\nMessage-ID: <{marker}@example.org>\r\n"
        f"Date: Fri, 13 Nov 2026 10:00:00 +0000\r\n\r\n{body}\r\n"
    ).encode()


def deliver(marker: str, address: str, content: bytes) -> int:
    with smtplib.SMTP(*GATEWAY, timeout=120) as client:
        client.ehlo("mx.example.org")
        code, _ = client.mail(f"{marker}@example.org")
        if code != 250:
            return code
        code, _ = client.rcpt(address)
        if code != 250:
            return code
        code, _ = client.data(content)
        return code


def send(marker: str) -> int:
    settings = Settings(_env_file=None, rate_limit_auth_per_ip=10_000)  # type: ignore[call-arg]
    engine = create_db_engine(settings)
    try:
        person = live_person(settings, sessionmaker(bind=engine, expire_on_commit=False))
        name = "pc" + marker[-10:]
        response = person.client.post("/v1/addresses", json={"local_part": name})
        assert response.status_code == 201, response.text
        address = f"{name}@{settings.mail_domain}"
        results = {
            "ordinary": deliver(marker, address, message(marker, address, f"{marker} body")),
            "gtube": deliver(marker, address, message(marker, address, f"{marker}\r\n{GTUBE}")),
            "oversized": deliver(
                marker, address, message(marker, address, (marker + " x" * 300 + "\r\n") * 2000)
            ),
        }
        print(f"address={address}", file=sys.stderr)
        print(f"results={results}", file=sys.stderr)
        assert results["ordinary"] == 250, results
        assert results["gtube"] == 550, results  # Rspamd: reject
        assert results["oversized"] == 552, results
        person.client.__exit__(None, None, None)
    finally:
        engine.dispose()
    print(address)
    return 0


def scan(marker: str, address: str) -> int:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    engine = create_db_engine(settings)
    try:
        local_part = address.split("@", 1)[0]
        controls = found_in_database(engine, local_part)
        assert "mail_addresses (text)" in controls, controls  # the search works
        database = found_in_database(engine, marker)
        cache = found_in_redis(settings.redis_url, marker)
    finally:
        engine.dispose()
    print(f"database={database} redis={cache}", file=sys.stderr)
    return 0 if not database and not cache else 1


if __name__ == "__main__":
    command, *args = sys.argv[1:]
    sys.exit(send(*args) if command == "send" else scan(*args))
