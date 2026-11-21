"""The outbound service process: keys, startup refusals, DNS records, and the
guard that decryption exists only in the queue key module."""

import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pysequoia
import pytest

from agnusmail.apps.smtp_outbound import __main__ as service
from agnusmail.core.config import Environment, Settings
from agnusmail.infrastructure.openpgp import generate_gateway_key
from agnusmail.modules.outbound.queue_key import (
    QueueKeyError,
    create_queue_key,
    generate_queue_key,
    load_queue_key,
)
from agnusmail.testing.fakes import make_settings

REPO = Path(__file__).resolve().parents[2]


def test_decryption_lives_only_in_the_queue_key_module() -> None:
    """The backend cannot decrypt user data; the single exception is the outbound queue."""
    pattern = re.compile(r"\bdecrypt(or)?\s*\(|decrypt_file\s*\(")
    allowed = {REPO / "src/agnusmail/modules/outbound/queue_key.py"}
    offenders = [
        str(path.relative_to(REPO))
        for path in (REPO / "src").rglob("*.py")
        if pattern.search(path.read_text(encoding="utf-8")) and path not in allowed
    ]
    assert offenders == []


def test_queue_key_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "queue.pgp"
    key = create_queue_key(path)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        create_queue_key(path)
    sealed = pysequoia.encrypt(
        b"mime", recipients=[pysequoia.Cert.from_bytes(key.certificate)], armor=False
    )
    assert key.open(sealed) == b"mime"


@pytest.mark.parametrize(
    "material",
    [
        b"garbage",
        bytes(pysequoia.Tsk.from_bytes(generate_queue_key()).extract_certificate()),  # public
        generate_gateway_key(),  # sign-only: not the device profile
    ],
)
def test_unusable_queue_keys(material: bytes) -> None:
    with pytest.raises(QueueKeyError):
        load_queue_key(material, now=datetime.now(UTC))


def deployed(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "outbound_key_file": Path("/k"),
        "outbound_dkim_key_file": Path("/d"),
        "outbound_hostname": "out.mail.example.com",
    }
    values.update(overrides)
    return make_settings(**values)


@pytest.mark.parametrize(
    ("settings", "hardened", "problem"),
    [
        (deployed(), {"rlimit_core", "not_dumpable"}, None),
        (
            deployed(outbound_key_file=None),
            {"rlimit_core", "not_dumpable"},
            "outbound_queue_key_missing",
        ),
        (deployed(outbound_dkim_key_file=None), set(), "outbound_dkim_key_missing"),
        (deployed(outbound_hostname=None), set(), None),  # local: EHLO "localhost" is fine
    ],
)
def test_startup_problems_local(
    settings: Settings, hardened: set[str], problem: str | None
) -> None:
    assert service.startup_problem(settings, hardened) == problem


def test_startup_problems_deployed(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = deployed()
    monkeypatch.setattr(settings, "environment", "production")
    assert service.startup_problem(settings, set()) == "outbound_process_not_hardened"
    full = {"rlimit_core", "not_dumpable"}
    assert service.startup_problem(settings, full) is None
    monkeypatch.setattr(settings, "outbound_hostname", None)
    assert service.startup_problem(settings, full) == "outbound_hostname_missing"


def test_relay_is_refused_in_production() -> None:
    with pytest.raises(ValueError, match="outbound_relay"):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            environment=Environment.PRODUCTION,
            database_url="postgresql+psycopg://u:p@h/db?sslmode=require",
            redis_url="redis://r",
            force_https=True,
            siwe_domain="mail.example.com",
            siwe_uri="https://mail.example.com/login",
            mail_domain="mail.example.com",
            outbound_relay="relay.example.com:25",
        )


def test_run_refuses_without_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "get_settings", lambda: make_settings())
    monkeypatch.setattr(service, "configure_logging", lambda **_: None)
    monkeypatch.setattr(service, "harden_process", set)  # keep the test process dumpable
    assert service.run() == 2


def test_run_refuses_unreadable_keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    bad.write_bytes(b"x")
    bad.chmod(0o600)
    settings = make_settings(outbound_key_file=bad, outbound_dkim_key_file=bad)
    monkeypatch.setattr(service, "get_settings", lambda: settings)
    monkeypatch.setattr(service, "configure_logging", lambda **_: None)
    monkeypatch.setattr(service, "harden_process", set)  # keep the test process dumpable
    assert service.run() == 2


def test_generate_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    queue, dkim_key = tmp_path / "queue.pgp", tmp_path / "dkim.pem"
    assert service.main(["generate-key", str(queue)]) == 0
    fingerprint = capsys.readouterr().out.strip()
    assert re.fullmatch(r"[0-9a-f]{64}", fingerprint)
    assert service.main(["generate-key", str(queue)]) == 1  # never overwritten
    assert service.main(["generate-key", str(queue), "--if-missing"]) == 0
    assert service.main(["generate-dkim-key", str(dkim_key)]) == 0
    assert dkim_key.read_bytes().startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_dns_records(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    dkim_key = tmp_path / "dkim.pem"
    service.main(["generate-dkim-key", str(dkim_key)])
    settings = make_settings(
        mail_domain="mail.example.com",
        outbound_dkim_key_file=dkim_key,
        outbound_hostname="out.mail.example.com",
    )
    monkeypatch.setattr(service, "get_settings", lambda: settings)
    assert service.main(["dns-records"]) == 0
    out = capsys.readouterr().out
    assert 'mail.example.com. TXT "v=spf1 a:out.mail.example.com -all"' in out
    assert 'agnus1._domainkey.mail.example.com. TXT "v=DKIM1; k=rsa; p=' in out
    assert '_dmarc.mail.example.com. TXT "v=DMARC1; p=reject' in out


def test_serve_survives_failed_rounds_and_stops() -> None:
    stop = threading.Event()
    calls: list[datetime] = []

    class Flaky:
        def run_once(self, now: datetime) -> int:
            calls.append(now)
            if len(calls) == 1:
                raise RuntimeError("database down")
            stop.set()
            return 0

    service.serve(make_settings(outbound_poll_seconds=0.1), Flaky(), stop)  # type: ignore[arg-type]
    assert len(calls) == 2
