"""Gateway signing key (protocol v1 §9): sign-only, published, kept as history."""

import base64
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pysequoia
import pytest
from fastapi.testclient import TestClient
from pysequoia.packet import PacketPile, Tag

from agnusmail.apps.smtp_inbound.__main__ import main
from agnusmail.infrastructure.openpgp import (
    GatewayKeyRejectedError,
    generate_gateway_key,
    load_gateway_key,
)
from agnusmail.modules.inbound.delivery import register_gateway_key
from agnusmail.modules.inbound.keyfile import KeyFileError, create_signing_key, read_signing_key
from agnusmail.testing.fakes import make_app, make_session_factory
from agnusmail.testing.openpgp import new_device

NOW = datetime.now(UTC)


def test_gateway_key_signs_and_cannot_be_encrypted_to() -> None:
    key = load_gateway_key(generate_gateway_key(), now=NOW)
    tags = [packet.tag for packet in PacketPile.from_bytes(key.certificate)]
    assert tags == [Tag.PublicKey, Tag.Signature, Tag.PublicSubkey, Tag.Signature]
    with pytest.raises(Exception):  # noqa: B017 (the library raises a plain error)
        pysequoia.encrypt(b"x", recipients=[pysequoia.Cert.from_bytes(key.certificate)])
    signed = pysequoia.sign(key.signer(), b"x", mode=pysequoia.SignatureMode.INLINE, armor=False)
    hashes = [p.hash_algorithm for p in PacketPile.from_bytes(signed) if p.tag == Tag.Signature]
    assert [str(h) for h in hashes] == ["HashAlgorithm.SHA512"]  # spec §6.1
    assert len(key.fingerprint) == 64  # v6
    assert timedelta(days=700) < key.expires_at - NOW <= timedelta(days=731)


def test_keys_that_could_decrypt_or_have_expired_are_refused() -> None:
    device = new_device()  # has an ML-KEM encryption subkey
    with pytest.raises(GatewayKeyRejectedError, match="encryption"):
        load_gateway_key(bytes(device.tsk), now=NOW)
    with pytest.raises(GatewayKeyRejectedError, match="expired"):
        load_gateway_key(generate_gateway_key(), now=NOW + timedelta(days=800))
    with pytest.raises(GatewayKeyRejectedError):
        load_gateway_key(b"not a key", now=NOW)
    with pytest.raises(GatewayKeyRejectedError):  # a public certificate is not enough
        load_gateway_key(load_gateway_key(generate_gateway_key(), now=NOW).certificate, now=NOW)


def test_key_file_is_private_and_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "gateway.pgp"
    created = create_signing_key(path)
    assert read_signing_key(path).fingerprint == created.fingerprint
    with pytest.raises(FileExistsError):
        create_signing_key(path)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        path.chmod(0o640)
        with pytest.raises(KeyFileError, match="group/others"):
            read_signing_key(path)
    with pytest.raises(KeyFileError, match="not found"):
        read_signing_key(tmp_path / "missing.pgp")


def test_generate_key_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "gateway.pgp"
    assert main(["generate-key", str(path)]) == 0
    fingerprint = capsys.readouterr().out.strip()
    assert read_signing_key(path).fingerprint == fingerprint
    assert main(["generate-key", str(path), "--if-missing"]) == 0  # kept as is
    assert read_signing_key(path).fingerprint == fingerprint
    assert main(["generate-key", str(path)]) == 1  # refuses to overwrite


def test_published_keys_are_public_and_kept_as_history() -> None:
    factory = make_session_factory()
    app, _ = make_app(session_factory=factory)
    first = load_gateway_key(generate_gateway_key(), now=NOW)
    second = load_gateway_key(generate_gateway_key(), now=NOW)
    with factory() as session, session.begin():
        assert register_gateway_key(session, first) is True
        assert register_gateway_key(session, first) is False  # idempotent restart
        assert register_gateway_key(session, second) is True  # rotation keeps the old one
    with TestClient(app) as anonymous:  # no session needed
        items = anonymous.get("/v1/gateway/keys").json()["items"]
    assert [item["fingerprint"] for item in items] == [first.fingerprint, second.fingerprint]
    assert base64.b64decode(items[0]["material"]) == first.certificate


@pytest.mark.parametrize(
    ("missing", "event"),
    [
        ({"inbound_rspamd_url": None}, "inbound_antispam_missing"),
        ({"inbound_tls_cert_file": None}, "inbound_tls_missing"),
        ({"inbound_signing_key_file": None}, "inbound_signing_key_missing"),
        ({"inbound_proxy_protocol": True}, "inbound_proxy_without_trusted_proxies"),
        ({"hardened": {"rlimit_core"}}, "inbound_process_not_hardened"),
    ],
)
def test_gateway_refuses_to_start_without_its_safeguards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: dict[str, Any], event: str
) -> None:
    """Outside local: antispam, STARTTLS and the signing key are mandatory."""
    from structlog.testing import capture_logs

    import agnusmail.apps.smtp_inbound.__main__ as entry
    from agnusmail.testing.fakes import make_settings
    from tests.unit.test_config import DEPLOYED

    complete = DEPLOYED | {
        "environment": "production",
        "inbound_rspamd_url": "http://rspamd:11333",
        "inbound_tls_cert_file": tmp_path / "cert.pem",
        "inbound_tls_key_file": tmp_path / "key.pem",
        "inbound_signing_key_file": tmp_path / "gateway.pgp",
    }
    hardened = missing.pop("hardened", {"rlimit_core", "not_dumpable"})
    settings = make_settings(**(complete | missing))
    monkeypatch.setattr(entry, "get_settings", lambda: settings)
    monkeypatch.setattr(entry, "configure_logging", lambda **_kw: None)
    monkeypatch.setattr(entry, "harden_process", lambda: hardened)
    monkeypatch.setattr(entry, "create_db_engine", lambda _s: pytest.fail("must stop before"))
    with capture_logs() as logs:
        assert entry.run() == 2
    assert event in [entry_log["event"] for entry_log in logs]
