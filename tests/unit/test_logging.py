"""Tests for log redaction (SECURITY.md: redaction is mandatory and tested)."""

import json

import pytest

from agnusmail.core.logging import REDACTED, configure_logging, get_logger, redact_sensitive


def test_redact_sensitive_masks_sensitive_keys() -> None:
    event = {
        "event": "login",
        "session_token": "abc",
        "Authorization": "Bearer x",
        "signature": "0xdead",
        "database_dsn": "postgres://u:p@h",
        "private_key": "k",
        "path": "/v1/auth/siwe/verify",
    }
    result = redact_sensitive(None, "info", event)
    assert result["event"] == "login"
    assert result["path"] == "/v1/auth/siwe/verify"
    for key in ("session_token", "Authorization", "signature", "database_dsn", "private_key"):
        assert result[key] == REDACTED


def test_rendered_logs_never_contain_secret_values(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging()
    get_logger("test").info("event", token="super-secret-token", status=200)
    line = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(line)
    assert "super-secret-token" not in line
    assert payload["token"] == REDACTED
    assert payload["status"] == 200
