"""Unit tests for the strict EIP-4361 parser and temporal checks (3.1.6-3.1.9)."""

from datetime import UTC, datetime, timedelta

import pytest

from agnusmail.modules.identity.siwe import (
    SiweError,
    SiweMessage,
    check_temporal_validity,
    parse_message,
    siwe_verify,
)

ADDRESS = "0x" + "aB" * 20
BASE_LINES = [
    "app.agnusmail wants you to sign in with your Ethereum account:",
    ADDRESS,
    "",
    "Sign in to Agnusmail.",
    "",
    "URI: https://app.agnusmail/login",
    "Version: 1",
    "Chain ID: 1",
    "Nonce: abcdef1234567890",
    "Issued At: 2026-11-10T12:00:00Z",
]


def message(lines: list[str]) -> str:
    return "\n".join(lines)


def test_parses_full_message_with_optional_fields() -> None:
    parsed = parse_message(
        message(
            [
                *BASE_LINES,
                "Expiration Time: 2026-11-10T12:10:00.000Z",
                "Not Before: 2026-11-10T11:59:00+00:00",
                "Request ID: req-1",
                "Resources:",
                "- https://app.agnusmail/terms",
            ]
        )
    )
    assert parsed.domain == "app.agnusmail"
    assert parsed.address == ADDRESS
    assert parsed.statement == "Sign in to Agnusmail."
    assert parsed.chain_id == 1
    assert parsed.expiration_time == datetime(2026, 11, 10, 12, 10, tzinfo=UTC)
    assert parsed.not_before == datetime(2026, 11, 10, 11, 59, tzinfo=UTC)
    assert parsed.request_id == "req-1"
    assert parsed.resources == ("https://app.agnusmail/terms",)


def test_parses_message_without_statement() -> None:
    lines = BASE_LINES[:3] + BASE_LINES[4:]
    parsed = parse_message(message(lines))
    assert parsed.statement is None
    assert parsed.expiration_time is None


@pytest.mark.parametrize(
    ("index", "replacement", "reason"),
    [
        (0, "app.agnusmail wants you to sign in with your account:", "malformed SIWE prefix"),
        (1, "0x1234", "invalid ethereum address"),
        (6, "Version: 2", "unsupported SIWE version"),
        (7, "Chain ID: abc", "invalid chain id"),
        (8, "Nonce: short", "invalid nonce"),
        (9, "Issued At: 2026-11-10", "invalid timestamp in Issued At"),
        (9, "Issued At: 2026-11-10T12:00:00", "timestamp in Issued At must include a timezone"),
        (5, "Version: 1", "malformed SIWE message: expected 'URI'"),
    ],
)
def test_rejects_malformed_fields(index: int, replacement: str, reason: str) -> None:
    lines = list(BASE_LINES)
    lines[index] = replacement
    with pytest.raises(SiweError, match=reason.replace("(", r"\(")):
        parse_message(message(lines))


def test_rejects_duplicate_fields_and_trailing_content() -> None:
    with pytest.raises(SiweError, match="trailing content"):
        parse_message(message([*BASE_LINES, "URI: https://evil.example/login"]))


def test_rejects_crlf_and_oversized_messages() -> None:
    with pytest.raises(SiweError, match="CR not allowed"):
        parse_message("\r\n".join(BASE_LINES))
    with pytest.raises(SiweError, match="too long"):
        parse_message(message(BASE_LINES) + "x" * 5000)


def parsed_at(issued: datetime, **kwargs: datetime | None) -> SiweMessage:
    return SiweMessage(
        domain="d",
        address=ADDRESS,
        statement=None,
        uri="u",
        version="1",
        chain_id=1,
        nonce="abcdef1234",
        issued_at=issued,
        expiration_time=kwargs.get("expiration"),
        not_before=kwargs.get("not_before"),
        request_id=None,
        resources=(),
    )


def test_temporal_validity_rules() -> None:
    now = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    skew = timedelta(seconds=60)
    check_temporal_validity(parsed_at(now + timedelta(seconds=30)), now, skew)  # within skew
    with pytest.raises(SiweError, match="issued in the future"):
        check_temporal_validity(parsed_at(now + timedelta(minutes=5)), now, skew)
    with pytest.raises(SiweError, match="not yet valid"):
        check_temporal_validity(parsed_at(now, not_before=now + timedelta(minutes=5)), now, skew)
    with pytest.raises(SiweError, match="expired"):
        check_temporal_validity(parsed_at(now, expiration=now), now, skew)


class CountingNonceStore:
    def __init__(self) -> None:
        self.calls = 0

    async def consume(self, nonce: str) -> bool:
        self.calls += 1
        return True


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"expected_domain": "other.example"}, "domain mismatch"),
        ({"expected_uri": "https://other.example/login"}, "uri mismatch"),
        ({"expected_chain_id": 5}, "chain id mismatch"),
    ],
)
async def test_expected_values_are_enforced_before_nonce_use(
    kwargs: dict[str, object], reason: str
) -> None:
    store = CountingNonceStore()
    result = await siwe_verify(message(BASE_LINES), "00" * 65, store, **kwargs)  # type: ignore[arg-type]
    assert result.ok is False
    assert result.reason == reason
    assert store.calls == 0


def test_parses_optional_scheme_prefix() -> None:
    lines = list(BASE_LINES)
    lines[0] = "https://app.agnusmail wants you to sign in with your Ethereum account:"
    parsed = parse_message(message(lines))
    assert parsed.scheme == "https"
    assert parsed.domain == "app.agnusmail"
    assert parse_message(message(BASE_LINES)).scheme is None


def test_rejects_malformed_scheme() -> None:
    lines = list(BASE_LINES)
    lines[0] = "1nvalid://app.agnusmail wants you to sign in with your Ethereum account:"
    with pytest.raises(SiweError, match="malformed SIWE scheme"):
        parse_message(message(lines))


async def test_scheme_must_match_expected_uri() -> None:
    lines = list(BASE_LINES)
    lines[0] = "http://app.agnusmail wants you to sign in with your Ethereum account:"
    store = CountingNonceStore()
    result = await siwe_verify(
        message(lines),
        "00" * 65,
        store,
        expected_domain="app.agnusmail",
        expected_uri="https://app.agnusmail/login",
    )
    assert result.reason == "scheme mismatch"
    assert store.calls == 0
