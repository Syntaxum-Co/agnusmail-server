"""Structural checks of message parts without decryption (protocol v1 §6.2)."""

from datetime import UTC, datetime

import pysequoia
import pytest

from agnusmail.infrastructure.openpgp import (
    EnvelopeRejectedError,
    check_seipd_v2,
    inspect_device_certificate,
    pkesk_recipient,
)
from agnusmail.testing.openpgp import encrypt_split, new_device


def reason(fn: object, data: bytes) -> str:
    with pytest.raises(EnvelopeRejectedError) as caught:
        fn(data)  # type: ignore[operator]
    return caught.value.reason


def test_pkesk_names_the_encryption_subkey_and_body_is_seipd_v2() -> None:
    sender, recipient = new_device(), new_device()
    pkesks, body = encrypt_split(b"hello", [recipient.cert], sender)
    described = inspect_device_certificate(recipient.material, now=datetime.now(UTC))
    assert pkesk_recipient(pkesks[0]) == described.encryption_fingerprint
    check_seipd_v2(body)


def test_non_profile_messages_are_refused() -> None:
    sender = new_device()
    legacy = new_device(profile=pysequoia.Profile.RFC4880)  # v4 recipient key
    pkesks, _ = encrypt_split(b"hello", [legacy.cert], sender)
    assert reason(pkesk_recipient, pkesks[0]) == "pkesk_recipient_not_v6"

    classic = new_device(encryption_algorithm=pysequoia.EncryptionAlgorithm.X25519)
    pkesks, _ = encrypt_split(b"hello", [classic.cert], sender)
    assert reason(pkesk_recipient, pkesks[0]) == "pkesk_algorithm"  # not post-quantum


def test_framing_and_header_violations() -> None:
    sender, recipient = new_device(), new_device()
    pkesks, body = encrypt_split(b"hello", [recipient.cert], sender)
    assert reason(check_seipd_v2, pkesks[0]) == "unexpected_packet"
    assert reason(pkesk_recipient, body) == "unexpected_packet"
    assert reason(check_seipd_v2, body + body) == "not_a_single_packet"
    assert reason(check_seipd_v2, b"-----BEGIN PGP MESSAGE-----") == "armored"
    assert reason(pkesk_recipient, b"\xff\xff\xff") in {"malformed", "not_a_single_packet"}
    header = body.index(bytes([2, 9, 2]))  # SEIPDv2: version 2, AES-256, OCB
    for offset, value, expected in (
        (0, 1, "seipd_not_v2"),
        (1, 7, "seipd_cipher"),
        (2, 1, "seipd_aead_mode"),
        (3, 17, "seipd_chunk_size"),
    ):
        raw = bytearray(body)
        raw[header + offset] = value
        assert reason(check_seipd_v2, bytes(raw)) == expected
    raw = bytearray(pkesks[0])
    raw[raw.index(bytes([6, 33, 6])) + 35] = 25  # algorithm 35 -> X25519 (25)
    # The fields that follow no longer fit X25519, so the packet framing itself may fail.
    assert reason(pkesk_recipient, bytes(raw)) in {"pkesk_algorithm", "malformed"}
