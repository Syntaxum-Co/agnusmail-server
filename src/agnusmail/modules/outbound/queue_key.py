"""The outbound queue key — the ONLY decryption capability in the backend (protocol v1
§10; see SECURITY.md, "The one exception").

Users encrypt the ready MIME message of a conventional (NOT end-to-end encrypted)
external send to this key; only the outbound service holds it and opens its own queue
with it. It never applies to E2EE messages, attachments, backups or user keys: those are
never encrypted to it (the API accepts only a single PKESK for this key on the outbound
route, and the key is not a device of any account). A test guards that no other module
decrypts.

The key follows the device profile (spec §3.1: Ed25519 primary and signing subkey,
ML-KEM-768+X25519 encryption subkey) so clients encrypt to it exactly as to a device.
"""

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pysequoia

from agnusmail.infrastructure.openpgp import (
    CertificateRejectedError,
    inspect_device_certificate,
)
from agnusmail.modules.inbound.keyfile import check_private_file

QUEUE_KEY_VALIDITY_SECONDS = 730 * 86400


class QueueKeyError(ValueError):
    pass


class QueueDecryptionError(Exception):
    """The payload does not open with this key (corrupt, or encrypted to another key)."""


@dataclass(frozen=True)
class QueueKey:
    tsk: Any
    certificate: bytes  # public, published at /v1/outbound/keys
    fingerprint: str
    encryption_fingerprint: str
    expires_at: datetime

    def open(self, payload: bytes) -> bytes:
        """Decrypt one queued payload, in memory. The caller keeps it only while sending."""
        try:
            result = pysequoia.decrypt(decryptor=self.tsk.decryptor(), bytes=payload)
        except Exception as exc:  # the library raises plain RuntimeError
            raise QueueDecryptionError() from exc
        return bytes(result.bytes or b"")


def generate_queue_key() -> bytes:
    tsk = pysequoia.Tsk.generate(
        profile=pysequoia.Profile.RFC9580,
        signing_algorithm=pysequoia.SigningAlgorithm.Ed25519,
        encryption_algorithm=pysequoia.EncryptionAlgorithm.MLKEM768_X25519,
        validity_seconds=QUEUE_KEY_VALIDITY_SECONDS,
    )
    data = bytes(tsk)
    load_queue_key(data, now=datetime.now(UTC))  # proves the result
    return data


def load_queue_key(data: bytes, *, now: datetime) -> QueueKey:
    try:
        tsk = pysequoia.Tsk.from_bytes(data)
        cert = tsk.extract_certificate()
    except Exception as exc:
        raise QueueKeyError("not an OpenPGP secret key") from exc
    certificate = bytes(cert)
    try:
        described = inspect_device_certificate(certificate, now=now)
    except CertificateRejectedError as exc:
        raise QueueKeyError(f"not a protocol v1 key: {exc.reason}") from exc
    key = QueueKey(
        tsk=tsk,
        certificate=certificate,
        fingerprint=described.fingerprint,
        encryption_fingerprint=described.encryption_fingerprint,
        expires_at=described.expires_at,
    )
    probe = b"agnusmail/outbound-queue-key-check/v1"
    try:  # also refuses a public certificate: there is no secret decryption key
        sealed: bytes = pysequoia.encrypt(probe, recipients=[cert], armor=False)
        opened = key.open(sealed)
    except QueueDecryptionError as exc:
        raise QueueKeyError("the key cannot decrypt") from exc
    if opened != probe:
        raise QueueKeyError("the key cannot decrypt")
    return key


def read_queue_key(path: Path) -> QueueKey:
    check_private_file(path)
    return load_queue_key(path.read_bytes(), now=datetime.now(UTC))


def create_queue_key(path: Path) -> QueueKey:
    """Write a new key with mode 0600; refuses to replace an existing file."""
    data = generate_queue_key()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    return load_queue_key(data, now=datetime.now(UTC))
