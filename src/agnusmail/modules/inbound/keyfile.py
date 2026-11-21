"""The gateway signing key file (protocol v1 §9).

The file holds the gateway's secret signing key (no encryption subkey — see
``infrastructure.openpgp``). It comes from the secret manager; on POSIX it must not be
readable by group or others. It is created once, never overwritten.
"""

import os
import stat
from datetime import UTC, datetime
from pathlib import Path

from agnusmail.infrastructure.openpgp import GatewayKey, generate_gateway_key, load_gateway_key


class KeyFileError(Exception):
    pass


def check_private_file(path: Path) -> None:
    """A secret file (signing key, TLS key) must exist and, on POSIX, not be accessible
    by group or others."""
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise KeyFileError(f"{path.name}: file not found") from exc
    if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise KeyFileError(f"{path.name}: must not be accessible by group/others")


def read_signing_key(path: Path) -> GatewayKey:
    check_private_file(path)
    return load_gateway_key(path.read_bytes(), now=datetime.now(UTC))


def create_signing_key(path: Path) -> GatewayKey:
    """Write a new key with mode 0600; refuses to replace an existing file."""
    data = generate_gateway_key()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    return load_gateway_key(data, now=datetime.now(UTC))
