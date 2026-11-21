"""The encrypted recovery backup without a session (protocol v1 §8.4).

Who lost their wallet (and has no passkey or signed-in browser) still needs the backup to
restore the recovery key and request the account migration (§8.5). The backup is an
OpenPGP message encrypted with Argon2 over 256 bits of entropy (§8.1, §8.3): handing it to
anyone does not weaken it.

What must not leak is **which accounts exist**. For an unknown account, or one without a
backup, the answer is a decoy shaped exactly like a real backup (same packet framing,
cipher and Argon2 parameters as the oldest stored backup) whose random-looking bytes come
from HMAC-SHA-256(server secret, account): the same request always gets the same answer,
like a real backup. The secret (``recovery_decoy_secret``) never leaves the server; a
backup owner cannot compute other accounts' decoys.
"""

import hashlib
import hmac

from sqlalchemy import select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import ResourceNotFoundError
from agnusmail.infrastructure.openpgp import split_packets
from agnusmail.modules.addresses.service import resolve
from agnusmail.modules.identity.models import User
from agnusmail.modules.identity.repository import InvalidAddressError, get_by_address
from agnusmail.modules.recovery.models import RecoveryBackup
from agnusmail.modules.recovery.service import latest_backup

ETH_PREFIX = "0x"


def _stream(secret: bytes, account: str, length: int) -> bytes:
    """``length`` deterministic pseudo-random bytes for ``account`` (HMAC-SHA-256 CTR)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(
            secret, f"agnusmail/recovery-decoy/v1\n{account}\n{counter}".encode(), hashlib.sha256
        ).digest()
        counter += 1
    return bytes(out[:length])


def _header_length(packet: bytes) -> int:
    first = packet[1]
    if first < 192:
        return 2
    if first < 224:
        return 3
    return 6


# Built-in shape when no backup exists yet: SKESK v6 (AES-256, OCB, Argon2 t=1 p=4
# m=2^16 KiB, as the reference client writes it) followed by a SEIPDv2 of a typical size.
def _default_template() -> bytes:
    skesk = bytes([6, 77, 9, 2, 20, 4]) + bytes(16) + bytes([1, 4, 16]) + bytes(15 + 32 + 16)
    seipd = bytes([2, 9, 2, 10]) + bytes(32 + 1700)

    def packet(tag: int, body: bytes) -> bytes:
        size = len(body)
        if size < 192:
            header = bytes([0xC0 | tag, size])
        elif size < 8384:
            size -= 192
            header = bytes([0xC0 | tag, (size >> 8) + 192, size & 0xFF])
        else:
            header = bytes([0xC0 | tag, 255]) + size.to_bytes(4, "big")
        return header + body

    return packet(3, skesk) + packet(18, seipd)


def decoy(session: Session, secret: bytes, account: str) -> bytes:
    template_row = session.scalars(
        select(RecoveryBackup.blob).order_by(RecoveryBackup.created_at, RecoveryBackup.id).limit(1)
    ).first()
    template = template_row if template_row is not None else _default_template()
    skesk, seipd = split_packets(template)[:2]
    noise = _stream(secret, account, len(skesk) + len(seipd))
    # Keep what is the same in every backup (framing, versions, algorithms, Argon2
    # parameters); replace what is random in a real one (salts, IVs, ciphertext).
    sh = _header_length(skesk)
    body = bytearray(skesk[sh:])
    body[6:22] = noise[0:16]  # S2K salt
    body[25:] = noise[16 : 16 + len(body) - 25]  # IV, encrypted session key, tag
    new_skesk = skesk[:sh] + bytes(body)
    eh = _header_length(seipd)
    tail = noise[len(skesk) : len(skesk) + len(seipd) - eh - 4]
    new_seipd = seipd[: eh + 4] + tail  # version, cipher, AEAD, chunk size kept
    return new_skesk + new_seipd


def find_user(session: Session, account: str, mail_domain: str) -> User | None:
    """By wallet address or by e-mail address; None if unknown (never raises)."""
    value = account.strip()
    if value.lower().startswith(ETH_PREFIX):
        try:
            return get_by_address(session, value)
        except InvalidAddressError:
            return None
    try:
        return resolve(session, value, mail_domain)[1]
    except ResourceNotFoundError:
        return None


def fetch(session: Session, account: str, mail_domain: str, secret: bytes) -> bytes:
    """The latest backup of the account, or the account's decoy. Same shape either way."""
    user = find_user(session, account, mail_domain)
    if user is not None:
        try:
            return latest_backup(session, user.id).blob
        except ResourceNotFoundError:
            pass
    return decoy(session, secret, account.strip().lower())
