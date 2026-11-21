"""Redis-backed stores for SIWE nonces and opaque sessions.

Session tokens are never stored as-is: Redis keys hold the SHA-256 of the token,
so a Redis dump does not yield usable session cookies.
"""

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from agnusmail.core.constants import NONCE_KEY_PREFIX, SESSION_KEY_PREFIX

NONCE_TTL_SECONDS = 300  # 5 minutes
MAX_TOKEN_LENGTH = 128
SESSION_DATA_PREFIX = SESSION_KEY_PREFIX + "v1:data:"
SESSION_OWNER_PREFIX = SESSION_KEY_PREFIX + "v1:owner:"
SESSION_DEVICE_PREFIX = SESSION_KEY_PREFIX + "v1:device:"
DEVICE_CHALLENGE_PREFIX = SESSION_KEY_PREFIX + "v1:challenge:"
DEVICE_CHALLENGE_TTL_SECONDS = 120
SESSION_PASSKEY_PREFIX = SESSION_KEY_PREFIX + "v1:passkey:"
PASSKEY_CHALLENGE_PREFIX = SESSION_KEY_PREFIX + "v1:webauthn:"
PASSKEY_CHALLENGE_TTL_SECONDS = 300


def _text(value: Any) -> str:
    return value if isinstance(value, str) else bytes(value).decode("utf-8")


class NonceStore:
    """Single-use SIWE nonces with mandatory expiry."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def _key(self, nonce: str) -> str:
        return f"{NONCE_KEY_PREFIX}v1:{nonce}"

    async def create(self) -> str:
        nonce = secrets.token_hex(16)
        await self._client.set(self._key(nonce), "1", ex=NONCE_TTL_SECONDS)
        return nonce

    async def consume(self, nonce: str) -> bool:
        """Atomically delete the nonce. True only for the single caller that removed it."""
        removed = await self._client.delete(self._key(nonce))
        return int(removed) == 1


@dataclass(frozen=True)
class SessionRecord:
    owner: str
    created_at: float
    data: dict[str, Any]
    # Hashed client fingerprint for suspicious-session detection; never sent to clients.
    fingerprint: dict[str, str] = field(default_factory=dict)


class SessionStore:
    """Opaque session tokens with idle TTL, absolute lifetime and per-owner limit."""

    def __init__(
        self,
        client: Any,
        idle_ttl_seconds: int,
        absolute_ttl_seconds: int,
        max_sessions_per_owner: int,
    ) -> None:
        if idle_ttl_seconds <= 0 or absolute_ttl_seconds < idle_ttl_seconds:
            raise ValueError("require 0 < idle_ttl_seconds <= absolute_ttl_seconds")
        if max_sessions_per_owner <= 0:
            raise ValueError("max_sessions_per_owner must be positive")
        self._client = client
        self._idle_ttl = idle_ttl_seconds
        self._absolute_ttl = absolute_ttl_seconds
        self._max_sessions = max_sessions_per_owner

    @property
    def idle_ttl_seconds(self) -> int:
        return self._idle_ttl

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _data_key(digest: str) -> str:
        return SESSION_DATA_PREFIX + digest

    @staticmethod
    def _owner_key(owner: str) -> str:
        return SESSION_OWNER_PREFIX + owner

    async def create(
        self, owner: str, data: dict[str, Any], fingerprint: dict[str, str] | None = None
    ) -> str:
        """Create a session and evict the owner's oldest sessions beyond the limit."""
        if not owner:
            raise ValueError("owner is required")
        token = secrets.token_urlsafe(32)
        digest = self._digest(token)
        now = time.time()
        record = json.dumps(
            {"owner": owner, "created_at": now, "data": data, "fingerprint": fingerprint or {}}
        )
        owner_key = self._owner_key(owner)
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.set(self._data_key(digest), record, ex=self._idle_ttl)
            pipe.zadd(owner_key, {digest: now})
            pipe.expire(owner_key, self._absolute_ttl)
            await pipe.execute()
        await self._enforce_limit(owner_key)
        return token

    async def _enforce_limit(self, owner_key: str) -> None:
        """Trim the owner index to the newest live sessions.

        Safe under concurrent logins: every creator adds its entry before reading the
        index, so the last reader sees all entries and trims to the limit; a stale
        reader only ever removes entries that a fresher reader would remove too.
        """
        members = [_text(m) for m in await self._client.zrange(owner_key, 0, -1)]
        if not members:
            return
        async with self._client.pipeline(transaction=False) as pipe:
            for member in members:
                pipe.exists(self._data_key(member))
            alive_flags = await pipe.execute()
        alive = [m for m, flag in zip(members, alive_flags, strict=True) if int(flag)]
        dead = [m for m, flag in zip(members, alive_flags, strict=True) if not int(flag)]
        excess = alive[: max(0, len(alive) - self._max_sessions)]
        to_remove = dead + excess
        if not to_remove:
            return
        async with self._client.pipeline(transaction=True) as pipe:
            for member in excess:
                pipe.delete(self._data_key(member))
            pipe.zrem(owner_key, *to_remove)
            await pipe.execute()

    async def get(self, token: str) -> SessionRecord | None:
        if not token or len(token) > MAX_TOKEN_LENGTH:
            return None
        raw = await self._client.get(self._data_key(self._digest(token)))
        if raw is None:
            return None
        parsed = json.loads(_text(raw))
        record = SessionRecord(
            owner=str(parsed["owner"]),
            created_at=float(parsed["created_at"]),
            data=dict(parsed["data"]),
            fingerprint={str(k): str(v) for k, v in parsed.get("fingerprint", {}).items()},
        )
        if time.time() >= record.created_at + self._absolute_ttl:
            await self.revoke(token)
            return None
        return record

    async def renew(self, token: str) -> int | None:
        """Slide the idle TTL, capped by the absolute lifetime.

        Returns the new TTL in seconds, or None when the session is unknown/expired.
        """
        record = await self.get(token)
        if record is None:
            return None
        remaining = int(record.created_at + self._absolute_ttl - time.time())
        ttl = min(self._idle_ttl, remaining)
        if ttl <= 0:
            await self.revoke(token)
            return None
        renewed = await self._client.expire(self._data_key(self._digest(token)), ttl)
        return ttl if renewed else None

    async def update_fingerprint(self, token: str, fingerprint: dict[str, str]) -> None:
        """Rewrite the stored fingerprint, keeping the session's remaining TTL."""
        key = self._data_key(self._digest(token))
        raw = await self._client.get(key)
        if raw is None:
            return
        parsed = json.loads(_text(raw))
        parsed["fingerprint"] = fingerprint
        await self._client.set(key, json.dumps(parsed), keepttl=True, xx=True)

    async def revoke(self, token: str) -> None:
        if not token or len(token) > MAX_TOKEN_LENGTH:
            return
        digest = self._digest(token)
        raw = await self._client.get(self._data_key(digest))
        await self._client.delete(self._data_key(digest))
        if raw is not None:
            owner = str(json.loads(_text(raw))["owner"])
            await self._client.zrem(self._owner_key(owner), digest)

    @staticmethod
    def digest(token: str) -> str:
        """Public handle of a session (SHA-256 of the token; never the token itself)."""
        return SessionStore._digest(token)

    async def bind_device(self, token: str, device_id: str) -> bool:
        """Record the device in the session and index the session by device so a
        device revocation can revoke its sessions. False if the session is gone."""
        digest = self._digest(token)
        key = self._data_key(digest)
        raw = await self._client.get(key)
        if raw is None:
            return False
        parsed = json.loads(_text(raw))
        parsed["data"]["device_id"] = device_id
        stored = await self._client.set(key, json.dumps(parsed), keepttl=True, xx=True)
        if not stored:
            return False
        await self._index(SESSION_DEVICE_PREFIX + device_id, digest)
        return True

    async def index_by_passkey(self, token: str, passkey_id: str) -> None:
        """Remember that the session was opened with this passkey."""
        await self._index(SESSION_PASSKEY_PREFIX + passkey_id, self._digest(token))

    async def _index(self, index: str, digest: str) -> None:
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.zadd(index, {digest: time.time()})
            pipe.expire(index, self._absolute_ttl)
            await pipe.execute()

    async def revoke_device_sessions(self, device_id: str) -> int:
        """Revoke every session bound to the device. Returns how many were alive."""
        return await self._revoke_indexed(SESSION_DEVICE_PREFIX + device_id)

    async def revoke_passkey_sessions(self, passkey_id: str) -> int:
        """Revoke every session opened with the passkey. Returns how many were alive."""
        return await self._revoke_indexed(SESSION_PASSKEY_PREFIX + passkey_id)

    async def _revoke_indexed(self, index: str) -> int:
        digests = [_text(d) for d in await self._client.zrange(index, 0, -1)]
        revoked = 0
        for digest in digests:
            raw = await self._client.get(self._data_key(digest))
            await self._client.delete(self._data_key(digest))
            if raw is not None:
                revoked += 1
                owner = str(json.loads(_text(raw))["owner"])
                await self._client.zrem(self._owner_key(owner), digest)
        await self._client.delete(index)
        return revoked


class DeviceChallengeStore:
    """Single-use challenges for binding a session to a device (protocol v1 §5)."""

    def __init__(self, client: Any) -> None:
        self._client = client

    @staticmethod
    def _key(session_digest: str) -> str:
        return DEVICE_CHALLENGE_PREFIX + session_digest

    async def create(self, session_digest: str, device_id: str) -> str:
        """A fresh challenge for this session; it replaces any earlier one."""
        challenge = secrets.token_hex(32)
        value = json.dumps({"device_id": device_id, "challenge": challenge})
        await self._client.set(self._key(session_digest), value, ex=DEVICE_CHALLENGE_TTL_SECONDS)
        return challenge

    async def consume(self, session_digest: str) -> dict[str, str] | None:
        """The pending challenge, removed atomically: only one caller gets it."""
        key = self._key(session_digest)
        raw = await self._client.get(key)
        if raw is None or int(await self._client.delete(key)) != 1:
            return None
        parsed = json.loads(_text(raw))
        return {"device_id": str(parsed["device_id"]), "challenge": str(parsed["challenge"])}


class PasskeyChallengeStore:
    """Single-use WebAuthn challenges.

    Registration challenges are tied to the session that asked for them; authentication
    challenges (no session yet) are keyed by the challenge itself.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    async def create_registration(self, session_digest: str) -> bytes:
        challenge = secrets.token_bytes(32)
        key = PASSKEY_CHALLENGE_PREFIX + "reg:" + session_digest
        await self._client.set(key, challenge.hex(), ex=PASSKEY_CHALLENGE_TTL_SECONDS)
        return challenge

    async def consume_registration(self, session_digest: str) -> bytes | None:
        key = PASSKEY_CHALLENGE_PREFIX + "reg:" + session_digest
        raw = await self._client.get(key)
        if raw is None or int(await self._client.delete(key)) != 1:
            return None
        return bytes.fromhex(_text(raw))

    async def create_authentication(self) -> bytes:
        challenge = secrets.token_bytes(32)
        key = PASSKEY_CHALLENGE_PREFIX + "auth:" + challenge.hex()
        await self._client.set(key, "1", ex=PASSKEY_CHALLENGE_TTL_SECONDS)
        return challenge

    async def consume_authentication(self, challenge: bytes) -> bool:
        """True only for the single caller that removes an issued, unexpired challenge."""
        key = PASSKEY_CHALLENGE_PREFIX + "auth:" + challenge.hex()
        return int(await self._client.delete(key)) == 1


def revoke_owner_sessions_sync(client: Any, owner: str) -> int:
    """Revoke every session of an account with a SYNCHRONOUS Redis client (worker jobs,
    e.g. when an account moves to a new wallet). Returns how many were alive."""
    owner_key = SESSION_OWNER_PREFIX + owner
    digests = [_text(d) for d in client.zrange(owner_key, 0, -1)]
    alive = sum(int(client.delete(SESSION_DATA_PREFIX + digest)) for digest in digests)
    client.delete(owner_key)
    return alive
