"""Global exception hierarchy and FastAPI-safe error responses."""

from typing import Any


class AgnusmailError(Exception):
    """Base class for all domain errors. Messages must be safe to expose.

    ``code`` is the stable machine-readable error code; it defaults to the class name.
    """

    status_code = 500
    message = "internal error"
    code: str | None = None

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail or self.message)
        self.detail = detail or self.message

    @property
    def error_code(self) -> str:
        return self.code or type(self).__name__


class DatabaseUnavailableError(AgnusmailError):
    status_code = 503
    message = "database unavailable"


class RedisUnavailableError(AgnusmailError):
    status_code = 503
    message = "cache unavailable"


class NotAuthenticatedError(AgnusmailError):
    status_code = 401
    message = "no session"
    code = "NO_SESSION"


class SessionRevokedError(AgnusmailError):
    """The session was revoked because it was used in a suspicious way."""

    status_code = 401
    message = "session revoked"
    code = "SESSION_REVOKED"


class RateLimitedError(AgnusmailError):
    status_code = 429
    message = "rate limit exceeded"
    code = "RATE_LIMITED"


class ResourceNotFoundError(AgnusmailError):
    """Missing OR owned by someone else: never reveal which (anti-enumeration/IDOR)."""

    status_code = 404
    message = "not found"
    code = "NOT_FOUND"


class ConflictError(AgnusmailError):
    """Concurrent change hit a uniqueness rule; the client may retry."""

    status_code = 409
    message = "conflicting concurrent change; retry"
    code = "CONFLICT"


class InvalidStateError(AgnusmailError):
    status_code = 409
    message = "operation not allowed in the current state"
    code = "INVALID_STATE"


class LimitExceededError(AgnusmailError):
    status_code = 409
    message = "limit exceeded"
    code = "LIMIT_EXCEEDED"


class ReauthenticationRequiredError(AgnusmailError):
    """Sensitive operation needs a recent login (step-up authentication)."""

    status_code = 403
    message = "recent authentication required"
    code = "REAUTHENTICATION_REQUIRED"


class KeyRejectedError(AgnusmailError):
    status_code = 422
    message = "public key rejected"
    code = "KEY_REJECTED"


def error_payload(detail: str, code: str) -> dict[str, Any]:
    """Build a response body that never exposes internals."""
    return {"error": {"code": code, "detail": detail}}
