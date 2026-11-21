"""Secure cookie policy for session identifiers."""

from fastapi import Response

from agnusmail.core.config import Settings

SESSION_COOKIE_NAME = "agnusmail_session"
# Browsers only accept "__Host-" cookies that are Secure, Path=/ and have no Domain,
# so a sibling subdomain cannot inject or fixate the session cookie.
SECURE_SESSION_COOKIE_NAME = "__Host-" + SESSION_COOKIE_NAME


def session_cookie_name(settings: Settings) -> str:
    return SECURE_SESSION_COOKIE_NAME if settings.force_https else SESSION_COOKIE_NAME


def set_session_cookie(
    response: Response, value: str, settings: Settings, max_age_seconds: int | None = None
) -> None:
    response.set_cookie(
        key=session_cookie_name(settings),
        value=value,
        max_age=max_age_seconds or settings.session_cookie_max_age_seconds,
        httponly=True,
        secure=settings.force_https,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=session_cookie_name(settings),
        path="/",
        httponly=True,
        secure=settings.force_https,
        samesite=settings.session_cookie_samesite,
    )
