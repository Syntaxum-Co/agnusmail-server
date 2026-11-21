"""Tests for the secure cookie policy."""

from agnusmail.core.config import Settings
from agnusmail.core.security import SESSION_COOKIE_NAME, set_session_cookie
from agnusmail.testing.fakes import make_settings


class CookieCapture:
    """Collects set_cookie kwargs without needing a real Response."""

    def __init__(self) -> None:
        self.flags: dict[str, str] = {}

    def set_cookie(self, **kwargs: object) -> None:
        for key, val in kwargs.items():
            self.flags[key] = "" if val is None else str(val)


def captured_cookie_flags(settings: Settings, max_age: int | None = None) -> dict[str, str]:
    capture = CookieCapture()
    set_session_cookie(capture, "opaque-session-id", settings, max_age)  # type: ignore[arg-type]
    return capture.flags


def test_session_cookie_policy_local() -> None:
    flags = captured_cookie_flags(make_settings())
    assert flags["key"] == SESSION_COOKIE_NAME
    assert flags["secure"] == "False"
    assert flags["httponly"] == "True"
    assert flags["samesite"] == "lax"
    assert flags["path"] == "/"
    assert int(flags["max_age"]) == 86400


def test_session_cookie_secure_when_https_forced() -> None:
    assert captured_cookie_flags(make_settings(force_https=True))["secure"] == "True"


def test_session_cookie_max_age_override() -> None:
    assert int(captured_cookie_flags(make_settings(), max_age=20)["max_age"]) == 20
