"""Tests for strict input validation (2.1.10)."""

from collections.abc import Iterable, Iterator
from typing import Any

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import BaseModel

from tests.unit.fakes import make_app

VERIFY = "/v1/auth/siwe/verify"


def iter_api_routes(routes: Iterable[Any]) -> Iterator[APIRoute]:
    """Flatten routes, descending into included routers (nested in recent FastAPI)."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif hasattr(route, "original_router"):
            yield from iter_api_routes(route.original_router.routes)


def test_every_request_body_model_is_strict() -> None:
    """Architecture guard: new endpoints must use strict models that forbid extra fields."""
    app, _ = make_app()
    checked = 0
    for route in iter_api_routes(app.routes):
        for param in route.dependant.body_params:
            model = param.field_info.annotation
            assert isinstance(model, type) and issubclass(model, BaseModel), route.path
            assert model.model_config.get("extra") == "forbid", route.path
            assert model.model_config.get("strict") is True, route.path
            checked += 1
    assert checked >= 1


def test_validation_errors_use_api_format_and_never_echo_input() -> None:
    secret_looking = "0x" + "ab" * 64 + "zz"
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(VERIFY, json={"message": "hello", "signature": secret_looking})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert error["fields"][0]["loc"] == ["body", "signature"]
    assert secret_looking not in response.text
    assert "input" not in response.text


def test_wrong_json_types_are_rejected_without_coercion() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(VERIFY, json={"message": 123, "signature": "00" * 65})
    assert response.status_code == 422


def test_malformed_json_is_422() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            VERIFY, content=b"{not json", headers={"Content-Type": "application/json"}
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_non_json_bodies_are_415() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        form = client.post(VERIFY, data={"message": "x", "signature": "00" * 65})
        text = client.post(VERIFY, content=b"x", headers={"Content-Type": "text/plain"})
        charset = client.post(
            VERIFY,
            content=b'{"message": "x", "signature": "' + b"00" * 65 + b'"}',
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
    assert form.status_code == 415
    assert text.status_code == 415
    assert form.json()["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"
    assert charset.status_code == 401  # JSON accepted; fails SIWE parsing, not media type


def test_bodyless_posts_are_allowed() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.post("/v1/auth/siwe/nonce").status_code == 200
