"""Tests for security middleware: proxies, HTTPS, headers, rate limit, CORS."""

from fastapi.testclient import TestClient

from agnusmail.testing.fakes import make_app, make_settings


def client_for(**overrides: object) -> TestClient:
    app, _ = make_app(make_settings(**overrides))
    return TestClient(app, raise_server_exceptions=False)


def test_security_headers_present_and_no_hsts_by_default() -> None:
    with client_for() as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" not in response.headers


def test_https_enforcement_off_by_default() -> None:
    with client_for() as client:
        assert client.get("/nowhere").status_code == 404


def test_https_enforcement_rejects_http_when_forced() -> None:
    with client_for(force_https=True) as client:
        response = client.get("/nowhere")  # /healthz is exempt; any other path is blocked
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "HTTPS_REQUIRED"
    assert "Strict-Transport-Security" in response.headers


def test_forwarded_proto_is_ignored_from_untrusted_peers() -> None:
    with client_for(force_https=True) as client:
        response = client.get("/nowhere", headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 400


def test_forwarded_proto_is_honoured_from_trusted_proxy() -> None:
    # TestClient's peer address is the literal "testclient".
    with client_for(force_https=True, trusted_proxies=["testclient"]) as client:
        response = client.get("/nowhere", headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 404
    assert "Strict-Transport-Security" in response.headers


def test_rate_limit_is_wired_by_default_and_blocks_over_limit() -> None:
    with client_for(rate_limit_per_ip=2) as client:
        statuses = [client.get("/nowhere").status_code for _ in range(3)]
        probe = client.get("/healthz")
    assert statuses == [404, 404, 429]
    assert probe.status_code == 200  # probes are exempt


def test_rate_limited_response_carries_security_headers() -> None:
    with client_for(rate_limit_per_ip=1) as client:
        client.get("/nowhere")
        response = client.get("/nowhere")
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMITED"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_rate_limit_fails_open_on_backend_error() -> None:
    app, fake = make_app()
    fake.fail = True
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/nowhere").status_code == 404


def test_cors_denies_unknown_origin() -> None:
    with client_for(cors_allowed_origins=["https://app.example"]) as client:
        response = client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in response.headers


def test_cors_allows_configured_origin() -> None:
    with client_for(cors_allowed_origins=["https://app.example"]) as client:
        response = client.get("/healthz", headers={"Origin": "https://app.example"})
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example"


def test_domain_errors_become_safe_json() -> None:
    from agnusmail.core.exceptions import DatabaseUnavailableError

    app, _ = make_app()

    @app.get("/boom")
    async def boom() -> None:
        raise DatabaseUnavailableError()

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/boom")
    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": "DatabaseUnavailableError", "detail": "database unavailable"}
    }
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_probes_are_exempt_from_https_enforcement() -> None:
    app, _ = make_app(make_settings(force_https=True))
    with TestClient(app, raise_server_exceptions=False) as client:
        app.state.db_check = lambda: True
        app.state.redis_check = lambda: True
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 200
        assert client.get("/v1/auth/session").status_code == 400  # non-probe still blocked
