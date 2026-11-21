# Agnusmail image (multi-stage, non-root): API, worker, SMTP gateways and admin CLI.
# Build: docker build -f docker/Dockerfile -t agnusmail-api .
# Config is provided at RUNTIME only; never bake secrets into the image.

FROM python:3.15-slim AS builder

# uv installer, pinned (same version used to produce uv.lock).
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# Build the venv at its final path: console-script shebangs are absolute.
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev

# Install the project itself NON-editable so the venv does not point at sources.
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

FROM python:3.15-slim

# Non-root user with a fixed UID/GID, so mounted key files can be owned by it.
RUN groupadd -r -g 10001 app && useradd -r -u 10001 -g app -d /app -s /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --chown=app:app apps /app/apps
# Migrations ship with the image so the one-shot `migrate` service can run them.
COPY --chown=app:app alembic.ini /app/alembic.ini
COPY --chown=app:app migrations /app/migrations

# Inbound gateway signing key: a private directory the volume inherits.
RUN install -d -o app -g app -m 700 /var/lib/agnusmail/gateway
# Outbound service keys: queue key and DKIM key, same treatment.
RUN install -d -o app -g app -m 700 /var/lib/agnusmail/outbound

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER app
EXPOSE 8000

# Liveness probe: /healthz needs no database and is exempt from HTTPS enforcement.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]

# Forwarded headers are handled inside the app, only from AGNUSMAIL_TRUSTED_PROXIES.
CMD ["uvicorn", "apps.api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
