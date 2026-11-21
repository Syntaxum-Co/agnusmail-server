"""Application settings loaded from environment variables (prefix ``AGNUSMAIL_``)."""

from enum import StrEnum
from functools import cache
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SIWE_DOMAIN = "app.agnusmail"
DEFAULT_SIWE_URI = "https://app.agnusmail/login"
DEFAULT_MAIL_DOMAIN = "mail.agnusmail.localhost"
MAIL_DOMAIN_PATTERN = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
TLS_SSLMODES = frozenset({"require", "verify-ca", "verify-full"})


class Environment(StrEnum):
    LOCAL = "local"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Process-wide configuration. Secret fields are excluded from repr."""

    model_config = SettingsConfigDict(env_prefix="AGNUSMAIL_", env_file=".env", extra="ignore")

    # Secure by default: every deployed-environment check applies unless a developer
    # explicitly opts into "local" (see .env.example and docker-compose.yml).
    environment: Environment = Environment.PRODUCTION
    app_name: str = "agnusmail-api"

    # Database. DSN may contain credentials, so it is never logged.
    database_url: str = Field(repr=False)
    db_pool_size: int = Field(default=10, ge=1)
    db_max_overflow: int = Field(default=5, ge=0)
    db_pool_timeout_seconds: int = Field(default=30, ge=1)
    db_statement_timeout_ms: int = Field(default=30_000, ge=1)
    # Bounds TCP connect so an unreachable database fails fast instead of pinning threads.
    db_connect_timeout_seconds: int = Field(default=5, ge=1)

    # Redis. URL may contain credentials, so it is never logged.
    redis_url: str = Field(repr=False)
    redis_pool_max_connections: int = Field(default=10, ge=1)
    # Every Redis call sits on the request path (rate limit, sessions): a hung Redis must
    # raise quickly so fail-open/503 paths engage instead of stalling every request.
    redis_socket_timeout_seconds: float = Field(default=1.0, gt=0)
    redis_connect_timeout_seconds: float = Field(default=1.0, gt=0)
    redis_health_check_interval_seconds: int = Field(default=30, ge=0)

    # HTTP. Bind host/port are uvicorn CLI arguments (see docker/Dockerfile).
    cors_allowed_origins: list[str] = Field(default_factory=list)
    request_timeout_seconds: int = Field(default=30, ge=1)
    max_request_body_bytes: int = Field(default=1 * 1024 * 1024, ge=1)
    force_https: bool = False
    max_concurrent_requests: int = Field(default=100, ge=1)
    readiness_timeout_seconds: float = Field(default=2.0, gt=0)
    # Reverse proxies whose X-Forwarded-For/-Proto headers are trusted (IPs or CIDRs).
    # Empty means forwarded headers are ignored and the socket peer is used.
    trusted_proxies: list[str] = Field(default_factory=list)

    # Rate limiting (fixed windows of rate_limit_window_seconds).
    rate_limit_per_ip: int = Field(default=120, ge=1)  # every route, per client IP
    # Login routes (/v1/auth/siwe/*): a login costs 2 requests (nonce + verify).
    rate_limit_auth_per_ip: int = Field(default=20, ge=1)
    rate_limit_per_user: int = Field(default=300, ge=1)  # authenticated routes, per user
    rate_limit_window_seconds: int = Field(default=60, ge=1)

    # Sessions. The cookie max-age is also the idle (sliding) TTL of the session;
    # the absolute TTL caps the total lifetime regardless of renewals.
    session_cookie_max_age_seconds: int = Field(default=86400, ge=1)  # 24h
    session_absolute_ttl_seconds: int = Field(default=7 * 86400, ge=1)  # 7 days
    session_cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    max_sessions_per_user: int = Field(default=10, ge=1)
    # Suspicious-session detection: revoke a session presented with a User-Agent other
    # than the one that logged in (cookie replay). Network changes are only logged.
    session_bind_user_agent: bool = True
    # Step-up: sensitive changes (e.g. authorizing a device) require a login this recent.
    step_up_max_auth_age_seconds: int = Field(default=600, ge=30)

    # Devices and public key directory.
    max_devices_per_user: int = Field(default=10, ge=1)  # pending + active
    max_passkeys_per_user: int = Field(default=10, ge=1)  # active passkeys
    # Messages: SEIPDv2 body size (base64 must also fit max_request_body_bytes;
    # large files are attachments) and recipient accounts per message.
    max_message_bytes: int = Field(default=512 * 1024, ge=1024, le=8 * 1024 * 1024)
    max_message_recipients: int = Field(default=20, ge=1, le=100)

    # Encrypted attachments in S3-compatible storage. Unset endpoint =
    # attachments disabled (503). Any S3-compatible provider works.
    object_storage_endpoint: str | None = None
    object_storage_region: str = "us-east-1"
    object_storage_bucket: str | None = None
    object_storage_access_key: str | None = None
    object_storage_secret_key: SecretStr | None = None
    max_attachment_bytes: int = Field(default=25 * 1024 * 1024, ge=1024)
    max_attachments_per_message: int = Field(default=10, ge=1, le=100)
    attachment_upload_url_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    attachment_download_url_ttl_seconds: int = Field(default=60, ge=10, le=900)
    attachment_orphan_hours: int = Field(default=24, ge=1)
    max_keys_per_device: int = Field(default=100, ge=1)  # all versions, any status
    # A protocol v1 device certificate (Ed25519 + ML-KEM-768+X25519) is about 2 KiB.
    max_public_key_bytes: int = Field(default=8192, ge=1024, le=16384)

    # Audit trail retention. The database refuses to delete anything
    # younger than 365 days regardless of this value; it can only be made longer.
    audit_retention_days: int = Field(default=365, ge=365)

    # Background worker. The lease must exceed the longest job; an expired lease
    # lets another worker run the job again (handlers are idempotent).
    worker_poll_seconds: float = Field(default=5.0, ge=0.1, le=300)
    worker_lease_seconds: int = Field(default=900, ge=30)
    worker_batch_size: int = Field(default=10, ge=1, le=1000)

    # Domain of the users' addresses name@mail_domain. Lowercase hostname.
    mail_domain: str = Field(
        default=DEFAULT_MAIL_DOMAIN, min_length=4, max_length=253, pattern=MAIL_DOMAIN_PATTERN
    )

    # Inbound SMTP gateway: separate process, in memory, no spool.
    # The hostname is the gateway's MX name (greeting and Received headers).
    inbound_smtp_host: str = "127.0.0.1"
    inbound_smtp_port: int = Field(default=2525, ge=1, le=65535)
    inbound_smtp_hostname: str | None = Field(
        default=None, max_length=253, pattern=MAIL_DOMAIN_PATTERN
    )
    # Unknown recipients tolerated per connection before it is closed (enumeration).
    inbound_max_unknown_recipients: int = Field(default=5, ge=1, le=100)
    # Gateway signing key (spec §9): binary OpenPGP secret key file, mode 0600, from the
    # secret manager. Create with ``python -m agnusmail.apps.smtp_inbound generate-key <path>``.
    inbound_signing_key_file: Path | None = None
    # Rspamd normal worker, internal network only: http://host:11333. Required
    # outside the local environment (the gateway refuses to start without it).
    inbound_rspamd_url: str | None = None
    inbound_rspamd_timeout_seconds: float = Field(default=30.0, ge=1, le=120)
    # STARTTLS certificate chain and key (PEM). Required outside the local environment.
    inbound_tls_cert_file: Path | None = None
    inbound_tls_key_file: Path | None = None
    # Connection limits (one gateway process).
    inbound_idle_timeout_seconds: float = Field(default=120.0, ge=1, le=600)
    inbound_max_connection_seconds: float = Field(default=600.0, ge=1, le=3600)
    inbound_max_connections: int = Field(default=200, ge=1)
    inbound_max_connections_per_ip: int = Field(default=10, ge=1)
    # Behind a TCP load balancer: PROXY protocol v1/v2 from these IPs/CIDRs only, so the
    # gateway sees the real client IP (Rspamd skips SPF/DKIM/DMARC for local IPs, and the
    # per-IP limits need it). Without it, publish the port so the source IP is preserved.
    inbound_proxy_protocol: bool = False
    inbound_trusted_proxies: list[str] = Field(default_factory=list)
    inbound_proxy_timeout_seconds: float = Field(default=10.0, ge=1, le=60)
    # Per client IP and hour, across connections and processes (Redis).
    inbound_unknown_recipients_per_ip_per_hour: int = Field(default=30, ge=1)
    inbound_messages_per_ip_per_hour: int = Field(default=300, ge=1)

    # Outbound conventional SMTP (spec §10) — NOT end-to-end encrypted.
    # Submission (API): the client encrypts the ready MIME message to the outbound
    # service's key; recipients travel apart, as metadata, for limits and delivery.
    outbound_max_message_bytes: int = Field(default=512 * 1024, ge=1024, le=8 * 1024 * 1024)
    outbound_max_recipients: int = Field(default=50, ge=1, le=100)
    # Per account (Redis, fail-closed): messages per hour, recipients per day.
    outbound_messages_per_hour: int = Field(default=30, ge=1)
    outbound_recipients_per_day: int = Field(default=300, ge=1)
    # Outbound service (``agnusmail.apps.smtp_outbound``, its own process and database role).
    # Queue key: binary OpenPGP secret key (device profile §3.1), mode 0600. Created with
    # ``python -m agnusmail.apps.smtp_outbound generate-key <path>``. DKIM: RSA private key (PEM).
    outbound_key_file: Path | None = None
    outbound_dkim_key_file: Path | None = None
    outbound_dkim_selector: str = Field(default="agnus1", pattern=r"^[a-z0-9]([a-z0-9-]{0,61})$")
    # EHLO name; must have matching A/AAAA and PTR records. Required outside local.
    outbound_hostname: str | None = Field(default=None, max_length=253, pattern=MAIL_DOMAIN_PATTERN)
    outbound_smtp_port: int = Field(default=25, ge=1, le=65535)
    # Deliver everything to this host:port instead of the MX (local development and
    # tests only; refused in production).
    outbound_relay: str | None = Field(default=None, pattern=r"^[A-Za-z0-9.-]+:[0-9]{1,5}$")
    outbound_require_tls: bool = False  # refuse servers without STARTTLS (default: opportunistic)
    outbound_poll_seconds: float = Field(default=5.0, ge=0.1, le=300)
    outbound_batch_size: int = Field(default=10, ge=1, le=100)
    outbound_lease_seconds: int = Field(default=600, ge=60, le=3600)
    # Per network operation (connect, each SMTP reply, DATA).
    outbound_smtp_timeout_seconds: float = Field(default=60.0, ge=1, le=600)
    # Previous queue keys, kept until their queued messages are gone (72 h after rotation).
    outbound_previous_key_files: list[Path] = Field(default_factory=list)

    # Secure portal (spec §11): external recipients open a message
    # encrypted with a password the sender passes on through another channel. Links are
    # ``{portal_base_url}#{token}`` (the token stays in the fragment, out of server logs).
    # Unset: the portal is disabled (503). Must be https outside the local environment.
    portal_base_url: str | None = Field(default=None, max_length=200)
    portal_max_recipients: int = Field(default=20, ge=1, le=100)
    portal_max_message_bytes: int = Field(default=512 * 1024, ge=1024, le=8 * 1024 * 1024)
    portal_max_days: int = Field(default=30, ge=1, le=30)  # spec §11: at most 30 days
    portal_max_replies_per_link: int = Field(default=5, ge=0, le=100)
    # Unauthenticated portal routes, per client IP (fail-open like the IP limit).
    portal_access_per_ip_per_minute: int = Field(default=30, ge=1)
    portal_replies_per_ip_per_hour: int = Field(default=20, ge=1)

    # Storage limit of every account: encrypted messages it holds, its attachments and
    # its secure-portal messages. Over it, sending, uploading and receiving are refused.
    storage_quota_bytes: int = Field(default=5 * 1024**3, ge=1024**2)

    # Key of the decoy recovery backups: unknown accounts get a stable fake backup,
    # so the unauthenticated backup fetch does not reveal which accounts exist. Required
    # outside the local environment (at least 32 characters, from the secret manager).
    recovery_decoy_secret: SecretStr | None = Field(default=None, repr=False)

    # Metrics: each process serves /metrics on this port when set;
    # keep it on the internal network (never published).
    metrics_port: int | None = Field(default=None, ge=1024, le=65535)
    metrics_host: str = "0.0.0.0"  # noqa: S104  (inside the container; port not published)

    # Abuse and reputation — metadata only, never content.
    internal_messages_per_hour: int = Field(default=200, ge=1)
    internal_recipients_per_day: int = Field(default=2000, ge=1)
    abuse_restricted_messages_per_day: int = Field(default=20, ge=0)
    outbound_per_domain_per_hour: int = Field(default=100, ge=1)
    device_registrations_per_day: int = Field(default=10, ge=1)
    new_accounts_per_ip_per_day: int = Field(default=10, ge=1)
    abuse_report_threshold: int = Field(default=5, ge=2)  # distinct reporting accounts
    abuse_report_window_days: int = Field(default=7, ge=1, le=90)
    abuse_bounce_ratio: float = Field(default=0.3, gt=0, le=1)
    abuse_bounce_minimum: int = Field(default=20, ge=1)
    abuse_restriction_days: int = Field(default=7, ge=1, le=90)

    # SIWE: expected values validated on every login. Empty domain/URI disables the check
    # (allowed only in the local environment).
    siwe_domain: str = DEFAULT_SIWE_DOMAIN
    siwe_uri: str = DEFAULT_SIWE_URI
    siwe_chain_id: int = Field(default=1, ge=1)
    siwe_clock_skew_seconds: int = Field(default=60, ge=0)

    @model_validator(mode="after")
    def enforce_security_invariants(self) -> "Settings":
        if "*" in self.cors_allowed_origins:
            raise ValueError("cors_allowed_origins must not contain '*' (credentials are allowed)")
        if self.object_storage_endpoint and not (
            self.object_storage_bucket
            and self.object_storage_access_key
            and self.object_storage_secret_key
        ):
            raise ValueError("object storage needs bucket, access key and secret key")
        if self.session_cookie_samesite == "none" and not self.force_https:
            raise ValueError("session_cookie_samesite='none' requires force_https=True")
        if self.session_absolute_ttl_seconds < self.session_cookie_max_age_seconds:
            raise ValueError(
                "session_absolute_ttl_seconds must be >= session_cookie_max_age_seconds"
            )
        if self.environment is not Environment.LOCAL:
            self._enforce_deployed_environment()
        return self

    def _enforce_deployed_environment(self) -> None:
        """Staging and production share the same hardening requirements."""
        query = parse_qs(urlsplit(self.database_url).query)
        sslmodes = query.get("sslmode", [])
        if len(sslmodes) != 1 or sslmodes[0] not in TLS_SSLMODES:
            raise ValueError(
                "database_url must set sslmode=require, verify-ca or verify-full "
                f"in {self.environment.value}"
            )
        if not self.force_https:
            raise ValueError(f"force_https must be True in {self.environment.value}")
        if not self.siwe_domain or self.siwe_domain == DEFAULT_SIWE_DOMAIN:
            raise ValueError(
                f"siwe_domain must be explicitly configured in {self.environment.value}"
            )
        if not self.siwe_uri or self.siwe_uri == DEFAULT_SIWE_URI:
            raise ValueError(f"siwe_uri must be explicitly configured in {self.environment.value}")
        if not self.siwe_uri.startswith("https://"):
            raise ValueError("siwe_uri must use https outside the local environment")
        if self.mail_domain == DEFAULT_MAIL_DOMAIN:
            raise ValueError(
                f"mail_domain must be explicitly configured in {self.environment.value}"
            )
        if self.portal_base_url and not self.portal_base_url.startswith("https://"):
            raise ValueError("portal_base_url must use https outside the local environment")
        if self.outbound_relay and self.environment is Environment.PRODUCTION:
            raise ValueError("outbound_relay is for local development and tests only")
        secret = self.recovery_decoy_secret
        if secret is None or len(secret.get_secret_value()) < 32:
            raise ValueError(
                f"recovery_decoy_secret (32+ characters) is required in {self.environment.value}"
            )


@cache
def get_settings() -> Settings:
    """Build Settings once from the process environment and optional .env file."""
    return Settings()  # type: ignore[call-arg]  # fields are populated from env
