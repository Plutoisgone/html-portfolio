"""Settings from environment variables and Docker secret files.

Secrets are never read from plain environment variables: each one comes from a
file under /run/secrets (Docker secrets), so they don't show up in
`docker inspect` or process listings.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

SECRETS_DIR = Path(os.environ.get("SIEM_SECRETS_DIR", "/run/secrets"))


class ConfigError(RuntimeError):
    pass


def secret(name: str, required: bool = True) -> str | None:
    path = SECRETS_DIR / name
    if not path.exists():
        if required:
            raise ConfigError(f"Missing secret file: {path}")
        return None
    value = path.read_text(encoding="utf-8").strip()
    if (required and not value) or "CHANGE_ME" in value:
        raise ConfigError(f"Secret {name} is empty or still CHANGE_ME")
    return value or None


def env(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if (required and not value) or "CHANGE_ME" in value:
        raise ConfigError(f"Environment variable {name} is not set")
    return value or ""


def _csv(value: str) -> list[str]:
    return [v.strip().lower() for v in value.split(",") if v.strip()]


@dataclass(frozen=True)
class Settings:
    hostname: str
    oidc_tenant_id: str
    oidc_client_id: str
    oidc_client_secret: str = field(repr=False)
    initial_super_admins: list[str]  # immutable Entra object UUIDs, not UPNs
    session_secret: str = field(repr=False)
    db_dsn: str = field(repr=False)
    session_idle_minutes: int = 30
    session_absolute_hours: int = 10
    require_mfa_claim: bool = False
    s3_endpoint: str = ""
    s3_bucket: str = ""
    s3_region: str = ""
    s3_access_key: str | None = field(default=None, repr=False)
    s3_secret_key: str | None = field(default=None, repr=False)
    audit_retention_days: int = 365
    heartbeat_url: str = field(default="", repr=False)
    extra: dict = field(default_factory=dict)

    @property
    def base_url(self) -> str:
        return f"https://{self.hostname}"

    @property
    def oidc_metadata_url(self) -> str:
        return (
            f"https://login.microsoftonline.com/{self.oidc_tenant_id}"
            "/v2.0/.well-known/openid-configuration"
        )

    @property
    def audit_export_enabled(self) -> bool:
        return bool(self.s3_bucket and self.s3_access_key and self.s3_secret_key)


def db_dsn(user_env: str, password_secret: str) -> str:
    user = env(user_env, required=True)
    password = secret(password_secret)
    host = env("SIEM_DB_HOST", "postgres")
    name = env("SIEM_DB_NAME", "siem")
    from psycopg.conninfo import make_conninfo
    return make_conninfo(host=host, dbname=name, user=user, password=password,
                         sslmode="verify-full", sslrootcert="/db-ca/ca.crt", connect_timeout=5)


def load_settings(service: str = "app") -> Settings:
    """Settings for one HTTP service.

    "app" is the web app: it authenticates existing sessions but never creates one,
    so it gets the web DB role and no OIDC client secret or OIDC state-cookie key.
    "auth" is the separate login service: the only process holding the DB role that
    may INSERT sessions (N12), the OIDC client secret and the state-cookie key.
    """
    if service not in ("app", "auth"):
        raise ConfigError("Unknown service")
    login = service == "auth"
    settings = Settings(
        hostname=env("SIEM_HOSTNAME", required=True),
        oidc_tenant_id=str(UUID(env("SIEM_OIDC_TENANT_ID", required=True))),
        oidc_client_id=str(UUID(env("SIEM_OIDC_CLIENT_ID", required=True))),
        oidc_client_secret=(secret("oidc_client_secret") or "") if login else "",
        initial_super_admins=[str(UUID(v)) for v in _csv(env("SIEM_INITIAL_SUPER_ADMIN_OIDS", required=True))],
        session_secret=(secret("session_secret") or "") if login else "",
        db_dsn=(db_dsn("SIEM_DB_AUTH_USER", "db_auth_password") if login
                else db_dsn("SIEM_DB_APP_USER", "db_app_password")),
        session_idle_minutes=int(env("SIEM_SESSION_IDLE_MINUTES", "30")),
        session_absolute_hours=int(env("SIEM_SESSION_ABSOLUTE_HOURS", "10")),
        require_mfa_claim=env("SIEM_REQUIRE_MFA_CLAIM", "false").lower() == "true",
        s3_endpoint=env("SIEM_S3_ENDPOINT", ""),
        s3_bucket=env("SIEM_S3_BUCKET", ""),
        s3_region=env("SIEM_S3_REGION", ""),
        s3_access_key=secret("s3_access_key", required=False),
        s3_secret_key=secret("s3_secret_key", required=False),
        audit_retention_days=int(env("SIEM_AUDIT_RETENTION_DAYS", "365")),
        heartbeat_url=env("SIEM_HEARTBEAT_URL", ""),
    )
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", settings.hostname):
        raise ConfigError("SIEM_HOSTNAME must be a DNS hostname without a port or path")
    if login and not re.fullmatch(r"[0-9a-f]{64}", settings.session_secret):
        raise ConfigError("Session secret must be a generated 32-byte hex value")
    if not 1 <= settings.session_idle_minutes <= 60 or not 1 <= settings.session_absolute_hours <= 24:
        raise ConfigError("Session lifetime outside allowed bounds")
    if env("SIEM_REQUIRE_MFA_CLAIM", "false").lower() not in {"true", "false"}:
        raise ConfigError("Invalid MFA setting")
    return settings


def load_auth_settings() -> Settings:
    return load_settings("auth")
