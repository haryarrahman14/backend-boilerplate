"""Environment config, parsed and validated once at startup (SPEC section 2)."""

import ipaddress
import ssl
from dataclasses import dataclass, field
from functools import cached_property
from typing import Annotated, Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BeforeValidator, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SSLMODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")


@dataclass(frozen=True)
class DatabaseTarget:
    """DATABASE_URL split into SQLAlchemy's asyncpg URL and libpq-style TLS settings (repr hides the URL)."""

    url: str = field(repr=False)
    sslmode: str | None = None
    sslrootcert: str | None = None

    def connect_args(self) -> dict[str, Any]:
        """asyncpg's own `ssl=verify-*` reads ~/.postgresql/root.crt; build a context that really verifies instead."""
        mode = self.sslmode
        if mode is None:
            return {}  # asyncpg default (prefer); production refuses a URL without an explicit sslmode
        if mode == "disable":
            return {"ssl": False}
        if mode in ("allow", "prefer"):
            return {"ssl": mode}
        # System trust store, or the CA bundle named by sslrootcert.
        context = ssl.create_default_context(cafile=self.sslrootcert)
        if mode == "require" and self.sslrootcert is None:
            # libpq: encrypt, do not verify (with a root cert, libpq verifies the CA; so do we, below).
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif mode in ("require", "verify-ca"):
            context.check_hostname = False  # CA chain verified, host name not
        return {"ssl": context}


def parse_database_url(url: str) -> DatabaseTarget:
    """The shared `postgres://...?sslmode=` form -> asyncpg URL + TLS settings, honouring every libpq sslmode."""
    parts = urlsplit(url)
    if parts.scheme not in ("postgres", "postgresql", "postgresql+asyncpg"):
        raise ValueError("DATABASE_URL must start with postgres:// or postgresql://")
    sslmode, rootcert, rest = None, None, []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key == "sslmode":
            if value not in SSLMODES:
                raise ValueError(f"sslmode must be one of {', '.join(SSLMODES)}")
            sslmode = value
        elif key == "sslrootcert":
            rootcert = value or None
        elif key == "ssl":
            raise ValueError("use sslmode=..., not ssl=...")
        else:
            rest.append((key, value))
    return DatabaseTarget(
        urlunsplit(parts._replace(scheme="postgresql+asyncpg", query=urlencode(rest))), sslmode, rootcert
    )


def _exact_bool(value: Any) -> Any:
    # SPEC: booleans are exactly `true` / `false` (pydantic alone would also take yes/1/on).
    if isinstance(value, str):
        if value not in ("true", "false"):
            raise ValueError("must be exactly true or false")
        return value == "true"
    return value


Bool = Annotated[bool, BeforeValidator(_exact_bool)]


class DatabaseSettings(BaseSettings):
    """Just what `alembic` needs, so `make migrate` works without the app's secrets.

    Secrets are SecretStr, so printing the settings (or a traceback's locals) shows `**********`.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: SecretStr

    @field_validator("database_url")
    @classmethod
    def _parsable(cls, v: SecretStr) -> SecretStr:
        parse_database_url(v.get_secret_value())
        return v

    @cached_property
    def database(self) -> DatabaseTarget:
        return parse_database_url(self.database_url.get_secret_value())


class Settings(DatabaseSettings):
    port: int = Field(8080, ge=1, le=65535)
    app_env: Literal["development", "production"] = "development"
    app_url: str = "http://localhost:3000"
    jwt_secret: SecretStr  # used byte for byte: never trimmed
    access_token_ttl_seconds: int = Field(900, ge=1)
    refresh_token_ttl_seconds: int = Field(2592000, ge=1)
    auth_require_verified_email: Bool = False
    rate_limit_auth_per_minute: int = Field(10, ge=1)
    trusted_proxy_hops: int = Field(0, ge=0, le=32)
    trusted_proxy_cidrs: str = ""
    email_token_cooldown_seconds: int = Field(60, ge=0)
    cors_origins: str = "http://localhost:3000"
    smtp_host: str = ""
    smtp_port: int = Field(1025, ge=1, le=65535)
    smtp_user: str = ""
    smtp_pass: SecretStr = SecretStr("")
    mail_from: str = "no-reply@example.com"
    s3_endpoint: str
    s3_region: str = "auto"
    s3_access_key_id: str
    s3_secret_access_key: SecretStr
    s3_bucket: str
    upload_max_bytes: int = Field(10485760, ge=1)
    upload_allowed_types: str = "image/jpeg,image/png,image/webp,application/pdf"

    @field_validator("app_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def _cidrs(cls, v: str) -> str:
        for cidr in filter(None, (c.strip() for c in v.split(","))):
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise ValueError(f"{cidr!r} is not a CIDR") from None
        return v

    @field_validator("cors_origins")
    @classmethod
    def _no_wildcard(cls, v: str) -> str:
        if "*" in v:
            raise ValueError("'*' is not allowed (CORS runs with credentials); list the origins")
        return v

    @field_validator("s3_endpoint", "s3_access_key_id", "s3_bucket")
    @classmethod
    def _required(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be empty")
        return v.strip()

    @field_validator("s3_secret_access_key")
    @classmethod
    def _required_secret(cls, v: SecretStr) -> SecretStr:
        if not v.get_secret_value().strip():
            raise ValueError("must not be empty")
        return v

    @field_validator("jwt_secret")
    @classmethod
    def _long_secret(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("must be at least 32 characters")
        return v

    @model_validator(mode="after")
    def _cross_field_rules(self) -> "Settings":
        if self.trusted_proxy_hops > 0 and not self.trusted_proxy_networks:
            # A hop count alone trusts X-Forwarded-For from whoever can reach the port.
            raise ValueError("TRUSTED_PROXY_CIDRS is required when TRUSTED_PROXY_HOPS > 0")
        if self.app_env == "production":
            if self.database.sslmode is None:
                raise ValueError(
                    "DATABASE_URL needs an explicit sslmode in production (verify-full recommended, disable to opt out)"
                )
            if not self.app_url.startswith("https://"):
                raise ValueError("APP_URL must be https:// in production (email links carry one-time tokens)")
            if not self.s3_endpoint.startswith("https://"):
                raise ValueError("S3_ENDPOINT must be https:// in production")
            # Without SMTP the mailer logs whole emails, one-time tokens included.
            if not self.smtp_host.strip():
                raise ValueError("SMTP_HOST is required when APP_ENV=production")
            if "change-me" in self.jwt_secret.get_secret_value():
                raise ValueError("JWT_SECRET still contains the .env.example placeholder 'change-me'")
        return self

    @cached_property
    def trusted_proxy_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return tuple(
            ipaddress.ip_network(c.strip(), strict=False) for c in self.trusted_proxy_cidrs.split(",") if c.strip()
        )

    @cached_property
    def cors_origin_list(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()]

    @cached_property
    def allowed_types(self) -> frozenset[str]:
        return frozenset(t.strip() for t in self.upload_allowed_types.split(",") if t.strip())

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


def describe_errors(exc: Exception) -> str:
    """One readable line per bad env var, for the startup failure message."""
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return str(exc)
    lines = []
    for e in errors():
        msg = "is required" if e["type"] == "missing" else e["msg"].removeprefix("Value error, ")
        lines.append(f"  {str(e['loc'][0]).upper()}: {msg}" if e["loc"] else f"  {msg}")
    return "\n".join(lines)
