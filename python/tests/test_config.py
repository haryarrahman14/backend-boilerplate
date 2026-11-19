import ssl

import pytest
from pydantic import ValidationError

from app.platform.config import Settings, parse_database_url

REQUIRED = {
    "database_url": "postgres://u:p@localhost:5432/db",
    "jwt_secret": "s" * 32,
    "s3_endpoint": "http://localhost:9000",
    "s3_access_key_id": "k",
    "s3_secret_access_key": "s3-secret-value",
    "s3_bucket": "b",
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in Settings.model_fields:  # only what each test passes: ignore whatever the shell exported
        monkeypatch.delenv(name.upper(), raising=False)


def make(**overrides) -> Settings:
    return Settings(_env_file=None, **{**REQUIRED, **overrides})


def test_defaults_and_url_conversion():
    s = make()
    assert s.database.url == "postgresql+asyncpg://u:p@localhost:5432/db"
    assert s.database.sslmode is None and s.database.connect_args() == {}
    assert (s.port, s.access_token_ttl_seconds, s.rate_limit_auth_per_minute, s.s3_region) == (8080, 900, 10, "auto")
    assert (s.trusted_proxy_hops, s.email_token_cooldown_seconds, s.auth_require_verified_email) == (0, 60, False)
    assert s.allowed_types == {"image/jpeg", "image/png", "image/webp", "application/pdf"}


def test_secrets_are_not_printable():
    s = make(smtp_pass="smtp-secret-value", jwt_secret="j" * 40)
    for text in (repr(s), str(s), f"{s}"):
        for secret in ("u:p@", "j" * 40, "s3-secret-value", "smtp-secret-value"):
            assert secret not in text


# ---------- sslmode ----------


def _ssl(url: str):
    return parse_database_url(url).connect_args().get("ssl")


def test_sslmode_is_removed_from_the_url_and_other_params_kept():
    target = parse_database_url("postgres://u:p@h:5432/db?application_name=api&sslmode=verify-full")
    assert target.url == "postgresql+asyncpg://u:p@h:5432/db?application_name=api"
    assert target.sslmode == "verify-full"
    assert "u:p" not in repr(target)


def test_sslmode_disable_and_prefer():
    assert _ssl("postgres://h/db?sslmode=disable") is False
    assert _ssl("postgres://h/db?sslmode=prefer") == "prefer"


def test_sslmode_require_encrypts_without_verifying():
    ctx = _ssl("postgres://h/db?sslmode=require")
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname


def test_sslmode_verify_ca_verifies_the_chain_only():
    ctx = _ssl("postgres://h/db?sslmode=verify-ca")
    assert ctx.verify_mode == ssl.CERT_REQUIRED and not ctx.check_hostname


def test_sslmode_verify_full_verifies_chain_and_host():
    ctx = _ssl("postgres://h/db?sslmode=verify-full")
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


@pytest.mark.parametrize("url", ["postgres://h/db?sslmode=bogus", "postgres://h/db?ssl=require", "mysql://h/db"])
def test_bad_database_urls(url):
    with pytest.raises(ValueError):
        parse_database_url(url)


def test_short_jwt_secret_is_refused_and_secret_is_not_trimmed():
    with pytest.raises(ValidationError, match="jwt_secret"):
        make(jwt_secret="s" * 31)
    with pytest.raises(ValidationError, match="jwt_secret"):
        make(jwt_secret=" " * 2 + "s" * 29)  # 31 chars even with the spaces kept
    assert make(jwt_secret=" " + "s" * 31).jwt_secret.get_secret_value() == " " + "s" * 31


def test_wildcard_cors_is_refused():
    with pytest.raises(ValidationError, match="cors_origins"):
        make(cors_origins="*")


@pytest.mark.parametrize("value", ["yes", "1", "on", "True", "TRUE", "no", "0", ""])
def test_booleans_are_exactly_true_or_false(value):
    with pytest.raises(ValidationError, match="auth_require_verified_email"):
        make(auth_require_verified_email=value)


def test_booleans_true_false():
    assert make(auth_require_verified_email="true").auth_require_verified_email is True
    assert make(auth_require_verified_email="false").auth_require_verified_email is False


PROD = {
    "app_env": "production",
    "smtp_host": "smtp.example.com",
    "app_url": "https://app.example.com",
    "s3_endpoint": "https://acct.r2.cloudflarestorage.com",
    "database_url": "postgres://u:p@db.example.com/app?sslmode=verify-full",
}


def test_production_accepts_a_correct_config():
    assert make(**PROD).is_production
    assert make(**{**PROD, "database_url": "postgres://u:p@db/app?sslmode=disable"})  # a visible opt-out is fine


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"smtp_host": ""}, "SMTP_HOST is required"),
        ({"jwt_secret": "change-me-to-a-long-random-string-xx"}, "change-me"),
        ({"database_url": "postgres://u:p@db.example.com/app"}, "explicit sslmode"),
        ({"app_url": "http://app.example.com"}, "APP_URL must be https"),
        ({"s3_endpoint": "http://minio:9000"}, "S3_ENDPOINT must be https"),
    ],
)
def test_production_refuses(override, message):
    with pytest.raises(ValidationError, match=message):
        make(**{**PROD, **override})


def test_development_is_lenient():
    assert make(jwt_secret="change-me-to-a-long-random-string-xx", app_url="http://localhost:3000")


def test_proxy_hops_need_cidrs():
    with pytest.raises(ValidationError, match="TRUSTED_PROXY_CIDRS is required"):
        make(trusted_proxy_hops=1)
    with pytest.raises(ValidationError, match="not a CIDR"):
        make(trusted_proxy_hops=1, trusted_proxy_cidrs="10.0.0.0/8,nope")
    s = make(trusted_proxy_hops=1, trusted_proxy_cidrs="10.0.0.0/8, ::1/128")
    assert [str(n) for n in s.trusted_proxy_networks] == ["10.0.0.0/8", "::1/128"]
