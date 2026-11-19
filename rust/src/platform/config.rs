use std::{env, str::FromStr};

use anyhow::{Context, Result, bail};

use super::middleware::Cidr;

/// All settings, parsed and validated once at startup (SPEC section 2).
/// Deliberately not `Debug`: it holds the JWT secret, SMTP and S3 credentials.
#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub production: bool,
    pub app_url: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub access_token_ttl: i64,
    pub refresh_token_ttl: i64,
    pub require_verified_email: bool,
    pub rate_limit_auth_per_minute: u32,
    pub trusted_proxy_hops: usize,
    pub trusted_proxy_cidrs: Vec<Cidr>,
    pub email_token_cooldown: i64,
    pub cors_origins: Vec<String>,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub mail_from: String,
    pub s3_endpoint: String,
    pub s3_region: String,
    pub s3_access_key_id: String,
    pub s3_secret_access_key: String,
    pub s3_bucket: String,
    pub upload_max_bytes: i64,
    pub upload_allowed_types: Vec<String>,
}

const MAX_PROXY_HOPS: usize = 32;

/// Reads variables through `get`, so tests can feed a map instead of the process environment.
struct Env<F: Fn(&str) -> Option<String>>(F);

impl<F: Fn(&str) -> Option<String>> Env<F> {
    /// Raw value, untrimmed (secrets are used byte for byte).
    fn raw(&self, name: &str) -> Option<String> {
        (self.0)(name).filter(|v| !v.is_empty())
    }

    fn var(&self, name: &str) -> Option<String> {
        self.raw(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    }

    fn or(&self, name: &str, default: &str) -> String {
        self.var(name).unwrap_or_else(|| default.to_owned())
    }

    fn required(&self, name: &str) -> Result<String> {
        self.var(name)
            .with_context(|| format!("{name} is required"))
    }

    fn parse<T: FromStr>(&self, name: &str, default: &str) -> Result<T> {
        let raw = self.or(name, default);
        raw.parse()
            .ok()
            .with_context(|| format!("{name} has an invalid value: {raw:?}"))
    }

    fn boolean(&self, name: &str, default: bool) -> Result<bool> {
        match self.var(name).as_deref() {
            None => Ok(default),
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            Some(other) => bail!("{name} must be true or false, got {other:?}"),
        }
    }

    fn list(&self, name: &str, default: &str) -> Vec<String> {
        self.or(name, default)
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

/// `migrate` only needs the database, so it does not require the rest of the config.
pub fn database_url() -> Result<String> {
    Env(|n: &str| env::var(n).ok()).required("DATABASE_URL")
}

/// The `sslmode` query parameter of a Postgres URL, if any.
fn sslmode(url: &str) -> Option<&str> {
    let query = url.split_once('?')?.1;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix("sslmode="))
        .filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let e = Env(get);
        let production = match e.or("APP_ENV", "development").as_str() {
            "production" => true,
            "development" => false,
            other => bail!("APP_ENV must be development or production, got {other:?}"),
        };

        // Byte for byte: never trimmed.
        let jwt_secret = e.raw("JWT_SECRET").context("JWT_SECRET is required")?;
        if jwt_secret.chars().count() < 32 {
            bail!("JWT_SECRET must be at least 32 characters");
        }
        if production && jwt_secret.contains("change-me") {
            bail!("JWT_SECRET still contains the .env.example placeholder (change-me)");
        }

        let cors_origins = e.list("CORS_ORIGINS", "http://localhost:3000");
        if cors_origins.iter().any(|o| o == "*") {
            bail!("CORS_ORIGINS must not contain * (credentials are allowed)");
        }

        let trusted_proxy_cidrs = e
            .list("TRUSTED_PROXY_CIDRS", "")
            .iter()
            .map(|c| {
                Cidr::parse(c)
                    .with_context(|| format!("TRUSTED_PROXY_CIDRS entry {c:?} is not a CIDR"))
            })
            .collect::<Result<Vec<_>>>()?;

        let cfg = Config {
            port: e.parse("PORT", "8080")?,
            production,
            app_url: e
                .or("APP_URL", "http://localhost:3000")
                .trim_end_matches('/')
                .to_owned(),
            database_url: e.required("DATABASE_URL")?,
            jwt_secret,
            access_token_ttl: e.parse("ACCESS_TOKEN_TTL_SECONDS", "900")?,
            refresh_token_ttl: e.parse("REFRESH_TOKEN_TTL_SECONDS", "2592000")?,
            require_verified_email: e.boolean("AUTH_REQUIRE_VERIFIED_EMAIL", false)?,
            rate_limit_auth_per_minute: e.parse("RATE_LIMIT_AUTH_PER_MINUTE", "10")?,
            trusted_proxy_hops: e.parse("TRUSTED_PROXY_HOPS", "0")?,
            trusted_proxy_cidrs,
            email_token_cooldown: e.parse("EMAIL_TOKEN_COOLDOWN_SECONDS", "60")?,
            cors_origins,
            smtp_host: e.or("SMTP_HOST", ""),
            smtp_port: e.parse("SMTP_PORT", "1025")?,
            smtp_user: e.or("SMTP_USER", ""),
            // Not trimmed: a password may legitimately start or end with spaces.
            smtp_pass: e.raw("SMTP_PASS").unwrap_or_default(),
            mail_from: e.or("MAIL_FROM", "no-reply@example.com"),
            s3_endpoint: e.required("S3_ENDPOINT")?,
            s3_region: e.or("S3_REGION", "auto"),
            s3_access_key_id: e.required("S3_ACCESS_KEY_ID")?,
            s3_secret_access_key: e.required("S3_SECRET_ACCESS_KEY")?,
            s3_bucket: e.required("S3_BUCKET")?,
            upload_max_bytes: e.parse("UPLOAD_MAX_BYTES", "10485760")?,
            upload_allowed_types: e.list(
                "UPLOAD_ALLOWED_TYPES",
                "image/jpeg,image/png,image/webp,application/pdf",
            ),
        };

        if cfg.access_token_ttl < 1 || cfg.refresh_token_ttl < 1 {
            bail!("ACCESS_TOKEN_TTL_SECONDS and REFRESH_TOKEN_TTL_SECONDS must be positive");
        }
        if cfg.rate_limit_auth_per_minute < 1 {
            bail!("RATE_LIMIT_AUTH_PER_MINUTE must be at least 1");
        }
        if cfg.trusted_proxy_hops > MAX_PROXY_HOPS {
            bail!("TRUSTED_PROXY_HOPS must be at most {MAX_PROXY_HOPS}");
        }
        if cfg.trusted_proxy_hops > 0 && cfg.trusted_proxy_cidrs.is_empty() {
            // A hop count alone would trust whoever can reach the port.
            bail!("TRUSTED_PROXY_CIDRS is required when TRUSTED_PROXY_HOPS > 0");
        }
        if cfg.email_token_cooldown < 0 {
            bail!("EMAIL_TOKEN_COOLDOWN_SECONDS must be 0 or more");
        }
        if cfg.upload_max_bytes < 1 {
            bail!("UPLOAD_MAX_BYTES must be at least 1");
        }
        cfg.mail_from
            .parse::<lettre::Address>()
            .context("MAIL_FROM must be a bare address (no display name)")?;

        if cfg.production {
            // The dev fallback logs the email body, which carries a one-time token.
            if cfg.smtp_host.is_empty() {
                bail!("SMTP_HOST is required when APP_ENV=production");
            }
            // sqlx honours disable/allow/prefer/require/verify-ca/verify-full from the URL; its
            // default (prefer) silently falls back to plaintext, so production must say which.
            if sslmode(&cfg.database_url).is_none() {
                bail!(
                    "DATABASE_URL must carry an explicit sslmode in production (verify-full recommended)"
                );
            }
            if !cfg.app_url.starts_with("https://") {
                bail!("APP_URL must be https:// in production (email links carry one-time tokens)");
            }
            if !cfg.s3_endpoint.starts_with("https://") {
                bail!("S3_ENDPOINT must be https:// in production");
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn prod() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("APP_ENV", "production"),
            ("APP_URL", "https://app.example.com"),
            ("DATABASE_URL", "postgres://u:p@db/app?sslmode=verify-full"),
            ("JWT_SECRET", "a-real-production-secret-of-40-characters"),
            ("SMTP_HOST", "smtp.example.com"),
            ("S3_ENDPOINT", "https://acct.r2.cloudflarestorage.com"),
            ("S3_ACCESS_KEY_ID", "k"),
            ("S3_SECRET_ACCESS_KEY", "s"),
            ("S3_BUCKET", "b"),
        ])
    }

    fn load(vars: &HashMap<&str, &str>) -> Result<Config> {
        Config::from_lookup(|n| vars.get(n).map(|v| v.to_string()))
    }

    fn err(vars: HashMap<&'static str, &'static str>) -> String {
        match load(&vars) {
            Ok(_) => panic!("expected a config error"),
            Err(e) => format!("{e:#}"),
        }
    }

    fn with(k: &'static str, v: &'static str) -> HashMap<&'static str, &'static str> {
        let mut m = prod();
        m.insert(k, v);
        m
    }

    #[test]
    fn production_rules() {
        assert!(load(&prod()).is_ok());
        assert!(err(with("DATABASE_URL", "postgres://u:p@db/app")).contains("sslmode"));
        assert!(err(with("DATABASE_URL", "postgres://u:p@db/app?sslmode=")).contains("sslmode"));
        assert!(
            load(&with(
                "DATABASE_URL",
                "postgres://u:p@db/app?application_name=x&sslmode=disable"
            ))
            .is_ok()
        );
        assert!(err(with("APP_URL", "http://app.example.com")).contains("APP_URL"));
        assert!(err(with("S3_ENDPOINT", "http://minio:9000")).contains("S3_ENDPOINT"));
        assert!(err(with("SMTP_HOST", "")).contains("SMTP_HOST"));
        assert!(
            err(with(
                "JWT_SECRET",
                "change-me-to-a-long-random-string-of-32"
            ))
            .contains("change-me")
        );
    }

    #[test]
    fn development_is_relaxed_but_still_strict_on_secrets_and_proxies() {
        let mut dev = prod();
        dev.insert("APP_ENV", "development");
        dev.insert("DATABASE_URL", "postgres://u:p@localhost/app");
        dev.insert("APP_URL", "http://localhost:3000");
        dev.insert("S3_ENDPOINT", "http://localhost:9000");
        dev.insert("SMTP_HOST", "");
        assert!(load(&dev).is_ok());

        let mut short = dev.clone();
        short.insert("JWT_SECRET", " 31-characters-plus-two-spaces ");
        assert!(
            err(short).contains("32"),
            "secret is not trimmed but counted as given"
        );

        let mut hops = dev.clone();
        hops.insert("TRUSTED_PROXY_HOPS", "1");
        assert!(err(hops.clone()).contains("TRUSTED_PROXY_CIDRS"));
        hops.insert("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, ::1/128");
        assert_eq!(load(&hops).unwrap().trusted_proxy_cidrs.len(), 2);
        hops.insert("TRUSTED_PROXY_CIDRS", "10.0.0.0/40");
        assert!(err(hops.clone()).contains("TRUSTED_PROXY_CIDRS"));
        hops.insert("TRUSTED_PROXY_CIDRS", "10.0.0.0/8");
        hops.insert("TRUSTED_PROXY_HOPS", "33");
        assert!(err(hops).contains("at most 32"));

        let mut boolean = dev.clone();
        boolean.insert("AUTH_REQUIRE_VERIFIED_EMAIL", "TRUE");
        assert!(err(boolean).contains("true or false"));
    }
}
