pub mod config;
pub mod db;
pub mod error;
pub mod mailer;
pub mod middleware;
pub mod rate_limit;
pub mod storage;
pub mod validate;

use std::{ops::Deref, sync::Arc, time::Duration};

use anyhow::Result;
use sqlx::PgPool;
use tokio_util::task::TaskTracker;

use crate::features::auth::crypto::{self, JwtKeys};
use config::Config;
use mailer::Mailer;
use rate_limit::RateLimiter;
use storage::Storage;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub db: PgPool,
    pub config: Config,
    pub mailer: Mailer,
    pub storage: Storage,
    pub limiter: RateLimiter,
    pub jwt: JwtKeys,
    /// Verified against when the login email is unknown, so both paths cost one argon2 run.
    pub dummy_hash: String,
    /// Background work (emails, forgot-password lookups) that shutdown waits for.
    pub tasks: TaskTracker,
}

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(config: Config, db: PgPool) -> Result<Self> {
        let tasks = TaskTracker::new();
        Ok(Self(Arc::new(Inner {
            mailer: Mailer::new(&config, tasks.clone())?,
            storage: Storage::new(&config),
            limiter: RateLimiter::new(
                config.rate_limit_auth_per_minute,
                Duration::from_secs(60),
                rate_limit::MAX_KEYS,
            ),
            jwt: JwtKeys::new(&config.jwt_secret, config.access_token_ttl)?,
            dummy_hash: crypto::hash_password(&crypto::random_token())?,
            tasks,
            db,
            config,
        })))
    }
}
