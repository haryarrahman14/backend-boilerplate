use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::{PgPool, postgres::PgPoolOptions};

pub async fn connect(url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(url)
        .await
        .context("connecting to the database")
}

/// Run by `boilerplate migrate` (`make migrate`), never on app start.
pub async fn migrate(url: &str) -> Result<()> {
    let pool = connect(url).await?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running migrations")?;
    pool.close().await;
    Ok(())
}
