use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

use crate::platform::validate::Page;

/// `Debug` is hand-written so the password hash never reaches a log line.
#[derive(Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub role: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("password_hash", &"<redacted>")
            .field("name", &self.name)
            .field("role", &self.role)
            .field("email_verified_at", &self.email_verified_at)
            .field("disabled_at", &self.disabled_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Column list shared by every query that returns a `User` (also used by the auth guard).
#[macro_export]
macro_rules! user_columns {
    ($p:literal) => {
        concat!(
            $p,
            ".id, ",
            $p,
            ".email, ",
            $p,
            ".password_hash, ",
            $p,
            ".name, ",
            $p,
            ".role, ",
            $p,
            ".email_verified_at, ",
            $p,
            ".disabled_at, ",
            $p,
            ".created_at"
        )
    };
}

/// `None` when the email is already registered.
pub async fn create(
    db: impl PgExecutor<'_>,
    email: &str,
    password_hash: &str,
    name: &str,
) -> sqlx::Result<Option<User>> {
    sqlx::query_as(concat!(
        "INSERT INTO auth.users AS u (email, password_hash, name) VALUES ($1, $2, $3) ",
        "ON CONFLICT (email) DO NOTHING RETURNING ",
        user_columns!("u")
    ))
    .bind(email)
    .bind(password_hash)
    .bind(name)
    .fetch_optional(db)
    .await
}

pub async fn find_by_email(db: impl PgExecutor<'_>, email: &str) -> sqlx::Result<Option<User>> {
    sqlx::query_as(concat!(
        "SELECT ",
        user_columns!("u"),
        " FROM auth.users u WHERE u.email = $1"
    ))
    .bind(email)
    .fetch_optional(db)
    .await
}

pub async fn update_name(
    db: impl PgExecutor<'_>,
    id: Uuid,
    name: &str,
) -> sqlx::Result<Option<User>> {
    sqlx::query_as(concat!(
        "UPDATE auth.users AS u SET name = $2, updated_at = now() WHERE u.id = $1 RETURNING ",
        user_columns!("u")
    ))
    .bind(id)
    .bind(name)
    .fetch_optional(db)
    .await
}

pub async fn list(db: impl PgExecutor<'_> + Copy, page: Page) -> sqlx::Result<(Vec<User>, i64)> {
    let users = sqlx::query_as(concat!(
        "SELECT ",
        user_columns!("u"),
        " FROM auth.users u ORDER BY u.created_at DESC, u.id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(page.per_page)
    .bind(page.offset())
    .fetch_all(db)
    .await?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM auth.users")
        .fetch_one(db)
        .await?;
    Ok((users, total))
}

/// Password reset: new hash, and the link proved ownership of the address.
pub async fn set_password_and_verify(
    db: impl PgExecutor<'_>,
    id: Uuid,
    password_hash: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE auth.users SET password_hash = $2, email_verified_at = COALESCE(email_verified_at, now()), \
         updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(password_hash)
    .execute(db)
    .await?;
    Ok(())
}

/// Sets `email_verified_at` only if it is still null.
pub async fn mark_verified(db: impl PgExecutor<'_>, id: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE auth.users SET email_verified_at = now(), updated_at = now() WHERE id = $1 AND email_verified_at IS NULL",
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn find_by_id(db: impl PgExecutor<'_>, id: Uuid) -> sqlx::Result<Option<User>> {
    sqlx::query_as(concat!(
        "SELECT ",
        user_columns!("u"),
        " FROM auth.users u WHERE u.id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
}

pub async fn set_role(db: impl PgExecutor<'_>, id: Uuid, role: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE auth.users SET role = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(role)
        .execute(db)
        .await?;
    Ok(())
}

/// Disabling keeps the first `disabled_at`; enabling clears it.
pub async fn set_disabled(db: impl PgExecutor<'_>, id: Uuid, disabled: bool) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE auth.users SET disabled_at = CASE WHEN $2 THEN COALESCE(disabled_at, now()) END, \
         updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(disabled)
    .execute(db)
    .await?;
    Ok(())
}

/// Removes the user; sessions, tokens and file rows go with it (ON DELETE CASCADE).
pub async fn delete(db: impl PgExecutor<'_>, id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query("DELETE FROM auth.users WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}
