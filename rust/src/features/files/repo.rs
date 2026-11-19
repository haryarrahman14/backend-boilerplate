use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

use crate::platform::validate::Page;

#[derive(Debug, FromRow)]
pub struct FileRow {
    pub id: Uuid,
    pub key: String,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub uploaded_at: Option<DateTime<Utc>>,
}

macro_rules! cols {
    () => {
        "id, key, filename, content_type, size, status, created_at, uploaded_at"
    };
}

pub struct NewFile<'a> {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key: &'a str,
    pub filename: &'a str,
    pub content_type: &'a str,
    pub size: i64,
}

pub async fn create(db: impl PgExecutor<'_>, f: NewFile<'_>) -> sqlx::Result<FileRow> {
    sqlx::query_as(concat!(
        "INSERT INTO storage.files (id, user_id, key, filename, content_type, size) VALUES ($1, $2, $3, $4, $5, $6) RETURNING ",
        cols!()
    ))
    .bind(f.id)
    .bind(f.user_id)
    .bind(f.key)
    .bind(f.filename)
    .bind(f.content_type)
    .bind(f.size)
    .fetch_one(db)
    .await
}

/// Scoped to the owner: someone else's file is indistinguishable from a missing one.
pub async fn find(
    db: impl PgExecutor<'_>,
    id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Option<FileRow>> {
    sqlx::query_as(concat!(
        "SELECT ",
        cols!(),
        " FROM storage.files WHERE id = $1 AND user_id = $2"
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(db)
    .await
}

/// Keeps the first `uploaded_at`, so a repeated complete is idempotent. `None` when a concurrent
/// delete removed the row.
pub async fn mark_uploaded(
    db: impl PgExecutor<'_>,
    id: Uuid,
    size: i64,
) -> sqlx::Result<Option<FileRow>> {
    sqlx::query_as(concat!(
        "UPDATE storage.files SET status = 'uploaded', size = $2, uploaded_at = COALESCE(uploaded_at, now()) ",
        "WHERE id = $1 RETURNING ",
        cols!()
    ))
    .bind(id)
    .bind(size)
    .fetch_optional(db)
    .await
}

pub async fn delete(db: impl PgExecutor<'_>, id: Uuid) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM storage.files WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list(
    db: impl PgExecutor<'_> + Copy,
    user_id: Uuid,
    page: Page,
) -> sqlx::Result<(Vec<FileRow>, i64)> {
    let rows = sqlx::query_as(concat!(
        "SELECT ",
        cols!(),
        " FROM storage.files WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(user_id)
    .bind(page.per_page)
    .bind(page.offset())
    .fetch_all(db)
    .await?;
    let total = sqlx::query_scalar("SELECT count(*) FROM storage.files WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?;
    Ok((rows, total))
}

/// Object keys of the user's files, in id order after `after` (keyset paging for account deletion).
pub async fn keys_after(
    db: impl PgExecutor<'_>,
    user_id: Uuid,
    after: Option<Uuid>,
    limit: i64,
) -> sqlx::Result<Vec<(Uuid, String)>> {
    sqlx::query_as(
        "SELECT id, key FROM storage.files WHERE user_id = $1 AND ($2::uuid IS NULL OR id > $2) \
         ORDER BY id LIMIT $3",
    )
    .bind(user_id)
    .bind(after)
    .bind(limit)
    .fetch_all(db)
    .await
}
