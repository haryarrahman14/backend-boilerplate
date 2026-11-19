use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgConnection, PgExecutor};
use uuid::Uuid;

use crate::{features::users::repo::User, user_columns};

pub const EMAIL_VERIFICATION: &str = "email_verification";
pub const PASSWORD_RESET: &str = "password_reset";

#[derive(FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

pub struct NewSession<'a> {
    pub id: Uuid,
    pub user_id: Uuid,
    pub refresh_token_hash: &'a str,
    pub user_agent: Option<&'a str>,
    pub ip: Option<String>,
    pub ttl_seconds: i64,
}

/// Creates the session only if the user's hash is still the one login verified (the verify ran
/// outside any transaction). `FOR SHARE` waits for a reset/change that holds the user row, so a
/// login in flight with the old password cannot outlive their revocation. `false` = no session.
pub async fn create_session(
    db: impl PgExecutor<'_>,
    s: NewSession<'_>,
    verified_hash: &str,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "INSERT INTO auth.sessions (id, user_id, refresh_token_hash, user_agent, ip, expires_at) \
         SELECT $1, u.id, $3, $4, $5, now() + $6::bigint * interval '1 second' \
         FROM auth.users u WHERE u.id = $2 AND u.password_hash = $7 AND u.disabled_at IS NULL FOR SHARE",
    )
    .bind(s.id)
    .bind(s.user_id)
    .bind(s.refresh_token_hash)
    .bind(s.user_agent)
    .bind(s.ip)
    .bind(s.ttl_seconds)
    .bind(verified_hash)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// The SPEC's atomic rotation statement (keeping the replaced hash for reuse detection), joined
/// to the user so `user` is re-read in the same round trip. `None` = nothing rotated.
pub async fn rotate_refresh(
    db: impl PgExecutor<'_>,
    session_id: Uuid,
    old_hash: &str,
    new_hash: &str,
    ttl_seconds: i64,
) -> sqlx::Result<Option<User>> {
    sqlx::query_as(concat!(
        "WITH s AS (",
        "UPDATE auth.sessions SET refresh_token_hash = $3, previous_refresh_token_hash = $2, ",
        "last_used_at = now(), expires_at = now() + $4::bigint * interval '1 second' ",
        "WHERE id = $1 AND refresh_token_hash = $2 AND revoked_at IS NULL AND expires_at > now() ",
        "AND EXISTS (SELECT 1 FROM auth.users d WHERE d.id = auth.sessions.user_id AND d.disabled_at IS NULL) ",
        "RETURNING user_id) ",
        "SELECT ",
        user_columns!("u"),
        " FROM s JOIN auth.users u ON u.id = s.user_id"
    ))
    .bind(session_id)
    .bind(old_hash)
    .bind(new_hash)
    .bind(ttl_seconds)
    .fetch_optional(db)
    .await
}

/// `previous_refresh_token_hash` of a live session (`None`: no live session, or never rotated).
pub async fn previous_refresh_hash(
    db: impl PgExecutor<'_>,
    session_id: Uuid,
) -> sqlx::Result<Option<String>> {
    let row: Option<Option<String>> = sqlx::query_scalar(
        "SELECT previous_refresh_token_hash FROM auth.sessions \
         WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(session_id)
    .fetch_optional(db)
    .await?;
    Ok(row.flatten())
}

/// Reuse detected: revoke, still conditional on the presented hash being the previous one.
pub async fn revoke_replayed_session(
    db: impl PgExecutor<'_>,
    session_id: Uuid,
    presented_hash: &str,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "UPDATE auth.sessions SET revoked_at = now() WHERE id = $1 AND previous_refresh_token_hash = $2 \
         AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(session_id)
    .bind(presented_hash)
    .execute(db)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn revoke_session(
    db: impl PgExecutor<'_>,
    session_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "UPDATE auth.sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(session_id)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Revokes every active session of the user except `keep` (pass `None` to revoke all).
pub async fn revoke_user_sessions(
    db: impl PgExecutor<'_>,
    user_id: Uuid,
    keep: Option<Uuid>,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE auth.sessions SET revoked_at = now() \
         WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)",
    )
    .bind(user_id)
    .bind(keep)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list_active_sessions(
    db: impl PgExecutor<'_>,
    user_id: Uuid,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "SELECT id, user_agent, ip, created_at, last_used_at FROM auth.sessions \
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() \
         ORDER BY created_at DESC, id DESC",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
}

/// Issues a one-time token unless the cooldown says no (`Ok(false)`: issue nothing, send nothing).
/// Serialised per user and type by an advisory lock so the cooldown check cannot be raced;
/// touches `user_tokens` only.
pub async fn issue_token(
    conn: &mut PgConnection,
    user_id: Uuid,
    kind: &str,
    token_hash: &str,
    ttl_seconds: i64,
    cooldown_seconds: i64,
) -> sqlx::Result<bool> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("{user_id}:{kind}"))
        .execute(&mut *conn)
        .await?;
    if cooldown_seconds > 0 {
        let recent: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM auth.user_tokens WHERE user_id = $1 AND type = $2 \
             AND created_at > clock_timestamp() - $3::bigint * interval '1 second')",
        )
        .bind(user_id)
        .bind(kind)
        .bind(cooldown_seconds)
        .fetch_one(&mut *conn)
        .await?;
        if recent {
            return Ok(false);
        }
    }
    // Older tokens stay valid: issuing is anonymous, consuming one burns the rest.
    sqlx::query(
        "INSERT INTO auth.user_tokens (user_id, type, token_hash, expires_at) \
         VALUES ($1, $2, $3, now() + $4::bigint * interval '1 second')",
    )
    .bind(user_id)
    .bind(kind)
    .bind(token_hash)
    .bind(ttl_seconds)
    .execute(&mut *conn)
    .await?;
    Ok(true)
}

/// Compare-and-swap of the password hash: only if it is still the hash that was verified and the
/// session making the request is still live. `false` = something changed underneath the request.
pub async fn swap_password_hash(
    db: impl PgExecutor<'_>,
    user_id: Uuid,
    verified_hash: &str,
    new_hash: &str,
    session_id: Uuid,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "UPDATE auth.users SET password_hash = $3, updated_at = now() \
         WHERE id = $1 AND password_hash = $2 AND EXISTS ( \
           SELECT 1 FROM auth.sessions WHERE id = $4 AND revoked_at IS NULL AND expires_at > now())",
    )
    .bind(user_id)
    .bind(verified_hash)
    .bind(new_hash)
    .bind(session_id)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Atomic single use: returns the owner only if the token was valid and is now consumed. Callers
/// then `burn_tokens` the user's other unused tokens of that type in the same transaction.
pub async fn consume_token(
    db: impl PgExecutor<'_>,
    token_hash: &str,
    kind: &str,
) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar(
        "UPDATE auth.user_tokens SET used_at = now() \
         WHERE token_hash = $1 AND type = $2 AND used_at IS NULL AND expires_at > now() RETURNING user_id",
    )
    .bind(token_hash)
    .bind(kind)
    .fetch_optional(db)
    .await
}

/// Marks every unused token of that type for the user as used.
pub async fn burn_tokens(db: impl PgExecutor<'_>, user_id: Uuid, kind: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE auth.user_tokens SET used_at = now() WHERE user_id = $1 AND type = $2 AND used_at IS NULL")
        .bind(user_id)
        .bind(kind)
        .execute(db)
        .await?;
    Ok(())
}
