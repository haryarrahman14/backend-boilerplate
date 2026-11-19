use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use uuid::Uuid;

use crate::{
    features::users::repo::User,
    platform::{
        AppState,
        error::{AppError, AppResult},
        middleware::LogUser,
    },
    user_columns,
};

/// Authenticated caller. Verifies the JWT, then loads session + user in one query, so a revoked
/// or expired session (logout, reset, revoke) or a deleted user is rejected immediately and the
/// role always comes from the database.
pub struct AuthUser {
    pub user: User,
    pub session_id: Uuid,
}

impl AuthUser {
    pub fn require_admin(&self) -> AppResult<()> {
        if self.user.role == "admin" {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

fn bearer(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let claims = bearer(parts)
            .and_then(|t| state.jwt.verify(t))
            .ok_or(AppError::Unauthorized)?;
        let user: User = sqlx::query_as(concat!(
            "SELECT ",
            user_columns!("u"),
            " FROM auth.sessions s JOIN auth.users u ON u.id = s.user_id",
            " WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now()"
        ))
        .bind(claims.sid)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::Unauthorized)?;

        if let Some(log_user) = parts.extensions.get::<LogUser>() {
            log_user.set(user.id);
        }
        Ok(AuthUser {
            user,
            session_id: claims.sid,
        })
    }
}
