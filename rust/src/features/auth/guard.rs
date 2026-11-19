use axum::{
    extract::{FromRequestParts, Request, State},
    http::{header, request::Parts},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::{
    features::users::repo::User,
    platform::{AppState, error::AppError, middleware::LogUser},
    user_columns,
};

/// Authenticated caller. Verifies the JWT, then loads session + user in one query, so a revoked
/// or expired session (logout, reset, revoke) or a deleted user is rejected immediately and the
/// role always comes from the database.
#[derive(Clone)]
pub struct AuthUser {
    pub user: User,
    pub session_id: Uuid,
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
            " WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now()",
            " AND u.disabled_at IS NULL"
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

/// An authenticated caller whose role is `admin` (read from the database by the guard query).
/// Only `require_admin` creates it; the extractor fails closed with 403 if that layer is missing.
#[derive(Clone)]
pub struct AdminUser(pub AuthUser);

/// The one admin check, applied as a layer to the whole `/admin` router (see `users::router`):
/// 401 without a valid session, 403 unless the role is `admin`, before any handler extractor
/// (path id, query, body) runs. A route can only be served under `/admin` through that router.
pub async fn require_admin(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let (mut parts, body) = req.into_parts();
    let auth = AuthUser::from_request_parts(&mut parts, &state).await?;
    if auth.user.role != "admin" {
        return Err(AppError::Forbidden);
    }
    parts.extensions.insert(AdminUser(auth));
    Ok(next.run(Request::from_parts(parts, body)).await)
}

impl<S: Send + Sync> FromRequestParts<S> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AdminUser>()
            .cloned()
            .ok_or(AppError::Forbidden)
    }
}
