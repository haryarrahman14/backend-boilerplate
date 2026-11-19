use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
};

use super::{dto::*, guard::AuthUser, repo, service};
use crate::{
    features::users::dto::UserResponse,
    platform::{
        AppState,
        error::{AppError, AppResult, ErrorBody},
        middleware::ClientIp,
        validate::{AppJson, Errors, normalize_email, parse_path_id},
    },
};

const ACCEPTED: MessageResponse = MessageResponse {
    message: "If the address belongs to an account, an email is on its way.",
};

#[utoipa::path(post, path = "/api/v1/auth/register", tag = "auth", request_body = RegisterRequest,
    responses((status = 201, body = UserResponse), (status = 409, description = "email_taken", body = ErrorBody),
              (status = 422, body = ErrorBody), (status = 429, body = ErrorBody)))]
pub async fn register(
    State(state): State<AppState>,
    AppJson(body): AppJson<RegisterRequest>,
) -> AppResult<(StatusCode, Json<UserResponse>)> {
    let mut v = Errors::default();
    let email = v.email("email", &body.email);
    let password = v.password("password", &body.password);
    let name = v.name("name", &body.name);
    v.finish()?;
    let (Some(email), Some(password), Some(name)) = (email, password, name) else {
        unreachable!()
    };
    let user = service::register(&state, email, password, name).await?;
    Ok((StatusCode::CREATED, Json(user.into())))
}

#[utoipa::path(post, path = "/api/v1/auth/login", tag = "auth", request_body = LoginRequest,
    responses((status = 200, body = TokensResponse), (status = 401, description = "invalid_credentials", body = ErrorBody),
              (status = 403, description = "email_not_verified", body = ErrorBody),
              (status = 422, body = ErrorBody), (status = 429, body = ErrorBody)))]
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    AppJson(body): AppJson<LoginRequest>,
) -> AppResult<Json<TokensResponse>> {
    let mut v = Errors::default();
    let email = v.required("email", &body.email).map(normalize_email);
    let password = v.required("password", &body.password).map(str::to_owned);
    v.finish()?;
    let (Some(email), Some(password)) = (email, password) else {
        unreachable!()
    };
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    Ok(Json(
        service::login(&state, &email, password, user_agent, ip).await?,
    ))
}

#[utoipa::path(post, path = "/api/v1/auth/refresh", tag = "auth", request_body = RefreshRequest,
    responses((status = 200, body = TokensResponse), (status = 401, description = "unauthorized", body = ErrorBody),
              (status = 422, body = ErrorBody), (status = 429, body = ErrorBody)))]
pub async fn refresh(
    State(state): State<AppState>,
    AppJson(body): AppJson<RefreshRequest>,
) -> AppResult<Json<TokensResponse>> {
    let mut v = Errors::default();
    let token = v.required("refresh_token", &body.refresh_token);
    v.finish()?;
    Ok(Json(
        service::refresh(&state, token.unwrap_or_default()).await?,
    ))
}

#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "auth", security(("bearer" = [])),
    responses((status = 204, description = "current session revoked"), (status = 401, body = ErrorBody)))]
pub async fn logout(State(state): State<AppState>, auth: AuthUser) -> AppResult<StatusCode> {
    repo::revoke_session(&state.db, auth.session_id, auth.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/api/v1/auth/logout-all", tag = "auth", security(("bearer" = [])),
    responses((status = 204, description = "every session revoked"), (status = 401, body = ErrorBody)))]
pub async fn logout_all(State(state): State<AppState>, auth: AuthUser) -> AppResult<StatusCode> {
    repo::revoke_user_sessions(&state.db, auth.user.id, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/api/v1/auth/verify-email", tag = "auth", request_body = TokenRequest,
    responses((status = 204, description = "email verified"), (status = 400, description = "invalid_token", body = ErrorBody),
              (status = 422, body = ErrorBody)))]
pub async fn verify_email(
    State(state): State<AppState>,
    AppJson(body): AppJson<TokenRequest>,
) -> AppResult<StatusCode> {
    let mut v = Errors::default();
    let token = v.required("token", &body.token);
    v.finish()?;
    service::verify_email(&state, token.unwrap_or_default()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/api/v1/auth/resend-verification", tag = "auth", request_body = EmailRequest,
    responses((status = 202, body = MessageResponse), (status = 422, body = ErrorBody)))]
pub async fn resend_verification(
    State(state): State<AppState>,
    AppJson(body): AppJson<EmailRequest>,
) -> AppResult<(StatusCode, Json<MessageResponse>)> {
    let mut v = Errors::default();
    let email = v.email("email", &body.email);
    v.finish()?;
    service::resend_verification(&state, email.unwrap_or_default());
    Ok((StatusCode::ACCEPTED, Json(ACCEPTED)))
}

#[utoipa::path(post, path = "/api/v1/auth/forgot-password", tag = "auth", request_body = EmailRequest,
    responses((status = 202, body = MessageResponse), (status = 422, body = ErrorBody)))]
pub async fn forgot_password(
    State(state): State<AppState>,
    AppJson(body): AppJson<EmailRequest>,
) -> AppResult<(StatusCode, Json<MessageResponse>)> {
    let mut v = Errors::default();
    let email = v.email("email", &body.email);
    v.finish()?;
    service::forgot_password(&state, email.unwrap_or_default());
    Ok((StatusCode::ACCEPTED, Json(ACCEPTED)))
}

#[utoipa::path(post, path = "/api/v1/auth/reset-password", tag = "auth", request_body = ResetPasswordRequest,
    responses((status = 204, description = "password set, every session revoked"),
              (status = 400, description = "invalid_token", body = ErrorBody), (status = 422, body = ErrorBody)))]
pub async fn reset_password(
    State(state): State<AppState>,
    AppJson(body): AppJson<ResetPasswordRequest>,
) -> AppResult<StatusCode> {
    let mut v = Errors::default();
    let token = v.required("token", &body.token).map(str::to_owned);
    let password = v.password("password", &body.password);
    v.finish()?;
    let (Some(token), Some(password)) = (token, password) else {
        unreachable!()
    };
    service::reset_password(&state, &token, password).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/api/v1/auth/change-password", tag = "auth", request_body = ChangePasswordRequest,
    security(("bearer" = [])),
    responses((status = 204, description = "password changed, other sessions revoked"),
              (status = 401, description = "unauthorized / invalid_credentials", body = ErrorBody),
              (status = 422, body = ErrorBody)))]
pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    AppJson(body): AppJson<ChangePasswordRequest>,
) -> AppResult<StatusCode> {
    let mut v = Errors::default();
    let current = v
        .required("current_password", &body.current_password)
        .map(str::to_owned);
    let new = v.password("new_password", &body.new_password);
    v.finish()?;
    let (Some(current), Some(new)) = (current, new) else {
        unreachable!()
    };
    service::change_password(&state, &auth, current, new).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/api/v1/auth/sessions", tag = "auth", security(("bearer" = [])),
    responses((status = 200, body = SessionList), (status = 401, body = ErrorBody)))]
pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Json<SessionList>> {
    let rows = repo::list_active_sessions(&state.db, auth.user.id).await?;
    let data = rows
        .into_iter()
        .map(|s| SessionDto {
            current: s.id == auth.session_id,
            id: s.id,
            user_agent: s.user_agent,
            ip: s.ip,
            created_at: s.created_at,
            last_used_at: s.last_used_at,
        })
        .collect();
    Ok(Json(SessionList { data }))
}

#[utoipa::path(delete, path = "/api/v1/auth/sessions/{id}", tag = "auth", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "session id, canonical 36-char UUID; any other form is 404")),
    responses((status = 204, description = "session revoked"), (status = 401, body = ErrorBody),
              (status = 404, body = ErrorBody)))]
pub async fn delete_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let id = parse_path_id(&id).ok_or(AppError::NotFound)?;
    if repo::revoke_session(&state.db, id, auth.user.id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}
