use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use super::{
    dto::{AdminUpdateUserRequest, DeleteMeRequest, UpdateMeRequest, UserDto, UserResponse},
    repo, service,
};
use crate::{
    features::auth::{
        crypto,
        guard::{AdminUser, AuthUser},
    },
    platform::{
        AppState,
        error::{AppError, AppResult, ErrorBody},
        validate::{AppJson, Errors, Page, PageParams, Paginated, parse_path_id},
    },
};

#[utoipa::path(get, path = "/api/v1/users/me", tag = "users", security(("bearer" = [])),
    responses((status = 200, body = UserResponse), (status = 401, body = ErrorBody)))]
pub async fn me(auth: AuthUser) -> Json<UserResponse> {
    Json(auth.user.into())
}

/// Only `name` can change; omitting it returns the profile unchanged.
#[utoipa::path(patch, path = "/api/v1/users/me", tag = "users", security(("bearer" = [])),
    request_body = UpdateMeRequest,
    responses((status = 200, body = UserResponse), (status = 401, body = ErrorBody), (status = 422, body = ErrorBody)))]
pub async fn update_me(
    State(state): State<AppState>,
    auth: AuthUser,
    AppJson(body): AppJson<UpdateMeRequest>,
) -> AppResult<Json<UserResponse>> {
    if body.name.is_none() {
        return Ok(Json(auth.user.into()));
    }
    let mut v = Errors::default();
    let name = v.name("name", &body.name);
    v.finish()?;
    let user = repo::update_name(&state.db, auth.user.id, &name.unwrap_or_default())
        .await?
        .ok_or(AppError::Unauthorized)?;
    Ok(Json(user.into()))
}

/// Admins only. Promote with `UPDATE auth.users SET role = 'admin' WHERE email = '...'`.
#[utoipa::path(get, path = "/api/v1/admin/users", tag = "users", security(("bearer" = [])),
    params(PageParams),
    responses((status = 200, body = Paginated<UserDto>), (status = 401, body = ErrorBody),
              (status = 403, description = "forbidden", body = ErrorBody), (status = 422, body = ErrorBody)))]
pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser, // 403 before any query validation: the admin layer runs first
    page: Page,
) -> AppResult<Json<Paginated<UserDto>>> {
    let (users, total) = repo::list(&state.db, page).await?;
    Ok(Json(page.wrap(
        users.into_iter().map(UserDto::from).collect(),
        total,
    )))
}

/// Deletes the caller's account after re-checking the password (argon2 rules as for login):
/// sessions, bucket objects, then the user row with everything that cascades from it.
#[utoipa::path(delete, path = "/api/v1/users/me", tag = "users", security(("bearer" = [])),
    request_body = DeleteMeRequest,
    responses((status = 204, description = "account deleted"),
              (status = 401, description = "unauthorized / invalid_credentials", body = ErrorBody),
              (status = 422, body = ErrorBody)))]
pub async fn delete_me(
    State(state): State<AppState>,
    auth: AuthUser,
    AppJson(body): AppJson<DeleteMeRequest>,
) -> AppResult<StatusCode> {
    let mut v = Errors::default();
    let password = v.required("password", &body.password).map(str::to_owned);
    v.finish()?;
    let password = password.unwrap_or_default();
    let phc = auth.user.password_hash.clone();
    if !crypto::verify_password_async(password, phc, &state.dummy_hash).await? {
        return Err(AppError::InvalidCredentials);
    }
    service::delete_account(&state, auth.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Admins only (403 before any validation). Sets `role` and/or `disabled`; disabling revokes every
/// session of the user. An admin cannot change their own role or disable themselves (403).
#[utoipa::path(patch, path = "/api/v1/admin/users/{id}", tag = "users", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "user id, canonical 36-char UUID; any other form is 404")),
    request_body = AdminUpdateUserRequest,
    responses((status = 200, body = UserResponse), (status = 401, body = ErrorBody),
              (status = 403, description = "forbidden (not an admin, or a change to oneself)", body = ErrorBody),
              (status = 404, body = ErrorBody), (status = 422, body = ErrorBody)))]
pub async fn admin_update_user(
    State(state): State<AppState>,
    AdminUser(auth): AdminUser,
    Path(id): Path<String>,
    AppJson(body): AppJson<AdminUpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    let id = parse_path_id(&id).ok_or(AppError::NotFound)?;
    if let Some(role) = &body.role
        && role != "user"
        && role != "admin"
    {
        return Err(AppError::field("role", "must be user or admin"));
    }
    let target = repo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if service::is_forbidden_self_change(auth.user.id, &target, body.role.as_deref(), body.disabled)
    {
        return Err(AppError::Forbidden);
    }
    let user = service::admin_update(&state, target, body.role.as_deref(), body.disabled).await?;
    Ok(Json(user.into()))
}

/// Admins only. Deletes the account like `DELETE /users/me`; own id is 403 (use that route).
#[utoipa::path(delete, path = "/api/v1/admin/users/{id}", tag = "users", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "user id, canonical 36-char UUID; any other form is 404")),
    responses((status = 204, description = "account deleted"), (status = 401, body = ErrorBody),
              (status = 403, description = "forbidden (not an admin, or own id)", body = ErrorBody),
              (status = 404, body = ErrorBody)))]
pub async fn admin_delete_user(
    State(state): State<AppState>,
    AdminUser(auth): AdminUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let id = parse_path_id(&id).ok_or(AppError::NotFound)?;
    if id == auth.user.id {
        return Err(AppError::Forbidden);
    }
    repo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    service::delete_account(&state, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
