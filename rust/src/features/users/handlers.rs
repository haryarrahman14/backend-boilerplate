use axum::{Json, extract::State};

use super::{
    dto::{UpdateMeRequest, UserDto, UserResponse},
    repo,
};
use crate::{
    features::auth::guard::AuthUser,
    platform::{
        AppState,
        error::{AppError, AppResult, ErrorBody},
        validate::{AppJson, Errors, Page, PageParams, Paginated},
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
    auth: AuthUser,
    page: Result<Page, AppError>,
) -> AppResult<Json<Paginated<UserDto>>> {
    auth.require_admin()?; // 403 before any query validation
    let page = page?;
    let (users, total) = repo::list(&state.db, page).await?;
    Ok(Json(page.wrap(
        users.into_iter().map(UserDto::from).collect(),
        total,
    )))
}
