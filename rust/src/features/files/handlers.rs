use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use super::{
    dto::*,
    repo::{self, FileRow, NewFile},
};
use crate::{
    features::auth::guard::AuthUser,
    platform::{
        AppState,
        error::{AppError, AppResult, ErrorBody},
        storage::PRESIGN_TTL,
        validate::{AppJson, Errors, Page, PageParams, Paginated, parse_path_id},
    },
};

/// `users/<user_id>/<file_id>` plus the lowercased extension when it is `^\.[a-z0-9]{1,10}$`.
/// The client filename itself never reaches the key.
pub fn object_key(user_id: Uuid, file_id: Uuid, filename: &str) -> String {
    let ext = filename
        .rfind('.')
        .map(|i| filename[i..].to_lowercase())
        .filter(|e| {
            (2..=11).contains(&e.len())
                && e[1..]
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        .unwrap_or_default();
    format!("users/{user_id}/{file_id}{ext}")
}

async fn owned(state: &AppState, auth: &AuthUser, id: &str) -> AppResult<FileRow> {
    let id = parse_path_id(id).ok_or(AppError::NotFound)?;
    repo::find(&state.db, id, auth.user.id)
        .await?
        .ok_or(AppError::NotFound)
}

/// The presigned PUT signs `Content-Type` and `Content-Length` = `size`: send exactly `size` bytes.
#[utoipa::path(post, path = "/api/v1/files/presign", tag = "files", security(("bearer" = [])),
    request_body = PresignRequest,
    responses((status = 201, body = PresignResponse), (status = 401, body = ErrorBody), (status = 422, body = ErrorBody)))]
pub async fn presign(
    State(state): State<AppState>,
    auth: AuthUser,
    AppJson(body): AppJson<PresignRequest>,
) -> AppResult<(StatusCode, Json<PresignResponse>)> {
    let cfg = &state.config;
    let mut v = Errors::default();
    let filename = body.filename.unwrap_or_default();
    v.text("filename", &filename, 255);
    let content_type = body.content_type.unwrap_or_default();
    if !cfg.upload_allowed_types.contains(&content_type) {
        v.add(
            "content_type",
            &format!("must be one of: {}", cfg.upload_allowed_types.join(", ")),
        );
    }
    match body.size {
        Some(size) if size >= 1 && size <= cfg.upload_max_bytes => {}
        Some(size) if size > cfg.upload_max_bytes => v.add(
            "size",
            &format!("must be at most {} bytes", cfg.upload_max_bytes),
        ),
        _ => v.add("size", "must be an integer >= 1"),
    }
    v.finish()?;

    let size = body.size.unwrap_or_default(); // validated above
    let id = Uuid::new_v4();
    let key = object_key(auth.user.id, id, &filename);
    let url = state.storage.presign_put(&key, &content_type, size).await?;
    let file = repo::create(
        &state.db,
        NewFile {
            id,
            user_id: auth.user.id,
            key: &key,
            filename: &filename,
            content_type: &content_type,
            size,
        },
    )
    .await?;
    let upload = UploadInstructions {
        url,
        method: "PUT",
        headers: UploadHeaders { content_type },
        expires_in: PRESIGN_TTL.as_secs(),
    };
    Ok((
        StatusCode::CREATED,
        Json(PresignResponse {
            file: file.into(),
            upload,
        }),
    ))
}

#[utoipa::path(post, path = "/api/v1/files/{id}/complete", tag = "files", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "canonical 36-char UUID; any other form is 404")),
    responses((status = 200, body = FileResponse), (status = 404, body = ErrorBody),
              (status = 409, description = "upload_incomplete", body = ErrorBody),
              (status = 422, description = "object larger than UPLOAD_MAX_BYTES (file deleted)", body = ErrorBody)))]
pub async fn complete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<FileResponse>> {
    let file = owned(&state, &auth, &id).await?;
    if file.status == "uploaded" {
        return Ok(Json(FileResponse { file: file.into() }));
    }
    let size = state
        .storage
        .head(&file.key)
        .await?
        .ok_or(AppError::UploadIncomplete)?;
    if size > state.config.upload_max_bytes {
        state.storage.delete(&file.key).await?;
        repo::delete(&state.db, file.id).await?;
        return Err(AppError::field(
            "size",
            &format!(
                "uploaded object is larger than {} bytes and was deleted",
                state.config.upload_max_bytes
            ),
        ));
    }
    let file = repo::mark_uploaded(&state.db, file.id, size)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(FileResponse { file: file.into() }))
}

#[utoipa::path(get, path = "/api/v1/files", tag = "files", security(("bearer" = [])), params(PageParams),
    responses((status = 200, body = Paginated<FileDto>), (status = 401, body = ErrorBody), (status = 422, body = ErrorBody)))]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    page: Page,
) -> AppResult<Json<Paginated<FileDto>>> {
    let (rows, total) = repo::list(&state.db, auth.user.id, page).await?;
    Ok(Json(page.wrap(
        rows.into_iter().map(FileDto::from).collect(),
        total,
    )))
}

/// `download_url` is a presigned GET (900 s) with `Content-Disposition: attachment`.
#[utoipa::path(get, path = "/api/v1/files/{id}", tag = "files", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "canonical 36-char UUID; any other form is 404")),
    responses((status = 200, body = FileWithDownload), (status = 401, body = ErrorBody), (status = 404, body = ErrorBody)))]
pub async fn get_one(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<FileWithDownload>> {
    let file = owned(&state, &auth, &id).await?;
    let download_url = if file.status == "uploaded" {
        Some(state.storage.presign_get(&file.key).await?)
    } else {
        None
    };
    Ok(Json(FileWithDownload {
        file: file.into(),
        download_url,
    }))
}

#[utoipa::path(delete, path = "/api/v1/files/{id}", tag = "files", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "canonical 36-char UUID; any other form is 404")),
    responses((status = 204, description = "object and row deleted"), (status = 401, body = ErrorBody),
              (status = 404, body = ErrorBody)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let file = owned(&state, &auth, &id).await?;
    state.storage.delete(&file.key).await?;
    repo::delete(&state.db, file.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_key_never_contains_the_client_filename() {
        let (u, f) = (Uuid::nil(), Uuid::max());
        let base = format!("users/{u}/{f}");
        assert_eq!(
            object_key(u, f, "../../Evil Name.PNG"),
            format!("{base}.png")
        );
        assert_eq!(object_key(u, f, "archive.tar.gz"), format!("{base}.gz"));
        assert_eq!(object_key(u, f, "../../etc/passwd"), base);
        assert_eq!(object_key(u, f, "noext"), base);
        assert_eq!(object_key(u, f, "x.verylongext1"), base);
        assert_eq!(object_key(u, f, "x.p_g"), base);
        assert_eq!(object_key(u, f, "x."), base);
    }
}
