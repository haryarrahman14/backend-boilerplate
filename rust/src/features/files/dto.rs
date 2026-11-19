use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::repo::FileRow;

#[derive(Deserialize, ToSchema)]
pub struct PresignRequest {
    /// Original client filename (stored for display only, never used in the object key).
    #[schema(value_type = String, min_length = 1, max_length = 255, example = "avatar.png")]
    pub filename: Option<String>,
    #[schema(value_type = String, example = "image/png")]
    pub content_type: Option<String>,
    /// Declared size in bytes; the real size is checked on complete.
    #[schema(value_type = i64, minimum = 1)]
    pub size: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct FileDto {
    pub id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    #[schema(example = "pending")]
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub uploaded_at: Option<DateTime<Utc>>,
}

impl From<FileRow> for FileDto {
    fn from(f: FileRow) -> Self {
        Self {
            id: f.id,
            filename: f.filename,
            content_type: f.content_type,
            size: f.size,
            status: f.status,
            created_at: f.created_at,
            uploaded_at: f.uploaded_at,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct FileResponse {
    pub file: FileDto,
}

#[derive(Serialize, ToSchema)]
pub struct FileWithDownload {
    pub file: FileDto,
    /// Presigned GET (900 s) once uploaded, `null` while pending.
    pub download_url: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PresignResponse {
    pub file: FileDto,
    pub upload: UploadInstructions,
}

#[derive(Serialize, ToSchema)]
pub struct UploadInstructions {
    pub url: String,
    #[schema(example = "PUT")]
    pub method: &'static str,
    pub headers: UploadHeaders,
    #[schema(example = 900)]
    pub expires_in: u64,
}

/// Headers the client must send with the PUT; they are part of the signature.
#[derive(Serialize, ToSchema)]
pub struct UploadHeaders {
    #[serde(rename = "Content-Type")]
    pub content_type: String,
}
