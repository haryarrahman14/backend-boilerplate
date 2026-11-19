//! Request fields are `Option` so missing ones become 422 `validation_error` with field details
//! (not serde errors); `value_type` keeps them documented as required strings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::features::users::dto::UserDto;

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    #[schema(value_type = String, format = "email", example = "ada@example.com")]
    pub email: Option<String>,
    #[schema(value_type = String, min_length = 15, max_length = 128)]
    pub password: Option<String>,
    #[schema(value_type = String, min_length = 1, max_length = 100, example = "Ada Lovelace")]
    pub name: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    #[schema(value_type = String, format = "email")]
    pub email: Option<String>,
    #[schema(value_type = String)]
    pub password: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct RefreshRequest {
    /// `<session_id>.<secret>` as returned by login/refresh.
    #[schema(value_type = String)]
    pub refresh_token: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct TokenRequest {
    /// The `token` query parameter of the emailed link.
    #[schema(value_type = String)]
    pub token: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct EmailRequest {
    #[schema(value_type = String, format = "email")]
    pub email: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    #[schema(value_type = String)]
    pub token: Option<String>,
    #[schema(value_type = String, min_length = 15, max_length = 128)]
    pub password: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    #[schema(value_type = String)]
    pub current_password: Option<String>,
    #[schema(value_type = String, min_length = 15, max_length = 128)]
    pub new_password: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct TokensResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[schema(example = "Bearer")]
    pub token_type: &'static str,
    #[schema(example = 900)]
    pub expires_in: i64,
    pub user: UserDto,
}

#[derive(Serialize, ToSchema)]
pub struct MessageResponse {
    pub message: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct SessionDto {
    pub id: Uuid,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    /// True for the session the request was made with.
    pub current: bool,
}

#[derive(Serialize, ToSchema)]
pub struct SessionList {
    pub data: Vec<SessionDto>,
}
