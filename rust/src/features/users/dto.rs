use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::repo::User;

/// Public view of a user: never carries the password hash.
#[derive(Serialize, ToSchema)]
pub struct UserDto {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    #[schema(example = "user")]
    pub role: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserDto {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            name: u.name,
            role: u.role,
            email_verified: u.email_verified_at.is_some(),
            created_at: u.created_at,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct UserResponse {
    pub user: UserDto,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self { user: u.into() }
    }
}

/// Only `name` is accepted; any other field (role, email, ...) is ignored.
#[derive(Deserialize, ToSchema)]
pub struct UpdateMeRequest {
    #[schema(example = "Grace Hopper")]
    pub name: Option<String>,
}
