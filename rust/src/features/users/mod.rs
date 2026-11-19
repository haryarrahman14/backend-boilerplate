pub mod dto;
pub mod handlers;
pub mod repo;

use axum::{Router, routing::get};

use crate::platform::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users/me", get(handlers::me).patch(handlers::update_me))
        .route("/admin/users", get(handlers::list_users))
}
