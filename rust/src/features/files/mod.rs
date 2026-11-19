pub mod dto;
pub mod handlers;
pub mod repo;

use axum::{
    Router,
    routing::{get, post},
};

use crate::platform::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/files", get(handlers::list))
        .route("/files/presign", post(handlers::presign))
        .route(
            "/files/{id}",
            get(handlers::get_one).delete(handlers::delete),
        )
        .route("/files/{id}/complete", post(handlers::complete))
}
