pub mod crypto;
pub mod dto;
pub mod guard;
pub mod handlers;
pub mod repo;
pub mod service;

use axum::{
    Router, middleware,
    routing::{delete, get, post},
};

use crate::platform::{AppState, rate_limit};

/// Everything under `/api/v1/auth`, behind the per-IP rate limit.
pub fn router(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/register", post(handlers::register))
        .route("/login", post(handlers::login))
        .route("/refresh", post(handlers::refresh))
        .route("/logout", post(handlers::logout))
        .route("/logout-all", post(handlers::logout_all))
        .route("/verify-email", post(handlers::verify_email))
        .route("/resend-verification", post(handlers::resend_verification))
        .route("/forgot-password", post(handlers::forgot_password))
        .route("/reset-password", post(handlers::reset_password))
        .route("/change-password", post(handlers::change_password))
        .route("/sessions", get(handlers::list_sessions))
        .route("/sessions/{id}", delete(handlers::delete_session))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit::limit_auth,
        ))
}
