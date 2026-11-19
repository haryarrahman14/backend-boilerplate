pub mod dto;
pub mod handlers;
pub mod repo;
pub mod service;

use axum::{
    Router, middleware,
    routing::{get, patch},
};

use crate::{features::auth::guard, platform::AppState};

pub fn router(state: &AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/users/me",
            get(handlers::me)
                .patch(handlers::update_me)
                .delete(handlers::delete_me),
        )
        .nest("/admin", admin_router(state))
}

/// Every `/admin` route lives here, behind one admin layer; handlers take `AdminUser`, which only
/// that layer provides. Add new admin routes to this router and nowhere else.
fn admin_router(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/users", get(handlers::list_users))
        .route(
            "/users/{id}",
            patch(handlers::admin_update_user).delete(handlers::admin_delete_user),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            guard::require_admin,
        ))
}
