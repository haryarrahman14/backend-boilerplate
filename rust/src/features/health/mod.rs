use std::time::Duration;

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::Serialize;
use utoipa::ToSchema;

use crate::platform::AppState;

#[derive(Serialize, ToSchema)]
pub struct Status {
    #[schema(example = "ok")]
    status: &'static str,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(live))
        .route("/health/ready", get(ready))
}

/// Liveness: the process answers; no dependencies are checked.
#[utoipa::path(get, path = "/health", tag = "health", responses((status = 200, body = Status)))]
pub async fn live() -> Json<Status> {
    Json(Status { status: "ok" })
}

/// Readiness: the database answers `SELECT 1`.
#[utoipa::path(get, path = "/health/ready", tag = "health",
    responses((status = 200, body = Status), (status = 503, body = Status, example = json!({"status": "unavailable"}))))]
pub async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Status>) {
    let check = sqlx::query("SELECT 1").execute(&state.db);
    match tokio::time::timeout(Duration::from_secs(2), check).await {
        Ok(Ok(_)) => (StatusCode::OK, Json(Status { status: "ok" })),
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(Status {
                    status: "unavailable",
                }),
            )
        }
        Err(_) => {
            tracing::warn!("readiness check timed out");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(Status {
                    status: "unavailable",
                }),
            )
        }
    }
}
