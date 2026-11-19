use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

/// One entry of `error.details` on a `validation_error`; `field` is the snake_case JSON name.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

impl FieldError {
    pub fn new(field: &str, message: &str) -> Self {
        Self {
            field: field.to_owned(),
            message: message.to_owned(),
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Vec<FieldError>>,
}

#[derive(Debug)]
pub enum AppError {
    BadRequest(&'static str),
    InvalidToken,
    InvalidCredentials,
    Unauthorized,
    EmailNotVerified,
    Forbidden,
    NotFound,
    EmailTaken,
    UploadIncomplete,
    PayloadTooLarge,
    Validation(Vec<FieldError>),
    RateLimited { retry_after: u64 },
    Timeout,
    Internal(anyhow::Error),
}

impl AppError {
    pub fn field(field: &str, message: &str) -> Self {
        Self::Validation(vec![FieldError::new(field, message)])
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        Self::Internal(err.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut details = None;
        let mut retry_after = None;
        let (status, code, message) = match self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg),
            AppError::InvalidToken => (
                StatusCode::BAD_REQUEST,
                "invalid_token",
                "token is invalid or expired",
            ),
            AppError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "invalid email or password",
            ),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication required",
            ),
            AppError::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                "email_not_verified",
                "email address is not verified",
            ),
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "you are not allowed to do this",
            ),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource not found"),
            AppError::EmailTaken => (
                StatusCode::CONFLICT,
                "email_taken",
                "email is already registered",
            ),
            AppError::UploadIncomplete => (
                StatusCode::CONFLICT,
                "upload_incomplete",
                "the object has not been uploaded yet",
            ),
            AppError::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "request body is too large",
            ),
            AppError::Validation(fields) => {
                details = Some(fields);
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "validation_error",
                    "request validation failed",
                )
            }
            AppError::RateLimited { retry_after: secs } => {
                retry_after = Some(secs);
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limited",
                    "too many requests, slow down",
                )
            }
            AppError::Timeout => (
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "request took too long",
            ),
            AppError::Internal(err) => {
                // The real cause goes to the log (with the request id from the span), never to the client.
                log_internal(&err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "something went wrong",
                )
            }
        };
        let body = ErrorBody {
            error: ErrorDetail {
                code,
                message: message.to_owned(),
                details,
            },
        };
        let mut res = (status, Json(body)).into_response();
        if let Some(secs) = retry_after {
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        res
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// Logs the cause without the `Debug` form, which for driver errors can carry row or parameter
/// values: database errors as code + message + constraint, anything else as its message chain.
fn log_internal(err: &anyhow::Error) {
    if let Some(sqlx::Error::Database(db)) = err.downcast_ref::<sqlx::Error>() {
        tracing::error!(
            db_code = db.code().as_deref().unwrap_or(""),
            db_message = db.message(),
            db_constraint = db.constraint().unwrap_or(""),
            "internal error (database)"
        );
    } else {
        tracing::error!(error = %format!("{err:#}"), "internal error");
    }
}
