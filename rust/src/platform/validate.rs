//! Request body / query parsing that always answers with the SPEC error envelope.

use axum::{
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Query, Request},
    http::{header, request::Parts},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use utoipa::{IntoParams, ToSchema};

use super::error::{AppError, FieldError};

/// JSON body extractor: wrong content type or malformed JSON -> 400 `bad_request`;
/// well-formed JSON of the wrong shape -> 422 `validation_error` naming the field.
pub struct AppJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for AppJson<T> {
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(|mime| {
                let mime = mime.trim().to_ascii_lowercase();
                mime == "application/json"
                    || (mime.starts_with("application/") && mime.ends_with("+json"))
            })
            .unwrap_or(false);
        if !is_json {
            return Err(AppError::BadRequest("expected an application/json body"));
        }
        let bytes = Bytes::from_request(req, state).await.map_err(|rejection| {
            if rejection.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
                AppError::PayloadTooLarge
            } else {
                AppError::BadRequest("could not read the request body")
            }
        })?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| AppError::BadRequest("malformed JSON body"))?;
        if !value.is_object() {
            return Err(AppError::field("body", "must be a JSON object"));
        }
        serde_path_to_error::deserialize(value)
            .map(AppJson)
            .map_err(|err| {
                let field = err.path().to_string();
                AppError::field(&field, "has the wrong type")
            })
    }
}

/// Collects field errors so a response lists every problem at once.
#[derive(Default)]
pub struct Errors(Vec<FieldError>);

impl Errors {
    pub fn add(&mut self, field: &str, message: &str) {
        self.0.push(FieldError::new(field, message));
    }

    pub fn finish(self) -> Result<(), AppError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(AppError::Validation(self.0))
        }
    }

    /// Present, non-empty string (no trimming: used for passwords and tokens).
    pub fn required<'a>(&mut self, field: &str, value: &'a Option<String>) -> Option<&'a str> {
        match value.as_deref() {
            Some(v) if !v.is_empty() => Some(v),
            _ => {
                self.add(field, "is required");
                None
            }
        }
    }

    /// Password policy (SPEC 4): 15-128 characters, no composition rules, never trimmed.
    pub fn password(&mut self, field: &str, value: &Option<String>) -> Option<String> {
        let v = self.required(field, value)?;
        let len = v.chars().count();
        if !(15..=128).contains(&len) {
            self.add(field, "must be 15-128 characters");
            return None;
        }
        Some(v.to_owned())
    }

    /// Trims + lowercases, then checks the shape and the 254 character limit.
    pub fn email(&mut self, field: &str, value: &Option<String>) -> Option<String> {
        let email = normalize_email(value.as_deref().unwrap_or(""));
        if email.is_empty() {
            self.add(field, "is required");
            return None;
        }
        if email.chars().count() > 254 || !is_valid_email(&email) {
            self.add(field, "must be a valid email address");
            return None;
        }
        Some(email)
    }

    /// Trimmed display name, 1-100 code points, no control characters.
    pub fn name(&mut self, field: &str, value: &Option<String>) -> Option<String> {
        let name = value.as_deref().unwrap_or("").trim();
        self.text(field, name, 100).then(|| name.to_owned())
    }

    /// 1..=`max` code points and no control characters (U+0000-U+001F, U+007F; Postgres cannot
    /// store NUL). Not trimmed.
    pub fn text(&mut self, field: &str, value: &str, max: usize) -> bool {
        if !(1..=max).contains(&value.chars().count()) {
            self.add(field, &format!("must be 1-{max} characters"));
            false
        } else if value.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}') {
            self.add(field, "must not contain control characters");
            false
        } else {
            true
        }
    }
}

pub fn normalize_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// Exactly ``^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$`` (SPEC 4), on the
/// normalised address. Nothing a mail library could read as `Name <other@address>` gets through.
pub fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b".!#$%&'*+/=?^_`{|}~-".contains(&b)
        });
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    local_ok && domain_ok
}

/// Path ids: only the canonical 36-char hyphenated form (either hex case); braces, `urn:` and
/// dash-less forms are `None` (-> 404).
pub fn parse_path_id(raw: &str) -> Option<uuid::Uuid> {
    let canonical = raw.len() == 36
        && raw.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    canonical.then(|| uuid::Uuid::parse_str(raw).ok()).flatten()
}

/// `?page=1&per_page=20`, validated into 422s rather than axum's default 400.
#[derive(Debug, Clone, Copy)]
pub struct Page {
    pub page: i64,
    pub per_page: i64,
}

impl Page {
    pub fn offset(&self) -> i64 {
        (self.page - 1) * self.per_page
    }

    pub fn wrap<T: Serialize>(self, data: Vec<T>, total: i64) -> Paginated<T> {
        Paginated {
            data,
            meta: PageMeta {
                page: self.page,
                per_page: self.per_page,
                total,
            },
        }
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageParams {
    /// Page number, starting at 1.
    #[param(value_type = Option<i64>, minimum = 1, maximum = 2147483647)]
    page: Option<String>,
    /// Items per page, 1-100 (default 20).
    #[param(value_type = Option<i64>, minimum = 1, maximum = 100)]
    per_page: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for Page {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(q) = Query::<PageParams>::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::field("query", "is malformed"))?;
        let mut errors = Errors::default();
        let mut num = |field: &str, raw: Option<String>, default: i64, max: i64| match raw {
            None => default,
            Some(s) => match s.trim().parse::<i64>() {
                Ok(n) if (1..=max).contains(&n) => n,
                _ => {
                    errors.add(field, &format!("must be an integer between 1 and {max}"));
                    default
                }
            },
        };
        let page = num("page", q.page, 1, i32::MAX as i64);
        let per_page = num("per_page", q.per_page, 20, 100);
        errors.finish()?;
        Ok(Page { page, per_page })
    }
}

#[derive(Serialize, ToSchema)]
pub struct Paginated<T> {
    pub data: Vec<T>,
    pub meta: PageMeta,
}

#[derive(Serialize, ToSchema)]
pub struct PageMeta {
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_matches_the_spec_regex_exactly() {
        for ok in [
            "a@b.co",
            "first.last+tag@sub.example.com",
            "o'neil@x-y.io",
            "a!#$%&'*+/=?^_`{|}~-@a.b",
        ] {
            assert!(is_valid_email(ok), "{ok}");
        }
        for bad in [
            "victim<attacker@evil.example>",
            "\"a b\"@example.com",
            "a@b",
            "a@@example.com",
            "jos\u{e9}@example.com",
            "a b@example.com",
            "a@exa_mple.com",
            "a@example..com",
            "a@.example.com",
            "a@example.com.",
            "@example.com",
            "A@example.com",
            "a@example.com\n",
            "a@[127.0.0.1]",
        ] {
            assert!(!is_valid_email(bad), "{bad:?}");
        }
    }

    #[test]
    fn path_ids_must_be_canonical() {
        let id = uuid::Uuid::new_v4();
        assert_eq!(parse_path_id(&id.to_string()), Some(id));
        assert_eq!(parse_path_id(&id.to_string().to_uppercase()), Some(id));
        for bad in [
            id.simple().to_string(),
            format!("{{{id}}}"),
            id.urn().to_string(),
            "not-a-uuid".into(),
        ] {
            assert_eq!(parse_path_id(&bad), None, "{bad}");
        }
    }

    #[test]
    fn email_is_normalised_and_checked() {
        let mut e = Errors::default();
        assert_eq!(
            e.email("email", &Some("  Ada@Example.COM ".into()))
                .as_deref(),
            Some("ada@example.com")
        );
        assert!(e.email("email", &Some("not-an-email".into())).is_none());
        assert!(e.email("email", &Some("a@b".into())).is_none());
        assert!(
            e.email("email", &Some(format!("{}@example.com", "a".repeat(250))))
                .is_none()
        );
    }

    #[test]
    fn password_length_counts_characters_and_is_not_trimmed() {
        let mut e = Errors::default();
        assert!(e.password("p", &Some("x".repeat(14))).is_none());
        assert!(e.password("p", &Some("é".repeat(15))).is_some());
        assert_eq!(
            e.password("p", &Some(" 1234567890123 ".into())).as_deref(),
            Some(" 1234567890123 ")
        );
        assert!(e.password("p", &Some("é".repeat(128))).is_some());
        assert!(e.password("p", &Some("x".repeat(129))).is_none());
    }

    #[test]
    fn text_rejects_control_characters_and_counts_code_points() {
        let mut e = Errors::default();
        assert_eq!(
            e.name("name", &Some("  Ada  ".into())).as_deref(),
            Some("Ada")
        );
        assert!(e.name("name", &Some("nul\u{0}byte".into())).is_none());
        assert!(e.name("name", &Some("del\u{7f}".into())).is_none());
        assert!(e.name("name", &Some("   ".into())).is_none());
        assert!(e.name("name", &Some("é".repeat(100))).is_some());
        assert!(e.name("name", &Some("é".repeat(101))).is_none());
        assert!(!e.text("filename", "a\u{1f}.png", 255));
        assert!(e.text("filename", "../../Evil Name.PNG", 255));
    }
}
