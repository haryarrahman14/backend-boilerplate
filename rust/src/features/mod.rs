pub mod auth;
pub mod files;
pub mod health;
pub mod users;

use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};

/// `/openapi.json`, generated from the `#[utoipa::path]` annotations on every handler.
#[derive(OpenApi)]
#[openapi(
    info(title = "Backend boilerplate (Rust)", description = "Same contract as SPEC.md in every language."),
    paths(
        health::live, health::ready,
        auth::handlers::register, auth::handlers::login, auth::handlers::refresh,
        auth::handlers::logout, auth::handlers::logout_all, auth::handlers::verify_email,
        auth::handlers::resend_verification, auth::handlers::forgot_password,
        auth::handlers::reset_password, auth::handlers::change_password,
        auth::handlers::list_sessions, auth::handlers::delete_session,
        users::handlers::me, users::handlers::update_me, users::handlers::list_users,
        users::handlers::delete_me, users::handlers::admin_update_user, users::handlers::admin_delete_user,
        files::handlers::presign, files::handlers::complete, files::handlers::list,
        files::handlers::get_one, files::handlers::delete,
    ),
    modifiers(&BearerAuth),
)]
pub struct ApiDoc;

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let scheme = HttpBuilder::new()
            .scheme(HttpAuthScheme::Bearer)
            .bearer_format("JWT")
            .build();
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme("bearer", SecurityScheme::Http(scheme));
    }
}
