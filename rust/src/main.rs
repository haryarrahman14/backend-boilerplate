mod features;
mod platform;

use std::{net::SocketAddr, process::ExitCode, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Router,
    extract::{ConnectInfo, DefaultBodyLimit},
    http::{HeaderValue, Method, header},
    middleware,
    response::IntoResponse,
};
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::graceful::GracefulShutdown,
};
use tokio::net::TcpListener;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{AllowOrigin, CorsLayer},
    set_header::SetResponseHeaderLayer,
};
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use features::{ApiDoc, auth, files, health, users};
use platform::{
    AppState,
    config::{self, Config},
    db,
    error::AppError,
    middleware::{X_REQUEST_ID, request_context, timeout},
};

const BODY_LIMIT: usize = 1024 * 1024;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let result = match std::env::args().nth(1).as_deref() {
        None | Some("serve") => serve().await,
        Some("migrate") => migrate().await,
        Some(other) => Err(anyhow::anyhow!(
            "unknown command {other:?} (expected: serve | migrate)"
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn migrate() -> Result<()> {
    db::migrate(&config::database_url()?).await?;
    tracing::info!("migrations applied");
    Ok(())
}

async fn serve() -> Result<()> {
    let config = Config::from_env().context("invalid configuration")?;
    let port = config.port;
    let pool = db::connect(&config.database_url).await?;
    let state = AppState::new(config, pool.clone())?;
    let tasks = state.tasks.clone();
    let app = app(state)?;

    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .context("binding port")?;
    tracing::info!(port, "listening");

    let graceful = GracefulShutdown::new();
    let mut http = http1::Builder::new();
    // Slow clients cannot hold a connection open forever while sending headers; the 30 s
    // request deadline (platform::middleware::timeout) covers body + handler. HTTP/1.1 only.
    http.timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);

    let mut shutdown = std::pin::pin!(shutdown_signal());
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(conn) => conn,
                    Err(err) => {
                        tracing::warn!(error = %err, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let router = app.clone();
                let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let mut req = req.map(axum::body::Body::new);
                    req.extensions_mut().insert(ConnectInfo(peer));
                    router.clone().oneshot(req)
                });
                let conn = graceful.watch(http.serve_connection(TokioIo::new(stream), service));
                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        tracing::debug!(error = %err, "connection closed with error");
                    }
                });
            }
            () = &mut shutdown => break,
        }
    }

    // Stop accepting, let in-flight requests and background emails finish, then close the pool.
    drop(listener);
    tracing::info!("shutting down, draining connections");
    let drain = async {
        graceful.shutdown().await;
        tasks.close();
        tasks.wait().await;
    };
    tokio::select! {
        () = drain => tracing::info!("connections and background tasks drained"),
        () = tokio::time::sleep(DRAIN_TIMEOUT) => tracing::warn!("drain timed out, closing anyway"),
    }
    pool.close().await;
    Ok(())
}

fn app(state: AppState) -> Result<Router> {
    let cfg = &state.config;
    let origins = cfg
        .cors_origins
        .iter()
        .map(|o| HeaderValue::from_str(o).with_context(|| format!("CORS_ORIGINS entry {o:?}")))
        .collect::<Result<Vec<_>>>()?;
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            X_REQUEST_ID.clone(),
        ])
        .expose_headers([X_REQUEST_ID.clone(), header::RETRY_AFTER])
        .allow_credentials(true)
        .max_age(Duration::from_secs(600));
    let hsts = cfg.production.then(|| {
        SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        )
    });

    let api = Router::new()
        .nest("/auth", auth::router(&state))
        .merge(users::router(&state))
        .merge(files::router());

    let mut router = Router::new().merge(health::router()).nest("/api/v1", api);
    // API docs only outside production (there they fall through to the 404 fallback). The UI
    // assets are vendored into the binary: no CDN script.
    if !cfg.production {
        router = router.merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()));
    }
    let router = router
        .fallback(|| async { AppError::NotFound })
        // The contract has no 405: a known path with another method is 404 too.
        .method_not_allowed_fallback(|| async { AppError::NotFound })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(state.clone())
        // Listed outermost first.
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(state, request_context))
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("no-referrer"),
                ))
                .option_layer(hsts)
                .layer(cors)
                .layer(CatchPanicLayer::custom(|_| {
                    AppError::Internal(anyhow::anyhow!("handler panicked")).into_response()
                }))
                .layer(middleware::from_fn(timeout)),
        );
    Ok(router)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    use super::*;

    const LOCAL_DB: &str = "postgres://postgres:postgres@localhost:5433/boilerplate_rust";

    fn test_state(db_url: &str) -> AppState {
        let config = Config::from_lookup(|name| {
            let v = match name {
                "DATABASE_URL" => db_url,
                "JWT_SECRET" => "unit-test-secret-0123456789abcdef-xyz",
                "S3_ENDPOINT" => "http://localhost:9000",
                "S3_ACCESS_KEY_ID" | "S3_SECRET_ACCESS_KEY" => "test",
                "S3_BUCKET" => "test",
                _ => return None,
            };
            Some(v.to_owned())
        })
        .unwrap();
        // Lazy: nothing connects until a query runs.
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(2))
            .connect_lazy(db_url)
            .unwrap();
        AppState::new(config, pool).unwrap()
    }

    /// Every operation under /api/v1/admin, read from the generated OpenAPI document so a new
    /// admin route is covered without touching this test.
    fn admin_operations() -> Vec<(Method, String)> {
        let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let mut ops = Vec::new();
        for (path, item) in doc["paths"].as_object().unwrap() {
            if !path.starts_with("/api/v1/admin") {
                continue;
            }
            let concrete = path
                .split('/')
                .map(|seg| {
                    if seg.starts_with('{') {
                        Uuid::new_v4().to_string()
                    } else {
                        seg.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            for method in item.as_object().unwrap().keys() {
                if let Ok(m) = method.to_uppercase().parse::<Method>() {
                    ops.push((m, concrete.clone()));
                }
            }
        }
        ops
    }

    async fn call(
        app: &Router,
        method: &Method,
        path: &str,
        token: Option<&str>,
    ) -> (StatusCode, String) {
        let mut req = Request::builder()
            .method(method.clone())
            .uri(path)
            .header("content-type", "application/json");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let res = app
            .clone()
            .oneshot(req.body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let code = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        (status, code)
    }

    #[tokio::test]
    async fn every_admin_route_is_admin_only() {
        let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DB.to_owned());
        let state = test_state(&db_url);
        let app = app(state.clone()).unwrap();
        let ops = admin_operations();
        assert!(
            ops.len() >= 3,
            "no admin routes found in the OpenAPI document: {ops:?}"
        );

        for (method, path) in &ops {
            let got = call(&app, method, path, None).await;
            assert_eq!(
                got,
                (StatusCode::UNAUTHORIZED, "unauthorized".into()),
                "{method} {path} without a token"
            );
        }

        // A real non-admin session needs the (migrated) database; without one this half is skipped.
        let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(2), state.db.acquire()).await
        else {
            eprintln!("skipping the non-admin half: no database at {db_url}");
            return;
        };
        let email = format!("admin-guard-{}@example.com", Uuid::new_v4());
        let user_id: Uuid = sqlx::query_scalar(
            "INSERT INTO auth.users (email, password_hash, name) VALUES ($1, 'x', 'Guard test') RETURNING id",
        )
        .bind(&email)
        .fetch_one(&state.db)
        .await
        .expect("insert test user (run `make migrate` first)");
        let session_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO auth.sessions (id, user_id, refresh_token_hash, expires_at) \
             VALUES ($1, $2, 'x', now() + interval '5 minutes')",
        )
        .bind(session_id)
        .bind(user_id)
        .execute(&state.db)
        .await
        .unwrap();
        let token = state.jwt.issue(user_id, session_id).unwrap();

        let mut failures = Vec::new();
        for (method, path) in &ops {
            let got = call(&app, method, path, Some(&token)).await;
            if got != (StatusCode::FORBIDDEN, "forbidden".into()) {
                failures.push(format!("{method} {path} as a non-admin gave {got:?}"));
            }
        }
        sqlx::query("DELETE FROM auth.users WHERE id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await
            .unwrap();
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
