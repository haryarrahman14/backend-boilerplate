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
        .merge(users::router())
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
