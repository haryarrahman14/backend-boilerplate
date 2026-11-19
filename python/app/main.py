"""App factory: config -> platform services -> middleware -> feature routers."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.features.auth.router import router as auth_router
from app.features.files.router import router as files_router
from app.features.health.router import router as health_router
from app.features.users.router import router as users_router
from app.platform import tasks
from app.platform.config import Settings
from app.platform.db import make_engine, make_sessionmaker
from app.platform.docs import install_docs
from app.platform.errors import install_error_handlers
from app.platform.logs import configure_logging
from app.platform.mailer import Mailer
from app.platform.middleware import Guard, RateLimit, RequestContext
from app.platform.ratelimit import FixedWindowLimiter
from app.platform.storage import Storage

log = logging.getLogger("app")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.engine = make_engine(settings.database)
        app.state.sessionmaker = make_sessionmaker(app.state.engine)
        log.info("started", extra={"port": settings.port, "env": settings.app_env})
        yield
        # uvicorn has stopped accepting and drained in-flight requests by now.
        await tasks.drain()
        await app.state.engine.dispose()
        log.info("stopped")

    app = FastAPI(
        title="Backend boilerplate (Python)",
        version="1.0.0",
        docs_url=None,  # our own pinned + SRI page, see platform.docs
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",  # production: both are 404
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.storage = Storage(settings)
    app.state.mailer = Mailer(settings)

    install_error_handlers(app)
    for router in (auth_router, users_router, files_router):
        app.include_router(router, prefix="/api/v1")
    app.include_router(health_router)
    if not settings.is_production:
        install_docs(app)

    # add_middleware prepends, so the last one added is the outermost.
    app.add_middleware(Guard)
    app.add_middleware(
        RateLimit,
        limiter=FixedWindowLimiter(settings.rate_limit_auth_per_minute),
        trusted_proxy_hops=settings.trusted_proxy_hops,
        trusted_proxies=settings.trusted_proxy_networks,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
        expose_headers=["X-Request-Id", "Retry-After"],
        max_age=600,
    )
    app.add_middleware(RequestContext, production=settings.is_production)
    return app
