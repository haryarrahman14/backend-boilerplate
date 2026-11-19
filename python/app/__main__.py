"""`python -m app [--reload]`: validate config (refusing to start on a bad value), then serve."""

import sys

import uvicorn
from pydantic import ValidationError

from app.platform.config import Settings, describe_errors


def main() -> None:
    try:
        settings = Settings()
    except ValidationError as e:
        print(f"invalid configuration, refusing to start:\n{describe_errors(e)}", file=sys.stderr)
        sys.exit(1)
    uvicorn.run(
        "app.main:create_app",
        factory=True,
        host="0.0.0.0",  # noqa: S104  (inside a container; put a proxy in front)
        port=settings.port,
        reload="--reload" in sys.argv,
        log_config=None,  # app.platform.logs owns logging (JSON)
        proxy_headers=False,  # the client IP comes from TRUSTED_PROXY_HOPS in our code, not uvicorn's own rewrite
        server_header=False,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=20,  # SIGTERM/SIGINT: stop accepting, drain for up to 20 s, then lifespan shutdown
    )


if __name__ == "__main__":
    main()
