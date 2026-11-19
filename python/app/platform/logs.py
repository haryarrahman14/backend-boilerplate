"""JSON lines on stdout via stdlib logging. Every line carries the current request_id / user_id."""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

# A mutable dict per request: the auth guard fills in user_id and the request middleware reads it back,
# whichever task/context copy each runs in.
request_ctx: ContextVar[dict | None] = ContextVar("request_ctx", default=None)

_RESERVED = set(vars(logging.makeLogRecord({}))) | {"message", "asctime", "taskName", "color_message"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        line = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        ctx = request_ctx.get()
        if ctx:
            line["request_id"] = ctx.get("request_id")
            if ctx.get("user_id"):
                line["user_id"] = ctx["user_id"]
        line.update({k: v for k, v in vars(record).items() if k not in _RESERVED})
        if record.exc_info:
            line["exception"] = self.formatException(record.exc_info)
        return json.dumps(line, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").disabled = True  # replaced by our one-line-per-request log
    for noisy in ("botocore", "boto3", "urllib3", "aiosmtplib"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
