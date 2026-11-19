"""The single error envelope (SPEC section 1) and the handlers that force every error into it."""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("app.errors")


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: list[dict[str, str]] | None = None,
        headers: dict[str, str] | None = None,
    ):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.details, self.headers = details, headers


def validation_error(field: str, message: str) -> ApiError:
    return ApiError(422, "validation_error", "Request validation failed", [{"field": field, "message": message}])


def unauthorized() -> ApiError:
    return ApiError(401, "unauthorized", "Authentication required")


def not_found(what: str = "Resource") -> ApiError:
    return ApiError(404, "not_found", f"{what} not found")


def error_body(code: str, message: str, details: list[dict[str, str]] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    return {"error": error}


def error_response(status: int, code: str, message: str, details=None, headers=None) -> JSONResponse:
    return JSONResponse(error_body(code, message, details), status_code=status, headers=headers)


# --- OpenAPI description of the envelope ---


class ErrorDetail(BaseModel):
    field: str
    message: str


class ErrorObject(BaseModel):
    code: str
    message: str
    details: list[ErrorDetail] | None = None


class ErrorResponse(BaseModel):
    error: ErrorObject


ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    422: {"model": ErrorResponse, "description": "Validation error"},
    "4XX": {"model": ErrorResponse, "description": "Error envelope"},
}

# --- handlers ---

_STATUS_CODES = {
    400: ("bad_request", "Bad request"),
    401: ("unauthorized", "Authentication required"),
    403: ("forbidden", "Forbidden"),
    404: ("not_found", "Not found"),
}


def _is_json(content_type: str | None) -> bool:
    media = (content_type or "").split(";")[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


def _field(loc: tuple) -> str:
    # ('body', 'email') -> 'email'; ('query', 'page') -> 'page'; ('body',) -> 'body'
    names = [str(p) for p in loc[1:] if isinstance(p, str)]
    return ".".join(names) if names else str(loc[0]) if loc else "body"


def _message(err: dict) -> str:
    msg = err.get("msg", "Invalid value")
    return msg.removeprefix("Value error, ") if err.get("type") == "value_error" else msg


async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = exc.errors()
    if any(e.get("type") == "json_invalid" for e in errors):
        return error_response(400, "bad_request", "Malformed JSON body")
    # FastAPI only parses JSON when Content-Type says so; otherwise the whole body fails at loc ('body',).
    if not _is_json(request.headers.get("content-type")) and any(tuple(e["loc"]) == ("body",) for e in errors):
        return error_response(400, "bad_request", "Request body must be JSON with Content-Type: application/json")
    details, seen = [], set()
    for e in errors:
        field = _field(tuple(e["loc"]))
        if field not in seen:  # one message per field keeps the envelope readable
            seen.add(field)
            details.append({"field": field, "message": _message(e)})
    return error_response(422, "validation_error", "Request validation failed", details)


async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
    return error_response(exc.status, exc.code, exc.message, exc.details, exc.headers)


async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    if exc.status_code == 405:  # SPEC: a known path with an unsupported method is a plain 404, no Allow header
        return error_response(404, "not_found", "Not found")
    code, message = _STATUS_CODES.get(exc.status_code, ("internal_error", "Internal server error"))
    if exc.status_code >= 500:
        log.error("http exception", extra={"status": exc.status_code, "detail": str(exc.detail)})
    return error_response(exc.status_code, code, message, headers=getattr(exc, "headers", None))


def install_error_handlers(app: FastAPI) -> None:
    # Unhandled exceptions are turned into 500 `internal_error` by platform.middleware.Guard,
    # which sits inside CORS and the request-id middleware so the 500 still carries their headers.
    app.add_exception_handler(RequestValidationError, _validation)
    app.add_exception_handler(ApiError, _api_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
