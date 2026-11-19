"""Pure-ASGI middleware. Stack, outermost first (see main.create_app):

RequestContext (request id, security headers, access log) -> CORS -> RateLimit -> Guard (body limit,
timeouts, unhandled errors -> 500 envelope) -> FastAPI.
"""

import asyncio
import ipaddress
import logging
import re
import time
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.platform.errors import error_response
from app.platform.logs import request_ctx
from app.platform.ratelimit import FixedWindowLimiter

log = logging.getLogger("app.http")

_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")  # used with fullmatch: `$` would also accept a trailing \n
MAX_BODY_BYTES = 1024 * 1024
BODY_READ_TIMEOUT = 10.0
REQUEST_TIMEOUT = 30.0
_BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def parse_ip(value: str) -> str | None:
    """Canonical text of an IP address (IPv4-mapped IPv6 shown as IPv4), or None if `value` is not one."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


Networks = tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


def client_ip(scope: Scope, trusted_proxy_hops: int, trusted_proxies: Networks = ()) -> str | None:
    """The socket peer, or with N trusted proxies the N-th X-Forwarded-For entry from the right.

    X-Forwarded-For counts only when the socket peer is one of `trusted_proxies`; from anyone else it is
    ignored. Entries left of the N-th were written by the client and are never trusted. A missing or non-IP
    entry falls back to the socket peer. None when there is no usable peer address (e.g. a unix socket).
    """
    client = scope.get("client")
    peer = parse_ip(client[0]) if client else None
    if trusted_proxy_hops > 0 and peer is not None and any(ipaddress.ip_address(peer) in n for n in trusted_proxies):
        # Several X-Forwarded-For headers are one list, in order (RFC 7230 3.2.2).
        # latin-1 maps every byte, so a non-ASCII entry fails to parse on its own instead of voiding the header.
        values = [v.decode("latin-1") for k, v in scope.get("headers", []) if k == b"x-forwarded-for"]
        entries = ",".join(values).split(",") if values else []
        if len(entries) >= trusted_proxy_hops:
            forwarded = parse_ip(entries[-trusted_proxy_hops])
            if forwarded:
                return forwarded
    return peer


def rate_limit_key(ip: str | None) -> str:
    """IPv6 clients are keyed by their /64 (one host usually owns the whole prefix). Internal to the limiter:
    the placeholder for an unknown peer is never stored or shown."""
    if ip is None:
        return "unknown-peer"
    address = ipaddress.ip_address(ip)
    if address.version == 6:
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return ip


class RequestContext:
    def __init__(self, app: ASGIApp, production: bool):
        self.app, self.production = app, production

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = Headers(scope=scope).get("x-request-id", "")
        request_id = incoming if _REQUEST_ID.fullmatch(incoming) else str(uuid.uuid4())
        ctx = {"request_id": request_id, "user_id": None}
        token = request_ctx.set(ctx)
        scope.setdefault("state", {})["ctx"] = ctx
        started = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-Id"] = request_id
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                if self.production:
                    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            log.info(
                "request",
                extra={
                    "method": scope["method"],
                    "path": scope["path"],
                    "status": status,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            )
            request_ctx.reset(token)


class RateLimit:
    """All /api/v1/auth/* routes share one per-IP budget. CORS preflights are answered before this."""

    def __init__(
        self,
        app: ASGIApp,
        limiter: FixedWindowLimiter,
        trusted_proxy_hops: int,
        trusted_proxies: "Networks" = (),
        prefix: str = "/api/v1/auth/",
    ):
        self.app, self.limiter, self.prefix = app, limiter, prefix
        self.hops, self.proxies = trusted_proxy_hops, trusted_proxies

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"].startswith(self.prefix):
            allowed, retry_after = self.limiter.hit(rate_limit_key(client_ip(scope, self.hops, self.proxies)))
            if not allowed:
                response = error_response(
                    429, "rate_limited", "Too many requests, try again later", headers={"Retry-After": str(retry_after)}
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


class _BodyTooLarge(Exception):
    pass


class Guard:
    """Caps the body at 1 MB, bounds body read and handler time, and turns unhandled errors into a 500 envelope.

    Ceiling: uvicorn has no request-header read timeout (slowloris); run behind a proxy that has one.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            if scope["method"] in _BODY_METHODS:
                try:
                    async with asyncio.timeout(BODY_READ_TIMEOUT):
                        receive = await self._buffer_body(scope, receive)
                except _BodyTooLarge:
                    await error_response(413, "payload_too_large", "Request body exceeds 1 MB")(scope, receive, send)
                    return
                except TimeoutError:
                    await error_response(400, "bad_request", "Request body not received in time")(scope, receive, send)
                    return
            async with asyncio.timeout(REQUEST_TIMEOUT):
                await self.app(scope, receive, send_wrapper)
        except Exception:
            log.exception("unhandled error")
            if response_started:
                raise
            await error_response(500, "internal_error", "Internal server error")(scope, receive, send)

    @staticmethod
    async def _buffer_body(scope: Scope, receive: Receive) -> Receive:
        declared = Headers(scope=scope).get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            raise _BodyTooLarge
        chunks, size, more = [], 0, True
        while more:
            message = await receive()
            if message["type"] != "http.request":  # client went away; let the app see the disconnect
                return _replay_once(message)
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                raise _BodyTooLarge
            chunks.append(chunk)
            more = message.get("more_body", False)
        body, sent = b"".join(chunks), False

        async def replay() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()  # after the body: wait for disconnect like the real channel

        return replay


def _replay_once(message: Message) -> Receive:
    async def receive() -> Message:
        return message

    return receive
