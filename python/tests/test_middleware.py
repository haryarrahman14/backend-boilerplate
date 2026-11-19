"""ASGI-level checks for the parts the black-box suite cannot trigger: unhandled errors and the body cap."""

import asyncio
import json

from app.platform.middleware import MAX_BODY_BYTES, Guard, RequestContext


async def _call(app, method="GET", body=b"", headers=()):
    scope = {"type": "http", "method": method, "path": "/x", "headers": list(headers), "client": ("1.2.3.4", 1)}
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), json.loads(payload)


async def _boom(scope, receive, send):
    raise RuntimeError("SELECT secret FROM somewhere")


def test_unhandled_error_becomes_generic_500_with_request_id():
    status, headers, body = asyncio.run(_call(RequestContext(Guard(_boom), production=False)))
    assert status == 500
    assert body == {"error": {"code": "internal_error", "message": "Internal server error"}}
    assert headers[b"x-request-id"] and headers[b"x-content-type-options"] == b"nosniff"


def test_body_over_1mb_is_413_before_the_app_runs():
    status, _, body = asyncio.run(_call(Guard(_boom), "POST", b"a" * (MAX_BODY_BYTES + 1)))
    assert status == 413 and body["error"]["code"] == "payload_too_large"


def test_production_adds_hsts():
    _, headers, _ = asyncio.run(_call(RequestContext(Guard(_boom), production=True)))
    assert headers[b"strict-transport-security"].startswith(b"max-age=")


def test_request_id_must_fullmatch():
    async def ok(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    def echoed(value: bytes) -> bytes:
        _, headers, _ = asyncio.run(_call(RequestContext(ok, production=False), headers=[(b"x-request-id", value)]))
        return headers[b"x-request-id"]

    assert echoed(b"abc_123-XYZ") == b"abc_123-XYZ"
    for bad in (b"abc\n", b"a" * 65, b"has space", b""):
        assert echoed(bad) != bad


def test_background_jobs_are_capped():
    from app.platform import tasks

    async def scenario():
        gate = asyncio.Event()
        assert all([tasks.spawn(gate.wait(), "t", max_jobs=3) for _ in range(3)])
        assert not tasks.spawn(gate.wait(), "t", max_jobs=3)  # dropped (and closed, so no "never awaited")
        gate.set()
        await tasks.drain(1)
        assert tasks.spawn(gate.wait(), "t", max_jobs=3)
        await tasks.drain(1)

    asyncio.run(scenario())
