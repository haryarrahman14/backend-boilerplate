"""Every route under /api/v1/admin must be admin-only. Walks the app's REAL route table (not a hand-written
list), so a route added later is covered automatically, and checks it two ways: structurally (the role check
is among the route's dependencies) and behaviourally (401 without a token, 403 for a non-admin, before the id,
query or body are looked at), through the full ASGI stack with only the DB and the token check stubbed."""

import asyncio
import json
import re
import uuid

import pytest
from fastapi.routing import iter_route_contexts

from app.features.auth.deps import Principal, current_principal
from app.features.users.models import User
from app.main import create_app
from app.platform.config import Settings
from app.platform.db import get_db

SETTINGS = {
    "database_url": "postgres://u:p@localhost:5432/db",
    "jwt_secret": "s" * 32,
    "s3_endpoint": "http://localhost:9000",
    "s3_access_key_id": "k",
    "s3_secret_access_key": "s",
    "s3_bucket": "b",
}

app = create_app(Settings(_env_file=None, **SETTINGS))
# FastAPI >= 0.16x keeps included routers nested in app.routes; iter_route_contexts is the walker its own
# OpenAPI generator uses, yielding each route with its effective path and dependencies (router ones included).
# Filter on the path only: a non-FastAPI route under /admin has no dependant and must FAIL below, not vanish.
ADMIN_ROUTES = [r for r in iter_route_contexts(app.routes) if (r.path or "").startswith("/api/v1/admin")]
CASES = [(method, route.path) for route in ADMIN_ROUTES for method in sorted(route.methods)]


def _roles(route) -> set[str]:
    roles: set[str] = set()
    dependant = getattr(route, "dependant", None)  # None for a plain Starlette route: no guard possible
    for dependency in dependant.dependencies if dependant else []:  # top level: router + route dependencies
        roles |= getattr(dependency.call, "required_roles", set())
    return roles


def test_admin_routes_exist():
    assert len(ADMIN_ROUTES) >= 3, "the route table walk found no admin routes; the filter is broken"


@pytest.mark.parametrize("route", ADMIN_ROUTES, ids=lambda r: f"{sorted(r.methods)} {r.path}")
def test_every_admin_route_carries_the_admin_check(route):
    assert "admin" in _roles(route), f"{route.path} is under /admin but has no require_role('admin')"


async def _no_db():
    yield None  # never touched: every case below stops at the guard or the role check


def _non_admin() -> Principal:
    return Principal(User(id=uuid.uuid4(), role="user", email="u@example.com", name="U"), uuid.uuid4())


async def _call(method: str, path: str) -> tuple[int, dict]:
    url = re.sub(r"\{[^}]+\}", "not-a-uuid", path)  # an id that would be 404 if anything looked at it
    body = b'{"role": "nonsense", "disabled": "yes"}' if method in ("POST", "PUT", "PATCH") else b""
    scope = {
        "type": "http",
        "method": method,
        "path": url,
        "raw_path": url.encode(),
        "root_path": "",
        "scheme": "http",
        "query_string": b"page=0&per_page=1000",  # invalid paging too: must not surface as 422
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
        "http_version": "1.1",
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict] = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(payload)


@pytest.mark.parametrize(("method", "path"), CASES)
def test_admin_route_answers_401_without_a_token(method, path):
    app.dependency_overrides = {get_db: _no_db}
    try:
        status, body = asyncio.run(_call(method, path))
    finally:
        app.dependency_overrides = {}
    assert (status, body["error"]["code"]) == (401, "unauthorized")


@pytest.mark.parametrize(("method", "path"), CASES)
def test_admin_route_answers_403_to_a_non_admin_before_validation(method, path):
    app.dependency_overrides = {get_db: _no_db, current_principal: _non_admin}
    try:
        status, body = asyncio.run(_call(method, path))
    finally:
        app.dependency_overrides = {}
    assert (status, body["error"]["code"]) == (403, "forbidden")
