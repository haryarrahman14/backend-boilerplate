# Backend boilerplate: Python

FastAPI + SQLAlchemy 2 (async, asyncpg) + Alembic. Implements [`../SPEC.md`](../SPEC.md) and passes `../contract/`.

## Run

```sh
cp .env.example .env      # infra from ../docker-compose.yml
make migrate              # alembic upgrade head; never run on app start
make dev                  # http://localhost:8080, docs at /docs, spec at /openapi.json (both 404 in production)
make test lint            # pytest, ruff
make build                # docker image (non-root, APP_ENV=production); migrate: docker run --rm <image> alembic upgrade head
```

Needs [uv](https://docs.astral.sh/uv/); it installs Python 3.13 from `.python-version`.
Start the server with `python -m app` (what `make dev` and the image do): it validates config with a clear
message first and runs uvicorn with proxy-header rewriting off, so `TRUSTED_PROXY_HOPS` alone decides the client IP.

Contract suite, from the repo root (sync, migrate, start on 8083, run, stop):

```sh
contract/run.sh python
```

## Env

All variables and defaults are in SPEC section 2 and `.env.example`. `DATABASE_URL` is the plain `postgres://` form;
it is converted for asyncpg internally (`sslmode` becomes `ssl`). The service refuses to start on a bad value:
`JWT_SECRET` under 32 chars, booleans other than `true`/`false`, `TRUSTED_PROXY_HOPS` without
`TRUSTED_PROXY_CIDRS`, and in production: an empty `SMTP_HOST`, a `JWT_SECRET` containing `change-me`, a
`DATABASE_URL` without `sslmode`, or a non-https `APP_URL` / `S3_ENDPOINT`. Behind N reverse proxies set
`TRUSTED_PROXY_HOPS=N` and their CIDRs; X-Forwarded-For from any other peer is ignored.

`sslmode` is honoured like libpq: `require` encrypts without verifying, `verify-ca` checks the chain and
`verify-full` the chain and host name, against the system trust store or `sslrootcert=<file>` (app and alembic).
`/docs` is a small page pinned to swagger-ui-dist 5.34.1 with SRI hashes (see `app/platform/docs.py` to upgrade).

## Database

Tables live in `auth` (`users`, `sessions`, `user_tokens`) and `storage` (`files`); `public` is left for
the application built on top (only `alembic_version` lives there). Every query is schema-qualified through the
models; nothing relies on `search_path`. There is no seed command; promote an admin with:

```sql
UPDATE auth.users SET role = 'admin' WHERE email = 'you@example.com';
```

## Layout

```
app/
  main.py               app factory: middleware order, routers, lifespan (DB pool, shutdown drain)
  __main__.py           entry point: validate config, start uvicorn
  features/
    auth/               router, service (register/login/refresh/sessions/tokens), security (argon2, JWT,
                        opaque tokens), deps (auth guard: session + user in one query), models, schemas
    users/              /users/me, /admin/users, User model, shared field rules (email, name, password)
    files/              presign / complete / list / get / delete against S3 (R2 or MinIO)
    health/             /health, /health/ready
  platform/             config, db, errors (envelope), middleware (incl. client IP), logs (JSON), mailer,
                        storage, ratelimit, pagination, validation (body base, path ids), tasks (background
                        email, capped), cpu (bounded argon2 pool), docs (pinned Swagger UI)
migrations/             alembic: one initial revision creating schemas auth + storage and their tables
tests/                  unit tests: tokens, passwords, JWT, rate limiter, config, client IP, email syntax,
                        path ids, middleware
```
