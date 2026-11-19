# Rust implementation

axum + tokio, sqlx (Postgres), jsonwebtoken, argon2, aws-sdk-s3, lettre, utoipa. Implements [`../SPEC.md`](../SPEC.md).

## Run

```sh
cp .env.example .env      # Makefile loads it
make migrate              # embedded migrations; never run on app start
make dev                  # http://localhost:8080, docs at /docs, spec at /openapi.json
make test                 # unit tests (tokens, passwords, rate limiter, validation)
make lint                 # clippy -D warnings + rustfmt check
```

Contract suite, from the repo root, against a running service:

```sh
BASE_URL=http://localhost:8080 DATABASE_URL=postgres://postgres:postgres@localhost:5433/boilerplate_rust node --test contract/
```

Docker: `docker build -t boilerplate-rust .`, then `docker run --env-file .env boilerplate-rust migrate` and `docker run --env-file .env -p 8080:8080 boilerplate-rust`.

## Env

All variables and defaults are in SPEC section 2 and `.env.example`. The process exits with a clear message on a bad or missing value, including a `JWT_SECRET` shorter than 32 characters. `RUST_LOG` sets the log filter (default `info`). With `APP_ENV=production` (the Docker image's default) these are startup errors: an empty `SMTP_HOST`, a `JWT_SECRET` containing `change-me`, a `DATABASE_URL` without `sslmode`, a non-https `APP_URL` or `S3_ENDPOINT`; `/docs` and `/openapi.json` are 404 there. Client IP comes from `TRUSTED_PROXY_HOPS` (N-th `X-Forwarded-For` entry from the right; 0 = socket peer), honoured only when the peer is inside `TRUSTED_PROXY_CIDRS` (required when hops > 0). SMTP: 465 implicit TLS, any other port STARTTLS (mandatory in production).

## Database

`make migrate` applies one embedded migration that creates the schemas `auth` (users, sessions, user_tokens) and `storage` (files). `public` stays empty for the application on top, apart from sqlx's `_sqlx_migrations`. All SQL in the code is schema-qualified; nothing depends on `search_path`. There is no seed command; promote an admin with:

```sql
UPDATE auth.users SET role = 'admin' WHERE email = 'you@example.com';
```

## Outside the shared contract

- Every request has a 30 s deadline (body read + handler); past it the answer is 408 `request_timeout`. Header reads time out after 10 s (connection closed).
- The server speaks HTTP/1.1 only.
- Concurrent argon2 runs are capped at the CPU count, with up to 4x that many waiting; beyond that 429 `Retry-After: 1`.
- At most 1 000 background mail jobs at once; extra jobs are dropped and logged.
- Shutdown waits up to 30 s in total for connections and background emails.

## Layout

```
src/main.rs              CLI (serve | migrate), router, HTTP server, graceful shutdown
src/features/
  auth/                  routes, handlers, service (flows), repo (SQL), dto, guard (AuthUser), crypto
  users/                 /users/me, /admin/users
  files/                 presign / complete / list / get / delete against S3
  health/                /health, /health/ready
  mod.rs                 OpenAPI document (utoipa)
src/platform/            config, db, error envelope, validation + JSON extractor, middleware,
                         rate limiter, mailer, storage
migrations/              sqlx migration (schemas auth + storage)
```
