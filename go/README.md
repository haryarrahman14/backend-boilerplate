# Go implementation

Go 1.27, `net/http` + chi, pgx/v5 (hand-written SQL), goose migrations, golang-jwt v5, argon2id,
aws-sdk-go-v2 S3 (path-style), `log/slog` JSON logs. The contract is `../SPEC.md`.

## Run

```sh
cp .env.example .env        # local infra: `docker compose up -d` in the repo root
make migrate                # goose up (never runs on app start); CMD=status|down for others
make dev                    # http://localhost:8080, docs at /docs, spec at /openapi.json
make test lint build        # unit tests (-race), gofmt + vet, bin/api
```

Contract suite: `contract/run.sh go` from the repo root (build, migrate, start on 8081, test, stop),
or by hand against a running service with a high `RATE_LIMIT_AUTH_PER_MINUTE`:

```sh
BASE_URL=http://localhost:8080 DATABASE_URL=postgres://postgres:postgres@localhost:5433/boilerplate_go?sslmode=disable node --test contract/
```

Docker: `docker build -t api-go .`, then `docker run --env-file .env api-go` (and `... api-go migrate`).

## Database

Tables live in `auth` (`users`, `sessions`, `user_tokens`) and `storage` (`files`); every
query is schema-qualified, nothing relies on `search_path`. `public` holds only goose's
`goose_db_version`. There is no seed command; promote an admin with:

```sql
UPDATE auth.users SET role = 'admin' WHERE email = 'you@example.com';
```

Later admins are managed over the API: `PATCH /api/v1/admin/users/{id}` (`role`, `disabled`) and
`DELETE /api/v1/admin/users/{id}`; an admin cannot demote, disable or delete themselves there.
Disabling revokes every session at once; a disabled account gets `403 account_disabled` on login
(only after the right password) and no verification or reset mail. Deleting an account
(`DELETE /api/v1/users/me` with the password, or the admin route) revokes sessions first, deletes
the user's bucket objects, then the user row (cascade). A bucket failure returns 500 and the call
can be repeated. Ceiling: an upload URL issued before the deletion can still create an orphan
object for up to 15 minutes; add a bucket lifecycle rule on `users/` to clean those up.

## Env

All vars and defaults are in SPEC section 2 and `.env.example`. Config is validated once at
startup and every problem is printed before exiting (e.g. `JWT_SECRET` shorter than 32 chars,
or `APP_ENV=production` without `SMTP_HOST`). Secret values (`JWT_SECRET`, `DATABASE_URL`,
`SMTP_PASS`, `S3_SECRET_ACCESS_KEY`) are a `config.Secret` type that prints as `[redacted]`.

Uploads: the presigned PUT signs `Content-Type` and `Content-Length`, so the client must send
exactly the declared `size` bytes (browsers set Content-Length themselves). Downloads are
presigned with `response-content-disposition=attachment`.

Production (`APP_ENV=production`, the Docker image default) refuses to start without an explicit
`sslmode` in `DATABASE_URL`, with non-https `APP_URL`/`S3_ENDPOINT`, without `SMTP_HOST`, or with a
`change-me` JWT secret; `/docs` and `/openapi.json` are 404 there. `TRUSTED_PROXY_HOPS > 0` needs
`TRUSTED_PROXY_CIDRS`.

Known ceilings (each also noted in code): the auth rate limiter is in-memory and single-instance
(a full map lets new keys through untracked); background emails run on 2 workers with at most
1000 jobs queued or in flight, overflow is dropped and logged; argon2 runs on NumCPU slots with at
most 4x that many waiters, beyond which requests get 429 with `Retry-After: 1`.

## Layout

```
cmd/api/main.go            wiring, `migrate` subcommand, graceful shutdown
migrations/                goose SQL, embedded in the binary: schemas auth (users, sessions,
                           user_tokens) and storage (files); 00002 adds users.disabled_at
internal/features/
  auth/                    routes, guard, service, queries, argon2/JWT/token helpers (+ tests)
  users/                   /users/me (get, patch, delete), /admin/users (list, patch, delete) (+ tests)
  files/                   presign / complete / list / get / delete
  health/                  /health, /health/ready, /openapi.json (embedded), /docs
internal/platform/
  config/ db/ httpx/       env parsing, pgx pool + tx helper, error envelope + middleware
  mailer/ storage/         SMTP (or log), S3 client
  ratelimit/               in-memory fixed window, single instance only (+ tests)
```
