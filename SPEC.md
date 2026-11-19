# Backend boilerplate — shared contract

Four implementations (`go/`, `rust/`, `python/`, `nestjs/`) expose **the same HTTP API, the same
database schema and the same env vars**. `contract/` is one black-box test suite run against each.
If an implementation and this file disagree, this file wins.

## 1. Conventions

- Base path `/api/v1`. Health and docs live outside it.
- JSON only, `snake_case` keys, timestamps RFC 3339 UTC (`2026-01-02T03:04:05Z`, fractional seconds allowed), ids are UUID strings.
- Unknown JSON fields are ignored. Strings are trimmed for `email` and `name` only (never passwords).
- Every response carries `X-Request-Id` (echo the incoming header if it is 1–64 chars of `[A-Za-z0-9_-]`, else generate a UUID). It is on every log line of that request.
- Error body, always:
  ```json
  { "error": { "code": "validation_error", "message": "human text", "details": [ { "field": "email", "message": "..." } ] } }
  ```
  `details` only on `validation_error`. Never leak internals (SQL, stack traces) in `message`.

| HTTP | code | when |
|---|---|---|
| 400 | `bad_request` | malformed JSON, or a body sent without `Content-Type: application/json` |
| 400 | `invalid_token` | verify-email / reset-password token unknown, used or expired |
| 401 | `invalid_credentials` | login failed (any reason), wrong current password |
| 401 | `unauthorized` | missing/invalid/expired access token, revoked session, bad refresh token |
| 403 | `email_not_verified` | login while `AUTH_REQUIRE_VERIFIED_EMAIL=true` and not verified |
| 403 | `forbidden` | role not allowed |
| 404 | `not_found` | unknown route, **known path with an unsupported method** (no 405), or unknown resource (also: resource owned by someone else) |
| 409 | `email_taken` | register with existing email |
| 409 | `upload_incomplete` | complete called but object is not in the bucket |
| 413 | `payload_too_large` | request body over 1 MB |
| 422 | `validation_error` | body/query validation: missing field, wrong JSON type, body that is valid JSON but not an object, out-of-range value |
| 429 | `rate_limited` | with `Retry-After` seconds header |
| 500 | `internal_error` | anything else; log the real error, return a generic message |

- A string that is not well-formed Unicode (lone surrogate) is rejected with 400 or 422 — never a 500, never stored.
- Path ids must be the canonical 36-char hyphenated UUID form (`^[0-9a-fA-F]{8}-(…){3}-[0-9a-fA-F]{12}$`); braces, `urn:` and dash-less forms are 404.
- Lengths are counted in Unicode code points. `name` and `filename` reject control characters (U+0000–U+001F, U+007F) with 422 — Postgres cannot store NUL.
- Pagination: `?page=1&per_page=20` (`1<=page<=2147483647`, `1<=per_page<=100`; anything else, including non-integers and overflowing numbers, is 422) → `{ "data": [...], "meta": { "page": 1, "per_page": 20, "total": 57 } }`, newest first.

## 2. Env vars (identical names everywhere; each service ships `.env.example`)

| var | default | notes |
|---|---|---|
| `PORT` | `8080` | |
| `APP_ENV` | `development` | `development` \| `production` |
| `APP_URL` | `http://localhost:3000` | frontend base, used in email links. Must be `https://` in production (the links carry one-time tokens). |
| `DATABASE_URL` | required | Postgres. **In production it must carry an explicit `sslmode`** (refuse to start without one): driver defaults differ per language and several silently fall back to plaintext. `disable` is then a visible operator choice; `verify-full` is the recommendation. Every implementation must honour `disable`, `require`, `verify-ca` and `verify-full` (a stricter reading of `require` is fine, a looser one is not). |
| `JWT_SECRET` | required | **refuse to start if < 32 chars**. Used byte for byte (no trimming). In production also refuse a value containing `change-me` (the `.env.example` placeholder). |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` | 30 days, sliding |
| `AUTH_REQUIRE_VERIFIED_EMAIL` | `false` | |
| `RATE_LIMIT_AUTH_PER_MINUTE` | `10` | per client IP, all `/auth/*` routes together |
| `TRUSTED_PROXY_HOPS` | `0` | number of reverse proxies in front of the app. `0` → client IP is the socket peer, `X-Forwarded-For` is ignored. `N` → the **N-th entry from the right** of `X-Forwarded-For` (the left side is written by the client and must never be trusted). If that entry is missing or not a valid IP, fall back to the socket peer. |
| `TRUSTED_PROXY_CIDRS` | empty | comma-separated CIDRs of the reverse proxies. **Required when `TRUSTED_PROXY_HOPS` > 0** (refuse to start otherwise). `X-Forwarded-For` is honoured only when the socket peer is inside one of them; from any other peer the header is ignored and the peer address is the client IP. A hop count alone trusts whoever can reach the port. |
| `EMAIL_TOKEN_COOLDOWN_SECONDS` | `60` | minimum gap between two emails of the same type to the same user; `0` disables |
| `CORS_ORIGINS` | `http://localhost:3000` | comma separated, no `*` with credentials |
| `SMTP_HOST` | empty | empty → log the email (to, subject, body) instead of sending. **Required when `APP_ENV=production`** (refuse to start), because the body carries a one-time token and tokens must never reach production logs |
| `SMTP_PORT` | `1025` | `465` → implicit TLS. Any other port → STARTTLS with the server name verified; **mandatory in production** (fail the send rather than fall back to plaintext), opportunistic in development. 10 s connect/send timeout. |
| `SMTP_USER`, `SMTP_PASS` | empty | |
| `MAIL_FROM` | `no-reply@example.com` | |
| `S3_ENDPOINT` | required | R2: `https://<account_id>.r2.cloudflarestorage.com`. Must be `https://` in production. |
| `S3_REGION` | `auto` | |
| `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_BUCKET` | required | |
| `UPLOAD_MAX_BYTES` | `10485760` | |
| `UPLOAD_ALLOWED_TYPES` | `image/jpeg,image/png,image/webp,application/pdf` | |

Booleans accept exactly `true` / `false`. Config is parsed and validated once at startup; a bad/missing value stops the process with a clear message.
S3 client always uses **path-style** addressing (works for both R2 and MinIO).

## 3. Database (Postgres)

Same tables and columns in all four. Migrations are run by an explicit command (`make migrate`), never on app start.

Tables live in two Postgres schemas, never in `public` — `public` is left for the application built on top, so its own `sessions` or `files` tables cannot collide and a reporting role can be granted `public` without seeing password hashes:

| schema | tables |
|---|---|
| `auth` | `users`, `sessions`, `user_tokens` |
| `storage` | `files` |

One initial migration creates both schemas and every table inside them. Every statement is schema-qualified (`auth.users`); nothing relies on `search_path`. Only the migration tool's own bookkeeping table stays in `public`.

```sql
auth.users(
  id uuid pk default gen_random_uuid(),
  email text not null unique,            -- stored lowercased + trimmed
  password_hash text not null,           -- argon2id PHC string
  name text not null,
  role text not null default 'user' check (role in ('user','admin')),
  email_verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
)
auth.sessions(
  id uuid pk default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  refresh_token_hash text not null,      -- sha256 hex of the secret part
  previous_refresh_token_hash text,      -- the hash this one replaced; null until the first rotation
  user_agent text, ip text,
  created_at timestamptz not null default now(),
  last_used_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz
)  -- index (user_id)
auth.user_tokens(
  id uuid pk default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  type text not null check (type in ('email_verification','password_reset')),
  token_hash text not null unique,       -- sha256 hex
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
)  -- index (user_id, type)
storage.files(
  id uuid pk default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  key text not null unique,
  filename text not null, content_type text not null, size bigint not null,
  status text not null default 'pending' check (status in ('pending','uploaded')),
  created_at timestamptz not null default now(),
  uploaded_at timestamptz
)  -- index (user_id, created_at desc)
```

## 4. Auth rules (read every line)

**Passwords**
- 15–128 characters, no composition rules (NIST SP 800-63B-4 requires 15 for password-only login). Login and `current_password` are never rejected for being short, so raising the minimum later cannot lock anyone out. Hash with **argon2id** (m=19456 KiB, t=2, p=1), PHC string.
- Never log passwords, tokens, hashes or `Authorization` headers. (Only exception: the dev-only email log when `SMTP_HOST` is empty.)

**Email**
- Normalise: trim + lowercase before validating, storing or looking up. Max 254 chars. After normalising it must match exactly
  ``^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$`` (ASCII only). Never hand a looser string to a mail library: `victim<attacker@evil.com>` must be a 422, not a mail to the attacker. `name` 1–100 chars after trim.

**Access token** — JWT, HS256, claims `sub` (user id), `sid` (session id), `iat`, `exp`.
- Verification pins the algorithm to HS256 (reject `none` and anything else) and requires `exp`.
- Sent as `Authorization: Bearer <token>`; the scheme is matched case-insensitively. `iat` is informational and not validated (clock skew between replicas must not cause 401s).
- The auth guard also loads the session + user in **one query** per request and rejects with 401 `unauthorized` when the session is revoked/expired or the user is gone. So logout, password reset and session revocation take effect immediately, and `role` always comes from the DB, not the token.

**Refresh token** — opaque string `<session_id>.<secret>`; `secret` = 32 random bytes (CSPRNG), base64url without padding. Only `sha256(secret)` hex is stored — the hash is taken over the base64url **string as transmitted** (same for one-time tokens), so all four implementations produce identical rows. A refresh token is well-formed only if it is `<lowercase canonical 36-char uuid>.<43 base64url chars>`.
- Rotation on every refresh, done as one atomic statement:
  `UPDATE auth.sessions SET refresh_token_hash=$new, previous_refresh_token_hash=$old, last_used_at=now(), expires_at=now()+ttl WHERE id=$sid AND refresh_token_hash=$old AND revoked_at IS NULL AND expires_at>now()`.
- **Reuse detection**: if that updates 0 rows, revoke the session only when the presented hash equals `previous_refresh_token_hash` of a live session — that proves the secret was really issued and already rotated (`UPDATE auth.sessions SET revoked_at=now() WHERE id=$sid AND previous_refresh_token_hash=$presented AND revoked_at IS NULL AND expires_at>now()`). A secret that was never issued must **not** revoke anything: the session id is public (it is the token prefix and the JWT `sid`), so revoking on any mismatch lets anyone who has seen an id log that user out. Every failure (malformed, unknown session, expired, revoked, wrong secret, reuse) → 401 `unauthorized`, same message.
- Compare hashes in constant time wherever the comparison happens in app code.

**One-time tokens** (email verification 24 h, password reset 1 h) — 32 random bytes base64url; only sha256 hex stored; single use (`used_at`), consumed atomically (`UPDATE ... WHERE token_hash=$1 AND type=$2 AND used_at IS NULL AND expires_at>now() RETURNING user_id`). Issuing a new token does **not** invalidate older ones: `forgot-password` and `resend-verification` are anonymous, so invalidate-on-issue would let anyone keep killing the link a user is about to click, and a failed send would leave the user with no working link. Instead, **consuming** a token marks the user's other unused tokens of that type as used, in the same transaction. Issuance is serialised per user with `pg_advisory_xact_lock(hashtext('<user_id>:<type>'))` at the start of its transaction, so the cooldown check cannot be raced. If the user's newest token of that type is younger than `EMAIL_TOKEN_COOLDOWN_SECONDS`, issue nothing and send nothing (the HTTP response is unchanged).
- Links: `{APP_URL}/verify-email?token=<token>` and `{APP_URL}/reset-password?token=<token>`. Plain-text email body made of **fixed text plus the link only — no user-controlled value** (not the name, not anything else a registrant typed), because anyone can register any address and would otherwise send their own text from your domain. The verification mail includes the sentence `If you did not create this account, ignore this email and do not use the link.`
- Background mail work is bounded: at most 1 000 mail jobs queued or in flight per process; beyond that the job is dropped and logged (the HTTP response is unchanged). No DB connection is held during the SMTP send.
- Emails are sent **after the response, in the background** (goroutine / `tokio::spawn` / background task / un-awaited promise with a catch). A mail failure is logged, never fails the request, and response time must not reveal whether an account exists.

**No user enumeration**
- Login: unknown email and wrong password give the same 401 `invalid_credentials` and message. When the user does not exist, still run one argon2 verify against a fixed dummy hash.
- `forgot-password` and `resend-verification` always return 202 with the same body, whatever the email.
- (`register` does return 409 `email_taken` — accepted trade-off, it is rate limited.)
- Login validates presence only: `email` and `password` must be non-empty strings (else 422). A malformed email or a too-short/too-long password is **not** a validation error there — it is 401 `invalid_credentials` like any other miss.
- `forgot-password` / `resend-verification`: a malformed email is 422; for any well-formed email the user lookup, token creation and mail **all** happen in the background after the 202.
- With `AUTH_REQUIRE_VERIFIED_EMAIL=true`, the 403 `email_not_verified` is returned only after the password was verified; a wrong password is still 401.

**Password writes and locking** — these rules exist because a black-box test cannot see races:
- Lock order in every transaction is `user_tokens` → `users` → `sessions`. (Token issuance touches `user_tokens` only, under the advisory lock.)
- **Login binds the session to the password it verified.** The verify happens outside any transaction, so the session insert must be conditional: `INSERT INTO auth.sessions (...) SELECT ... FROM auth.users WHERE id=$uid AND password_hash=$hash_that_was_verified FOR SHARE`. The `FOR SHARE` is required: without it the SELECT reads the old hash while a reset is still uncommitted and inserts a session the reset never sees; with it the login waits for the in-flight password write and re-checks the hash after it commits. 0 rows → the password changed while argon2 ran → 401 `invalid_credentials`, no session. Otherwise a login in flight with the old password outlives the revocation a concurrent reset or change performs.
- `reset-password`, in one transaction: consume the token → mark the user's other unused `password_reset` tokens used → set the hash and `email_verified_at` → revoke all sessions.
- `change-password`, in one transaction: **compare-and-swap** the hash (it does **not** touch `password_reset` tokens: a reset link only ever reaches the mailbox owner, and control of the mailbox must outrank knowledge of the password — otherwise whoever registered or stole the account first can cancel every recovery attempt by looping change-password):
  `UPDATE auth.users SET password_hash=$new WHERE id=$uid AND password_hash=$hash_that_was_verified AND EXISTS (SELECT 1 FROM auth.sessions WHERE id=$sid AND revoked_at IS NULL AND expires_at>now())`
  → 0 rows means the password or session changed underneath the request: roll back, 401 `invalid_credentials`. → revoke other sessions.
  Without the CAS, an attacker holding a stolen session can race a victim's reset and silently overwrite it.
- Never hold a DB connection/transaction open while argon2 runs. Bound concurrent argon2 work to roughly the CPU count (19 MiB each). The bound must hold for the whole hash (a cancelled request must not free its slot while its hash is still running), waiting for a slot must stop when the request is cancelled or passes its deadline, and at most 4× the slot count may wait — a request arriving beyond that gets 429 `rate_limited` with `Retry-After: 1`. Argon2 never runs on a login or current password longer than 128 code points: verify the fixed dummy hash instead and return the usual 401.
- DB driver errors must not put statement parameters in logs (they contain hashes).
- Types holding secrets (config, user row) must not be printable with their secrets by a debug formatter.

**Rate limit** — in-memory fixed window per client IP over all `/api/v1/auth/*` routes; 429 + `Retry-After`. Key IPv6 clients by their /64. Expired keys are swept at most once per window (never per request); the map is capped at 100 000 keys; a new key arriving while it is full is **allowed and not tracked** (existing keys stay limited). Refusing new keys would let anyone with 100 000 addresses lock every other user out of login and refresh, while that attacker already has 100 000 budgets either way. Mark it as single-instance only in a comment (swap for Redis when scaled out). The stored session `ip` is always a parsed IP (IPv4-mapped IPv6 shown as IPv4) or null — never a raw header or a placeholder string. A forwarded header containing bytes outside ASCII is still split and parsed entry by entry, never discarded as a whole.

**HTTP hardening** — CORS from `CORS_ORIGINS`; headers `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` (+ `Strict-Transport-Security` in production); JSON body limit 1 MB; server read/request timeouts; graceful shutdown on SIGTERM/SIGINT (stop accepting, drain, wait for in-flight background emails, close DB pool).

## 5. Endpoints

`user` object everywhere: `{ "id", "email", "name", "role", "email_verified": bool, "created_at" }`.
`tokens` response: `{ "access_token", "refresh_token", "token_type": "Bearer", "expires_in": 900, "user": {user} }`.
🔒 = requires access token. Rate limited = everything under `/auth`.

### Health / docs (no prefix)
- `GET /health` → 200 `{ "status": "ok" }` (liveness, no DB).
- `GET /health/ready` → 200 `{ "status": "ok" }` if `SELECT 1` works, else 503 `{ "status": "unavailable" }`.
- `GET /docs` → Swagger UI (or equivalent) and `GET /openapi.json` → OpenAPI 3 document covering all routes below. **Both are 404 `not_found` when `APP_ENV=production`.** Where the UI page loads script from a CDN, it pins an exact version and carries Subresource Integrity hashes.

### Auth
| route | body | success | notes |
|---|---|---|---|
| `POST /auth/register` | `email, password, name` | 201 `{ "user" }` | creates user, sends verification email. No tokens. 409 `email_taken`. |
| `POST /auth/login` | `email, password` | 200 tokens | creates a session (stores `User-Agent` truncated to 255, client IP). |
| `POST /auth/refresh` | `refresh_token` | 200 tokens | rotation + reuse detection. `user` is re-read from DB. |
| `POST /auth/logout` 🔒 | – | 204 | revokes the current session (`sid`). |
| `POST /auth/logout-all` 🔒 | – | 204 | revokes every session of the user. |
| `POST /auth/verify-email` | `token` | 204 | sets `email_verified_at` (if null) and marks the user's other unused verification tokens used. 400 `invalid_token`. |
| `POST /auth/resend-verification` | `email` | 202 `{ "message" }` | sends only if user exists and is unverified. |
| `POST /auth/forgot-password` | `email` | 202 `{ "message" }` | sends only if user exists. |
| `POST /auth/reset-password` | `token, password` | 204 | sets password, **revokes all sessions**, marks email verified (the link proved ownership). 400 `invalid_token`. Validate `password` before consuming the token. |
| `POST /auth/change-password` 🔒 | `current_password, new_password` | 204 | wrong current → 401 `invalid_credentials`. **Revokes all other sessions**, keeps the current one. Leaves `password_reset` tokens alone: the mailbox owner can always recover with a reset link, which revokes every session. |
| `GET /auth/sessions` 🔒 | – | 200 `{ "data": [ { "id", "user_agent", "ip", "created_at", "last_used_at", "current": bool } ] }` | active sessions only, newest first. |
| `DELETE /auth/sessions/{id}` 🔒 | – | 204 | own **active** sessions only, else 404 (already revoked/expired → 404). Non-UUID id → 404. Revoking the current one equals logout. |

Password reset / change and token consumption + side effects happen in **one DB transaction**.

### Users
- `GET /users/me` 🔒 → 200 `{ "user" }`
- `PATCH /users/me` 🔒 `{ name }` → 200 `{ "user" }`. `name` absent → 200, nothing changes.
- `GET /admin/users` 🔒 role `admin` → paginated list of `user`. Others → 403 `forbidden`, checked **before** query validation (a non-admin never sees 422).
  (No seed command: promote with `UPDATE auth.users SET role='admin' WHERE email='…'`.)

### Files (R2 / S3, direct-to-bucket uploads) — all 🔒, scoped to the owner
`file` object: `{ "id", "filename", "content_type", "size", "status", "created_at", "uploaded_at" }`.

| route | body | success | notes |
|---|---|---|---|
| `POST /files/presign` | `filename` (1–255), `content_type`, `size` (int ≥ 1) | 201 `{ "file", "upload": { "url", "method": "PUT", "headers": { "Content-Type": "<content_type>" }, "expires_in": 900 } }` | 422 if type not in `UPLOAD_ALLOWED_TYPES` or `size > UPLOAD_MAX_BYTES`. Row is `pending`. Object key = `users/<user_id>/<file_id>` + lowercased extension of `filename` if it matches `^\.[a-z0-9]{1,10}$` — the client filename never goes into the key. The presigned PUT signs `Content-Type` **and `Content-Length` = `size`**, so the bucket rejects a body of any other length, before and after `complete` (clients just send exactly `size` bytes; browsers set the header themselves). |
| `POST /files/{id}/complete` | – | 200 `{ "file" }` | `HEAD` the object. Missing → 409 `upload_incomplete`. Actual size > `UPLOAD_MAX_BYTES` → delete object + row, 422. Else status `uploaded`, `size` = actual size, `uploaded_at` = now. Idempotent when already uploaded. |
| `GET /files` | `page, per_page` | paginated `file` list | |
| `GET /files/{id}` | – | 200 `{ "file", "download_url" }` | `download_url` = presigned GET (900 s, with `response-content-disposition=attachment` so the bucket origin never renders a file inline) when uploaded, `null` when pending. |
| `DELETE /files/{id}` | – | 204 | deletes the object, then the row. A delete racing a `complete` yields 404, not 500. |

Someone else's file id, or a non-UUID id → 404 `not_found`.

## 6. Every service ships

- Feature-based folders: `auth`, `users`, `files`, `health` each own their routes/handlers, service logic, queries and DTOs; cross-cutting code (config, db, errors, middleware, mailer, storage client) lives in a small shared/platform area. Follow the framework's own idioms where they exist.
- Structured JSON logs (one line per request: method, path, status, duration_ms, request_id, user_id when known).
- `Makefile` with the same targets: `dev`, `build`, `migrate`, `test`, `lint`.
- `Dockerfile` (multi-stage, non-root user), `.env.example`, short `README.md` (run, env, layout).
- Unit tests for the pure, security-relevant pieces (token generate/hash/parse, password hash/verify, rate limiter window) and it must pass the whole `contract/` suite.
