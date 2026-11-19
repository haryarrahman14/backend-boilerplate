# Backend Boilerplate

**One auth + storage API. Four implementations. One contract test suite.**

```mermaid
flowchart LR
    M["Mobile app"] -->|"Bearer JWT"| API
    W["Web server (BFF)"] -->|"Bearer JWT"| API

    subgraph API["API — pick one"]
        direction TB
        G["Go · chi · pgx"]
        R["Rust · axum · sqlx"]
        P["Python · FastAPI · SQLAlchemy"]
        N["NestJS · Prisma"]
    end

    API --> PG[("Postgres<br/>auth · storage")]
    API -->|"presign"| S3[("R2 / S3")]
    API --> SMTP["SMTP"]
    M -.->|"file bytes"| S3
    CT["24 contract tests"] -.->|"same suite"| API
```

| | |
|---|---|
| **Auth** | email + password, argon2id, 15-min JWT, rotating refresh token, server-side sessions, email verification, password reset, roles, account deletion, admin suspend / delete |
| **Storage** | direct-to-bucket uploads with presigned URLs (Cloudflare R2 / any S3) |
| **Platform** | validated config, SQL migrations, one error format, request ids, JSON logs, rate limit, health, OpenAPI, Dockerfile |
| **Parity** | same endpoints, env and schema in all four, enforced by [`contract/`](contract/contract.test.mjs) |

```bash
make infra                      # Postgres :5433 · MinIO :9000 · Mailpit :8025
cd go && cp .env.example .env   # or rust / python / nestjs
make migrate && make dev
make contract                   # repo root: the suite against all four
```

---

## Design decisions

| Decision | Because |
|---|---|
| JWT is checked against the session row on **every request** | logout, password reset, role changes, suspension and deletion apply immediately, not after 15 minutes |
| Refresh token is opaque, rotated on every use, stored as SHA-256 | a database leak yields no usable token |
| Reuse detection compares against the **previous** hash only | the session id is public (JWT `sid`); a guessed secret must not log a user out |
| Login inserts the session with `INSERT … SELECT … FOR SHARE` on the verified hash | a login in flight cannot outlive a concurrent password reset |
| `change-password` is compare-and-swap and leaves reset links alone | the mailbox owner can always recover an account |
| One-time tokens are invalidated on **use**, not on issue | an anonymous resend cannot kill the link a user is about to click |
| Presigned `PUT` signs `Content-Type` and `Content-Length` | the bucket rejects any other type or size |
| `X-Forwarded-For` is trusted only from `TRUSTED_PROXY_CIDRS` | the rate-limit key cannot be forged |
| Rate limiter at capacity lets new clients through | a flood of addresses cannot lock everyone out |
| Production refuses weak config | no silent plaintext database, mail or links |
| Tables live in `auth` and `storage` | `public` stays yours |

---

## Standards

| This repo | Follows |
|---|---|
| argon2id, 19 MiB, 2 iterations, 1 thread | [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) minimum configuration |
| minimum 15 characters, no composition rules, up to 128 | [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) §3.1.1.2 |
| refresh token rotation with replay detection | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) §2.2.2, §4.14.2 |
| JWT verification pinned to one algorithm | [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) §3.1 |
| generic login failure | [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |
| same answer for known and unknown emails; single-use, expiring, CSPRNG reset tokens | [OWASP Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) |
| server-side session invalidation on logout and password change | [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| web clients keep tokens on a server behind an `HttpOnly` cookie | [RFC 10017](https://datatracker.ietf.org/doc/html/rfc10017) §6.1 |
| no tokens in `localStorage` | [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), HTML5 Web Storage |
| presigned upload with signed `Content-Type` | [Cloudflare R2 presigned URLs](https://developers.cloudflare.com/r2/api/s3/presigned-urls/) |
| row lock on login (`FOR SHARE`) | [PostgreSQL row-level locks](https://www.postgresql.org/docs/current/explicit-locking.html) §13.3.2 |

**Where it differs**

| | This repo | Standard |
|---|---|---|
| MFA | none | — |
| JWT signing | HS256, one shared secret | asymmetric keys allow rotation and third-party verification |

**How it was checked**

| | |
|---|---|
| Contract suite | 24 black-box tests, identical for all four implementations, including concurrency races |
| Security audit | one structured multi-agent review; 14 findings: 13 fixed, 1 mitigated (anonymous mail flooding is bounded, not eliminated) |
| Test infrastructure | local Postgres, MinIO and Mailpit — not yet a real R2 bucket, TLS Postgres or TLS SMTP |

---

## Auth

| Token | Format | Lifetime | Stored by client in |
|---|---|---|---|
| `access_token` | JWT HS256 (`sub`, `sid`, `exp`) | 15 min | memory |
| `refresh_token` | `<session_id>.<secret>` | 30 days, sliding | Keychain / Keystore, or your server's `HttpOnly` cookie |

### Session lifecycle

```mermaid
flowchart LR
    L(["login"]) --> A["Active"]
    A -->|"refresh"| R["Token rotated"]
    R -->|"same session"| A
    A -->|"revoke"| X["Revoked"]
    A -->|"30 days idle"| E["Expired"]
```

| Revoked by | Scope |
|---|---|
| `POST /auth/logout` | this session |
| `DELETE /auth/sessions/{id}` | one chosen session |
| `POST /auth/logout-all` · password reset | every session |
| password change | every other session |
| a replayed refresh token | that session |
| admin disables or deletes the user · user deletes own account | every session |

### Login → call → refresh

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant D as Postgres
    C->>A: POST /auth/login
    A->>D: verify argon2id, insert session
    A-->>C: access_token + refresh_token
    C->>A: GET /users/me (Bearer)
    A->>D: session live? user role?
    A-->>C: 200
    Note over C,A: access token expires
    C->>A: GET /users/me
    A-->>C: 401
    C->>A: POST /auth/refresh
    A->>D: swap hash atomically
    A-->>C: new access_token + new refresh_token
```

### What the server does with a refresh token

```mermaid
flowchart TD
    A["POST /auth/refresh"] --> B{"matches current hash?"}
    B -- yes --> C["rotate, keep old hash as previous<br/>200"]
    B -- no --> D{"matches previous hash?"}
    D -- yes --> E["replay of a rotated token<br/>revoke session, 401"]
    D -- no --> F["401, nothing revoked"]
```

### What the client does on 401

```mermaid
flowchart TD
    R["401 unauthorized"] --> Q{"refresh already running?"}
    Q -- yes --> W["wait, then retry"]
    Q -- no --> F["POST /auth/refresh"]
    F -- 200 --> S["save new refresh_token<br/>retry once"]
    F -- 401 --> L["clear tokens, login"]
```

One refresh at a time: two parallel refreshes with the same token count as a replay.

### Where the refresh token lives

| Client | Storage |
|---|---|
| iOS · Android · React Native · Flutter | Keychain / Keystore |
| Web with a server (Next.js, Remix) | `HttpOnly; Secure; SameSite=Lax` cookie set by **your** server |
| SPA without a server | memory only |
| Never | `localStorage`, `AsyncStorage` |

```mermaid
sequenceDiagram
    participant B as Browser
    participant W as Your web server
    participant A as API
    B->>W: login form
    W->>A: POST /auth/login
    A-->>W: tokens
    W-->>B: Set-Cookie (HttpOnly)
    B->>W: request + cookie
    W->>A: request + Bearer
    A-->>W: 200
    W-->>B: data
```

### Email verification and password reset

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant M as Mailbox
    C->>A: POST /auth/register or /auth/forgot-password
    A-->>C: 201 or 202
    A->>M: APP_URL/verify-email?token= or /reset-password?token=
    M->>C: user opens the link in your frontend
    C->>A: POST /auth/verify-email or /auth/reset-password
    A-->>C: 204
    Note over A: reset revokes every session
```

---

## Storage

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant S as R2 bucket
    C->>A: POST /files/presign (filename, content_type, size)
    A-->>C: file + upload.url (15 min)
    C->>S: PUT bytes (exact type and size)
    C->>A: POST /files/{id}/complete
    A->>S: HEAD
    A-->>C: file, status uploaded
    C->>A: GET /files/{id}
    A-->>C: file + download_url (15 min)
```

Object key: `users/<user_id>/<file_id>.<ext>`. The client filename never reaches the bucket.

---

## API

Base `/api/v1` · JSON · `snake_case` · 🔒 = `Authorization: Bearer <access_token>`

<details open>
<summary><b>Auth</b> — rate limited per IP</summary>

| | Path | Body | OK | Errors |
|---|---|---|---|---|
| POST | `/auth/register` | `email` `password` (15–128) `name` | 201 `{user}` | 409 `email_taken` · 422 |
| POST | `/auth/login` | `email` `password` | 200 tokens | 401 `invalid_credentials` · 403 `email_not_verified` |
| POST | `/auth/refresh` | `refresh_token` | 200 tokens | 401 |
| POST | `/auth/logout` 🔒 | | 204 | 401 |
| POST | `/auth/logout-all` 🔒 | | 204 | 401 |
| POST | `/auth/verify-email` | `token` | 204 | 400 `invalid_token` |
| POST | `/auth/resend-verification` | `email` | 202 | 422 |
| POST | `/auth/forgot-password` | `email` | 202 | 422 |
| POST | `/auth/reset-password` | `token` `password` | 204 | 400 `invalid_token` · 422 |
| POST | `/auth/change-password` 🔒 | `current_password` `new_password` | 204 | 401 `invalid_credentials` · 422 |
| GET | `/auth/sessions` 🔒 | | 200 `{data:[session]}` | 401 |
| DELETE | `/auth/sessions/{id}` 🔒 | | 204 | 404 |

</details>

<details>
<summary><b>Users</b></summary>

| | Path | Body / query | OK | Errors |
|---|---|---|---|---|
| GET | `/users/me` 🔒 | | 200 `{user}` | 401 |
| PATCH | `/users/me` 🔒 | `name` | 200 `{user}` | 422 |
| DELETE | `/users/me` 🔒 | `password` | 204 | 401 `invalid_credentials` |
| GET | `/admin/users` 🔒 admin | `page` `per_page` | 200 list | 403 `forbidden` |
| PATCH | `/admin/users/{id}` 🔒 admin | `role` `disabled` | 200 `{user}` | 403 · 404 · 422 |
| DELETE | `/admin/users/{id}` 🔒 admin | | 204 | 403 · 404 |

| Action | Effect |
|---|---|
| `disabled: true` | every session revoked, login answers 403 `account_disabled`, data kept |
| `disabled: false` | account can log in again |
| delete | sessions, tokens, file rows and bucket objects removed; the email can register again |

An admin cannot change, disable or delete their own account through `/admin`.

Promote: `UPDATE auth.users SET role='admin' WHERE email='…'`

</details>

<details>
<summary><b>Files</b> — 🔒, owner only</summary>

| | Path | Body / query | OK | Errors |
|---|---|---|---|---|
| POST | `/files/presign` | `filename` `content_type` `size` | 201 `{file, upload}` | 422 |
| POST | `/files/{id}/complete` | | 200 `{file}` | 409 `upload_incomplete` |
| GET | `/files` | `page` `per_page` | 200 list | |
| GET | `/files/{id}` | | 200 `{file, download_url}` | 404 |
| DELETE | `/files/{id}` | | 204 | 404 |

</details>

<details>
<summary><b>Health and docs</b> — no prefix</summary>

| | Path | OK |
|---|---|---|
| GET | `/health` | 200 |
| GET | `/health/ready` | 200 · 503 if the database is down |
| GET | `/docs` `/openapi.json` | Swagger UI · OpenAPI 3 · 404 in production |

</details>

<details>
<summary><b>Objects</b></summary>

```jsonc
// user
{ "id": "uuid", "email": "a@b.co", "name": "Ada", "role": "user|admin", "email_verified": false, "disabled": false, "created_at": "2026-01-02T03:04:05Z" }
// tokens
{ "access_token": "jwt", "refresh_token": "<session_id>.<secret>", "token_type": "Bearer", "expires_in": 900, "user": {} }
// file
{ "id": "uuid", "filename": "a.png", "content_type": "image/png", "size": 123, "status": "pending|uploaded", "created_at": "…", "uploaded_at": null }
// upload
{ "url": "https://…", "method": "PUT", "headers": { "Content-Type": "image/png" }, "expires_in": 900 }
// session
{ "id": "uuid", "user_agent": "…", "ip": "203.0.113.9", "created_at": "…", "last_used_at": "…", "current": true }
// list  ?page=1&per_page=20 (max 100)
{ "data": [], "meta": { "page": 1, "per_page": 20, "total": 57 } }
// error
{ "error": { "code": "validation_error", "message": "…", "details": [ { "field": "email", "message": "…" } ] } }
```

</details>

<details>
<summary><b>Error codes</b></summary>

| HTTP | `code` |
|---|---|
| 400 | `bad_request` · `invalid_token` |
| 401 | `invalid_credentials` · `unauthorized` |
| 403 | `email_not_verified` · `account_disabled` · `forbidden` |
| 404 | `not_found` |
| 409 | `email_taken` · `upload_incomplete` |
| 413 | `payload_too_large` (1 MB) |
| 422 | `validation_error` |
| 429 | `rate_limited` (`Retry-After`) |
| 500 | `internal_error` |

</details>

---

## Database

<img src="docs/erd.svg" alt="ERD: auth.users has many auth.sessions, auth.user_tokens and storage.files" width="980">

| Schema | Tables | Migrations |
|---|---|---|
| `auth` | `users` · `sessions` · `user_tokens` | goose · sqlx · Alembic · Prisma |
| `storage` | `files` | |
| `public` | yours | |

Deleting a user through the API removes sessions, tokens, file rows and bucket objects. A raw `DELETE FROM auth.users` cascades the rows but leaves bucket objects.

---

## Env

Same names in all four.

<details open>
<summary><b>Required</b></summary>

| Var | Example |
|---|---|
| `DATABASE_URL` | `postgres://user:pass@host:5432/db?sslmode=verify-full` |
| `JWT_SECRET` | 32+ random characters |
| `S3_ENDPOINT` | `https://<account_id>.r2.cloudflarestorage.com` |
| `S3_ACCESS_KEY_ID` · `S3_SECRET_ACCESS_KEY` · `S3_BUCKET` | R2 API token and bucket |

</details>

<details>
<summary><b>Optional</b></summary>

| Var | Default | |
|---|---|---|
| `PORT` | `8080` | |
| `APP_ENV` | `development` | or `production` |
| `APP_URL` | `http://localhost:3000` | frontend, base of email links |
| `CORS_ORIGINS` | `http://localhost:3000` | comma separated, no `*` |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` | |
| `AUTH_REQUIRE_VERIFIED_EMAIL` | `false` | |
| `RATE_LIMIT_AUTH_PER_MINUTE` | `10` | per IP |
| `EMAIL_TOKEN_COOLDOWN_SECONDS` | `60` | per user, per mail type |
| `TRUSTED_PROXY_HOPS` | `0` | proxies in front of the app |
| `TRUSTED_PROXY_CIDRS` | | required when hops > 0 |
| `SMTP_HOST` | | empty = log the mail |
| `SMTP_PORT` | `1025` | `465` TLS · others STARTTLS |
| `SMTP_USER` · `SMTP_PASS` | | |
| `MAIL_FROM` | `no-reply@example.com` | |
| `S3_REGION` | `auto` | |
| `UPLOAD_MAX_BYTES` | `10485760` | |
| `UPLOAD_ALLOWED_TYPES` | `image/jpeg,image/png,image/webp,application/pdf` | |

</details>

**Production will not start if** `JWT_SECRET` is short or the example value · `SMTP_HOST` is empty · `DATABASE_URL` has no `sslmode` · `APP_URL` or `S3_ENDPOINT` is not `https` · proxy hops are set without CIDRs.

R2 bucket CORS: allow `PUT` with `Content-Type` from your frontend origin.

---

## Not included

OAuth · 2FA · email change · cookie auth · teams / organisations · fine-grained permissions · distributed rate limiter · file quota

Full rules: [SPEC.md](SPEC.md)
