-- +goose Up
-- Boilerplate tables live in their own schemas; `public` is left to the application built on top
-- (only goose's own goose_db_version table stays there).
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS storage;

CREATE TABLE auth.users (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email             text NOT NULL UNIQUE,
    password_hash     text NOT NULL,
    name              text NOT NULL,
    role              text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    email_verified_at timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth.sessions (
    id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                     uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    refresh_token_hash          text NOT NULL,
    -- the hash the current one replaced; only it may trigger reuse revocation (SPEC 4)
    previous_refresh_token_hash text,
    user_agent                  text,
    ip                          text,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    last_used_at                timestamptz NOT NULL DEFAULT now(),
    expires_at                  timestamptz NOT NULL,
    revoked_at                  timestamptz
);
CREATE INDEX sessions_user_id_idx ON auth.sessions (user_id);

CREATE TABLE auth.user_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    type       text NOT NULL CHECK (type IN ('email_verification', 'password_reset')),
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_tokens_user_id_type_idx ON auth.user_tokens (user_id, type);

CREATE TABLE storage.files (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    key          text NOT NULL UNIQUE,
    filename     text NOT NULL,
    content_type text NOT NULL,
    size         bigint NOT NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'uploaded')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    uploaded_at  timestamptz
);
CREATE INDEX files_user_id_created_at_idx ON storage.files (user_id, created_at DESC);

-- +goose Down
DROP TABLE storage.files;
DROP TABLE auth.user_tokens;
DROP TABLE auth.sessions;
DROP TABLE auth.users;
-- RESTRICT (the default): refuses to drop a schema the application has added its own objects to.
DROP SCHEMA storage;
DROP SCHEMA auth;
