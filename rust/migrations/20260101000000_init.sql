-- Boilerplate tables live outside `public`, which is left to the application built on top
-- (only sqlx's own _sqlx_migrations table stays there). Every statement in the code is
-- schema-qualified; nothing relies on search_path.
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
    user_id                     uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    refresh_token_hash          text NOT NULL,
    -- The hash this one replaced: reuse detection revokes only on a token that was really issued.
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
    user_id    uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    type       text NOT NULL CHECK (type IN ('email_verification', 'password_reset')),
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_tokens_user_id_type_idx ON auth.user_tokens (user_id, type);

CREATE TABLE storage.files (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    key          text NOT NULL UNIQUE,
    filename     text NOT NULL,
    content_type text NOT NULL,
    size         bigint NOT NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'uploaded')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    uploaded_at  timestamptz
);
CREATE INDEX files_user_id_created_at_idx ON storage.files (user_id, created_at DESC);
