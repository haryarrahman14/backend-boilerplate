"""Initial schema (SPEC section 3): auth.{users,sessions,user_tokens} and storage.files.

`public` is left empty for the application built on top; only alembic_version lives there.

Revision ID: 0001
Revises:
Create Date: 2026-11-19
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# Plain SQL so the schema reads exactly like the SPEC; every name is schema-qualified (no search_path).
UPGRADE = """
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS storage;
CREATE TABLE auth.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  name text NOT NULL,
  role text NOT NULL DEFAULT 'user' CONSTRAINT users_role_check CHECK (role IN ('user','admin')),
  email_verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE auth.sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  refresh_token_hash text NOT NULL,
  previous_refresh_token_hash text,
  user_agent text,
  ip text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX sessions_user_id_idx ON auth.sessions (user_id);
CREATE TABLE auth.user_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  type text NOT NULL CONSTRAINT user_tokens_type_check CHECK (type IN ('email_verification','password_reset')),
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_tokens_user_id_type_idx ON auth.user_tokens (user_id, type);
CREATE TABLE storage.files (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  key text NOT NULL UNIQUE,
  filename text NOT NULL,
  content_type text NOT NULL,
  size bigint NOT NULL,
  status text NOT NULL DEFAULT 'pending' CONSTRAINT files_status_check CHECK (status IN ('pending','uploaded')),
  created_at timestamptz NOT NULL DEFAULT now(),
  uploaded_at timestamptz
);
CREATE INDEX files_user_id_created_at_idx ON storage.files (user_id, created_at DESC)
"""

# RESTRICT, not CASCADE: if the application built on top put its own objects in these schemas, the downgrade
# stops instead of silently dropping them.
DOWNGRADE = """
DROP TABLE IF EXISTS storage.files, auth.user_tokens, auth.sessions, auth.users;
DROP SCHEMA IF EXISTS storage RESTRICT;
DROP SCHEMA IF EXISTS auth RESTRICT
"""


def _run(sql: str) -> None:
    for statement in filter(str.strip, sql.split(";")):  # asyncpg runs one statement per call
        op.execute(statement)


def upgrade() -> None:
    _run(UPGRADE)


def downgrade() -> None:
    _run(DOWNGRADE)
