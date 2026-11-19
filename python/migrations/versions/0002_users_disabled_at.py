"""auth.users.disabled_at: null = active; set by an admin (SPEC sections 3 and 5).

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-19
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE auth.users ADD COLUMN disabled_at timestamptz")


def downgrade() -> None:
    op.execute("ALTER TABLE auth.users DROP COLUMN disabled_at")
