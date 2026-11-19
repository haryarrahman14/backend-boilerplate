import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.platform.db import Base


class AuthSession(Base):
    """A login on one device; the refresh token is `<id>.<secret>` and only sha256(secret) is stored."""

    __tablename__ = "sessions"
    __table_args__ = (Index("sessions_user_id_idx", "user_id"), {"schema": "auth"})

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("auth.users.id", ondelete="CASCADE"))
    refresh_token_hash: Mapped[str] = mapped_column(Text)
    previous_refresh_token_hash: Mapped[str | None] = mapped_column(Text)  # the hash the current one replaced
    user_agent: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


EMAIL_VERIFICATION = "email_verification"
PASSWORD_RESET = "password_reset"  # noqa: S105  (a token type, not a secret)


class UserToken(Base):
    """One-time email verification / password reset token; only sha256(token) is stored."""

    __tablename__ = "user_tokens"
    __table_args__ = (
        CheckConstraint("type in ('email_verification','password_reset')", name="user_tokens_type_check"),
        Index("user_tokens_user_id_type_idx", "user_id", "type"),
        {"schema": "auth"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("auth.users.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
