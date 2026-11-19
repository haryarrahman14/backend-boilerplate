"""Auth logic (SPEC section 4). Each public function is one unit of work and commits it.

Locking (SPEC "Password writes and locking"): every transaction touches user_tokens -> users -> sessions in that
order, and no DB connection is held while argon2 runs (`await db.commit()` before hashing hands it back). Because
the argon2 verify happens outside any transaction, every write that depends on it is conditional on the hash
that was verified (login's session insert, the login rehash, change-password).
"""

import logging
import uuid
from datetime import timedelta

from sqlalchemy import Text, exists, func, literal, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.features.auth.models import EMAIL_VERIFICATION, PASSWORD_RESET, AuthSession, UserToken
from app.features.auth.schemas import SessionOut, TokensResponse
from app.features.auth.security import (
    DUMMY_HASH,
    encode_access_token,
    hash_password,
    is_reuse,
    make_refresh_token,
    needs_rehash,
    new_secret,
    parse_refresh_token,
    sha256_hex,
    verify_password,
)
from app.features.users.models import User
from app.features.users.schemas import MAX_PASSWORD, UserOut, is_valid_email
from app.platform.config import Settings
from app.platform.cpu import PoolBusy, argon2_pool
from app.platform.errors import ApiError, not_found
from app.platform.mailer import Mailer
from app.platform.validation import path_uuid

log = logging.getLogger("app.auth")

VERIFY_TTL = timedelta(hours=24)
RESET_TTL = timedelta(hours=1)
_NO_SYNC = {"synchronize_session": False}  # bulk UPDATEs: we never rely on identity-map objects afterwards


def _invalid_credentials() -> ApiError:
    return ApiError(401, "invalid_credentials", "Invalid email or password")


def _invalid_token() -> ApiError:
    return ApiError(400, "invalid_token", "This link is invalid or has expired")


def _bad_refresh() -> ApiError:
    return ApiError(401, "unauthorized", "Invalid or expired refresh token")


# ---------- argon2, bounded (platform.cpu) ----------


async def _argon2(fn, *args):
    try:
        return await argon2_pool.run(fn, *args)
    except PoolBusy:
        raise ApiError(429, "rate_limited", "Server busy, try again", headers={"Retry-After": "1"}) from None


async def _hash(password: str) -> str:
    return await _argon2(hash_password, password)


async def _verify(password_hash: str, password: str) -> bool:
    """Never runs argon2 on more than 128 code points: such a password can match no stored hash, so it is
    checked against the dummy hash (same cost as any miss) and fails."""
    if len(password) > MAX_PASSWORD:
        await _argon2(verify_password, DUMMY_HASH, password[:MAX_PASSWORD])
        return False
    return await _argon2(verify_password, password_hash, password)


async def check_password(password_hash: str, password: str) -> bool:
    """argon2 verify with the login rules (bounded pool, nothing over 128 code points), for other features."""
    return await _verify(password_hash, password)


def _tokens(settings: Settings, user: User, session_id: uuid.UUID, secret: str) -> TokensResponse:
    return TokensResponse(
        access_token=encode_access_token(
            settings.jwt_secret.get_secret_value(), user.id, session_id, settings.access_token_ttl_seconds
        ),
        refresh_token=make_refresh_token(session_id, secret),
        expires_in=settings.access_token_ttl_seconds,
        user=UserOut.of(user),
    )


# ---------- one-time tokens ----------


async def _issue_token(db: AsyncSession, user_id: uuid.UUID, kind: str, ttl: timedelta, cooldown: int) -> str | None:
    """New token of `kind`. Must open its transaction. Older tokens stay valid (issuing is anonymous, so
    invalidate-on-issue would let anyone kill the link a user is about to click); consuming one burns the rest.

    Serialised per (user, kind) by an advisory lock so the cooldown cannot be raced. Returns None (issue
    nothing, send nothing) inside the cooldown after the newest token of that kind.
    """
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"{user_id}:{kind}"})
    if cooldown > 0:
        recent = await db.scalar(
            select(UserToken.id)
            .where(
                UserToken.user_id == user_id,
                UserToken.type == kind,
                UserToken.created_at > func.now() - timedelta(seconds=cooldown),
            )
            .limit(1)
        )
        if recent is not None:
            return None
    token = new_secret()
    await db.execute(
        insert(UserToken).values(user_id=user_id, type=kind, token_hash=sha256_hex(token), expires_at=func.now() + ttl)
    )
    return token


async def _consume_token(db: AsyncSession, token: str, kind: str) -> uuid.UUID | None:
    """Single use, atomically; on success the user's other unused tokens of `kind` are burnt in the same
    transaction, so exactly one link of a batch ever works."""
    user_id = await db.scalar(
        update(UserToken)
        .where(
            UserToken.token_hash == sha256_hex(token),
            UserToken.type == kind,
            UserToken.used_at.is_(None),
            UserToken.expires_at > func.now(),
        )
        .values(used_at=func.now())
        .returning(UserToken.user_id)
        .execution_options(**_NO_SYNC)
    )
    if user_id is not None:
        await db.execute(
            update(UserToken)
            .where(UserToken.user_id == user_id, UserToken.type == kind, UserToken.used_at.is_(None))
            .values(used_at=func.now())
            .execution_options(**_NO_SYNC)
        )
    return user_id


# Fixed text plus the link only: anyone can register any address, so nothing a registrant typed (not even the
# name) may reach the mail, or they could send their own text from this domain.
def _verify_mail(settings: Settings, token: str) -> tuple[str, str]:
    link = f"{settings.app_url}/verify-email?token={token}"
    return "Confirm your email address", (
        f"Confirm your email address by opening this link (valid for 24 hours):\n\n{link}\n\n"
        "If you did not create this account, ignore this email and do not use the link.\n"
    )


def _reset_mail(settings: Settings, token: str) -> tuple[str, str]:
    link = f"{settings.app_url}/reset-password?token={token}"
    return "Reset your password", (
        f"Reset your password by opening this link (valid for 1 hour):\n\n{link}\n\n"
        "If you did not ask for this, ignore this email; your password stays the same.\n"
    )


# ---------- register / login / refresh ----------


def login_refusal(user: User, require_verified_email: bool) -> ApiError | None:
    """What a login whose password DID verify is still refused with. Only ever asked after the verify, so a
    403 never tells someone without the password that the account exists or is disabled."""
    if user.disabled_at is not None:
        return ApiError(403, "account_disabled", "This account has been disabled")
    if require_verified_email and user.email_verified_at is None:
        return ApiError(403, "email_not_verified", "Verify your email address before logging in")
    return None


async def register(db: AsyncSession, email: str, password: str, name: str) -> User:
    """Creates the user only; the verification token is issued and mailed in the background, like a resend."""
    password_hash = await _hash(password)  # before touching the DB: no connection held during argon2
    user = await db.scalar(
        insert(User)
        .values(email=email, password_hash=password_hash, name=name)
        .on_conflict_do_nothing(index_elements=[User.email])
        .returning(User)
    )
    if user is None:
        raise ApiError(409, "email_taken", "An account with this email already exists")
    await db.commit()
    return user


async def login(
    db: AsyncSession, settings: Settings, email: str, password: str, user_agent: str | None, ip: str | None
) -> TokensResponse:
    # A malformed email or out-of-policy password can match no account: answer it like any other miss,
    # same message and the same argon2 cost, without asking the database (it also keeps NUL out of queries).
    well_formed = is_valid_email(email) and len(password) <= MAX_PASSWORD
    user = await db.scalar(select(User).where(User.email == email)) if well_formed else None
    await db.commit()  # hand the connection back before argon2
    if user is None:
        await _verify(DUMMY_HASH, password)  # same argon2 cost as a wrong password: no timing oracle
        raise _invalid_credentials()
    verified_hash = user.password_hash
    if not await _verify(verified_hash, password):
        raise _invalid_credentials()
    refusal = login_refusal(user, settings.auth_require_verified_email)  # only after the password verified
    if refusal is not None:
        raise refusal
    if needs_rehash(verified_hash):  # argon2 parameters changed since this hash was made
        new_hash = await _hash(password)
        swapped = await db.scalar(  # compare-and-swap first, then bind the session to the hash now stored
            update(User)
            .where(User.id == user.id, User.password_hash == verified_hash)
            .values(password_hash=new_hash)
            .returning(User.id)
            .execution_options(**_NO_SYNC)
        )
        if swapped is None:
            await db.rollback()
            raise _invalid_credentials()
        verified_hash = new_hash
    secret = new_secret()
    # The session exists only if the password it was verified against is still the stored one. FOR SHARE makes
    # a concurrent reset/change wait for this insert (so its revoke sees the session) or, if the reset came
    # first, makes this insert re-check the new hash and add nothing.
    session_id = await db.scalar(
        insert(AuthSession)
        .from_select(
            ["user_id", "refresh_token_hash", "user_agent", "ip", "expires_at"],
            select(
                User.id,
                literal(sha256_hex(secret), Text),
                literal(user_agent[:255] if user_agent else None, Text),
                literal(ip, Text),
                func.now() + timedelta(seconds=settings.refresh_token_ttl_seconds),
            )
            .where(User.id == user.id, User.password_hash == verified_hash, User.disabled_at.is_(None))
            .with_for_update(read=True),
        )
        .returning(AuthSession.id)
    )
    if session_id is None:  # the password changed while argon2 ran
        await db.rollback()
        raise _invalid_credentials()
    await db.commit()
    return _tokens(settings, user, session_id, secret)


async def refresh(db: AsyncSession, settings: Settings, refresh_token: str) -> TokensResponse:
    parsed = parse_refresh_token(refresh_token)
    if parsed is None:
        raise _bad_refresh()
    session_id, secret = parsed
    old_hash, new = sha256_hex(secret), new_secret()
    # Rotation as one atomic statement: only the current secret of a live session can be exchanged.
    user_id = await db.scalar(
        update(AuthSession)
        .where(
            AuthSession.id == session_id,
            AuthSession.refresh_token_hash == old_hash,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > func.now(),
            # Disabling revokes every session anyway; this also covers a refresh racing the disable.
            exists().where(User.id == AuthSession.user_id, User.disabled_at.is_(None)),
        )
        .values(
            refresh_token_hash=sha256_hex(new),
            previous_refresh_token_hash=old_hash,
            last_used_at=func.now(),
            expires_at=func.now() + timedelta(seconds=settings.refresh_token_ttl_seconds),
        )
        .returning(AuthSession.user_id)
        .execution_options(**_NO_SYNC)
    )
    if user_id is None:
        previous = await db.scalar(
            select(AuthSession.previous_refresh_token_hash).where(
                AuthSession.id == session_id, AuthSession.revoked_at.is_(None), AuthSession.expires_at > func.now()
            )
        )
        if is_reuse(previous, old_hash):
            # The secret really was issued and already rotated: someone else may hold the session.
            revoked = await db.scalar(
                update(AuthSession)
                .where(
                    AuthSession.id == session_id,
                    AuthSession.previous_refresh_token_hash == old_hash,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > func.now(),
                )
                .values(revoked_at=func.now())
                .returning(AuthSession.id)
                .execution_options(**_NO_SYNC)
            )
            await db.commit()
            if revoked is not None:
                log.warning("refresh token reuse detected, session revoked", extra={"session_id": str(session_id)})
        raise _bad_refresh()
    user = await db.scalar(select(User).where(User.id == user_id))  # re-read: role/name/verified may have changed
    await db.commit()
    if user is None:
        raise _bad_refresh()
    return _tokens(settings, user, session_id, new)


# ---------- sessions ----------


async def revoke_session(db: AsyncSession, user_id: uuid.UUID, session_id: uuid.UUID) -> bool:
    revoked = await db.scalar(
        update(AuthSession)
        .where(
            AuthSession.id == session_id,
            AuthSession.user_id == user_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > func.now(),  # active sessions only: expired is 404 like revoked
        )
        .values(revoked_at=func.now())
        .returning(AuthSession.id)
        .execution_options(**_NO_SYNC)
    )
    await db.commit()
    return revoked is not None


async def revoke_all_sessions(db: AsyncSession, user_id: uuid.UUID, keep: uuid.UUID | None = None) -> None:
    """Revokes every live session of the user, except `keep`. Does not commit (callers compose it)."""
    stmt = update(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
    if keep is not None:
        stmt = stmt.where(AuthSession.id != keep)
    await db.execute(stmt.values(revoked_at=func.now()).execution_options(**_NO_SYNC))


async def list_sessions(db: AsyncSession, user_id: uuid.UUID, current: uuid.UUID) -> list[SessionOut]:
    rows = await db.scalars(
        select(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None), AuthSession.expires_at > func.now())
        .order_by(AuthSession.created_at.desc(), AuthSession.id)
    )
    return [
        SessionOut(
            id=s.id,
            user_agent=s.user_agent,
            ip=s.ip,
            created_at=s.created_at,
            last_used_at=s.last_used_at,
            current=s.id == current,
        )
        for s in rows
    ]


async def delete_session(db: AsyncSession, user_id: uuid.UUID, raw_id: str) -> None:
    session_id = path_uuid(raw_id)
    if session_id is None or not await revoke_session(db, user_id, session_id):
        raise not_found("Session")


# ---------- email verification / password ----------


async def verify_email(db: AsyncSession, token: str) -> None:
    """One transaction: consume (and burn the other verification tokens) -> users."""
    user_id = await _consume_token(db, token, EMAIL_VERIFICATION)
    if user_id is None:
        raise _invalid_token()
    await db.execute(
        update(User)
        .where(User.id == user_id, User.email_verified_at.is_(None))
        .values(email_verified_at=func.now(), updated_at=func.now())
        .execution_options(**_NO_SYNC)
    )
    await db.commit()


async def send_verification_if_unverified(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings, mailer: Mailer, email: str
) -> None:
    """Runs in the background, so the 202 takes the same time whether or not the account exists."""
    async with sessionmaker() as db:
        user = await db.scalar(select(User).where(User.email == email))
        await db.commit()  # the issuing transaction starts with the advisory lock
        if user is None or user.email_verified_at is not None or user.disabled_at is not None:
            return
        token = await _issue_token(db, user.id, EMAIL_VERIFICATION, VERIFY_TTL, settings.email_token_cooldown_seconds)
        await db.commit()
    # The session (and its connection) is closed here: no DB connection is held during the SMTP send.
    if token is not None:
        await mailer.send(user.email, *_verify_mail(settings, token))


async def send_reset_if_exists(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings, mailer: Mailer, email: str
) -> None:
    """Runs in the background, so the 202 takes the same time whether or not the account exists."""
    async with sessionmaker() as db:
        user = await db.scalar(select(User).where(User.email == email))
        await db.commit()  # the issuing transaction starts with the advisory lock
        if user is None or user.disabled_at is not None:  # a disabled account gets no recovery mail
            return
        token = await _issue_token(db, user.id, PASSWORD_RESET, RESET_TTL, settings.email_token_cooldown_seconds)
        await db.commit()
    if token is not None:
        await mailer.send(user.email, *_reset_mail(settings, token))


async def reset_password(db: AsyncSession, token: str, password: str) -> None:
    """One transaction, in lock order: consume token + burn the other reset tokens -> users -> sessions."""
    password_hash = await _hash(password)  # before the transaction: no connection held during argon2
    user_id = await _consume_token(db, token, PASSWORD_RESET)
    if user_id is None:
        raise _invalid_token()
    await db.execute(
        update(User)
        .where(User.id == user_id)
        .values(
            password_hash=password_hash,
            email_verified_at=func.coalesce(User.email_verified_at, func.now()),  # the link proved ownership
            updated_at=func.now(),
        )
        .execution_options(**_NO_SYNC)
    )
    await revoke_all_sessions(db, user_id)
    await db.commit()


async def change_password(db: AsyncSession, user: User, session_id: uuid.UUID, current: str, new: str) -> None:
    """`user` was loaded by the auth guard, which already gave its connection back.

    The verify happens outside the transaction, so the write is a compare-and-swap on the hash that was
    verified and on the session still being live. Without it, an attacker with a stolen session and the old
    password could race the victim's reset-password and silently overwrite it. Reset tokens are left alone:
    the mailbox owner must always be able to recover, whoever knows the password.
    """
    verified_hash = user.password_hash
    if not await _verify(verified_hash, current):
        raise _invalid_credentials()
    new_hash = await _hash(new)
    # One transaction, in lock order: users -> sessions.
    swapped = await db.scalar(
        update(User)
        .where(
            User.id == user.id,
            User.password_hash == verified_hash,
            exists().where(
                AuthSession.id == session_id, AuthSession.revoked_at.is_(None), AuthSession.expires_at > func.now()
            ),
        )
        .values(password_hash=new_hash, updated_at=func.now())
        .returning(User.id)
        .execution_options(**_NO_SYNC)
    )
    if swapped is None:  # the password or the session changed underneath this request
        await db.rollback()
        raise _invalid_credentials()
    await revoke_all_sessions(db, user.id, keep=session_id)
    await db.commit()
