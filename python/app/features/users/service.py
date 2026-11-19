"""Account deletion and admin user management (SPEC section 5, "Disabling" / "Deleting a user").

Lock order as everywhere: users -> sessions. No DB connection is held during argon2 or bucket calls.
"""

import logging
import uuid

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.features.auth.service import check_password, revoke_all_sessions
from app.features.files.models import File
from app.features.users.models import User
from app.platform.errors import ApiError, not_found
from app.platform.storage import Storage

log = logging.getLogger("app.users")
FILE_PAGE = 1000  # bucket keys per page: one DeleteObjects call


def forbidden(message: str) -> ApiError:
    return ApiError(403, "forbidden", message)


def self_change_refusal(actor_id: uuid.UUID, target: User, role: str | None, disabled: bool | None) -> ApiError | None:
    """An admin may not demote or disable themselves (the last admin could lock everyone out). Setting a
    value to what it already is (role=admin, disabled=false on oneself) is not a change and is allowed."""
    if actor_id != target.id:
        return None
    if role is not None and role != target.role:
        return forbidden("You cannot change your own role")
    if disabled:
        return forbidden("You cannot disable your own account")
    return None


async def admin_update(
    db: AsyncSession, actor_id: uuid.UUID, target_id: uuid.UUID, role: str | None, disabled: bool | None
) -> User:
    target = await db.scalar(select(User).where(User.id == target_id).with_for_update())
    if target is None:
        raise not_found("User")
    refusal = self_change_refusal(actor_id, target, role, disabled)
    if refusal is not None:
        raise refusal
    values = {}
    if role is not None:
        values["role"] = role  # no session change needed: the guard reads the role from the DB every request
    if disabled is True:
        values["disabled_at"] = func.coalesce(User.disabled_at, func.now())  # keep the original time
    elif disabled is False:
        values["disabled_at"] = None
    if not values:
        await db.commit()
        return target  # no fields: unchanged
    updated = await db.scalar(
        update(User)
        .where(User.id == target_id)
        .values(**values, updated_at=func.now())
        .returning(User)
        .execution_options(populate_existing=True)
    )
    if disabled:
        await revoke_all_sessions(db, target_id)  # same transaction: access stops with the commit
    await db.commit()
    return updated


async def delete_me(db: AsyncSession, storage: Storage, user: User, password: str) -> None:
    verified_hash = user.password_hash  # the guard already gave its connection back
    if not await check_password(verified_hash, password):
        raise ApiError(401, "invalid_credentials", "Invalid email or password")
    await delete_user(db, storage, user.id, verified_hash=verified_hash)


async def delete_user(db: AsyncSession, storage: Storage, user_id: uuid.UUID, verified_hash: str | None = None) -> None:
    """1. revoke every session (committed, so access stops even if a later step fails); 2. delete the user's
    bucket objects; 3. delete the users row (sessions, tokens, file rows cascade). A bucket failure raises
    (500) with the user row still there, so the call can simply be repeated.

    Ceiling: an upload URL issued before this can still create an object for up to 15 minutes after it; that
    orphan is accepted, and a bucket lifecycle rule on `users/` cleans it up.
    """
    # Lock the row first (users -> sessions). With `verified_hash`, the password must not have changed since
    # it was verified (same compare-and-swap reason as change-password).
    condition = [User.id == user_id]
    if verified_hash is not None:
        condition.append(User.password_hash == verified_hash)
    locked = await db.scalar(select(User.id).where(*condition).with_for_update())
    if locked is None:
        await db.rollback()
        if verified_hash is not None:
            raise ApiError(401, "invalid_credentials", "Invalid email or password")
        raise not_found("User")
    await revoke_all_sessions(db, user_id)
    await db.commit()

    after: uuid.UUID | None = None
    while True:  # keyset pages by id, every object whatever its status (pending ones may have bytes too)
        query = select(File.id, File.key).where(File.user_id == user_id).order_by(File.id).limit(FILE_PAGE)
        if after is not None:
            query = query.where(File.id > after)
        page = (await db.execute(query)).all()
        await db.commit()  # no DB connection held during the bucket call
        if not page:
            break
        await storage.delete_many([row.key for row in page])
        after = page[-1].id

    await db.execute(delete(User).where(User.id == user_id))
    await db.commit()
    log.info("user deleted", extra={"deleted_user_id": str(user_id)})
