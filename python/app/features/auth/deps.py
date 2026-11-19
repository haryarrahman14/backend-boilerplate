"""The auth guard: verify the JWT, then load session + user in ONE query, so revocation is immediate
and `role` always comes from the database, never from the token."""

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select

from app.features.auth.models import AuthSession
from app.features.auth.security import decode_access_token
from app.features.users.models import User
from app.platform.db import Db
from app.platform.errors import ApiError, unauthorized

_bearer = HTTPBearer(auto_error=False, description="Access token from /auth/login or /auth/refresh")


@dataclass
class Principal:
    user: User
    session_id: uuid.UUID


async def current_principal(
    request: Request,
    db: Db,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    # HTTPBearer returns None unless the header is `Bearer <token>`; the scheme is matched case-insensitively.
    if credentials is None or not credentials.credentials:
        raise unauthorized()
    claims = decode_access_token(request.app.state.settings.jwt_secret.get_secret_value(), credentials.credentials)
    if claims is None:
        raise unauthorized()
    user = await db.scalar(
        select(User)
        .join(AuthSession, AuthSession.user_id == User.id)
        .where(
            AuthSession.id == claims.session_id,
            AuthSession.user_id == claims.user_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > func.now(),
            User.disabled_at.is_(None),  # a disabled account is locked out at once, whatever sessions remain
        )
    )
    await db.commit()  # end the read so the connection goes back to the pool (handlers may run argon2 next)
    if user is None:
        raise unauthorized()
    request.scope["state"]["ctx"]["user_id"] = str(user.id)  # shows up on this request's log lines
    return Principal(user, claims.session_id)


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


async def current_user(principal: CurrentPrincipal) -> User:
    return principal.user


CurrentUser = Annotated[User, Depends(current_user)]


def require_role(*roles: str):
    async def check(user: CurrentUser) -> User:
        if user.role not in roles:
            raise ApiError(403, "forbidden", "You do not have access to this resource")
        return user

    check.required_roles = frozenset(roles)  # lets tests find the guard on the real route table
    return check
