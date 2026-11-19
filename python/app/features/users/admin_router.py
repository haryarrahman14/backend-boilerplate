"""Admin user management. Every route here is admin-only because the ROUTER carries the role check, so a new
`/admin/...` endpoint cannot be added without it (tests/test_admin_guard.py also walks the route table).

The router-level dependency runs before each route's own parameters, so a non-admin gets 403 before the id,
query or body is validated (never a 422 or 404 that describes the route); 401 without a valid token comes from
the auth guard inside it, and the role is read from the database on every request.
"""

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select

from app.features.auth.deps import CurrentUser, require_role
from app.features.users import service
from app.features.users.models import User
from app.features.users.schemas import AdminUpdateRequest, UserOut, UserPage, UserResponse
from app.platform.db import Db
from app.platform.errors import ERROR_RESPONSES, not_found
from app.platform.pagination import PageMeta, Pagination
from app.platform.validation import path_uuid

admin_router = APIRouter(
    prefix="/admin", tags=["admin"], dependencies=[Depends(require_role("admin"))], responses=ERROR_RESPONSES
)


@admin_router.get("/users", response_model=UserPage)
async def list_users(page: Pagination, db: Db) -> UserPage:
    total = await db.scalar(select(func.count()).select_from(User))
    users = await db.scalars(
        select(User).order_by(User.created_at.desc(), User.id).offset(page.offset).limit(page.per_page)
    )
    return UserPage(
        data=[UserOut.of(u) for u in users], meta=PageMeta(page=page.page, per_page=page.per_page, total=total)
    )


@admin_router.patch("/users/{user_id}", response_model=UserResponse)
async def admin_update_user(user_id: str, body: AdminUpdateRequest, admin: CurrentUser, db: Db) -> UserResponse:
    target_id = path_uuid(user_id)
    if target_id is None:
        raise not_found("User")
    user = await service.admin_update(db, admin.id, target_id, body.role, body.disabled)
    return UserResponse(user=UserOut.of(user))


@admin_router.delete("/users/{user_id}", status_code=204, response_class=Response)
async def admin_delete_user(user_id: str, request: Request, admin: CurrentUser, db: Db) -> None:
    target_id = path_uuid(user_id)
    if target_id is None:
        raise not_found("User")
    if target_id == admin.id:
        raise service.forbidden("Use DELETE /users/me to delete your own account")
    await service.delete_user(db, request.app.state.storage, target_id)
