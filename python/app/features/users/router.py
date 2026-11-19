from fastapi import APIRouter, Depends
from sqlalchemy import func, select, update

from app.features.auth.deps import CurrentUser, require_role
from app.features.users.models import User
from app.features.users.schemas import UpdateMeRequest, UserOut, UserPage, UserResponse
from app.platform.db import Db
from app.platform.errors import ERROR_RESPONSES
from app.platform.pagination import PageMeta, Pagination

router = APIRouter(tags=["users"], responses=ERROR_RESPONSES)


@router.get("/users/me", response_model=UserResponse)
async def get_me(user: CurrentUser) -> UserResponse:
    return UserResponse(user=UserOut.of(user))


@router.patch("/users/me", response_model=UserResponse)
async def update_me(body: UpdateMeRequest, user: CurrentUser, db: Db) -> UserResponse:
    if body.name is not None:
        user = await db.scalar(
            update(User)
            .where(User.id == user.id)
            .values(name=body.name, updated_at=func.now())
            .returning(User)
            .execution_options(populate_existing=True)
        )
        await db.commit()
    return UserResponse(user=UserOut.of(user))


@router.get("/admin/users", response_model=UserPage, dependencies=[Depends(require_role("admin"))])
async def list_users(page: Pagination, db: Db) -> UserPage:
    total = await db.scalar(select(func.count()).select_from(User))
    users = await db.scalars(
        select(User).order_by(User.created_at.desc(), User.id).offset(page.offset).limit(page.per_page)
    )
    return UserPage(
        data=[UserOut.of(u) for u in users], meta=PageMeta(page=page.page, per_page=page.per_page, total=total)
    )
