"""The signed-in user's own account. Admin routes live in admin_router.py, guarded at the router level."""

from fastapi import APIRouter, Request, Response
from sqlalchemy import func, update

from app.features.auth.deps import CurrentUser
from app.features.users import service
from app.features.users.models import User
from app.features.users.schemas import DeleteMeRequest, UpdateMeRequest, UserOut, UserResponse
from app.platform.db import Db
from app.platform.errors import ERROR_RESPONSES

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


@router.delete("/users/me", status_code=204, response_class=Response)
async def delete_me(body: DeleteMeRequest, request: Request, user: CurrentUser, db: Db) -> None:
    await service.delete_me(db, request.app.state.storage, user, body.password)
