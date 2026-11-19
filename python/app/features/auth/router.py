from fastapi import APIRouter, Request, Response, status

from app.features.auth import service
from app.features.auth.deps import CurrentPrincipal
from app.features.auth.schemas import (
    ChangePasswordRequest,
    EmailRequest,
    LoginRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    SessionList,
    TokenRequest,
    TokensResponse,
)
from app.features.users.schemas import UserOut, UserResponse
from app.platform.db import Db
from app.platform.errors import ERROR_RESPONSES
from app.platform.middleware import client_ip
from app.platform.tasks import spawn

# Rate limiting for every /auth/* route is applied by platform.middleware.RateLimit.
router = APIRouter(prefix="/auth", tags=["auth"], responses=ERROR_RESPONSES)

RESEND_MESSAGE = "If that account exists and is not verified yet, a verification email is on its way."
FORGOT_MESSAGE = "If that account exists, a password reset email is on its way."
NO_CONTENT = {"status_code": status.HTTP_204_NO_CONTENT, "response_class": Response}


@router.post("/register", status_code=201, response_model=UserResponse)
async def register(body: RegisterRequest, request: Request, db: Db) -> UserResponse:
    state = request.app.state
    user = await service.register(db, body.email, body.password, body.name)
    spawn(
        service.send_verification_if_unverified(state.sessionmaker, state.settings, state.mailer, user.email),
        "mail:verify",
    )
    return UserResponse(user=UserOut.of(user))


@router.post("/login", response_model=TokensResponse)
async def login(body: LoginRequest, request: Request, db: Db) -> TokensResponse:
    settings = request.app.state.settings
    return await service.login(
        db,
        settings,
        body.email,
        body.password,
        request.headers.get("user-agent"),
        client_ip(request.scope, settings.trusted_proxy_hops, settings.trusted_proxy_networks),
    )


@router.post("/refresh", response_model=TokensResponse)
async def refresh(body: RefreshRequest, request: Request, db: Db) -> TokensResponse:
    return await service.refresh(db, request.app.state.settings, body.refresh_token)


@router.post("/logout", **NO_CONTENT)
async def logout(principal: CurrentPrincipal, db: Db) -> None:
    await service.revoke_session(db, principal.user.id, principal.session_id)


@router.post("/logout-all", **NO_CONTENT)
async def logout_all(principal: CurrentPrincipal, db: Db) -> None:
    await service.revoke_all_sessions(db, principal.user.id)
    await db.commit()


@router.post("/verify-email", **NO_CONTENT)
async def verify_email(body: TokenRequest, db: Db) -> None:
    await service.verify_email(db, body.token)


@router.post("/resend-verification", status_code=202, response_model=MessageResponse)
async def resend_verification(body: EmailRequest, request: Request) -> MessageResponse:
    state = request.app.state
    spawn(
        service.send_verification_if_unverified(state.sessionmaker, state.settings, state.mailer, body.email),
        "mail:resend",
    )
    return MessageResponse(message=RESEND_MESSAGE)


@router.post("/forgot-password", status_code=202, response_model=MessageResponse)
async def forgot_password(body: EmailRequest, request: Request) -> MessageResponse:
    state = request.app.state
    spawn(service.send_reset_if_exists(state.sessionmaker, state.settings, state.mailer, body.email), "mail:reset")
    return MessageResponse(message=FORGOT_MESSAGE)


@router.post("/reset-password", **NO_CONTENT)
async def reset_password(body: ResetPasswordRequest, db: Db) -> None:
    # `body` (including the password rules) is validated before the token is touched.
    await service.reset_password(db, body.token, body.password)


@router.post("/change-password", **NO_CONTENT)
async def change_password(body: ChangePasswordRequest, principal: CurrentPrincipal, db: Db) -> None:
    await service.change_password(db, principal.user, principal.session_id, body.current_password, body.new_password)


@router.get("/sessions", response_model=SessionList)
async def list_sessions(principal: CurrentPrincipal, db: Db) -> SessionList:
    return SessionList(data=await service.list_sessions(db, principal.user.id, principal.session_id))


@router.delete("/sessions/{session_id}", **NO_CONTENT)
async def delete_session(session_id: str, principal: CurrentPrincipal, db: Db) -> None:
    # `str`, not UUID: a malformed id is a 404 like any unknown one, not a 422.
    await service.delete_session(db, principal.user.id, session_id)
