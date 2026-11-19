import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, StringConstraints

from app.features.users.schemas import Email, Name, Password, UserOut
from app.platform.validation import RequestBody

# Login and current_password check presence only: a malformed email or out-of-policy password is a plain
# 401 invalid_credentials (see service.login), never a 422 that hints at the rules.
PresentEmail = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, min_length=1)]
AnyPassword = Annotated[str, StringConstraints(min_length=1)]
# Any non-empty string: a malformed/unknown token is a 400 invalid_token / 401 unauthorized, not a 422.
Token = Annotated[str, StringConstraints(min_length=1)]


class RegisterRequest(RequestBody):
    email: Email
    password: Password
    name: Name


class LoginRequest(RequestBody):
    email: PresentEmail
    password: AnyPassword


class RefreshRequest(RequestBody):
    refresh_token: Token


class TokenRequest(RequestBody):
    token: Token


class EmailRequest(RequestBody):
    email: Email


class ResetPasswordRequest(RequestBody):
    token: Token
    password: Password


class ChangePasswordRequest(RequestBody):
    current_password: AnyPassword
    new_password: Password


class TokensResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105
    expires_in: int
    user: UserOut


class MessageResponse(BaseModel):
    message: str


class SessionOut(BaseModel):
    id: uuid.UUID
    user_agent: str | None
    ip: str | None
    created_at: datetime
    last_used_at: datetime
    current: bool


class SessionList(BaseModel):
    data: list[SessionOut]
