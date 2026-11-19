import re
import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, StringConstraints

from app.features.users.models import User
from app.platform.pagination import PageMeta
from app.platform.validation import RequestBody, no_control_chars

# SPEC section 4, exactly, ASCII only. Nothing a mail library could read as `Name <other@address>`, no quotes,
# no spaces, no control characters. Applied after trim + lowercase.
_EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(\.[a-z0-9-]+)+", re.ASCII)


def is_valid_email(value: str) -> bool:
    """`value` already normalised (trimmed + lowercased). Lengths are code points (Python `len`)."""
    return len(value) <= 254 and _EMAIL.fullmatch(value) is not None


def _check_email(value: str) -> str:
    if not is_valid_email(value):
        raise ValueError("must be a valid email address")
    return value


# Trimmed + lowercased *before* validation, storage and lookup.
Email = Annotated[
    str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=254), AfterValidator(_check_email)
]
Name = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100), AfterValidator(no_control_chars)
]
# Never trimmed. Bounded on both sides (code points); no composition rules.
MIN_PASSWORD, MAX_PASSWORD = 15, 128
Password = Annotated[str, StringConstraints(min_length=MIN_PASSWORD, max_length=MAX_PASSWORD)]


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    name: str
    role: str
    email_verified: bool
    created_at: datetime

    @classmethod
    def of(cls, user: User) -> "UserOut":
        return cls(
            id=user.id,
            email=user.email,
            name=user.name,
            role=user.role,
            email_verified=user.email_verified_at is not None,
            created_at=user.created_at,
        )


class UserResponse(BaseModel):
    user: UserOut


class UpdateMeRequest(RequestBody):
    name: Name | None = None  # only `name` is writable; role/email in the body are ignored


class UserPage(BaseModel):
    data: list[UserOut]
    meta: PageMeta
