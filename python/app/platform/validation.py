"""Input rules shared by every feature: request-body base model, canonical path ids, control characters."""

import re
import uuid
from typing import Any

from pydantic import BaseModel, field_validator

_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def path_uuid(raw: str) -> uuid.UUID | None:
    """Only the canonical 36-char hyphenated form; uuid.UUID alone would also take braces, `urn:` and no dashes."""
    return uuid.UUID(raw) if _UUID.fullmatch(raw) else None


def no_control_chars(value: str) -> str:
    if _CONTROL.search(value):
        raise ValueError("must not contain control characters")
    return value


class RequestBody(BaseModel):
    """Base of every JSON body. JSON can carry lone surrogates (`"\\ud800"`), which Python accepts as str but
    which cannot be encoded, hashed or stored: reject them as a 422 instead of failing later with a 500."""

    @field_validator("*", mode="before")
    @classmethod
    def _well_formed_unicode(cls, value: Any) -> Any:
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError("must be well-formed Unicode") from None
        return value
