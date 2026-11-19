import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field, StringConstraints

from app.features.files.models import File
from app.platform.pagination import PageMeta
from app.platform.validation import RequestBody, no_control_chars


class PresignRequest(RequestBody):
    # Kept verbatim (never trimmed, never in the key); control chars rejected, Postgres cannot store NUL.
    filename: Annotated[str, StringConstraints(min_length=1, max_length=255), AfterValidator(no_control_chars)]
    content_type: Annotated[str, StringConstraints(min_length=1, max_length=255)]  # must be in UPLOAD_ALLOWED_TYPES
    size: Annotated[int, Field(strict=True, ge=1)]  # allowed types / max size are checked against config


class FileOut(BaseModel):
    id: uuid.UUID
    filename: str
    content_type: str
    size: int
    status: str
    created_at: datetime
    uploaded_at: datetime | None

    @classmethod
    def of(cls, f: File) -> "FileOut":
        return cls(
            id=f.id,
            filename=f.filename,
            content_type=f.content_type,
            size=f.size,
            status=f.status,
            created_at=f.created_at,
            uploaded_at=f.uploaded_at,
        )


class UploadInstructions(BaseModel):
    url: str
    method: Literal["PUT"] = "PUT"
    headers: dict[str, str]
    expires_in: int


class PresignResponse(BaseModel):
    file: FileOut
    upload: UploadInstructions


class FileResponse(BaseModel):
    file: FileOut


class FileDetail(BaseModel):
    file: FileOut
    download_url: str | None


class FilePage(BaseModel):
    data: list[FileOut]
    meta: PageMeta
