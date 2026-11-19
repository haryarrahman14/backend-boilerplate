"""Direct-to-bucket uploads: the API only signs URLs and tracks metadata; bytes never pass through it."""

import os
import re
import uuid

from fastapi import APIRouter, Request, Response, status
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.features.auth.deps import CurrentUser
from app.features.files.models import File
from app.features.files.schemas import (
    FileDetail,
    FileOut,
    FilePage,
    FileResponse,
    PresignRequest,
    PresignResponse,
    UploadInstructions,
)
from app.platform.db import Db
from app.platform.errors import ERROR_RESPONSES, ApiError, not_found, validation_error
from app.platform.pagination import PageMeta, Pagination
from app.platform.storage import Storage
from app.platform.validation import path_uuid

router = APIRouter(prefix="/files", tags=["files"], responses=ERROR_RESPONSES)

URL_TTL = 900
_EXT = re.compile(r"^\.[a-z0-9]{1,10}$")


def object_key(user_id: uuid.UUID, file_id: uuid.UUID, filename: str) -> str:
    """`users/<user_id>/<file_id>[.ext]`: the client's filename never reaches the key, only a safe extension."""
    ext = os.path.splitext(filename)[1].lower()
    return f"users/{user_id}/{file_id}" + (ext if _EXT.match(ext) else "")


async def _owned(db: AsyncSession, user_id: uuid.UUID, raw_id: str) -> File:
    """Someone else's file and a malformed id look exactly like a missing one."""
    file_id = path_uuid(raw_id)
    if file_id is None:
        raise not_found("File")
    file = await db.scalar(select(File).where(File.id == file_id, File.user_id == user_id))
    if file is None:
        raise not_found("File")
    return file


def _storage(request: Request) -> Storage:
    return request.app.state.storage


@router.post("/presign", status_code=201, response_model=PresignResponse)
async def presign(body: PresignRequest, request: Request, user: CurrentUser, db: Db) -> PresignResponse:
    settings = request.app.state.settings
    if body.content_type not in settings.allowed_types:
        raise validation_error("content_type", f"must be one of: {', '.join(sorted(settings.allowed_types))}")
    if body.size > settings.upload_max_bytes:
        raise validation_error("size", f"must be at most {settings.upload_max_bytes} bytes")
    file_id = uuid.uuid4()
    key = object_key(user.id, file_id, body.filename)
    file = await db.scalar(
        insert(File)
        .values(
            id=file_id, user_id=user.id, key=key, filename=body.filename, content_type=body.content_type, size=body.size
        )
        .returning(File)
    )
    await db.commit()
    url = _storage(request).presign_put(key, body.content_type, body.size, URL_TTL)
    return PresignResponse(
        file=FileOut.of(file),
        upload=UploadInstructions(url=url, headers={"Content-Type": body.content_type}, expires_in=URL_TTL),
    )


@router.post("/{file_id}/complete", response_model=FileResponse)
async def complete(file_id: str, request: Request, user: CurrentUser, db: Db) -> FileResponse:
    file = await _owned(db, user.id, file_id)
    if file.status == "uploaded":
        return FileResponse(file=FileOut.of(file))  # idempotent
    storage, max_bytes = _storage(request), request.app.state.settings.upload_max_bytes
    await db.commit()  # no connection held during the S3 round trip
    size = await storage.object_size(file.key)
    if size is None:
        raise ApiError(409, "upload_incomplete", "The file has not been uploaded yet")
    if size > max_bytes:
        # Defence in depth: the signed Content-Length already pins the size (UPLOAD_MAX_BYTES may have shrunk).
        await storage.delete(file.key)
        await db.execute(delete(File).where(File.id == file.id))
        await db.commit()
        raise validation_error("size", f"uploaded object is larger than {max_bytes} bytes")
    updated = await db.scalar(
        update(File)
        .where(File.id == file.id, File.status == "pending")
        .values(status="uploaded", size=size, uploaded_at=func.now())
        .returning(File)
        .execution_options(populate_existing=True)
    )
    await db.commit()
    if updated is None:  # a concurrent complete won the race, or a delete did
        updated = await db.scalar(select(File).where(File.id == file.id).execution_options(populate_existing=True))
        if updated is None:
            raise not_found("File")
    return FileResponse(file=FileOut.of(updated))


@router.get("", response_model=FilePage)
async def list_files(page: Pagination, user: CurrentUser, db: Db) -> FilePage:
    total = await db.scalar(select(func.count()).select_from(File).where(File.user_id == user.id))
    files = await db.scalars(
        select(File)
        .where(File.user_id == user.id)
        .order_by(File.created_at.desc(), File.id)
        .offset(page.offset)
        .limit(page.per_page)
    )
    return FilePage(
        data=[FileOut.of(f) for f in files], meta=PageMeta(page=page.page, per_page=page.per_page, total=total)
    )


@router.get("/{file_id}", response_model=FileDetail)
async def get_file(file_id: str, request: Request, user: CurrentUser, db: Db) -> FileDetail:
    file = await _owned(db, user.id, file_id)
    url = _storage(request).presign_get(file.key, URL_TTL) if file.status == "uploaded" else None
    return FileDetail(file=FileOut.of(file), download_url=url)


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_file(file_id: str, request: Request, user: CurrentUser, db: Db) -> None:
    file = await _owned(db, user.id, file_id)
    await db.commit()  # no connection held during the S3 round trip
    await _storage(request).delete(file.key)  # object first: a failure here leaves the row, so it can be retried
    deleted = await db.scalar(delete(File).where(File.id == file.id).returning(File.id))
    await db.commit()
    if deleted is None:  # a concurrent delete got there first
        raise not_found("File")
