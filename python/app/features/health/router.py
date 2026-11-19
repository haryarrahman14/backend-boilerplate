import asyncio
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text

log = logging.getLogger("app.health")
router = APIRouter(tags=["health"])


class Status(BaseModel):
    status: str


@router.get("/health", response_model=Status)
async def live() -> Status:
    return Status(status="ok")  # liveness: no DB


@router.get("/health/ready", response_model=Status, responses={503: {"model": Status}})
async def ready(request: Request):
    try:
        async with asyncio.timeout(2):
            async with request.app.state.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
    except Exception as e:
        log.warning("readiness check failed", extra={"error": type(e).__name__})
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return Status(status="ok")
