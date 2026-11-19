"""Fire-and-forget work that runs after the response (emails). Failures are logged, never raised.

Bounded: at most MAX_JOBS queued or in flight; beyond that a job is dropped and logged (the HTTP response
does not change). Ceiling: in-process only; a crash loses pending jobs. Use a real queue when delivery must
be guaranteed.
"""

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

log = logging.getLogger("app.tasks")
MAX_JOBS = 1000
_running: set[asyncio.Task] = set()


def spawn(coro: Coroutine[Any, Any, Any], name: str, max_jobs: int = MAX_JOBS) -> bool:
    """Schedule `coro`; returns False (and closes it unstarted) when the bound is reached."""
    if len(_running) >= max_jobs:
        coro.close()
        log.warning("background job dropped: queue full", extra={"task": name, "limit": max_jobs})
        return False

    async def guarded() -> None:
        try:
            await coro
        except Exception:
            log.exception("background task failed", extra={"task": name})

    task = asyncio.create_task(guarded(), name=name)  # copies the context, so logs keep the request_id
    _running.add(task)
    task.add_done_callback(_running.discard)
    return True


async def drain(grace_seconds: float = 10.0) -> None:
    """On shutdown: wait for in-flight jobs (emails) before the DB pool closes; cancel what is left."""
    if _running:
        _, pending = await asyncio.wait(set(_running), timeout=grace_seconds)
        for task in pending:
            task.cancel()
