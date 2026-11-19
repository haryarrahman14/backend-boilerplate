"""A bounded pool for CPU-heavy work (argon2: tens of ms and 19 MiB per hash)."""

import asyncio
import os
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any


class PoolBusy(Exception):
    """More jobs are already waiting than the pool may queue."""


class BoundedPool:
    """`workers` threads, plus at most `queue_factor` x `workers` jobs waiting for one.

    A slot is held until the job really finishes: cancelling the awaiting request removes a job that has not
    started yet, but a running hash keeps its slot until it is done, so the bound covers the whole hash.
    """

    def __init__(self, workers: int, queue_factor: int = 4, name: str = "cpu"):
        self.workers = max(1, workers)
        self.capacity = self.workers * (1 + queue_factor)
        self._executor = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix=name)
        self._lock = threading.Lock()  # done-callbacks run on worker threads
        self._pending = 0

    @property
    def pending(self) -> int:
        return self._pending

    def _release(self, _: Future) -> None:
        with self._lock:
            self._pending -= 1

    async def run(self, fn: Callable[..., Any], *args: Any) -> Any:
        with self._lock:
            if self._pending >= self.capacity:
                raise PoolBusy
            self._pending += 1
        try:
            future = self._executor.submit(fn, *args)
        except BaseException:
            self._release(None)  # type: ignore[arg-type]
            raise
        future.add_done_callback(self._release)
        # Cancelling this await (client gone, request deadline) cancels the job if it has not started yet.
        return await asyncio.wrap_future(future)


argon2_pool = BoundedPool(os.cpu_count() or 2, name="argon2")
