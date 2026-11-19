"""The argon2 pool: bounded workers, at most 4x as many waiting, slots held for the whole job."""

import asyncio
import threading

import pytest

from app.platform.cpu import BoundedPool, PoolBusy


def test_waiters_beyond_4x_workers_are_refused_and_slots_return():
    async def scenario():
        pool = BoundedPool(workers=2, queue_factor=4)
        assert pool.capacity == 10
        gate = threading.Event()
        jobs = [asyncio.ensure_future(pool.run(gate.wait, 5)) for _ in range(10)]
        await asyncio.sleep(0)  # let every run() reach submit
        assert pool.pending == 10
        with pytest.raises(PoolBusy):
            await pool.run(lambda: None)
        gate.set()
        await asyncio.gather(*jobs)
        assert pool.pending == 0
        assert await pool.run(lambda: 42) == 42

    asyncio.run(scenario())


def test_cancelling_a_queued_job_frees_its_slot_but_a_running_one_keeps_it():
    async def scenario():
        pool = BoundedPool(workers=1, queue_factor=1)
        gate = threading.Event()
        running = asyncio.ensure_future(pool.run(gate.wait, 5))
        queued = asyncio.ensure_future(pool.run(lambda: "never"))
        await asyncio.sleep(0.05)
        assert pool.pending == 2
        queued.cancel()  # not started yet: removed from the queue, slot back at once
        running.cancel()  # already running in a thread: cannot stop, keeps its slot
        await asyncio.sleep(0.05)
        assert pool.pending == 1
        gate.set()
        for _ in range(100):
            if pool.pending == 0:
                break
            await asyncio.sleep(0.01)
        assert pool.pending == 0

    asyncio.run(scenario())
