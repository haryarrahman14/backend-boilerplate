"""Fixed-window rate limiter keyed by client IP (IPv6 by /64, see middleware.rate_limit_key).

Single-instance only: counters live in this process's memory. Swap for Redis (INCR + EXPIRE) when scaled out.
"""

import math
import time
from collections.abc import Callable


class FixedWindowLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: int = 60,
        clock: Callable[[], float] = time.time,
        max_keys: int = 100_000,
    ):
        self.limit, self.window, self.clock, self.max_keys = limit, window_seconds, clock, max_keys
        self._window_id = -1
        self._counts: dict[str, int] = {}

    def hit(self, key: str) -> tuple[bool, int]:
        """Count one request. Returns (allowed, retry_after_seconds); retry_after is 0 when allowed.

        No lock: it runs on the event loop thread only, with no await inside.
        """
        now = self.clock()
        window_id = int(now // self.window)
        retry_after = max(1, math.ceil((window_id + 1) * self.window - now))
        if window_id != self._window_id:
            # Windows are aligned, so every counter of the old window expired at once: this is the sweep,
            # and it runs at most once per window, never per request.
            self._window_id, self._counts = window_id, {}
        count = self._counts.get(key)
        if count is None:
            if len(self._counts) >= self.max_keys:
                # Memory cap reached: let the new key through untracked. Refusing it would let anyone with
                # 100 000 addresses lock every other user out, and that attacker has 100 000 budgets anyway.
                return True, 0
            count = 0
        self._counts[key] = count + 1
        if count + 1 <= self.limit:
            return True, 0
        return False, retry_after
