from app.platform.ratelimit import FixedWindowLimiter


class Clock:
    def __init__(self, t: float):
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_allows_up_to_limit_then_blocks_with_retry_after():
    clock = Clock(120.0)  # start of a window
    limiter = FixedWindowLimiter(3, 60, clock)
    assert [limiter.hit("1.1.1.1")[0] for _ in range(3)] == [True, True, True]
    clock.t = 130.2
    assert limiter.hit("1.1.1.1") == (False, 50)  # ceil(180 - 130.2)


def test_keys_are_independent():
    limiter = FixedWindowLimiter(1, 60, Clock(0.0))
    assert limiter.hit("a")[0]
    assert not limiter.hit("a")[0]
    assert limiter.hit("b")[0]


def test_new_window_resets_counts():
    clock = Clock(59.9)
    limiter = FixedWindowLimiter(1, 60, clock)
    assert limiter.hit("a")[0]
    assert limiter.hit("a") == (False, 1)  # retry_after is never 0 when blocked
    clock.t = 60.0
    assert limiter.hit("a") == (True, 0)


def test_full_map_allows_a_new_key_untracked_and_keeps_limiting_known_ones():
    clock = Clock(0.0)
    limiter = FixedWindowLimiter(1, 60, clock, max_keys=2)
    assert limiter.hit("a")[0] and limiter.hit("b")[0]
    for _ in range(5):
        assert limiter.hit("c") == (True, 0)  # map full: allowed, and never counted
    assert limiter.hit("a") == (False, 60)  # existing keys stay limited
    clock.t = 60.0
    assert limiter.hit("c") == (True, 0)
    assert limiter.hit("c") == (False, 60)  # tracked again after the window sweep freed the map
