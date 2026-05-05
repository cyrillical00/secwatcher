from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import httpx

LOW_HEADROOM = 200

logger = logging.getLogger(__name__)


@dataclass
class RateLimitState:
    remaining: int
    reset_at: int

    @classmethod
    def from_headers(cls, headers: httpx.Headers) -> RateLimitState | None:
        try:
            return cls(
                remaining=int(headers["x-ratelimit-remaining"]),
                reset_at=int(headers["x-ratelimit-reset"]),
            )
        except (KeyError, ValueError):
            return None


def sleep_if_low(state: RateLimitState | None, *, threshold: int = LOW_HEADROOM) -> None:
    if state is None:
        return
    if state.remaining > threshold:
        return
    delay = max(state.reset_at - int(time.time()), 0) + 5
    logger.warning(
        "Rate limit headroom %d <= %d; sleeping %ds until reset.",
        state.remaining,
        threshold,
        delay,
    )
    time.sleep(delay)
