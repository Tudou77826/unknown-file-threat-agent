"""Shared limiter: RPM/TPM dual-dimension token bucket with all-jitter
exponential backoff for 429s (design.md §4.2). The kernel never raises on
limit — ``acquire`` blocks until the budget exists. Business modules may
reuse this class; the kernel itself holds no provider-specific knowledge.
"""

from __future__ import annotations

import random
import threading
import time

from pydantic import Field

from ._base import StrictModel


class RateLimitConfig(StrictModel):
    rpm: int = Field(default=0, ge=0, description="每分钟请求数，0=不限")
    tpm: int = Field(default=0, ge=0, description="每分钟 token 数，0=不限")
    max_backoff_seconds: float = Field(default=60.0, gt=0)


class _Bucket:
    __slots__ = ("capacity", "tokens", "refill_rate", "updated")

    def __init__(self, capacity: float, refill_per_second: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_per_second
        self.updated = time.monotonic()

    def take(self, amount: float) -> float:
        """Try to take ``amount``; returns 0.0 on success else the seconds to
        wait before a retry could succeed."""

        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill_rate)
        self.updated = now
        if self.tokens >= amount:
            self.tokens -= amount
            return 0.0
        missing = amount - self.tokens
        return missing / self.refill_rate if self.refill_rate > 0 else float("inf")


class RateLimiter:
    """Thread-safe dual bucket. ``acquire(cost)`` blocks; ``register_429``
    injects a cooldown so all in-flight workers back off together."""

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._lock = threading.Lock()
        self._request_bucket: _Bucket | None = None
        self._token_bucket: _Bucket | None = None
        if config.rpm > 0:
            self._request_bucket = _Bucket(float(config.rpm), config.rpm / 60.0)
        if config.tpm > 0:
            self._token_bucket = _Bucket(float(config.tpm), config.tpm / 60.0)
        self._cooldown_until = 0.0
        self._backoff_attempt = 0
        self.throttled_acquires = 0

    def acquire(self, *, tokens: int = 1) -> None:
        while True:
            with self._lock:
                wait = 0.0
                now = time.monotonic()
                if now < self._cooldown_until:
                    wait = self._cooldown_until - now
                if self._request_bucket is not None:
                    wait = max(wait, self._request_bucket.take(1.0))
                if self._token_bucket is not None and tokens > 0:
                    wait = max(wait, self._token_bucket.take(float(tokens)))
                if wait <= 0:
                    return
            time.sleep(min(wait, self.config.max_backoff_seconds) * (0.5 + random.random() / 2))

    def register_429(self) -> None:
        """All-jitter exponential backoff shared by every worker: on a
        provider 429 everyone cools down, not just the caller."""

        with self._lock:
            self.throttled_acquires += 1
            delay = min(self.config.max_backoff_seconds, 2.0 ** self._backoff_attempt)
            self._backoff_attempt += 1
            self._cooldown_until = max(self._cooldown_until, time.monotonic() + delay * (0.5 + random.random() / 2))

    def register_success(self) -> None:
        with self._lock:
            self._backoff_attempt = 0
            self._cooldown_until = 0.0
