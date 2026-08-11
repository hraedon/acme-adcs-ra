"""In-process token bucket for unauthenticated endpoints.

``/acme/new-nonce`` is unauthenticated and every call performs a SQLite
``INSERT``. SQLite has a single writer, so an unauthenticated flood does not
just grow a table — it contends for the write lock with the issuance path,
where a blocked write surfaces as a 500 once ``busy_timeout`` expires. The
WI-016 per-account limiter cannot help: it keys on an account that does not
exist yet at nonce time.

The bucket is deliberately **in-process and pre-database**: a rejected request
must cost less than an accepted one, so a limiter that itself wrote to SQLite
would be self-defeating. Under IIS/HttpPlatformHandler the RA runs as a single
uvicorn process, so one bucket sees all traffic. If the deployment is ever
scaled to multiple workers the ceiling multiplies by worker count — that is a
documented consequence, not a silent one, and the reverse-proxy limit remains
the authoritative outer bound.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class TokenBucket:
    """A monotonic-clock token bucket, safe to call from the request path.

    ``capacity`` is the burst size; ``refill_per_second`` is the sustained
    rate. ``take`` is O(1), lock-guarded, and never blocks.
    """

    def __init__(
        self,
        *,
        capacity: int,
        refill_per_second: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be > 0")
        self._capacity = float(capacity)
        self._refill = float(refill_per_second)
        self._clock = clock
        self._tokens = float(capacity)
        self._updated = clock()
        self._lock = threading.Lock()

    def take(self, tokens: float = 1.0) -> bool:
        """Consume *tokens* if available. Returns False when the bucket is dry."""
        with self._lock:
            now = self._clock()
            elapsed = now - self._updated
            if elapsed > 0:
                self._tokens = min(
                    self._capacity, self._tokens + elapsed * self._refill
                )
                self._updated = now
            if self._tokens < tokens:
                return False
            self._tokens -= tokens
            return True

    def retry_after_seconds(self, tokens: float = 1.0) -> int:
        """Whole seconds until *tokens* would be available (at least 1)."""
        with self._lock:
            deficit = max(0.0, tokens - self._tokens)
        return max(1, int(deficit / self._refill) + 1)
