"""Bounded request-body reading.

Starlette's ``Request.body()`` / ``Request.json()`` accumulate every chunk of
the request stream and join them before decoding. That is fine for a body whose
size something else has already bounded, and a memory-exhaustion sink for one
where nothing has: the process learns the body was too big only after holding
all of it.

Every route that reads a body goes through here, so the bound is a property of
the RA rather than of whichever route remembered to apply one. The JWS routes
had this treatment from the start; the admin confirmation route did not, which
is what the 2026-08-17 scan found (F2).
"""

from __future__ import annotations

import asyncio
from typing import Any

from acme_adcs_ra.acme_errors import malformed

# Wall-clock ceiling on reading one request body. Bytes were bounded from the
# start; time was not (2026-08-19 F3, CWE-400). A peer that sends one byte per
# interval never trips the byte cap and never finishes, so it holds a worker for
# as long as it likes — and the supported direct-Uvicorn topology has no proxy
# in front to time it out. 30s is generous for an ACME JWS body over a slow
# link and still finite.
DEFAULT_BODY_TOTAL_TIMEOUT_SECONDS = 30.0


async def read_body_limited(
    request: Any,
    *,
    max_bytes: int,
    what: str = "request",
    total_timeout_seconds: float = DEFAULT_BODY_TOTAL_TIMEOUT_SECONDS,
) -> bytes:
    """Return the request body, refusing anything larger than *max_bytes*.

    Three checks, because no two of them are sufficient:

    * ``Content-Length``, when declared, is rejected **before a byte is read**
      — the cheapest possible refusal;
    * streamed bytes are counted as they arrive, which is the check that
      actually holds. A chunked request declares no length, and a declared
      length is a claim by the sender, not a limit on it;
    * the whole read is bounded by *total_timeout_seconds*, which is the only
      one of the three a slow-drip sender cannot simply stay under.

    The deadline is applied to each await rather than to the loop as a whole, so
    the budget cannot be reset by a sender that keeps producing tiny chunks: the
    remaining time is recomputed from a single start instant.

    *what* names the body in the error message (``"JWS request"``,
    ``"confirmation request"``), so the caller's diagnostics stay specific.
    """
    if max_bytes < 1:
        raise malformed(f"server {what} body-size limit is invalid")

    too_large = f"{what} body too large (max {max_bytes} bytes)"

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise malformed("invalid Content-Length header") from exc
        if declared_length < 0 or declared_length > max_bytes:
            raise malformed(too_large)

    too_slow = (
        f"{what} body read exceeded its {total_timeout_seconds}s deadline; "
        "the connection was too slow or stalled mid-body"
    )

    chunks: list[bytes] = []
    total = 0
    loop = asyncio.get_running_loop()
    deadline = loop.time() + total_timeout_seconds
    stream = request.stream()
    iterator = stream.__aiter__()
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise malformed(too_slow)
        try:
            # wait_for around each pull, against a deadline computed from one
            # fixed start — so a drip-feeder cannot renew its budget per chunk.
            chunk = await asyncio.wait_for(iterator.__anext__(), timeout=remaining)
        except StopAsyncIteration:
            break
        except TimeoutError as exc:
            raise malformed(too_slow) from exc
        total += len(chunk)
        if total > max_bytes:
            raise malformed(too_large)
        chunks.append(chunk)
    return b"".join(chunks)
