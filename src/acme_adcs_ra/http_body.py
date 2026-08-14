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

from fastapi import Request

from acme_adcs_ra.acme_errors import malformed


async def read_body_limited(
    request: Request, *, max_bytes: int, what: str = "request"
) -> bytes:
    """Return the request body, refusing anything larger than *max_bytes*.

    Two checks, because either alone is insufficient:

    * ``Content-Length``, when declared, is rejected **before a byte is read**
      — the cheapest possible refusal;
    * streamed bytes are counted as they arrive, which is the check that
      actually holds. A chunked request declares no length, and a declared
      length is a claim by the sender, not a limit on it.

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

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise malformed(too_large)
        chunks.append(chunk)
    return b"".join(chunks)
