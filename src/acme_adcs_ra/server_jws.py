"""JWS request verification used by the ACME server routes.

This module only **verifies** signatures; it never signs anything.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from fastapi import Request

from acme_adcs_ra.acme_errors import (
    bad_nonce,
    bad_public_key,
    malformed,
    unauthorized,
)
from acme_adcs_ra.jws import (
    JWSValidationError,
    _base64url_decode,
    _public_key_from_jwk,
    verify_flattened_jws,
)
from acme_adcs_ra.store import Store


def _kid_to_account_id(kid: str) -> str:
    """Extract the account UUID from a kid (account URL).

    RFC 8555 §6.2.1 requires kid to be the account URL. A bare ID is a
    protocol violation and is rejected.
    """
    marker = "/acme/acct/"
    idx = kid.find(marker)
    if idx == -1:
        raise malformed(
            f"kid is not a valid account URL (missing {marker!r}): {kid!r}"
        )
    return kid[idx + len(marker):].split("/", 1)[0]


def _verify_url(header: dict[str, Any], request_url: str) -> None:
    """Ensure the JWS protected-header url matches the request URL.

    RFC 8555 §6.4 requires full-URL binding (scheme + host + path + query).
    A stolen JWS replayed against a different host with the same path must
    be rejected.
    """
    header_url = header.get("url")
    if not header_url:
        raise malformed("protected header missing url")
    header_parsed = urlparse(str(header_url))
    request_parsed = urlparse(str(request_url))

    # The protected-header url MUST be absolute. A relative url would evade
    # the scheme/host comparison below and allow cross-host replay (a stolen
    # JWS replayed against a different host at the same path). RFC 8555 §6.4
    # requires full-URL binding.
    if not header_parsed.scheme or not header_parsed.netloc:
        raise malformed(
            "protected header 'url' must be an absolute URL "
            f"(got {header_url!r})"
        )

    # Scheme + host + path + query must all match (RFC 8555 §6.4).
    if header_parsed.scheme != request_parsed.scheme:
        raise malformed(
            f"url scheme mismatch: protected header {header_parsed.scheme}, "
            f"request {request_parsed.scheme}"
        )
    if header_parsed.netloc != request_parsed.netloc:
        raise malformed(
            f"url host mismatch: protected header {header_parsed.netloc}, "
            f"request {request_parsed.netloc}"
        )
    if header_parsed.path != request_parsed.path:
        raise malformed(
            f"url path mismatch: protected header {header_parsed.path}, "
            f"request {request_parsed.path}"
        )
    if header_parsed.query != request_parsed.query:
        raise malformed(
            f"url query mismatch: protected header {header_parsed.query!r}, "
            f"request {request_parsed.query!r}"
        )


def _consume_nonce(store: Store, header: dict[str, Any], request_url: str) -> None:
    nonce = header.get("nonce")
    if not nonce:
        raise bad_nonce(f"missing Replay-Nonce in protected header for {request_url}")
    if not store.consume_nonce(nonce):
        raise bad_nonce(f"invalid or replayed Replay-Nonce for {request_url}")


async def _parse_jws_body(request: Request) -> dict[str, Any]:
    body = await request.body()
    if not body:
        raise malformed("empty request body")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise malformed(f"request body is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise malformed("request body must be a JSON object")
    return data


async def _parse_jws_header(
    request: Request,
    store: Store,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse the JWS body, decode the protected header, consume the nonce,
    and verify the URL binding.

    Returns (header, jws_dict).
    """
    jws = await _parse_jws_body(request)
    protected_b64 = jws.get("protected")
    if not isinstance(protected_b64, str):
        raise malformed("JWS missing protected header")
    try:
        header = json.loads(_base64url_decode(protected_b64))
    except Exception as exc:
        raise malformed(f"invalid protected header: {exc}") from exc

    # Consume nonce BEFORE verifying URL so that a bad-URL probe still
    # burns the nonce, limiting replay probing (M6).
    _consume_nonce(store, header, str(request.url))
    _verify_url(header, str(request.url))

    return header, jws


def _verify_jws_signature(
    jws: dict[str, Any],
    public_key: Any,
) -> dict[str, Any]:
    """Verify the JWS signature and return the parsed payload dict."""
    try:
        payload = verify_flattened_jws(jws, public_key)
    except JWSValidationError as exc:
        raise unauthorized(f"JWS verification failed: {exc}") from exc

    try:
        payload_dict: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise malformed(f"JWS payload is not valid JSON: {exc}") from exc

    return payload_dict


async def verify_existing_account_jws(
    request: Request,
    store: Store,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Verify a JWS signed by an existing account (kid lookup).

    Returns (protected_header, payload_dict, account_id).
    """
    header, jws = await _parse_jws_header(request, store)

    kid = header.get("kid")
    if not kid:
        raise malformed("protected header missing kid")
    account_id = _kid_to_account_id(kid)
    account = store.get_account(account_id)
    if account is None:
        raise unauthorized("account not found")

    try:
        public_key = _public_key_from_jwk(json.loads(account.jwk_json))
    except Exception as exc:
        raise bad_public_key(f"stored account key is invalid: {exc}") from exc

    payload_dict = _verify_jws_signature(jws, public_key)

    return header, payload_dict, account_id


async def verify_new_account_jws(
    request: Request,
    store: Store,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Verify a JWS signed by the new account key (jwk in header).

    Returns (protected_header, payload_dict, account_jwk).
    """
    header, jws = await _parse_jws_header(request, store)

    account_jwk = header.get("jwk")
    if not account_jwk:
        raise malformed("newAccount JWS protected header missing jwk")

    try:
        public_key = _public_key_from_jwk(account_jwk)
    except Exception as exc:
        raise bad_public_key(f"invalid account JWK: {exc}") from exc

    payload_dict = _verify_jws_signature(jws, public_key)

    return header, payload_dict, account_jwk
