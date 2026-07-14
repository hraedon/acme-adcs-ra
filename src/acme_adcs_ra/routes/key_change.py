"""Account-key rollover (RFC 8555 §7.3.5)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import (
    bad_nonce,
    bad_public_key,
    malformed,
    unauthorized,
)
from acme_adcs_ra.app_state import (
    ServerContext,
    _ACME_PATHS,
    _audit,
    get_context,
)
from acme_adcs_ra.jws import (
    JWSValidationError,
    _base64url_decode,
    _public_key_from_jwk,
    jwk_thumbprint,
    verify_flattened_jws,
)
from acme_adcs_ra.server_jws import verify_existing_account_jws

router = APIRouter()


@router.post(_ACME_PATHS["keyChange"])
async def key_change(
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    """Account-key rollover (RFC 8555 §7.3.5).

    The outer JWS is signed by the *old* account key (kid lookup). Its
    payload is the *inner* JWS, signed by the *new* account key (jwk in
    the inner protected header). The inner payload carries the account
    URL and the old key JWK. After validation the account's stored key is
    replaced; the old key is no longer accepted.
    """
    outer_header, outer_payload, account_id = await verify_existing_account_jws(
        request, ctx.store
    )

    account = ctx.store.get_account(account_id)
    if account is None:
        raise unauthorized("account not found")

    inner_jws = outer_payload
    if not isinstance(inner_jws, dict) or "protected" not in inner_jws:
        raise malformed("keyChange payload must be an inner JWS object")

    try:
        inner_header = json.loads(_base64url_decode(inner_jws["protected"]))
    except Exception as exc:
        raise malformed(f"invalid inner JWS protected header: {exc}") from exc

    new_jwk = inner_header.get("jwk")
    if not new_jwk:
        raise malformed("inner JWS protected header missing jwk")

    inner_url = inner_header.get("url")
    if inner_url != outer_header.get("url"):
        raise malformed(
            "inner JWS url does not match outer JWS url (RFC 8555 §7.3.5)"
        )

    inner_nonce = inner_header.get("nonce")
    if not inner_nonce:
        raise bad_nonce("inner JWS protected header missing nonce")
    if not ctx.store.consume_nonce(inner_nonce):
        raise bad_nonce("invalid or replayed inner JWS nonce")

    try:
        new_public_key = _public_key_from_jwk(new_jwk)
    except Exception as exc:
        raise bad_public_key(f"invalid new account JWK: {exc}") from exc

    try:
        inner_payload_bytes = verify_flattened_jws(inner_jws, new_public_key)
    except JWSValidationError as exc:
        raise unauthorized(f"inner JWS verification failed: {exc}") from exc

    try:
        inner_payload = json.loads(inner_payload_bytes)
    except json.JSONDecodeError as exc:
        raise malformed(f"inner JWS payload is not valid JSON: {exc}") from exc

    inner_account = inner_payload.get("account")
    if inner_account != outer_header.get("kid"):
        raise malformed(
            "inner JWS account does not match outer JWS kid "
            "(RFC 8555 §7.3.5)"
        )

    old_key_jwk = inner_payload.get("oldKey")
    if not isinstance(old_key_jwk, dict):
        raise malformed("inner JWS payload missing oldKey")

    old_key_thumbprint = jwk_thumbprint(old_key_jwk)
    if old_key_thumbprint != jwk_thumbprint(json.loads(account.jwk_json)):
        raise unauthorized("oldKey in inner JWS does not match account key")

    new_key_thumbprint = jwk_thumbprint(new_jwk)
    if new_key_thumbprint == old_key_thumbprint:
        raise malformed("new key must differ from the current account key")

    existing = ctx.store.get_account_by_jwk(new_jwk)
    if existing is not None:
        raise bad_public_key("new account key is already registered to another account")

    ctx.store.update_account_key(account_id, new_jwk)

    _audit(ctx,
        event_type="account-key-changed",
        account_id=account_id,
        outcome="success",
        details={
            "eab_kid": account.eab_kid,
            "new_key_thumbprint": new_key_thumbprint,
        },
    )

    return JSONResponse(content={})
