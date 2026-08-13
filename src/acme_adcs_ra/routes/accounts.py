"""Account creation with EAB gating (RFC 8555 §7.3)."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import (
    account_does_not_exist,
    bad_external_account_binding,
    malformed,
    unauthorized,
)
from acme_adcs_ra.app_state import (
    _ACME_PATHS,
    ServerContext,
    _account_url,
    _audit,
    _dummy_hmac,
    _order_url,
    _url,
    authenticate_account,
    get_context,
)
from acme_adcs_ra.jws import (
    JWSValidationError,
    _base64url_decode,
    verify_eab_jws,
)
from acme_adcs_ra.serializers import _account_to_json
from acme_adcs_ra.server_jws import verify_new_account_jws
from acme_adcs_ra.store import AccountStatus

router = APIRouter()


@router.post(_ACME_PATHS["newAccount"])
async def new_account(
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    new_account_url = _url(ctx, _ACME_PATHS["newAccount"])
    _header, payload, account_jwk = await verify_new_account_jws(
        request,
        ctx.store,
        expected_url=new_account_url,
        max_body_size_bytes=ctx.config.max_jws_body_size_bytes,
    )

    # RFC 8555 §7.3: newAccount is idempotent on the account key. If an
    # account already exists for this key, return it (200) rather than
    # minting a duplicate; honor onlyReturnExisting (§7.3.1).
    existing = ctx.store.get_account_by_jwk(account_jwk)
    if existing is not None:
        return JSONResponse(
            status_code=200,
            content=_account_to_json(ctx, existing),
            headers={"Location": _account_url(ctx, existing.id)},
        )
    if payload.get("onlyReturnExisting") is True:
        raise account_does_not_exist("no account exists for this key")

    eab_jws = payload.get("externalAccountBinding")
    if not isinstance(eab_jws, dict):
        _audit(ctx,
            event_type="account-creation-denied",
            outcome="failed",
            details={"reason": "missing externalAccountBinding"},
        )
        raise bad_external_account_binding("externalAccountBinding is required")

    # The three JWS members are attacker-controlled and reach string operations
    # downstream — _base64url_decode, and _dummy_hmac's ASCII encode of
    # "protected.payload". A non-string member (or a non-ASCII one) surfaced as
    # an unhandled 500 with a stack trace instead of a 400. Check the shape once,
    # here, before anything touches them.
    if not all(isinstance(eab_jws.get(k), str) for k in ("protected", "payload", "signature")):
        _audit(ctx,
            event_type="account-creation-denied",
            outcome="failed",
            details={"reason": "EAB protected/payload/signature must be strings"},
        )
        raise bad_external_account_binding(
            "externalAccountBinding protected, payload, and signature must be strings"
        )

    try:
        eab_header = json.loads(_base64url_decode(eab_jws["protected"]))
    except Exception as exc:
        _audit(ctx,
            event_type="account-creation-denied",
            outcome="failed",
            details={"reason": "invalid EAB protected header"},
        )
        raise bad_external_account_binding(
            f"invalid externalAccountBinding protected header: {exc}"
        ) from exc

    # A protected header that decodes to valid JSON but is not an *object* (an
    # array, a bare string, a number) previously reached ``.get`` and raised
    # AttributeError — an unauthenticated 500. verify_eab_jws checks this too,
    # but the kid is read here, before that call.
    if not isinstance(eab_header, dict):
        _audit(ctx,
            event_type="account-creation-denied",
            outcome="failed",
            details={"reason": "EAB protected header is not a JSON object"},
        )
        raise bad_external_account_binding(
            "externalAccountBinding protected header must be a JSON object"
        )

    eab_kid = eab_header.get("kid")
    if eab_kid is not None and not isinstance(eab_kid, str):
        _audit(ctx,
            event_type="account-creation-denied",
            outcome="failed",
            details={"reason": "EAB kid must be a string"},
        )
        raise bad_external_account_binding(
            "externalAccountBinding protected header kid must be a string"
        )
    if not eab_kid:
        _audit(ctx,
            event_type="account-creation-denied",
            outcome="failed",
            details={"reason": "EAB protected header missing kid"},
        )
        raise bad_external_account_binding(
            "externalAccountBinding protected header missing kid"
        )
    mac_key = ctx.config.eab_key_bytes(eab_kid)
    # `not mac_key`, not `mac_key is None`: a configured key that decodes to
    # zero bytes is not a key. Treating b"" as present let anyone who knew the
    # kid forge the binding with an empty HMAC key. Config validation now
    # rejects such an entry at startup; this is the second line of defence.
    if not mac_key:
        # Timing equalization: perform a dummy HMAC with a random key so
        # the unknown-kid path takes comparable time to the known-kid path.
        # This mitigates the kid-existence timing side-channel (threat-model §4.B).
        _dummy_hmac(eab_jws)
        _audit(ctx,
            event_type="account-creation-denied",
            outcome="failed",
            details={"reason": "unknown EAB kid", "kid": eab_kid},
        )
        raise bad_external_account_binding("unknown external account kid")

    try:
        verified_kid = verify_eab_jws(
            eab_jws,
            account_jwk,
            mac_key,
            # The RA's OWN newAccount URL, from the configured base_url — never
            # str(request.url), which is built from the client's Host header and
            # so would let an EAB minted for another deployment verify here.
            expected_url=new_account_url,
        )
    except JWSValidationError as exc:
        _audit(ctx,
            event_type="account-creation-denied",
            outcome="failed",
            details={"reason": "EAB MAC verification failed", "kid": eab_kid},
        )
        raise bad_external_account_binding(f"EAB verification failed: {exc}") from exc

    contact = payload.get("contact", [])
    if not isinstance(contact, list):
        raise malformed("contact must be a list")

    try:
        account = ctx.store.create_account(
            jwk=account_jwk,
            eab_kid=verified_kid,
            status="valid",
            contact=contact,
        )
    except sqlite3.IntegrityError:
        # A concurrent newAccount for the same key won the UNIQUE index. That
        # is exactly the case the index exists to stop, and the right answer is
        # the RFC 8555 §7.3 one: return the account that already exists rather
        # than surfacing a 500 for what is a legitimate idempotent retry.
        winner = ctx.store.get_account_by_jwk(account_jwk)
        if winner is None:
            raise
        return JSONResponse(
            status_code=200,
            content=_account_to_json(ctx, winner),
            headers={"Location": _account_url(ctx, winner.id)},
        )

    _audit(ctx,
        event_type="account-created",
        account_id=account.id,
        outcome="success",
        details={"eab_kid": verified_kid, "alg": eab_header.get("alg")},
    )

    body: dict[str, Any] = {
        **_account_to_json(ctx, account),
        "externalAccountBinding": eab_jws,
    }
    if ctx.config.terms_of_service:
        body["termsOfServiceAgreed"] = payload.get("termsOfServiceAgreed", False)

    return JSONResponse(
        status_code=201,
        content=body,
        headers={"Location": _account_url(ctx, account.id)},
    )


@router.post("/acme/acct/{account_id}")
async def account_resource(
    account_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    """POST-as-GET the account, or deactivate it (RFC 8555 §7.3.2, §7.3.6).

    This is the URL newAccount returns in ``Location`` and the value clients
    carry as ``kid``; it previously had no handler.

    An empty payload reads the account. ``{"status": "deactivated"}`` is the
    client-side kill switch for a compromised account key: once deactivated,
    ``enforce_account_usable`` rejects every subsequent request from this
    account — including revoking its own live certificates. It is one-way; RFC
    8555 §7.3.6 says the server MUST NOT allow reactivation.
    """
    _header, payload, account = await authenticate_account(
        ctx, request, f"/acme/acct/{account_id}"
    )
    # The kid already identified the account; a mismatch means the caller is
    # POSTing to someone else's account URL with their own key.
    if account.id != account_id:
        raise unauthorized("account not found")

    requested_status = payload.get("status")
    if requested_status is not None:
        if requested_status != AccountStatus.DEACTIVATED:
            raise malformed(
                "the only supported account status change is 'deactivated' "
                "(RFC 8555 §7.3.6)"
            )
        applied = ctx.store.update_account_status(
            account.id, AccountStatus.DEACTIVATED
        )
        _audit(
            ctx,
            event_type="account-deactivated",
            account_id=account.id,
            outcome="success",
            details={"eab_kid": account.eab_kid, "applied": applied},
        )
        refreshed = ctx.store.get_account(account.id)
        if refreshed is None:  # pragma: no cover - defensive
            raise unauthorized("account not found")
        return JSONResponse(content=_account_to_json(ctx, refreshed))

    return JSONResponse(content=_account_to_json(ctx, account))


@router.post("/acme/acct/{account_id}/orders")
async def account_orders(
    account_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    """POST-as-GET the account's order list (RFC 8555 §7.1.2.1).

    The account object has always advertised this URL; it had no handler, so
    a client that followed the link got a 404.
    """
    _header, payload, account = await authenticate_account(
        ctx, request, f"/acme/acct/{account_id}/orders"
    )
    if account.id != account_id:
        raise unauthorized("account not found")
    if payload != {}:
        raise malformed("POST-as-GET requires an empty payload")

    orders = ctx.store.list_orders_by_account(account.id)
    return JSONResponse(
        content={"orders": [_order_url(ctx, o.id) for o in orders]}
    )
