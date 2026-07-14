"""Account creation with EAB gating (RFC 8555 §7.3)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import (
    account_does_not_exist,
    bad_external_account_binding,
    malformed,
)
from acme_adcs_ra.app_state import (
    ServerContext,
    _ACME_PATHS,
    _account_url,
    _audit,
    _dummy_hmac,
    get_context,
)
from acme_adcs_ra.jws import (
    JWSValidationError,
    _base64url_decode,
    verify_eab_jws,
)
from acme_adcs_ra.serializers import _account_to_json
from acme_adcs_ra.server_jws import verify_new_account_jws

router = APIRouter()


@router.post(_ACME_PATHS["newAccount"])
async def new_account(
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    header, payload, account_jwk = await verify_new_account_jws(request, ctx.store)

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
    eab_kid = eab_header.get("kid")
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
    if mac_key is None:
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
        verified_kid = verify_eab_jws(eab_jws, account_jwk, mac_key)
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

    account = ctx.store.create_account(
        jwk=account_jwk,
        eab_kid=verified_kid,
        status="valid",
        contact=contact,
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
