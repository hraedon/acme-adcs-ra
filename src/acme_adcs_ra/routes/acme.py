"""ACME protocol routes (RFC 8555 subset)."""

from __future__ import annotations

import json
from typing import Any, cast

from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.oid import ExtensionOID
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import (
    account_does_not_exist,
    bad_external_account_binding,
    bad_revocation_reason,
    malformed,
    not_found,
    server_internal,
    unauthorized,
    unsupported_identifier,
)
from acme_adcs_ra.app_state import (
    ServerContext,
    _ACME_PATHS,
    _account_url,
    _audit,
    _authz_url,
    _challenge_url,
    _dummy_hmac,
    _finalize_url,
    _order_url,
    _url,
    get_context,
    logger,
)
from acme_adcs_ra.finalize import (
    _finalize_complete,
    _finalize_existing_cert,
    _finalize_expired_order,
    _finalize_parse_and_validate_csr,
    _finalize_submit_enrollment,
    _finalize_transition_to_processing,
)
from acme_adcs_ra.jws import JWSValidationError, _base64url_decode, verify_eab_jws
from acme_adcs_ra.serializers import (
    _account_to_json,
    _authz_to_json,
    _challenge_to_json,
    _order_to_json,
)
from acme_adcs_ra.server_jws import (
    verify_existing_account_jws,
    verify_new_account_jws,
)
from acme_adcs_ra.store import CertStatus, OrderStatus, _now_iso


router = APIRouter()


@router.get("/directory", response_model=dict)
async def directory(ctx: ServerContext = Depends(get_context)) -> dict[str, Any]:
    meta: dict[str, Any] = {"externalAccountRequired": True}
    if ctx.config.terms_of_service:
        meta["termsOfService"] = ctx.config.terms_of_service
    return {
        "newNonce": _url(ctx, _ACME_PATHS["newNonce"]),
        "newAccount": _url(ctx, _ACME_PATHS["newAccount"]),
        "newOrder": _url(ctx, _ACME_PATHS["newOrder"]),
        "revokeCert": _url(ctx, _ACME_PATHS["revokeCert"]),
        "meta": meta,
    }


def _nonce_response(ctx: ServerContext) -> Response:
    nonce = ctx.store.create_nonce()
    return Response(
        status_code=204,
        headers={
            "Replay-Nonce": nonce,
            "Cache-Control": "no-store",
        },
    )


@router.head(_ACME_PATHS["newNonce"])
async def new_nonce_head(ctx: ServerContext = Depends(get_context)) -> Response:
    return _nonce_response(ctx)


@router.get(_ACME_PATHS["newNonce"])
async def new_nonce_get(ctx: ServerContext = Depends(get_context)) -> Response:
    return _nonce_response(ctx)


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


@router.post(_ACME_PATHS["newOrder"])
async def new_order(
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    header, payload, account_id = await verify_existing_account_jws(request, ctx.store)

    identifiers_raw = payload.get("identifiers")
    if not isinstance(identifiers_raw, list) or not identifiers_raw:
        raise malformed("newOrder payload must contain a non-empty identifiers list")

    # DoS cap: max identifiers per order (threat-model §4.G)
    max_idents = ctx.config.max_identifiers_per_order
    if len(identifiers_raw) > max_idents:
        raise malformed(
            f"too many identifiers in order (max {max_idents}, got {len(identifiers_raw)})"
        )

    identifiers: list[dict[str, str]] = []
    for item in identifiers_raw:
        if not isinstance(item, dict):
            raise malformed("identifier must be an object")
        ident_type = item.get("type")
        value = item.get("value")
        if ident_type != "dns" or not isinstance(value, str) or not value:
            raise unsupported_identifier(
                "only DNS identifiers are supported and value must be non-empty"
            )
        identifiers.append({"type": "dns", "value": value})

    # H5: atomic order creation — all order/authz/challenge rows and URLs
    # are written in a single transaction via Store.create_order_with_authz.
    refreshed_order = ctx.store.create_order_with_authz(
        account_id=account_id,
        identifiers=identifiers,
        challenge_url_fn=lambda cid: _challenge_url(ctx, cid),
        authz_url_fn=lambda aid: _authz_url(ctx, aid),
        finalize_url_fn=lambda oid: _finalize_url(ctx, oid),
    )

    _audit(ctx, 
        event_type="order-created",
        account_id=account_id,
        order_id=refreshed_order.id,
        sans=[i["value"] for i in identifiers],
        outcome="success",
        details={"identifier_count": len(identifiers)},
    )

    return JSONResponse(
        status_code=201,
        content=_order_to_json(refreshed_order),
        headers={"Location": _order_url(ctx, refreshed_order.id)},
    )


@router.get("/acme/authz/{authz_id}")
async def get_authorization(
    authz_id: str,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    authz = ctx.store.get_authorization(authz_id)
    if authz is None:
        raise unauthorized("authorization not found")
    return JSONResponse(content=_authz_to_json(authz))


def _maybe_ready_order(ctx: ServerContext, order_id: str) -> None:
    order = ctx.store.get_order(order_id)
    if order is None:
        return
    # Only a pending order advances to ready. Without this, re-POSTing a
    # challenge on an already valid/processing order would regress it to
    # ready (a state machine regression; finalize's guards prevent a double
    # issue, but the regression is still wrong).
    if order.status != OrderStatus.PENDING:
        return
    for authz_url in order.authorizations:
        authz_id = authz_url.rsplit("/", 1)[-1]
        authz = ctx.store.get_authorization(authz_id)
        if authz is None or authz.status != "valid":
            return
    ctx.store.update_order_status(order_id, OrderStatus.READY)


@router.post("/acme/challenge/{challenge_id}")
async def post_challenge(
    challenge_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    header, payload, account_id = await verify_existing_account_jws(request, ctx.store)

    challenge = ctx.store.get_challenge(challenge_id)
    if challenge is None:
        raise unauthorized("challenge not found")
    authz = ctx.store.get_authorization(challenge.authz_id)
    if authz is None or authz.account_id != account_id:
        raise unauthorized("challenge does not belong to account")

    # The challenge payload must be an empty object — defense-in-depth:
    # EAB + network allowlist + SAN-scope policy is the trust gate
    # (architecture.md); the payload body is intentionally ignored.
    if payload != {}:
        raise malformed("challenge payload must be an empty object {}")

    # ------------------------------------------------------------------
    # Enterprise trust decision point.
    #
    # This RA is gated by External Account Binding (enterprise identity) +
    # network access control + deterministic SAN-scope policy.  Public
    # domain-control proofs (DNS-01 / HTTP-01 against the internet) are
    # explicitly out of scope for this enterprise issuance path.  The
    # challenge object still exists and transitions per RFC 8555 shape so
    # generic ACME clients can drive it; the actual validation is the
    # enterprise authorization already established at account creation.
    #
    # If domain-validation is required later, replace the block below with
    # a real challenge verifier and gate it on policy.
    # ------------------------------------------------------------------
    validated_at = _now_iso()
    ctx.store.update_challenge_status(challenge_id, "valid", validated_at=validated_at)
    ctx.store.update_authorization_status(challenge.authz_id, "valid")

    _maybe_ready_order(ctx, authz.order_id)

    refreshed_challenge = ctx.store.get_challenge(challenge_id)
    if refreshed_challenge is None:
        raise server_internal("challenge disappeared after validation")

    _audit(ctx, 
        event_type="challenge-validated",
        account_id=account_id,
        order_id=authz.order_id,
        outcome="success",
        details={"challenge_id": challenge_id, "authz_id": authz.id},
    )
    return JSONResponse(content=_challenge_to_json(refreshed_challenge))


@router.post("/acme/finalize/{order_id}")
async def finalize_order(
    order_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    header, payload, account_id = await verify_existing_account_jws(request, ctx.store)

    order = ctx.store.get_order(order_id)
    if order is None or order.account_id != account_id:
        raise unauthorized("order not found")

    # Idempotent: order already valid.
    if order.status == OrderStatus.VALID:
        return JSONResponse(content=_order_to_json(order))

    # Double-issuance guard: if a cert already exists, return it.
    existing_cert = ctx.store.get_certificate_by_order(order_id)
    if existing_cert is not None:
        return _finalize_existing_cert(ctx, order_id, account_id, existing_cert)

    # Another finalize is mid-enrollment (or crashed). Tell client to poll.
    if order.status == OrderStatus.PROCESSING:
        return JSONResponse(
            content=_order_to_json(order), headers={"Retry-After": "3"}
        )

    # Expired order: CAS-flip to invalid or return current state.
    expired_resp = _finalize_expired_order(ctx, order_id, account_id, order)
    if expired_resp is not None:
        return expired_resp

    if order.status != OrderStatus.READY:
        raise malformed(
            f"order is not ready for finalization (status={order.status})"
        )

    # Parse CSR, validate SANs, evaluate policy (while still 'ready').
    csr, csr_subject, requested_sans, decision = _finalize_parse_and_validate_csr(
        ctx, payload, order, account_id, order_id
    )

    # Point of no return: transition ready→processing.
    race_resp = _finalize_transition_to_processing(ctx, order_id)
    if race_resp is not None:
        return race_resp

    # Submit to enrollment.
    enrollment_result = _finalize_submit_enrollment(
        ctx, order_id, account_id, requested_sans,
        csr, csr_subject, decision,
    )
    if isinstance(enrollment_result, JSONResponse):
        return enrollment_result

    # Record cert and transition to valid.
    return _finalize_complete(
        ctx, order_id, account_id, requested_sans,
        csr_subject, decision, enrollment_result,
    )


@router.get("/acme/cert/{cert_id}")
async def get_certificate(
    cert_id: str,
    ctx: ServerContext = Depends(get_context),
) -> Response:
    cert = ctx.store.get_certificate(cert_id)
    if cert is None:
        raise unauthorized("certificate not found")
    # H-1: revoked certs must not be installable — return 410 Gone.
    if cert.status == CertStatus.REVOKED:
        return Response(status_code=410)
    body = cert.cert_pem + "".join(cert.chain_pem)
    return Response(
        content=body,
        media_type="application/pem-certificate-chain",
    )


@router.post(_ACME_PATHS["revokeCert"])
async def revoke_cert(
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    header, payload, account_id = await verify_existing_account_jws(request, ctx.store)

    cert_b64 = payload.get("cert")
    if not isinstance(cert_b64, str) or not cert_b64:
        raise malformed("missing or invalid cert field")

    try:
        cert_der = _base64url_decode(cert_b64)
    except Exception as exc:
        raise malformed(f"cert is not valid base64url: {exc}") from exc

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as exc:
        raise malformed(f"unable to parse certificate: {exc}") from exc

    reason = payload.get("reason")
    if reason is not None:
        if not isinstance(reason, int) or reason < 0 or reason > 10:
            raise bad_revocation_reason(
                "reason code must be an integer in the range 0-10"
            )

    serial_hex = format(cert.serial_number, "x").upper()

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        cert_sans: list[str] = []
    else:
        san_value = cast(x509.SubjectAlternativeName, san_ext.value)
        cert_sans = [str(v) for v in san_value.get_values_for_type(DNSName)]

    # C-1: scope the serial lookup to (serial, account_id) so that a
    # serial collision cannot return another account's row.  Merging the
    # not-found and unauthorised outcomes into a single 404 avoids
    # information leakage about whether another account owns that serial.
    cert_record = ctx.store.get_certificate_by_serial(serial_hex, account_id)
    if cert_record is None:
        raise not_found("certificate not found in RA store")

    if cert_record.status == CertStatus.REVOKED:
        # H-4: RFC 8555 §7.6 says an already-revoked cert returns 200 OK
        # (idempotent) rather than 400 alreadyRevoked.
        return JSONResponse(status_code=200, content={})

    try:
        revocation_result = ctx.revocation.revoke(
            cert_record.cert_pem,
            reason,
        )
    except Exception as exc:
        _audit(
            ctx,
            event_type="certificate-revoked",
            account_id=account_id,
            order_id=cert_record.order_id,
            sans=cert_sans,
            outcome="failed",
            details={
                "certificate_id": cert_record.id,
                "serial": serial_hex,
                "error": str(exc),
            },
        )
        raise server_internal(f"revocation failed: {exc}") from exc

    revoked_at = revocation_result.revoked_at or _now_iso()
    updated = ctx.store.revoke_certificate(
        cert_record.id,
        revocation_result.reason if revocation_result.reason is not None else reason,
        revoked_at=revoked_at,
    )
    if updated is None:
        raise server_internal("certificate disappeared during revocation")

    # H-1: flip the order to a revoked state so order and cert are consistent.
    # WI-003: CAS-guarded on status IN ('valid', 'processing') so a concurrent
    # finalize cannot be clobbered. If the CAS doesn't apply (order is in an
    # unexpected state), log it — the cert is already revoked in the store.
    order_revoked = ctx.store.transition_to_revoked(cert_record.order_id)
    if not order_revoked:
        logger.warning(
            "revoke_cert: order %s was not in valid/processing state "
            "during revocation (cert %s already revoked in store)",
            cert_record.order_id, cert_record.id,
        )

    _audit(
        ctx,
        event_type="certificate-revoked",
        account_id=account_id,
        order_id=cert_record.order_id,
        sans=cert_sans,
        outcome="success",
        details={
            "certificate_id": cert_record.id,
            "serial": serial_hex,
            "reason": reason,
        },
    )

    return JSONResponse(status_code=200, content={})
