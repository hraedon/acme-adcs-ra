"""FastAPI ACME server (RFC 8555 subset) for the ADCS Registration Authority.

This module only **verifies** JWS signatures and CSRs; it never signs anything.
The enrollment leg (``EnrollmentLeg``) forwards accepted CSRs to ADCS.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import (
    DNSName,
    IPAddress,
    OtherName,
    RFC822Name,
    RegisteredID,
    UniformResourceIdentifier,
    load_der_x509_csr,
    load_pem_x509_csr,
)
from cryptography.x509.oid import ExtensionOID

from acme_adcs_ra.acme_errors import (
    AcmeError,
    bad_csr,
    bad_external_account_binding,
    malformed,
    rejected_identifier,
    server_internal,
    unauthorized,
    unsupported_identifier,
)
from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.enrollment import EnrollmentLeg
from acme_adcs_ra.jws import JWSValidationError, verify_eab_jws, _base64url_decode
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.server_jws import (
    verify_existing_account_jws,
    verify_new_account_jws,
)
from acme_adcs_ra.store import Store


# ---------------------------------------------------------------------------
# ACME surface paths
# ---------------------------------------------------------------------------

_ACME_PATHS = {
    "newNonce": "/acme/new-nonce",
    "newAccount": "/acme/new-acct",
    "newOrder": "/acme/new-order",
    "revokeCert": "/acme/revoke-cert",
}


# ---------------------------------------------------------------------------
# Server context and app factory
# ---------------------------------------------------------------------------


@dataclass
class ServerContext:
    """Dependencies shared across every request."""

    config: RAConfig
    store: Store
    policy: IssuancePolicy
    enrollment: EnrollmentLeg
    # Optional extension hook for SIEM emission (Phase 3).  Called after the
    # audit row is persisted, unconditionally, for every issuance event.
    audit_hook: Callable[[dict[str, Any]], None] | None = None


def _audit(ctx: ServerContext, **kwargs: Any) -> None:
    """Persist an audit row and notify the optional SIEM hook."""
    event = ctx.store.record_audit(**kwargs)
    if ctx.audit_hook is not None:
        ctx.audit_hook(event)


def _url(context: ServerContext, path: str) -> str:
    """Build an absolute URL from a configured base URL and a path."""
    base = context.config.base_url.rstrip("/")
    return f"{base}{path}"


def _account_url(context: ServerContext, account_id: str) -> str:
    return _url(context, f"/acme/acct/{account_id}")


def _order_url(context: ServerContext, order_id: str) -> str:
    return _url(context, f"/acme/order/{order_id}")


def _authz_url(context: ServerContext, authz_id: str) -> str:
    return _url(context, f"/acme/authz/{authz_id}")


def _challenge_url(context: ServerContext, challenge_id: str) -> str:
    return _url(context, f"/acme/challenge/{challenge_id}")


def _finalize_url(context: ServerContext, order_id: str) -> str:
    return _url(context, f"/acme/finalize/{order_id}")


def _certificate_url(context: ServerContext, cert_id: str) -> str:
    return _url(context, f"/acme/cert/{cert_id}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reject_non_dns_sans(san_value: x509.SubjectAlternativeName) -> None:
    """M4: reject the CSR if it contains any non-DNSName SAN type.

    With server-auth-only scope, IPAddress/otherName/URI/RFC822Name SANs
    are an expansion risk — the ADCS template might honor them.
    """
    # These are the GeneralName types that the cryptography library exposes.
    # We check for each one that is NOT DNSName.
    non_dns_types: list[type] = [
        IPAddress,
        RFC822Name,
        UniformResourceIdentifier,
        RegisteredID,
        OtherName,
    ]
    for gn_type in non_dns_types:
        try:
            values = san_value.get_values_for_type(gn_type)
        except Exception:
            values = []
        if values:
            raise bad_csr(
                f"CSR contains unsupported SAN type {gn_type.__name__}; "
                f"only DNSName SANs are accepted"
            )
    # Also iterate the SAN extension to catch any type we didn't explicitly
    # check above (e.g. OtherName via iteration even if get_values_for_type
    # missed it, or future GeneralName subtypes).
    for gn in san_value:
        if not isinstance(gn, DNSName):
            raise bad_csr(
                f"CSR contains unsupported SAN type {type(gn).__name__}; "
                f"only DNSName SANs are accepted"
            )


def _validate_csr_key_strength(csr: x509.CertificateSigningRequest) -> None:
    """M5: enforce minimum key size — RSA ≥ 2048, EC over P-256/P-384/P-521."""
    pub = csr.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 2048:
            raise bad_csr(
                f"RSA key size {pub.key_size} is below the minimum of 2048 bits"
            )
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        allowed_curves: set[str] = {
            "secp256r1", "secp384r1", "secp521r1",
        }
        if pub.curve.name not in allowed_curves:
            raise bad_csr(
                f"EC curve {pub.curve.name} is not accepted; "
                f"allowed curves: P-256, P-384, P-521"
            )
    else:
        raise bad_csr(
            f"unsupported key type {type(pub).__name__}; "
            f"only RSA and EC keys are accepted"
        )


def create_app(context: ServerContext) -> FastAPI:
    """Build a FastAPI app wired to the supplied server context."""
    app = FastAPI(title="acme-adcs-ra", version="0.1.0")
    app.state.context = context

    @app.exception_handler(AcmeError)
    async def acme_exception_handler(request: Request, exc: AcmeError) -> JSONResponse:  # noqa: ARG001
        return JSONResponse(
            status_code=exc.status,
            content=exc.to_problem(),
            headers={"Content-Type": "application/problem+json"},
        )

    def _ctx() -> ServerContext:
        return cast(ServerContext, app.state.context)

    # ------------------------------------------------------------------
    # directory
    # ------------------------------------------------------------------

    @app.get("/directory", response_model=dict)
    async def directory(ctx: ServerContext = Depends(_ctx)) -> dict[str, Any]:
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

    # ------------------------------------------------------------------
    # newNonce
    # ------------------------------------------------------------------

    def _nonce_response(ctx: ServerContext) -> Response:
        nonce = ctx.store.create_nonce()
        return Response(
            status_code=204,
            headers={
                "Replay-Nonce": nonce,
                "Cache-Control": "no-store",
            },
        )

    @app.head(_ACME_PATHS["newNonce"])
    async def new_nonce_head(ctx: ServerContext = Depends(_ctx)) -> Response:
        return _nonce_response(ctx)

    @app.get(_ACME_PATHS["newNonce"])
    async def new_nonce_get(ctx: ServerContext = Depends(_ctx)) -> Response:
        return _nonce_response(ctx)

    # ------------------------------------------------------------------
    # newAccount
    # ------------------------------------------------------------------

    @app.post(_ACME_PATHS["newAccount"])
    async def new_account(
        request: Request,
        ctx: ServerContext = Depends(_ctx),
    ) -> JSONResponse:
        header, payload, account_jwk = await verify_new_account_jws(request, ctx.store)

        eab_jws = payload.get("externalAccountBinding")
        if not isinstance(eab_jws, dict):
            raise bad_external_account_binding("externalAccountBinding is required")

        try:
            eab_header = json.loads(_base64url_decode(eab_jws["protected"]))
        except Exception as exc:
            raise bad_external_account_binding(
                f"invalid externalAccountBinding protected header: {exc}"
            ) from exc
        eab_kid = eab_header.get("kid")
        if not eab_kid:
            raise bad_external_account_binding(
                "externalAccountBinding protected header missing kid"
            )
        mac_key = ctx.config.eab_key_bytes(eab_kid)
        if mac_key is None:
            raise bad_external_account_binding("unknown external account kid")

        try:
            verified_kid = verify_eab_jws(eab_jws, account_jwk, mac_key)
        except JWSValidationError as exc:
            raise bad_external_account_binding(f"EAB verification failed: {exc}") from exc

        contact = payload.get("contact", [])
        if not isinstance(contact, list):
            contact = []

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
            "status": account.status,
            "contact": account.contact,
            "orders": _url(ctx, f"/acme/acct/{account.id}/orders"),
            "externalAccountBinding": eab_jws,
        }
        if ctx.config.terms_of_service:
            body["termsOfServiceAgreed"] = payload.get("termsOfServiceAgreed", False)

        return JSONResponse(
            status_code=201,
            content=body,
            headers={"Location": _account_url(ctx, account.id)},
        )

    # ------------------------------------------------------------------
    # newOrder
    # ------------------------------------------------------------------

    @app.post(_ACME_PATHS["newOrder"])
    async def new_order(
        request: Request,
        ctx: ServerContext = Depends(_ctx),
    ) -> JSONResponse:
        header, payload, account_id = await verify_existing_account_jws(request, ctx.store)

        identifiers_raw = payload.get("identifiers")
        if not isinstance(identifiers_raw, list) or not identifiers_raw:
            raise malformed("newOrder payload must contain a non-empty identifiers list")

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

    # ------------------------------------------------------------------
    # authorization
    # ------------------------------------------------------------------

    @app.get("/acme/authz/{authz_id}")
    async def get_authorization(
        authz_id: str,
        ctx: ServerContext = Depends(_ctx),
    ) -> JSONResponse:
        authz = ctx.store.get_authorization(authz_id)
        if authz is None:
            raise unauthorized("authorization not found")
        return JSONResponse(content=_authz_to_json(authz))

    # ------------------------------------------------------------------
    # challenge
    # ------------------------------------------------------------------

    @app.post("/acme/challenge/{challenge_id}")
    async def post_challenge(
        challenge_id: str,
        request: Request,
        ctx: ServerContext = Depends(_ctx),
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

    def _maybe_ready_order(ctx: ServerContext, order_id: str) -> None:
        order = ctx.store.get_order(order_id)
        if order is None:
            return
        for authz_url in order.authorizations:
            authz_id = authz_url.rsplit("/", 1)[-1]
            authz = ctx.store.get_authorization(authz_id)
            if authz is None or authz.status != "valid":
                return
        ctx.store.update_order_status(order_id, "ready")

    # ------------------------------------------------------------------
    # finalize
    # ------------------------------------------------------------------

    @app.post("/acme/finalize/{order_id}")
    async def finalize_order(
        order_id: str,
        request: Request,
        ctx: ServerContext = Depends(_ctx),
    ) -> JSONResponse:
        header, payload, account_id = await verify_existing_account_jws(request, ctx.store)

        order = ctx.store.get_order(order_id)
        if order is None or order.account_id != account_id:
            raise unauthorized("order not found")

        # M3: idempotent finalize - order already valid.
        if order.status == "valid":
            return JSONResponse(content=_order_to_json(order))

        # M3: double-issuance guard - if a cert already exists for this
        # order, return it instead of re-enrolling.
        existing_cert = ctx.store.get_certificate_by_order(order_id)
        if existing_cert is not None:
            refreshed = ctx.store.get_order(order_id)
            if refreshed is not None:
                return JSONResponse(content=_order_to_json(refreshed))
            raise server_internal("order disappeared after double-finalize check")

        # M3: an order at 'processing' with no cert means another finalize is
        # mid-enrollment (or crashed mid-flight). We MUST NOT re-enroll - that
        # would double-issue. Tell the client to poll. (Crash-recovery
        # reconciliation of a stuck 'processing' order is an ops follow-up.)
        if order.status == "processing":
            return JSONResponse(
                content=_order_to_json(order),
                headers={"Retry-After": "3"},
            )

        if order.status != "ready":
            raise malformed(
                f"order is not ready for finalization (status={order.status})"
            )

        # M3: atomically transition ready -> processing to prevent a
        # concurrent finalize from issuing a second certificate.
        if not ctx.store.transition_order_to_processing(order_id):
            # A concurrent finalize won the CAS; return the processing order.
            refreshed = ctx.store.get_order(order_id)
            if refreshed is not None and refreshed.status == "processing":
                return JSONResponse(
                    content=_order_to_json(refreshed),
                    headers={"Retry-After": "3"},
                )
            raise malformed(
                "order is no longer ready for finalization "
                "(concurrent finalize detected)"
            )

        csr_b64 = payload.get("csr")
        if not isinstance(csr_b64, str) or not csr_b64:
            raise bad_csr("missing or invalid csr field")

        try:
            csr_der = _base64url_decode(csr_b64)
        except Exception as exc:
            raise bad_csr(f"csr is not valid base64url: {exc}") from exc

        try:
            csr = load_der_x509_csr(csr_der)
        except Exception:
            try:
                csr = load_pem_x509_csr(csr_der)
            except Exception as exc2:
                raise bad_csr(f"unable to parse CSR: {exc2}") from exc2

        if not csr.is_signature_valid:
            raise bad_csr("CSR signature is invalid")

        # M5: enforce minimum key strength.
        _validate_csr_key_strength(csr)

        csr_subject = csr.subject.rfc4514_string()

        # M4: reject CSRs with non-DNSName SAN types and collect DNS SANs.
        try:
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except x509.ExtensionNotFound:
            san_values: list[str] = []
        else:
            # Check for non-DNSName SAN types first.
            san_value = cast(x509.SubjectAlternativeName, san_ext.value)
            _reject_non_dns_sans(san_value)
            san_values = [str(v) for v in san_value.get_values_for_type(DNSName)]

        requested_sans = san_values

        account = ctx.store.get_account(account_id)
        if account is None:
            raise unauthorized("account not found")

        decision = ctx.policy.evaluate(
            eab_kid=account.eab_kid,
            csr_subject=csr_subject,
            requested_sans=requested_sans,
        )
        if not decision.allowed:
            _audit(ctx, 
                event_type="finalize-policy-denied",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                outcome="denied",
                details={"reason": decision.reason},
            )
            if "out of scope" in decision.reason or "no SANs" in decision.reason:
                raise rejected_identifier(decision.reason)
            raise bad_csr(decision.reason)

        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        try:
            enrollment_result = ctx.enrollment.submit_csr(
                csr_pem,
                account_id=account_id,
                requested_sans=requested_sans,
            )
        except Exception as exc:
            _audit(ctx, 
                event_type="finalize-enrollment-failed",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                template=decision.template,
                outcome="failed",
                details={"error": str(exc)},
            )
            raise server_internal(f"enrollment failed: {exc}") from exc

        cert_record = ctx.store.create_certificate(
            order_id=order_id,
            account_id=account_id,
            cert_pem=enrollment_result.cert_pem,
            chain_pem=enrollment_result.chain_pem,
            template=enrollment_result.template,
            requester=enrollment_result.requester,
            metadata=dict(enrollment_result.metadata),
        )

        certificate_url = _certificate_url(ctx, cert_record.id)
        ctx.store.update_order_status(
            order_id,
            "valid",
            certificate_url=certificate_url,
        )

        _audit(ctx, 
            event_type="certificate-issued",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=enrollment_result.template,
            requester=enrollment_result.requester,
            outcome="success",
            details={
                "certificate_id": cert_record.id,
                "csr_subject": csr_subject,
            },
        )

        refreshed_order = ctx.store.get_order(order_id)
        if refreshed_order is None:
            raise server_internal("order disappeared after finalization")
        return JSONResponse(content=_order_to_json(refreshed_order))

    # ------------------------------------------------------------------
    # certificate
    # ------------------------------------------------------------------

    @app.get("/acme/cert/{cert_id}")
    async def get_certificate(
        cert_id: str,
        ctx: ServerContext = Depends(_ctx),
    ) -> Response:
        cert = ctx.store.get_certificate(cert_id)
        if cert is None:
            raise unauthorized("certificate not found")
        body = cert.cert_pem + "".join(cert.chain_pem)
        return Response(
            content=body,
            media_type="application/pem-certificate-chain",
        )

    # ------------------------------------------------------------------
    # revokeCert (placeholder)
    # ------------------------------------------------------------------

    @app.post(_ACME_PATHS["revokeCert"])
    async def revoke_cert(
        request: Request,
        ctx: ServerContext = Depends(_ctx),
    ) -> JSONResponse:
        return JSONResponse(
            status_code=501,
            content={
                "type": "urn:ietf:params:acme:error:serverInternal",
                "title": "notImplemented",
                "detail": "revokeCert is not implemented in this phase",
                "status": 501,
            },
        )

    return app


# ---------------------------------------------------------------------------
# JSON serializers
# ---------------------------------------------------------------------------


def _order_to_json(order: Any) -> dict[str, Any]:
    return {
        "status": order.status,
        "expires": order.expires,
        "identifiers": order.identifiers,
        "authorizations": order.authorizations,
        "finalize": order.finalize_url,
        **({"certificate": order.certificate_url} if order.certificate_url else {}),
    }


def _authz_to_json(authz: Any) -> dict[str, Any]:
    return {
        "status": authz.status,
        "identifier": authz.identifier,
        "expires": authz.expires,
        "challenges": [_challenge_to_json(c) for c in authz.challenges],
    }


def _challenge_to_json(challenge: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "type": challenge.type,
        "status": challenge.status,
        "url": challenge.url,
        "token": challenge.token,
    }
    if challenge.validated_at:
        obj["validated"] = challenge.validated_at
    return obj
