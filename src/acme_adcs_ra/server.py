"""FastAPI ACME server (RFC 8555 subset) for the ADCS Registration Authority.

This module only **verifies** JWS signatures and CSRs; it never signs anything.
The enrollment leg (``EnrollmentLeg``) forwards accepted CSRs to ADCS.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, cast

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import (
    DNSName,
    load_der_x509_csr,
    load_pem_x509_csr,
)
from cryptography.x509.oid import ExtensionOID

from acme_adcs_ra.acme_errors import (
    AcmeError,
    account_does_not_exist,
    bad_csr,
    bad_external_account_binding,
    bad_revocation_reason,
    malformed,
    not_found,
    rejected_identifier,
    server_internal,
    unauthorized,
    unsupported_identifier,
)
from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.enrollment import (
    EnrollmentLeg,
    EnrollmentDenied,
    EnrollmentTransportError,
)
from acme_adcs_ra.jws import JWSValidationError, verify_eab_jws, _base64url_decode
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import RevocationLeg
from acme_adcs_ra.server_jws import (
    verify_existing_account_jws,
    verify_new_account_jws,
)
from acme_adcs_ra.siem import SiemEmitter, build_siem_config
from acme_adcs_ra.store import Store, _now_iso, is_expired

logger = logging.getLogger("acme_adcs_ra.server")


def _dummy_hmac(eab_jws: dict[str, Any]) -> None:
    """Perform a dummy HMAC to equalize timing on unknown EAB kid path.

    This mitigates the kid-existence timing side-channel (threat-model §4.B).
    """
    protected_b64 = eab_jws.get("protected", "")
    payload_b64 = eab_jws.get("payload", "")
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    # Use a fixed dummy key - the result is discarded, only the time matters.
    dummy_key = b"dummy-timing-equalization-key-32-bytes!!"
    hmac.new(dummy_key, signing_input, hashlib.sha256).digest()


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
    revocation: RevocationLeg
    # Optional extension hook for SIEM emission (Phase 3).  Called after the
    # audit row is persisted, unconditionally, for every issuance event.
    # When None, create_app wires the default SIEM emitter from config.
    audit_hook: Callable[[dict[str, Any]], None] | None = None


def _audit(ctx: ServerContext, **kwargs: Any) -> None:
    """Persist an audit row and notify the optional SIEM hook."""
    event = ctx.store.record_audit(**kwargs)
    if ctx.audit_hook is not None:
        try:
            ctx.audit_hook(event)
        except Exception:
            logger.warning(
                "audit hook failed for event_type=%s; continuing",
                event.get("event_type"),
                exc_info=True,
            )


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


def _reject_non_dns_sans(san_value: x509.SubjectAlternativeName) -> None:
    """M4: reject the CSR if it contains any non-DNSName SAN type.

    With server-auth-only scope, IPAddress/otherName/URI/RFC822Name SANs
    are an expansion risk — the ADCS template might honor them.
    """
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


def _default_siem_emitter(config: RAConfig) -> SiemEmitter:
    """Build the default SIEM emitter from RAConfig."""
    return SiemEmitter(build_siem_config(config))


def create_app(context: ServerContext) -> FastAPI:
    """Build a FastAPI app wired to the supplied server context."""
    # Wire the default SIEM emitter when no test/operator hook is supplied.
    _siem_emitter: SiemEmitter | None = None
    if context.audit_hook is None:
        _siem_emitter = _default_siem_emitter(context.config)
        context.audit_hook = _siem_emitter.export

    # H-3: shut down the SIEM emitter pool on app shutdown via lifespan.
    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> Any:  # noqa: ARG001
        yield
        if _siem_emitter is not None:
            _siem_emitter.close()

    app = FastAPI(title="acme-adcs-ra", version="0.1.0", lifespan=_lifespan)
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

    def _require_admin_token(request: Request, ctx: ServerContext) -> None:
        """Verify the Authorization: Bearer <admin_token> header."""
        admin_token = ctx.config.admin_token.get_secret_value()
        if not admin_token:
            raise unauthorized("admin endpoint not configured")
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise unauthorized("missing Bearer token")
        provided = auth_header.split(" ", 1)[1]
        if not hmac.compare_digest(provided, admin_token):
            raise unauthorized("invalid admin token")

    # Administrative: explicit nonce cleanup endpoint for cron (replaces
    # probabilistic GC). Returns count of deleted nonces. Requires Bearer token.
    @app.delete("/acme/admin/nonces")
    async def cleanup_nonces(
        request: Request, ctx: ServerContext = Depends(_ctx)
    ) -> JSONResponse:
        _require_admin_token(request, ctx)
        deleted = ctx.store.cleanup_expired_nonces()
        _audit(ctx,
            event_type="admin-nonce-cleanup",
            outcome="success",
            details={"deleted": deleted},
        )
        return JSONResponse(content={"deleted": deleted})

    # Administrative: sweep expired orders to 'invalid' (RFC 8555 §7.1.6).
    # Intended for an external cron; expiry is also enforced lazily at finalize.
    @app.delete("/acme/admin/expired-orders")
    async def sweep_expired_orders(
        request: Request, ctx: ServerContext = Depends(_ctx)
    ) -> JSONResponse:
        _require_admin_token(request, ctx)
        invalidated = ctx.store.sweep_expired_orders()
        _audit(ctx,
            event_type="admin-expired-order-sweep",
            outcome="success",
            details={"invalidated": invalidated},
        )
        return JSONResponse(content={"invalidated": invalidated})

    # Administrative: reconcile an order wedged in 'processing' after a crash
    # mid-enrollment. See Store.transition_processing_to_ready / _to_valid for
    # the two-branch recovery and its double-issuance precondition.
    @app.post("/acme/admin/orders/{order_id}/reclaim-processing")
    async def reclaim_processing_order(
        order_id: str,
        request: Request,
        ctx: ServerContext = Depends(_ctx),
    ) -> JSONResponse:
        _require_admin_token(request, ctx)
        order = ctx.store.get_order(order_id)
        if order is None:
            # Audit the probe — a stolen admin token enumerating order IDs is a
            # meaningful reconnaissance signal (threat-model §4.A/§4.F).
            _audit(ctx,
                event_type="admin-order-reclaim-denied",
                order_id=order_id,
                outcome="failed",
                details={"reason": "order-not-found"},
            )
            raise not_found("order not found")

        # Idempotent no-op for anything not actually stuck in 'processing'.
        # Audited so a stolen admin token probing many order IDs is visible.
        if order.status != "processing":
            _audit(ctx,
                event_type="admin-order-reclaim-noop",
                order_id=order_id,
                account_id=order.account_id,
                outcome="noop",
                details={"reason": "not-processing", "order_status": order.status},
            )
            return JSONResponse(content=_order_to_json(order))

        existing_cert = ctx.store.get_certificate_by_order(order_id)
        if existing_cert is not None:
            # Enrollment succeeded but the status flip was missed — close the
            # loop safely (no re-enrollment, no double-issuance).
            certificate_url = _certificate_url(ctx, existing_cert.id)
            applied = ctx.store.transition_processing_to_valid(order_id, certificate_url)
            new_status = "valid"
            had_certificate = True
        else:
            # No cert recorded — the operator has verified at the ADCS CA DB
            # that no cert was issued for this request before calling this.
            applied = ctx.store.transition_processing_to_ready(order_id)
            new_status = "ready"
            had_certificate = False

        if not applied:
            # Lost a race with a concurrent finalize/reclaim; audit + return state.
            refreshed = ctx.store.get_order(order_id)
            if refreshed is None:
                raise server_internal("order disappeared during reclaim")
            _audit(ctx,
                event_type="admin-order-reclaim-denied",
                order_id=order_id,
                account_id=order.account_id,
                outcome="failed",
                details={"reason": "lost-race", "current_status": refreshed.status},
            )
            return JSONResponse(content=_order_to_json(refreshed))

        _audit(ctx,
            event_type="admin-order-reclaimed",
            order_id=order_id,
            account_id=order.account_id,
            outcome="success",
            details={
                "new_status": new_status,
                "had_certificate": had_certificate,
            },
        )
        refreshed = ctx.store.get_order(order_id)
        if refreshed is None:
            raise server_internal("order disappeared after reclaim")
        return JSONResponse(content=_order_to_json(refreshed))

    # Administrative: list orders by status — primarily for monitoring
    # stuck-processing orders (threat-model §4.D: monitor time-in-
    # ``processing`` p99). Requires admin token. Returns a minimal admin
    # view (no SANs/cert URLs) to limit blast radius of a stolen token.
    @app.get("/acme/admin/orders")
    async def list_orders(
        request: Request,
        ctx: ServerContext = Depends(_ctx),
        status: str = "processing",
        limit: int = 100,
    ) -> JSONResponse:
        _require_admin_token(request, ctx)
        valid_statuses = {
            "processing", "valid", "invalid", "ready", "pending", "revoked",
        }
        if status not in valid_statuses:
            raise malformed(f"invalid status filter: {status}")
        if not 1 <= limit <= 500:
            raise malformed("limit must be between 1 and 500")
        orders = ctx.store.list_orders_by_status(status, limit=limit)
        _audit(ctx,
            event_type="admin-list-orders",
            outcome="success",
            details={"status": status, "limit": limit, "returned": len(orders)},
        )
        return JSONResponse(
            content={"orders": [_order_to_admin_json(o) for o in orders]}
        )

    # ------------------------------------------------------------------
    # newAccount
    # ------------------------------------------------------------------

    @app.post(_ACME_PATHS["newAccount"])
    async def new_account(
        request: Request,
        ctx: ServerContext = Depends(_ctx),
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
        # Only a pending order advances to ready. Without this, re-POSTing a
        # challenge on an already valid/processing order would regress it to
        # ready (a state machine regression; finalize's guards prevent a double
        # issue, but the regression is still wrong).
        if order.status != "pending":
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
            if refreshed is None:
                raise server_internal("order disappeared after double-finalize check")
            # Self-heal the crash window between create_certificate and the
            # status flip to 'valid': a cert row exists, so issuance definitively
            # succeeded — close the loop so the client isn't left polling a
            # 'processing' order with no certificate URL. CAS-guarded (only
            # processing->valid), no re-enrollment, no double-issuance. Only
            # audit success when the CAS actually applied; on a lost race the
            # winner records the reconcile and we just return current state.
            if refreshed.status == "processing":
                certificate_url = _certificate_url(ctx, existing_cert.id)
                applied = ctx.store.transition_processing_to_valid(order_id, certificate_url)
                if applied:
                    _audit(ctx,
                        event_type="finalize-order-reconciled",
                        account_id=account_id,
                        order_id=order_id,
                        outcome="success",
                        details={
                            "certificate_id": existing_cert.id,
                            "prior_status": refreshed.status,
                        },
                    )
                refreshed = ctx.store.get_order(order_id)
                if refreshed is None:
                    raise server_internal("order disappeared after reconcile")
            return JSONResponse(content=_order_to_json(refreshed))

        # M3: an order at 'processing' with no cert means another finalize is
        # mid-enrollment (or crashed mid-flight). We MUST NOT re-enroll - that
        # would double-issue. Tell the client to poll. (Crash-recovery
        # reconciliation of a stuck 'processing' order is an ops follow-up.)
        if order.status == "processing":
            return JSONResponse(
                content=_order_to_json(order),
                headers={"Retry-After": "3"},
            )

        # RFC 8555 §7.1.6: an expired order MUST NOT be issued against. CAS-flip
        # pending/ready orders past their `expires` to `invalid` and refuse.
        # The CAS (status IN pending/ready) is load-bearing: without it, a
        # concurrent finalize that already moved this order to 'processing'
        # would be clobbered to 'invalid' out from under a live enrollment
        # (corrupting the audit trail and transient state).
        if is_expired(order.expires):
            applied = ctx.store.transition_active_to_invalid(order_id)
            if applied:
                _audit(ctx,
                    event_type="finalize-expired-order",
                    account_id=account_id,
                    order_id=order_id,
                    outcome="denied",
                    details={"expires": order.expires},
                )
                raise malformed(
                    f"order has expired (expires={order.expires}); "
                    f"create a new order to retry"
                )
            # Lost the race: a concurrent finalize/reclaim moved the order out
            # of pending/ready after our snapshot. Return its current state
            # rather than erroring on a stale view.
            refreshed = ctx.store.get_order(order_id)
            if refreshed is None:
                raise server_internal("order disappeared during expiry check")
            if refreshed.status == "valid":
                return JSONResponse(content=_order_to_json(refreshed))
            if refreshed.status == "processing":
                return JSONResponse(
                    content=_order_to_json(refreshed), headers={"Retry-After": "3"}
                )
            raise malformed(
                f"order has expired (expires={order.expires}); "
                f"create a new order to retry"
            )

        if order.status != "ready":
            raise malformed(
                f"order is not ready for finalization (status={order.status})"
            )

        # NOTE: all CSR validation and policy evaluation below run while the
        # order is still 'ready'. The transition to 'processing' (the
        # point-of-no-return CAS) happens only after they pass, so a rejected
        # CSR or policy denial leaves the order retryable instead of wedging it
        # in 'processing' forever.
        csr_b64 = payload.get("csr")
        if not isinstance(csr_b64, str) or not csr_b64:
            raise bad_csr("missing or invalid csr field")

        try:
            csr_der = _base64url_decode(csr_b64)
        except Exception as exc:
            raise bad_csr(f"csr is not valid base64url: {exc}") from exc

        # DoS cap: max CSR size (threat-model §4.G)
        if len(csr_der) > ctx.config.max_csr_size_bytes:
            raise bad_csr(
                f"CSR too large (max {ctx.config.max_csr_size_bytes} bytes, got {len(csr_der)})"
            )

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

        # RFC 8555 §7.4: the CSR must not request identifiers beyond the order's.
        # Without this, the order/authz machinery is decorative and the issued
        # SANs are gated only by EAB policy — the authorized identifier set and
        # the issued cert could diverge. Compare case-insensitively (RFC 4343).
        order_dns = {
            i["value"].lower()
            for i in order.identifiers
            if i.get("type") == "dns" and isinstance(i.get("value"), str)
        }
        out_of_order = sorted(s for s in requested_sans if s.lower() not in order_dns)
        if out_of_order:
            _audit(
                ctx,
                event_type="finalize-csr-mismatch",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                outcome="denied",
                details={
                    "reason": "CSR SANs not in order identifiers",
                    "out_of_order": out_of_order,
                },
            )
            raise rejected_identifier(
                "CSR contains identifiers not present in the order: "
                + ", ".join(out_of_order)
            )

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

        # Point of no return: atomically transition ready -> processing so a
        # concurrent finalize cannot issue a second certificate. Done only now,
        # after all validation has passed, so failed validation never wedges the
        # order in 'processing'.
        if not ctx.store.transition_order_to_processing(order_id):
            refreshed = ctx.store.get_order(order_id)
            if refreshed is not None and refreshed.status == "processing":
                return JSONResponse(
                    content=_order_to_json(refreshed),
                    headers={"Retry-After": "3"},
                )
            # Lost the race to a finalize that already produced a cert, or the
            # order otherwise moved on — return its current state.
            if refreshed is not None:
                return JSONResponse(content=_order_to_json(refreshed))
            raise server_internal("order disappeared during finalization")

        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        try:
            enrollment_result = ctx.enrollment.submit_csr(
                csr_pem,
                account_id=account_id,
                requested_sans=requested_sans,
            )
        except EnrollmentDenied as exc:
            # The CA definitively denied the request (policy violation) — no cert
            # was issued, so reverting to 'ready' is safe. Use the CAS-guarded
            # transition so a concurrent reclaim or finalize self-heal that
            # already moved the order cannot be clobbered (threat-model §4.D).
            applied = ctx.store.transition_processing_to_ready(order_id)
            _audit(ctx,
                event_type="finalize-enrollment-denied",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                template=decision.template,
                outcome="denied",
                details={"error": str(exc), "revert_applied": applied},
            )
            if not applied:
                # Lost the race: a concurrent reclaim or self-heal already moved
                # the order. Return its current state instead of clobbering it.
                refreshed = ctx.store.get_order(order_id)
                if refreshed is None:
                    raise server_internal(
                        "order disappeared during enrollment denial"
                    )
                return JSONResponse(content=_order_to_json(refreshed))
            raise rejected_identifier(str(exc)) from exc
        except EnrollmentTransportError as exc:
            _audit(ctx,
                event_type="finalize-enrollment-transport-failed",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                template=decision.template,
                outcome="failed",
                details={"error": str(exc)},
            )
            order = ctx.store.get_order(order_id)
            if order is None:
                raise server_internal("order disappeared during enrollment transport error")
            return JSONResponse(
                status_code=503,
                content=_order_to_json(order),
                headers={"Retry-After": "30"},
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

        # Re-check for an existing cert before creating one. A concurrent
        # self-heal or reclaim-to-valid may have already recorded a cert for
        # this order; if so, use it instead of inserting a duplicate row.
        existing_cert = ctx.store.get_certificate_by_order(order_id)
        if existing_cert is not None:
            cert_record = existing_cert
        else:
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
        applied = ctx.store.transition_processing_to_valid(
            order_id, certificate_url
        )

        if applied:
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
        else:
            # Lost the CAS race with a concurrent reclaim or finalize self-heal.
            # Audit the anomaly for operator investigation — this indicates the
            # RA's view of an issuance diverged from its own store.
            refreshed = ctx.store.get_order(order_id)
            winner_cert_id = (
                refreshed.certificate_url.rsplit("/", 1)[-1]
                if refreshed and refreshed.certificate_url
                else None
            )
            _audit(ctx,
                event_type="finalize-enrollment-race",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                template=enrollment_result.template,
                requester=enrollment_result.requester,
                outcome="failed",
                details={
                    "certificate_id": cert_record.id,
                    "winner_certificate_id": winner_cert_id,
                    "reason": "lost-processing-cas",
                },
            )
            logger.error(
                "finalize CAS lost race for order %s; cert %s recorded but "
                "order was moved by a concurrent operation (winner cert=%s)",
                order_id,
                cert_record.id,
                winner_cert_id,
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
        # H-1: revoked certs must not be installable — return 410 Gone.
        if cert.status == "revoked":
            return Response(status_code=410)
        body = cert.cert_pem + "".join(cert.chain_pem)
        return Response(
            content=body,
            media_type="application/pem-certificate-chain",
        )

    # ------------------------------------------------------------------
    # revokeCert (RFC 8555 §7.6)
    # ------------------------------------------------------------------

    @app.post(_ACME_PATHS["revokeCert"])
    async def revoke_cert(
        request: Request,
        ctx: ServerContext = Depends(_ctx),
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

        if cert_record.status == "revoked":
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
        ctx.store.update_order_status(cert_record.order_id, "revoked")

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

    return app


# ---------------------------------------------------------------------------
# JSON serializers
# ---------------------------------------------------------------------------


def _account_to_json(context: ServerContext, account: Any) -> dict[str, Any]:
    return {
        "status": account.status,
        "contact": account.contact,
        "orders": _url(context, f"/acme/acct/{account.id}/orders"),
    }


def _order_to_json(order: Any) -> dict[str, Any]:
    return {
        "status": order.status,
        "expires": order.expires,
        "identifiers": order.identifiers,
        "authorizations": order.authorizations,
        "finalize": order.finalize_url,
        **({"certificate": order.certificate_url} if order.certificate_url else {}),
        **({"processing_started_at": order.processing_started_at}
           if order.processing_started_at else {}),
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


def _order_to_admin_json(order: Any) -> dict[str, Any]:
    """Minimal admin view — no SANs or certificate URLs (blast-radius bound)."""
    obj: dict[str, Any] = {
        "id": order.id,
        "account_id": order.account_id,
        "status": order.status,
        "expires": order.expires,
        "created_at": order.created_at,
        "updated_at": order.updated_at,
    }
    if order.processing_started_at:
        obj["processing_started_at"] = order.processing_started_at
    return obj
