"""Finalize-order helpers (WI-001: decomposed from ~350-line handler)."""

from __future__ import annotations

from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import DNSName, load_der_x509_csr
from cryptography.x509.oid import ExtensionOID
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import (
    bad_csr,
    malformed,
    rejected_identifier,
    server_internal,
    unauthorized,
)
from acme_adcs_ra.app_state import (
    ServerContext,
    _audit,
    _certificate_url,
    logger,
)
from acme_adcs_ra.csr_validation import (
    _reject_invalid_dns_sans,
    _reject_non_dns_sans,
    _reject_wildcard_sans,
    _validate_csr_key_strength,
)
from acme_adcs_ra.enrollment import (
    EnrollmentDenied,
    EnrollmentResult,
    EnrollmentTransportError,
)
from acme_adcs_ra.jws import _base64url_decode
from acme_adcs_ra.policy import PolicyDecision
from acme_adcs_ra.serializers import _order_to_json
from acme_adcs_ra.store import (
    CertificateRecord,
    OrderRecord,
    OrderStatus,
    is_expired,
)


def _refresh_order_or_500(
    ctx: ServerContext, order_id: str, context: str,
) -> OrderRecord:
    """Refresh the order after a lost CAS race, or raise 500 if it disappeared."""
    refreshed = ctx.store.get_order(order_id)
    if refreshed is None:
        raise server_internal(f"order disappeared {context}")
    return refreshed


def _finalize_existing_cert(
    ctx: ServerContext, order_id: str, account_id: str,
    existing_cert: CertificateRecord,
) -> JSONResponse:
    """Handle a finalize call when a cert already exists for this order.

    Self-heals the crash window between create_certificate and the status flip
    to 'valid': a cert row exists, so issuance definitively succeeded — close
    the loop so the client isn't left polling a 'processing' order with no
    certificate URL. CAS-guarded (only processing->valid), no re-enrollment,
    no double-issuance.
    """
    refreshed = _refresh_order_or_500(ctx, order_id, "after double-finalize check")
    if refreshed.status == OrderStatus.PROCESSING:
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
        refreshed = _refresh_order_or_500(ctx, order_id, "after reconcile")
    return JSONResponse(content=_order_to_json(refreshed))


def _finalize_expired_order(
    ctx: ServerContext, order_id: str, account_id: str, order: OrderRecord,
) -> JSONResponse | None:
    """If order is expired, CAS-flip to invalid and raise/return.

    Returns None if the order is not expired.
    Returns a JSONResponse if the CAS lost the race (return current state).
    Raises malformed if the CAS applied (order is definitively expired).
    """
    if not is_expired(order.expires):
        return None
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
    refreshed = _refresh_order_or_500(ctx, order_id, "during expiry check")
    if refreshed.status == OrderStatus.VALID:
        return JSONResponse(content=_order_to_json(refreshed))
    if refreshed.status == OrderStatus.PROCESSING:
        return JSONResponse(
            content=_order_to_json(refreshed), headers={"Retry-After": "3"}
        )
    raise malformed(
        f"order has expired (expires={order.expires}); "
        f"create a new order to retry"
    )


def _finalize_parse_and_validate_csr(
    ctx: ServerContext,
    payload: dict[str, Any],
    order: OrderRecord,
    account_id: str,
    order_id: str,
) -> tuple[x509.CertificateSigningRequest, str, list[str], PolicyDecision]:
    """Parse CSR, validate key strength/SANs, check against order, evaluate policy.

    All validation runs while the order is still 'ready'. The transition to
    'processing' (the point-of-no-return CAS) happens only after this passes,
    so a rejected CSR or policy denial leaves the order retryable.

    Returns (csr, csr_subject, requested_sans, decision).
    """
    csr_b64 = payload.get("csr")
    if not isinstance(csr_b64, str) or not csr_b64:
        raise bad_csr("missing or invalid csr field")

    try:
        csr_der = _base64url_decode(csr_b64)
    except Exception as exc:
        raise bad_csr(f"csr is not valid base64url: {exc}") from exc

    if len(csr_der) > ctx.config.max_csr_size_bytes:
        raise bad_csr(
            f"CSR too large (max {ctx.config.max_csr_size_bytes} bytes, got {len(csr_der)})"
        )

    try:
        csr = load_der_x509_csr(csr_der)
    except Exception as exc:
        raise bad_csr(f"unable to parse CSR: {exc}") from exc

    if not csr.is_signature_valid:
        raise bad_csr("CSR signature is invalid")

    _validate_csr_key_strength(csr)

    csr_subject = csr.subject.rfc4514_string()

    try:
        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        san_values: list[str] = []
    else:
        san_value = cast(x509.SubjectAlternativeName, san_ext.value)
        _reject_non_dns_sans(san_value)
        san_values = [str(v) for v in san_value.get_values_for_type(DNSName)]
        _reject_wildcard_sans(san_values)
        _reject_invalid_dns_sans(san_values)

    requested_sans = san_values

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

    return csr, csr_subject, requested_sans, decision


def _finalize_transition_to_processing(
    ctx: ServerContext, order_id: str,
) -> JSONResponse | None:
    """Atomically transition ready→processing.

    Returns None on success (proceed with enrollment).
    Returns a JSONResponse if the CAS lost the race (return current state).
    """
    if ctx.store.transition_order_to_processing(order_id):
        return None
    refreshed = _refresh_order_or_500(ctx, order_id, "during finalization")
    if refreshed.status == OrderStatus.PROCESSING:
        return JSONResponse(
            content=_order_to_json(refreshed), headers={"Retry-After": "3"}
        )
    return JSONResponse(content=_order_to_json(refreshed))


def _finalize_submit_enrollment(
    ctx: ServerContext,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    csr: x509.CertificateSigningRequest,
    csr_subject: str,
    decision: PolicyDecision,
) -> EnrollmentResult | JSONResponse:
    """Submit CSR to enrollment.

    Returns EnrollmentResult on success, or JSONResponse on recoverable error
    (enrollment denied with lost race, or transport error).
    Raises on unrecoverable error.
    """
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    try:
        return ctx.enrollment.submit_csr(
            csr_pem,
            account_id=account_id,
            requested_sans=requested_sans,
        )
    except EnrollmentDenied as exc:
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
            refreshed = _refresh_order_or_500(
                ctx, order_id, "during enrollment denial"
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
        order = _refresh_order_or_500(
            ctx, order_id, "during enrollment transport error"
        )
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


def _finalize_complete(
    ctx: ServerContext,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    csr_subject: str,
    decision: PolicyDecision,
    enrollment_result: EnrollmentResult,
) -> JSONResponse:
    """Record the certificate and transition to valid.

    Handles the post-enrollment completion: create cert record, CAS-flip
    processing→valid, audit, and return the final order state.
    """
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

    refreshed_order = _refresh_order_or_500(ctx, order_id, "after finalization")
    return JSONResponse(content=_order_to_json(refreshed_order))
