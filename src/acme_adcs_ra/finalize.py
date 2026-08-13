"""Finalize-order helpers (WI-001: decomposed from ~350-line handler)."""

from __future__ import annotations

from typing import Any, NoReturn, cast

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
    emit_audit_hook,
    logger,
)
from acme_adcs_ra.csr_validation import (
    _reject_ca_capable_csr_extensions,
    _reject_invalid_dns_sans,
    _reject_non_dns_sans,
    _reject_unrequested_common_names,
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
        # Guarded on the lease we just read: this call does not hold one, so if
        # the order's lease moved on between the read and here, the decision
        # this branch was made on is stale and the CAS must lose.
        applied = ctx.store.transition_processing_to_valid(
            order_id,
            certificate_url,
            expected_generation=refreshed.processing_generation,
        )
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

    # The template takes the subject and extensions from the request.  Scope
    # the legacy CN identity path and reject any attempt to request a CA-capable
    # certificate before the CSR reaches ADCS.
    _reject_ca_capable_csr_extensions(csr)

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

    _reject_unrequested_common_names(csr, requested_sans)

    return csr, csr_subject, requested_sans, decision


def _finalize_transition_to_processing(
    ctx: ServerContext, order_id: str,
) -> int | JSONResponse:
    """Atomically transition ready→processing and take the enrollment lease.

    Returns the lease generation (an ``int >= 1``) on success — the caller
    must carry it to the worker and hand it back on every lease re-check.
    Returns a JSONResponse if the CAS lost the race (return current state).
    """
    generation = ctx.store.acquire_processing_lease(order_id)
    if generation is not None:
        return generation
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
    generation: int,
) -> EnrollmentResult | JSONResponse:
    """Submit CSR to enrollment, if this call still owns the order.

    Runs on a threadpool thread. ``generation`` is the lease minted by the
    ``ready``→``processing`` CAS that admitted this call; it is re-checked
    against the store here, *immediately* before the CA is touched, because
    an arbitrary amount of wall-clock time can pass between the CAS and this
    function actually running — the threadpool may be saturated, and the task
    can sit queued past the reclaim age floor. In that window an operator can
    truthfully verify at the CA that nothing was issued, reclaim the order to
    ``ready``, and a second finalize can take a fresh lease. Submitting anyway
    would put two requests for one order in front of ADCS.

    Returns EnrollmentResult on success, or JSONResponse on recoverable error
    (stale lease, enrollment denied with lost race, or transport error).
    Raises on unrecoverable error.
    """
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    stale = _abandon_if_lease_lapsed(
        ctx, order_id, account_id, requested_sans, decision, generation
    )
    if stale is not None:
        return stale
    return _submit_enrollment_inner(
        ctx, order_id, account_id, requested_sans, csr_pem, decision, generation
    )


def _abandon_if_lease_lapsed(
    ctx: ServerContext,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    decision: PolicyDecision,
    generation: int,
) -> JSONResponse | None:
    """Return a response (and audit) if this call no longer owns the order.

    Returns None when the lease is still held and the caller should proceed.

    There is exactly one place this can be asked, and it is deliberate:
    immediately before ``submit_csr``. Once the CA has issued, the answer stops
    mattering — the certificate exists and must be recorded whether or not the
    order moved on, which is what ``record_issuance`` does (row written, order
    flip lease-scoped). A lease check *after* issuance could only choose to
    orphan a live certificate, which is the defect the earlier reviews closed.

    The abandoning call must not write to the order: it does not own it any
    more, and whoever does is mid-flight. It reports the order's *current*
    state to its own client, which is the truthful answer — the client's
    finalize was superseded, and the order status tells it what to do next.

    The audit row is the operator's signal that a reclaim landed on a request
    that was still queued. It should be rare; if it is not, the threadpool is
    saturated and the reclaim floor is being crossed by ordinary queueing.
    """
    if ctx.store.holds_processing_lease(order_id, generation):
        return None
    order = _refresh_order_or_500(ctx, order_id, "after a lapsed lease")
    _audit(ctx,
        event_type="finalize-enrollment-abandoned",
        account_id=account_id,
        order_id=order_id,
        sans=requested_sans,
        template=decision.template,
        outcome="denied",
        details={
            "reason": "processing-lease-lapsed",
            "stage": "before-submit",
            "held_generation": generation,
            "current_generation": order.processing_generation,
            "current_status": order.status,
        },
    )
    logger.warning(
        "abandoned enrollment for order %s before submitting to the CA: this "
        "call held processing generation %d but the order is now %s at "
        "generation %d. The CA was NOT called. A reclaim (or a competing "
        "finalize) took the order while this request was queued.",
        order_id, generation, order.status, order.processing_generation,
    )
    return JSONResponse(
        content=_order_to_json(order), headers={"Retry-After": "3"}
    )


def _submit_enrollment_inner(
    ctx: ServerContext,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    csr_pem: str,
    decision: PolicyDecision,
    generation: int,
) -> EnrollmentResult | JSONResponse:
    try:
        return ctx.enrollment.submit_csr(
            csr_pem,
            account_id=account_id,
            requested_sans=requested_sans,
        )
    except EnrollmentDenied as exc:
        # Revert only our own lease: if the order moved on while the CA was
        # deciding, releasing it back to `ready` would hand a client a second
        # finalize against work someone else now owns.
        applied = ctx.store.transition_processing_to_ready(
            order_id, expected_generation=generation
        )
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
        if exc.ca_issued:
            # The CA issued and then something downstream failed — the leaf
            # fetch, the PKCS#7 chain fetch, or the chain-binds-to-leaf check.
            # A live, domain-trusted certificate exists at the CA. Recording
            # only the error string (the previous behaviour) left it an
            # untracked orphan whose serial appeared nowhere in the RA, which
            # is the same defect the post-issuance verifiers were fixed for.
            return _quarantine_transport_orphan(
                ctx,
                order_id=order_id,
                account_id=account_id,
                requested_sans=requested_sans,
                template=decision.template,
                exc=exc,
                generation=generation,
            )
        _audit(ctx,
            event_type="finalize-enrollment-transport-failed",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=decision.template,
            outcome="failed",
            details={"error": str(exc), "ca_issued": False},
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


# SAN types that carry identity but are NOT DNS. A server-auth-only template
# driven by the CSR must never emit any of these; their presence on an issued
# cert means the template is misconfigured (or pulling from AD). The RA's CSR
# gate already rejects non-DNS SANs — this enforces the same on the *result*.
_NON_DNS_SAN_TYPES: tuple[tuple[type, str], ...] = (
    (x509.RFC822Name, "RFC822Name (email)"),
    (x509.IPAddress, "IPAddress"),
    (x509.UniformResourceIdentifier, "URI"),
    (x509.OtherName, "OtherName"),
    (x509.RegisteredID, "RegisteredID"),
    (x509.DirectoryName, "DirectoryName"),
)


def _issued_cert_san_violations(
    cert_pem: str, requested_sans: list[str]
) -> tuple[list[str], list[str], list[str]]:
    """MED-1: inspect the *issued* cert for SANs the order did not authorize.

    The RA enforces SAN-scope policy on the *request* (the CSR), but the ADCS
    template ultimately decides what SANs land on the cert. If the template is
    misconfigured (e.g. it maps SANs from AD rather than the request, or appends
    extras), the issued cert could authorize identities the RA's policy never
    approved — and a relying party would trust them. This closes that gap by
    inspecting the *result*:

    - every DNS SAN on the issued cert must be in the authorized set (the
      order's requested_sans), compared with the same normalization the policy
      uses — ``rstrip('.').lower()`` — so a trailing-dot/FQDN form or a case
      difference cannot cause a false rejection;
    - NO non-DNS SAN (email, IP, URI, OtherName, …) may be present at all —
      the CSR gate already rejects these, so their presence means the template
      bypassed the request.

    Returns ``(issued_dns_sans, unauthorized_dns, non_dns_san_types)``. A cert
    with no SAN extension yields ``([], [], [])``. The caller fails closed
    (500 + audit, no cert recorded) if either violation list is non-empty.
    """
    try:
        issued = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive; enrollment parsed it
        raise server_internal(f"issued cert unparseable: {exc}") from exc
    try:
        san_ext = issued.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return [], [], []
    san_value = cast(x509.SubjectAlternativeName, san_ext.value)
    issued_dns = [str(v) for v in san_value.get_values_for_type(DNSName)]
    authorized = {s.rstrip(".").lower() for s in requested_sans}
    unauthorized = [
        s for s in issued_dns if s.rstrip(".").lower() not in authorized
    ]
    non_dns = [
        label
        for san_type, label in _NON_DNS_SAN_TYPES
        if san_value.get_values_for_type(san_type)
    ]
    return issued_dns, unauthorized, non_dns


# WI-026: serverAuth is the ONLY EKU a server-authentication template may issue.
# A cert with NO EKU extension is all-purpose; anyExtendedKeyUsage is likewise
# unbounded; clientAuth/PKINIT would enable authenticating *as* a principal — the
# domain-takeover escalation the threat model names as the worst case short of a
# signing key. The "blast radius bounded to spoofing internal TLS" guarantee
# otherwise rests entirely on ADCS template config; this enforces it on the
# *result* so a misconfigured/swapped template cannot silently break it.
_SERVER_AUTH_EKU_OID = "1.3.6.1.5.5.7.3.1"
_EKU_OID_LABELS: dict[str, str] = {
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "2.5.29.37.0": "anyExtendedKeyUsage",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.4.1.311.20.2.2": "smartcardLogon",
    "1.3.6.1.5.2.3.3": "pkinitKDC",
    "1.3.6.1.5.2.3.4": "pkinitClientAuth",
    "1.3.6.1.5.2.3.5": "pkinitServerAuth",
}


def _issued_cert_eku_violations(cert_pem: str) -> list[str]:
    """WI-026: verify the *issued* cert's Extended Key Usage is exactly serverAuth.

    Returns a list of human-readable violations (empty = serverAuth-only). The
    caller fails closed (audit + 500, no cert recorded/served) on any violation,
    exactly as MED-1's SAN check does. Rejects: a missing EKU extension (a
    no-EKU cert is all-purpose), anyExtendedKeyUsage, and any EKU OID other than
    serverAuth (clientAuth, PKINIT, code-signing, …).
    """
    try:
        issued = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive; enrollment parsed it
        raise server_internal(f"issued cert unparseable: {exc}") from exc
    try:
        eku_ext = issued.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    except x509.ExtensionNotFound:
        return ["no Extended Key Usage extension (certificate is all-purpose)"]
    eku_value = cast(x509.ExtendedKeyUsage, eku_ext.value)
    oids = [oid.dotted_string for oid in eku_value]
    violations: list[str] = []
    non_server = [o for o in oids if o != _SERVER_AUTH_EKU_OID]
    if non_server:
        labelled = [
            f"{_EKU_OID_LABELS[o]} ({o})" if o in _EKU_OID_LABELS else o for o in non_server
        ]
        violations.append(f"EKU beyond serverAuth: {labelled}")
    if _SERVER_AUTH_EKU_OID not in oids:
        violations.append("serverAuth EKU (1.3.6.1.5.5.7.3.1) absent")
    return violations


def _issued_cert_ca_capability_violations(cert_pem: str) -> list[str]:
    """Reject an issued certificate that could act as a subordinate CA."""
    try:
        issued = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive; enrollment parsed it
        raise server_internal(f"issued cert unparseable: {exc}") from exc

    violations: list[str] = []
    try:
        basic_constraints = issued.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        if isinstance(basic_constraints, x509.BasicConstraints) and basic_constraints.ca:
            violations.append("BasicConstraints CA=true")

    try:
        key_usage = issued.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return violations
    if isinstance(key_usage, x509.KeyUsage):
        if key_usage.key_cert_sign:
            violations.append("KeyUsage keyCertSign=true")
        if key_usage.crl_sign:
            violations.append("KeyUsage cRLSign=true")
    return violations


def _quarantine_and_fail(
    ctx: ServerContext,
    *,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    enrollment_result: EnrollmentResult,
    event_type: str,
    violations: list[str],
    reason: str,
    message: str,
    extra_details: dict[str, Any] | None = None,
) -> NoReturn:
    """Quarantine a CA-issued certificate the RA refuses to honour, then 500.

    All three post-issuance verifiers (SAN, EKU, CA-capability) run *after*
    ADCS has issued: the certificate exists, has a serial, and is trusted
    domain-wide. Recording nothing — the previous behaviour — left it as an
    unrevocable orphan whose serial appeared neither in the store nor in the
    audit event. The quarantine row makes it identifiable and puts it in the
    existing CA-side revocation queue; the 500 is unchanged, because a
    template that issues outside policy really is a server-side fault.

    Quarantining must never itself lose the finding, so a store failure here
    is logged loudly and the original violation is still surfaced.
    """
    try:
        record, event = ctx.store.quarantine_certificate(
            order_id=order_id,
            account_id=account_id,
            cert_pem=enrollment_result.cert_pem,
            chain_pem=enrollment_result.chain_pem,
            template=enrollment_result.template,
            requester=enrollment_result.requester,
            metadata=dict(enrollment_result.metadata),
            event_type=event_type,
            violations=violations,
            reason=reason,
            sans=requested_sans,
            extra_details=extra_details,
        )
        emit_audit_hook(ctx, event)
        logger.error(
            "QUARANTINED a CA-issued certificate: serial=%s req_id=%s order=%s "
            "violations=%s. It is LIVE at the CA and queued for CA-side "
            "revocation; run the revocation sync agent.",
            record.serial_number,
            record.metadata.get("req_id", ""),
            order_id,
            violations,
        )
    except Exception:  # noqa: BLE001 - the finding must survive any store failure
        # Fall back to a plain audit row so the violation is never silent.
        logger.exception(
            "failed to quarantine a rejected CA-issued certificate for order %s; "
            "the certificate is LIVE at the CA and NOT tracked — revoke it manually",
            order_id,
        )
        _audit(
            ctx,
            event_type=event_type,
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=enrollment_result.template,
            requester=enrollment_result.requester,
            outcome="failed",
            details={
                "violations": violations,
                "reason": reason,
                "quarantined": False,
                "quarantine_error": "see logs",
                **(extra_details or {}),
            },
        )

    raise server_internal(message)


def _quarantine_transport_orphan(
    ctx: ServerContext,
    *,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    template: str | None,
    exc: EnrollmentTransportError,
    generation: int,
) -> JSONResponse:
    """Record a certificate the CA issued but the RA could not complete.

    Two cases, and the difference matters to whoever cleans up:

    * **The leaf is in hand** (the chain fetch or the chain-binds-to-leaf check
      failed). The serial is derivable, so this quarantines exactly like a
      verifier rejection: a ``quarantined`` row carrying the serial and ReqID,
      queued for CA-side revocation through the ordinary pull agent.
    * **Only the ReqID is known** (the leaf fetch itself failed). There is no
      certificate row to write — the store keys on the bytes, which the RA
      never received. All that can be done is to make the ReqID impossible to
      miss, so the operator can revoke by ReqID at the CA by hand.

    Either way the order goes terminal-``invalid``: a retried finalize must not
    re-enroll against a request the CA has already satisfied.
    """
    if exc.cert_pem is not None:
        try:
            record, event = ctx.store.quarantine_certificate(
                order_id=order_id,
                account_id=account_id,
                cert_pem=exc.cert_pem,
                chain_pem=exc.chain_pem,
                template=template or "",
                requester="",
                metadata={"req_id": exc.req_id or ""},
                event_type="finalize-enrollment-transport-orphan",
                violations=[str(exc)],
                reason=(
                    "the CA issued this certificate, but the RA could not "
                    "complete enrollment (chain fetch or chain validation "
                    "failed), so it was never honoured"
                ),
                sans=requested_sans,
                extra_details={"ca_issued": True, "transport_error": str(exc)},
            )
            emit_audit_hook(ctx, event)
            logger.error(
                "QUARANTINED a CA-issued certificate after a transport failure: "
                "serial=%s req_id=%s order=%s. It is LIVE at the CA and queued "
                "for CA-side revocation; run the revocation sync agent.",
                record.serial_number,
                exc.req_id,
                order_id,
            )
        except Exception:  # noqa: BLE001 - the finding must survive a store failure
            logger.exception(
                "failed to quarantine a CA-issued certificate for order %s "
                "(req_id %s); it is LIVE at the CA and NOT tracked — revoke it "
                "manually",
                order_id,
                exc.req_id,
            )
            _audit(ctx,
                event_type="finalize-enrollment-transport-orphan",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                template=template,
                outcome="failed",
                details={
                    "error": str(exc),
                    "ca_issued": True,
                    "req_id": exc.req_id,
                    "quarantined": False,
                    "quarantine_error": "see logs",
                },
            )
    else:
        # No bytes, so no row can be written. Make the ReqID loud instead.
        logger.error(
            "The CA ISSUED a certificate the RA could not retrieve: req_id=%s "
            "order=%s. It is LIVE at the CA, is NOT in the RA store, and CANNOT "
            "be revoked by the sync agent. Revoke it by ReqID at the CA by hand.",
            exc.req_id,
            order_id,
        )
        _audit(ctx,
            event_type="finalize-enrollment-transport-orphan",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=template,
            outcome="failed",
            details={
                "error": str(exc),
                "ca_issued": True,
                "req_id": exc.req_id,
                "quarantined": False,
                "reason": (
                    "the CA issued but the RA never received the certificate "
                    "bytes; revoke by ReqID at the CA manually"
                ),
            },
        )

    # Terminal either way — the CA has already satisfied this request.
    # NOT transition_active_to_invalid: that one excludes 'processing' on
    # purpose, so it would silently no-op here and leave the client polling.
    # Scoped to our own lease so this cannot terminate an order that a reclaim
    # plus a later finalize have since handed to a different enrollment.
    ctx.store.transition_processing_to_invalid(
        order_id, expected_generation=generation
    )
    order = _refresh_order_or_500(ctx, order_id, "after transport orphan")
    return JSONResponse(
        status_code=500,
        content=_order_to_json(order),
    )


def _finalize_complete(
    ctx: ServerContext,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    csr_subject: str,
    decision: PolicyDecision,
    enrollment_result: EnrollmentResult,
    generation: int,
) -> JSONResponse:
    """Record the certificate and transition to valid.

    Handles the post-enrollment completion: create cert record, CAS-flip
    processing→valid, audit, and return the final order state.

    ``generation`` is the enrollment lease this issuance was performed under.
    The CA has already issued by the time this runs, so the certificate row is
    written unconditionally — an issued certificate is never left untracked —
    but the order flip is scoped to the lease.
    """
    # MED-1: verify the issued cert carries only DNS SANs the order authorized.
    # A misconfigured template injecting an unauthorized SAN (or any non-DNS
    # SAN) must not be recorded or served, even though the CSR was approved.
    issued_dns_sans, unauthorized_dns, non_dns_san_types = _issued_cert_san_violations(
        enrollment_result.cert_pem, requested_sans
    )
    if unauthorized_dns or non_dns_san_types:
        violations: list[str] = []
        if unauthorized_dns:
            violations.append(
                f"unauthorized DNS SANs: {unauthorized_dns} "
                f"(authorized={requested_sans})"
            )
        if non_dns_san_types:
            violations.append(
                f"non-DNS SAN types present: {non_dns_san_types} "
                "(only DNS SANs are permitted)"
            )
        reason = (
            "issued cert SANs outside order scope — ADCS template likely "
            "misconfigured (it must take only DNS SANs from the request)"
        )
        _quarantine_and_fail(
            ctx,
            order_id=order_id,
            account_id=account_id,
            requested_sans=requested_sans,
            enrollment_result=enrollment_result,
            event_type="finalize-issued-cert-san-mismatch",
            violations=violations,
            reason=reason,
            message=(
                f"issued certificate fails SAN verification — {'; '.join(violations)}; "
                "the ADCS template is likely misconfigured"
            ),
            extra_details={
                "issued_dns_sans": issued_dns_sans,
                "unauthorized_dns_sans": unauthorized_dns,
                "non_dns_san_types": non_dns_san_types,
            },
        )

    # WI-026: verify the issued cert is serverAuth-only. The cardinal blast-radius
    # bound rests on the template issuing serverAuth EKU only; a template that ever
    # gained clientAuth/PKINIT/anyEKU (or a no-EKU all-purpose cert) would silently
    # break it — the domain-takeover escalation the threat model calls the worst
    # case short of a signing key. Enforce on the result; fail closed like MED-1.
    eku_violations = _issued_cert_eku_violations(enrollment_result.cert_pem)
    if eku_violations:
        _quarantine_and_fail(
            ctx,
            order_id=order_id,
            account_id=account_id,
            requested_sans=requested_sans,
            enrollment_result=enrollment_result,
            event_type="finalize-issued-cert-eku-mismatch",
            violations=eku_violations,
            reason=(
                "issued cert is not serverAuth-only — the ADCS template must "
                "issue the serverAuth EKU and nothing else"
            ),
            message=(
                f"issued certificate fails EKU verification — "
                f"{'; '.join(eku_violations)}; the ADCS template is likely "
                "misconfigured (serverAuth-only required)"
            ),
        )

    ca_capability_violations = _issued_cert_ca_capability_violations(
        enrollment_result.cert_pem
    )
    if ca_capability_violations:
        _quarantine_and_fail(
            ctx,
            order_id=order_id,
            account_id=account_id,
            requested_sans=requested_sans,
            enrollment_result=enrollment_result,
            event_type="finalize-issued-cert-ca-capability",
            violations=ca_capability_violations,
            reason=(
                "issued cert is CA-capable — the ADCS template is dangerously "
                "misconfigured"
            ),
            message=(
                "issued certificate is CA-capable — "
                f"{'; '.join(ca_capability_violations)}; "
                "the ADCS template is dangerously misconfigured"
            ),
        )

    # The certificate row, the order transition, and the mandatory issuance
    # audit row commit together — see Store.record_issuance.
    cert_record, applied, _event = ctx.store.record_issuance(
        order_id=order_id,
        account_id=account_id,
        cert_pem=enrollment_result.cert_pem,
        chain_pem=enrollment_result.chain_pem,
        template=enrollment_result.template,
        requester=enrollment_result.requester,
        metadata=dict(enrollment_result.metadata),
        certificate_url_fn=lambda cert_id: _certificate_url(ctx, cert_id),
        sans=requested_sans,
        csr_subject=csr_subject,
        expected_generation=generation,
    )
    # The audit row is already durable; this only fans it out to SIEM.
    emit_audit_hook(ctx, _event)

    if not applied:
        logger.error(
            "finalize CAS lost race for order %s; cert %s recorded but "
            "order was moved by a concurrent operation (winner cert=%s)",
            order_id,
            cert_record.id,
            _event["details"].get("winner_certificate_id"),
        )

    refreshed_order = _refresh_order_or_500(ctx, order_id, "after finalization")
    return JSONResponse(content=_order_to_json(refreshed_order))
