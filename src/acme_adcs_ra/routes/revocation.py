"""Certificate revocation (RFC 8555 §7.6)."""

from __future__ import annotations

from typing import Any, cast

from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.oid import ExtensionOID
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import (
    bad_revocation_reason,
    malformed,
    not_found,
    server_internal,
)
from acme_adcs_ra.app_state import (
    ServerContext,
    _ACME_PATHS,
    _audit,
    get_context,
    logger,
)
from acme_adcs_ra.jws import _base64url_decode
from acme_adcs_ra.server_jws import verify_existing_account_jws
from acme_adcs_ra.store import CertStatus, _now_iso

router = APIRouter()


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

    # RFC 5280 §5.3.1 reason codes 0-10 are valid for ACME revocation,
    # EXCEPT reason 7 ("unused" in RFC 5280). M-1: the out-of-band
    # `scripts/Revoke-Cert.ps1` rejects reason 7 (certutil rejects it), so the
    # ACME route must reject it too — otherwise an accepted reason 7 would
    # silently break the out-of-band revocation loop (the operator's
    # `Revoke-Cert.ps1` would fail on the recorded reason). The valid set is
    # {0,1,2,3,4,5,6,8,9,10} (7 excluded); the error uses bad_revocation_reason.
    _VALID_REVOCATION_REASONS = frozenset({0, 1, 2, 3, 4, 5, 6, 8, 9, 10})
    reason = payload.get("reason")
    if reason is not None:
        if not isinstance(reason, int) or isinstance(reason, bool) or reason not in _VALID_REVOCATION_REASONS:
            raise bad_revocation_reason(
                "reason code must be an integer in the set 0-6, 8-10 "
                "(reason 7 is unused in RFC 5280 and rejected by certutil)"
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
    updated, won_cas = ctx.store.revoke_certificate(
        cert_record.id,
        revocation_result.reason if revocation_result.reason is not None else reason,
        revoked_at=revoked_at,
    )
    if updated is None:
        # The cert row vanished between the serial lookup and the UPDATE —
        # surface as 404 (no information leak; same outcome as not-found above).
        raise not_found("certificate not found in RA store")

    # M-3: the store signals deterministically whether this caller won the CAS.
    # If a concurrent revocation won (won_cas=False), treat it as idempotent
    # success (RFC 8555 §7.6) and DO NOT emit a duplicate audit event — the
    # winning revocation already recorded one with its own reason/timestamp.
    # Return 200 with an empty body (the out_of_band_revocation hint is NOT
    # re-emitted on the idempotent second call; the first call's audit already
    # recorded it). Deterministic signal — no timestamp-inference race.
    if not won_cas:
        return JSONResponse(status_code=200, content={})

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

    # WI-010: honestly distinguish RA-store revocation from CA-CRL revocation.
    # The out-of-band leg records revocation_scope="ra-store-only" and
    # ca_crl_updated="false" — the cert is revoked in the RA (GET → 410, order
    # → revoked) but the CA CRL was NOT written. The operator must run
    # scripts/Revoke-Cert.ps1 out-of-band to write the CRL entry. Surfacing
    # this in the audit + response prevents the audit log from implying the
    # CA CRL was written when it was not.
    rev_meta = revocation_result.metadata
    revocation_scope = rev_meta.get("revocation_scope", "ra-store-only")
    ca_crl_updated = rev_meta.get("ca_crl_updated", "false")
    # The ADCS ReqID is carried in the cert's RA-store metadata (set by the
    # enrollment leg), not on the cert itself — surface it so the operator's
    # Revoke-Cert.ps1 has both identifiers (serial + ReqID) without re-parsing.
    req_id = cert_record.metadata.get("req_id", "")
    audit_details: dict[str, Any] = {
        "certificate_id": cert_record.id,
        "serial": serial_hex,
        "reason": reason,
        "revocation_scope": revocation_scope,
        "ca_crl_updated": ca_crl_updated,
    }
    if req_id:
        audit_details["req_id"] = req_id

    _audit(
        ctx,
        event_type="certificate-revoked",
        account_id=account_id,
        order_id=cert_record.order_id,
        sans=cert_sans,
        outcome="success",
        details=audit_details,
    )

    # WI-010: surface the out-of-band step in the ACME response. RFC 8555 §7.6
    # specifies an empty body on success; extra fields are non-normative and
    # ignored by standard ACME clients. The "out_of_band_revocation" hint tells
    # the operator (and any inspecting client) that the CA CRL was not written
    # and points at the runbook. It is absent when the leg reports the CRL was
    # written (ca_crl_updated == "true"), so a future in-band leg that does
    # write the CRL simply omits the hint.
    response_body: dict[str, Any] = {}
    if ca_crl_updated == "false":
        hint: dict[str, Any] = {
            "ca_crl_updated": False,
            "revocation_scope": revocation_scope,
            "serial": serial_hex,
            "runbook": "scripts/Revoke-Cert.ps1 (run by a CA officer; see docs/threat-model.md §E)",
        }
        if req_id:
            hint["req_id"] = req_id
        response_body = {"out_of_band_revocation": hint}

    return JSONResponse(status_code=200, content=response_body)
