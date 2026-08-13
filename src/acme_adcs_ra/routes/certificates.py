"""Certificate retrieval (RFC 8555 §7.4.2)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from acme_adcs_ra.acme_errors import malformed, unauthorized
from acme_adcs_ra.app_state import ServerContext, authenticate_account, get_context
from acme_adcs_ra.store import CertificateRecord, CertStatus

router = APIRouter()

_PEM_CHAIN_MEDIA_TYPE = "application/pem-certificate-chain"


def _certificate_response(cert: CertificateRecord) -> Response:
    # H-1: revoked certs must not be installable — return 410 Gone.
    if cert.status == CertStatus.REVOKED:
        return Response(status_code=410)
    # Fail closed on anything that is not an honoured issuance. A quarantined
    # certificate — one the CA issued and a post-issuance verifier rejected —
    # must never be served; no code path builds a URL for one, and this makes
    # that a property of the response builder rather than of its callers.
    if cert.status != CertStatus.VALID:
        return Response(status_code=410)
    body = cert.cert_pem + "".join(cert.chain_pem)
    return Response(content=body, media_type=_PEM_CHAIN_MEDIA_TYPE)


# The plain unauthenticated GET form was removed in the 2026-08-15 review
# (finding 4). It bypassed account deactivation and EAB-kid eviction — a URL
# captured before an eviction still read through it — and RFC 8555 §7.4.2
# specifies POST-as-GET, which every conforming client uses. Only the
# account-scoped POST-as-GET form below remains.
@router.post("/acme/cert/{cert_id}")
async def post_certificate(
    cert_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> Response:
    """POST-as-GET the certificate (RFC 8555 §6.3, §7.4.2).

    Account-scoped, so a caller holding only the URL cannot distinguish
    valid (200) from revoked (410) from unknown (401).
    """
    _header, payload, account = await authenticate_account(
        ctx, request, f"/acme/cert/{cert_id}"
    )
    if payload != {}:
        raise malformed("POST-as-GET requires an empty payload")

    cert = ctx.store.get_certificate(cert_id)
    if cert is None or cert.account_id != account.id:
        raise unauthorized("certificate not found")
    return _certificate_response(cert)
