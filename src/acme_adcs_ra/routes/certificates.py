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
    body = cert.cert_pem + "".join(cert.chain_pem)
    return Response(content=body, media_type=_PEM_CHAIN_MEDIA_TYPE)


@router.get("/acme/cert/{cert_id}")
async def get_certificate(
    cert_id: str,
    ctx: ServerContext = Depends(get_context),
) -> Response:
    """Unauthenticated read of a certificate by its unguessable URL.

    Retained for compatibility with the clients this RA was proven against.
    Prefer the POST-as-GET form below, which is what RFC 8555 §7.4.2
    specifies and which is account-scoped.
    """
    cert = ctx.store.get_certificate(cert_id)
    if cert is None:
        raise unauthorized("certificate not found")
    return _certificate_response(cert)


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
