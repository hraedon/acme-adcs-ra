"""Certificate retrieval (RFC 8555 §7.4.2)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from acme_adcs_ra.acme_errors import unauthorized
from acme_adcs_ra.app_state import ServerContext, get_context
from acme_adcs_ra.store import CertStatus

router = APIRouter()


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
