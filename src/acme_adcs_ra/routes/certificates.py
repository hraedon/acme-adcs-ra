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


@router.get("/acme/cert/{cert_id}")
async def get_certificate(
    cert_id: str,
    ctx: ServerContext = Depends(get_context),
) -> Response:
    """Unauthenticated read of a certificate by its unguessable URL.

    **Gated by config, default OFF.** Controlled by
    ``ACME_RA_ALLOW_UNAUTHENTICATED_RESOURCE_GET`` (default False as of the
    2026-08-15 review — see the config comment). Retained only for a client
    that cannot do POST-as-GET. It was justified as "not an existence oracle,
    the URL is unguessable", which is true and beside the point: it also
    answers for a certificate whose account has been *deactivated*, or whose
    EAB kid has been pulled from the allowlist. Kid eviction is supposed to be
    complete and is re-checked on every authenticated request — but a URL
    captured before the eviction still reads through here.
    """
    if not ctx.config.allow_unauthenticated_resource_get:
        raise unauthorized("use POST-as-GET (RFC 8555 §7.4.2)")
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
