"""Administrative routes for the ACME server."""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import malformed, not_found, unauthorized
from acme_adcs_ra.app_state import (
    ServerContext,
    _audit,
    _certificate_url,
    get_context,
)
from acme_adcs_ra.finalize import _refresh_order_or_500
from acme_adcs_ra.serializers import _order_to_admin_json, _order_to_json
from acme_adcs_ra.store import CertStatus, OrderStatus


router = APIRouter()


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
@router.delete("/acme/admin/nonces")
async def cleanup_nonces(
    request: Request, ctx: ServerContext = Depends(get_context)
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
@router.delete("/acme/admin/expired-orders")
async def sweep_expired_orders(
    request: Request, ctx: ServerContext = Depends(get_context)
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
@router.post("/acme/admin/orders/{order_id}/reclaim-processing")
async def reclaim_processing_order(
    order_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
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
    if order.status != OrderStatus.PROCESSING:
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
        new_status = OrderStatus.VALID
        had_certificate = True
    else:
        # No cert recorded — the operator has verified at the ADCS CA DB
        # that no cert was issued for this request before calling this.
        applied = ctx.store.transition_processing_to_ready(order_id)
        new_status = OrderStatus.READY
        had_certificate = False

    if not applied:
        # Lost a race with a concurrent finalize/reclaim; audit + return state.
        refreshed = _refresh_order_or_500(ctx, order_id, "during reclaim")
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
    refreshed = _refresh_order_or_500(ctx, order_id, "after reclaim")
    return JSONResponse(content=_order_to_json(refreshed))


# Administrative: list orders by status — primarily for monitoring
# stuck-processing orders (threat-model §4.D: monitor time-in-
# ``processing`` p99). Requires admin token. Returns a minimal admin
# view (no SANs/cert URLs) to limit blast radius of a stolen token.
@router.get("/acme/admin/orders")
async def list_orders(
    request: Request,
    ctx: ServerContext = Depends(get_context),
    status: str = "processing",
    limit: int = 100,
) -> JSONResponse:
    _require_admin_token(request, ctx)
    valid_statuses = {
        OrderStatus.PROCESSING, OrderStatus.VALID, OrderStatus.INVALID,
        OrderStatus.READY, OrderStatus.PENDING, OrderStatus.REVOKED,
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


# Administrative: list certificates the RA has marked revoked, for the
# out-of-band CA-side revocation loop (WI-024). Read-only; the CA agent
# pulls this view and runs certutil -revoke against the CA itself.
@router.get("/acme/admin/revocations/pending")
async def list_pending_revocations(
    request: Request,
    ctx: ServerContext = Depends(get_context),
    limit: int = 500,
) -> JSONResponse:
    _require_admin_token(request, ctx)
    if not 1 <= limit <= 500:
        raise malformed("limit must be between 1 and 500")
    certs = ctx.store.list_revoked_certificates(limit=limit)
    pending_revocations = []
    for cert in certs:
        if cert.serial_number is None:
            continue
        pending_revocations.append({
            "serial": cert.serial_number,
            "req_id": cert.metadata.get("req_id", ""),
            "reason": cert.revocation_reason,
            "revoked_at": cert.revoked_at,
        })
    _audit(ctx,
        event_type="admin-list-pending-revocations",
        outcome="success",
        details={"returned": len(pending_revocations)},
    )
    return JSONResponse(content={"pending_revocations": pending_revocations})


# Administrative: confirm that the CA-side CRL was written for a serial the
# RA had marked revoked (WI-024 callback). The pull agent calls this after a
# successful certutil -revoke so the RA flips ca_crl_updated=1 and the serial
# drops out of the pending set on the next pull. Idempotent: a repeat call for
# an already-confirmed serial returns 200 without a new audit event.
@router.post("/acme/admin/revocations/{serial}/confirm")
async def confirm_ca_revocation(
    serial: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    _require_admin_token(request, ctx)
    serial_upper = serial.strip().upper().removeprefix("0X").removeprefix("0x")
    if not serial_upper:
        raise malformed("serial must not be empty")
    cert = ctx.store.get_certificate_by_serial(serial_upper)
    if cert is None:
        _audit(ctx,
            event_type="admin-revocation-confirm-denied",
            outcome="failed",
            details={"serial": serial_upper, "reason": "not-found"},
        )
        raise not_found("certificate not found in RA store")
    if cert.status != CertStatus.REVOKED:
        _audit(ctx,
            event_type="admin-revocation-confirm-denied",
            outcome="failed",
            details={"serial": serial_upper, "reason": "not-revoked", "cert_status": cert.status},
        )
        raise malformed("certificate is not revoked in the RA store")
    flipped = ctx.store.confirm_ca_revocation(serial_upper)
    if not flipped:
        return JSONResponse(content={"serial": serial_upper, "ca_crl_updated": True})
    _audit(ctx,
        event_type="revocation-ca-confirmed",
        account_id=cert.account_id,
        order_id=cert.order_id,
        outcome="success",
        details={
            "serial": serial_upper,
            "certificate_id": cert.id,
            "ca_crl_updated": True,
            "revocation_scope": "ca-crl",
        },
    )
    return JSONResponse(content={"serial": serial_upper, "ca_crl_updated": True})
