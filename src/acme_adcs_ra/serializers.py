"""JSON serializers for ACME protocol objects."""

from __future__ import annotations

from typing import Any

from acme_adcs_ra.app_state import (
    ServerContext,
    _url,
)


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
