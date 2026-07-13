"""Shared state, helpers, and URL builders used by ACME routes."""

from __future__ import annotations

import hashlib
import hmac
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from fastapi import Request

from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.enrollment import EnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import RevocationLeg
from acme_adcs_ra.siem import SiemEmitter, build_siem_config
from acme_adcs_ra.store import Store


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


_ACME_PATHS = {
    "newNonce": "/acme/new-nonce",
    "newAccount": "/acme/new-acct",
    "newOrder": "/acme/new-order",
    "revokeCert": "/acme/revoke-cert",
    "keyChange": "/acme/key-change",
}


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


def _default_siem_emitter(config: RAConfig) -> SiemEmitter:
    """Build the default SIEM emitter from RAConfig."""
    return SiemEmitter(build_siem_config(config))


def get_context(request: Request) -> ServerContext:
    return cast(ServerContext, request.app.state.context)
