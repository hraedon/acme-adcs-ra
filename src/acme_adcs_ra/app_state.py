"""Shared state, helpers, and URL builders used by ACME routes."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any, cast

from fastapi import Request

from acme_adcs_ra.acme_errors import unauthorized
from acme_adcs_ra.audit_coalesce import DenialCoalescer
from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.crl_evidence import CrlEvidenceGate
from acme_adcs_ra.enrollment import EnrollmentGate, EnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.rate_limit import TokenBucket
from acme_adcs_ra.revocation import RevocationLeg
from acme_adcs_ra.server_jws import verify_existing_account_jws
from acme_adcs_ra.siem import SiemEmitter, build_siem_config
from acme_adcs_ra.store import AccountRecord, AccountStatus, Store

logger = logging.getLogger("acme_adcs_ra.server")


def _dummy_hmac(eab_jws: dict[str, Any]) -> None:
    """Perform a dummy HMAC to equalize timing on unknown EAB kid path.

    This mitigates the kid-existence timing side-channel (threat-model §4.B).

    The inputs are attacker-controlled and arrive before any signature check,
    so the encode must not be able to raise: a non-ASCII ``protected``/
    ``payload`` previously turned this timing-equalisation helper into an
    unauthenticated 500 (UnicodeEncodeError). Only the elapsed time matters
    here, never the bytes, so encoding losslessly in UTF-8 is equivalent for
    the purpose and cannot fail.
    """
    protected_b64 = eab_jws.get("protected", "")
    payload_b64 = eab_jws.get("payload", "")
    signing_input = f"{protected_b64}.{payload_b64}".encode()
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


class ActiveEnrollments:
    """Order IDs with a live enrollment in *this* process.

    The RA is a single application process (threat-model assumption). An
    enrollment holds its order in ``processing`` for the whole life of the ADCS
    call sequence. This registry is therefore an authoritative, in-memory
    answer to "is an enrollment in flight for this order right now" — which
    elapsed time can only approximate.

    The admin reclaim endpoint consults it to refuse reclaiming a genuinely
    live enrollment, independent of how long enrollment has run. That closes
    the double-issuance race where a reclaim fired during a slow (multi-call,
    up to ~4×30s) enrollment flipped the order back to ``ready`` and let the
    client drive a second CA issuance.

    **The mark must cover the whole in-flight interval, not just the running
    worker.** It is taken in the finalize *route* — around the
    ``ready``→``processing`` CAS, the threadpool hand-off, and the completion
    that records the certificate — precisely because the worker is not the
    unit of risk. Marking inside the worker (the original shape) left two
    gaps: a task still *queued* behind a saturated threadpool was invisible,
    and so was the window between the worker returning and the certificate row
    being written. In either gap a reclaim could truthfully observe "no live
    worker, no cert row", reopen the order, and let a second finalize race the
    first to the CA.

    The registry is process-local and advisory. The durable half of the
    guarantee is the store's ``processing_generation`` lease, which every
    worker re-checks immediately before submitting to the CA.

    It deliberately does NOT survive a process restart: after a crash the
    registry is empty, which is correct — a crashed worker is exactly the
    wedged-``processing`` case reclaim exists to recover, and that path
    additionally requires the operator's explicit CA-checked assertion (see the
    reclaim endpoint).

    Reference-counted rather than a plain set: if two holders for one order ever
    overlap, the first to exit must not clear the mark out from under the
    second. That should not happen — the CAS admits one finalize at a time —
    but "should not" is the wrong strength for the thing standing between a
    reclaim and a double issuance.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: dict[str, int] = {}

    @contextmanager
    def enrolling(self, order_id: str) -> Iterator[None]:
        """Mark ``order_id`` as actively enrolling for the duration of the block."""
        with self._lock:
            self._active[order_id] = self._active.get(order_id, 0) + 1
        try:
            yield
        finally:
            with self._lock:
                remaining = self._active.get(order_id, 0) - 1
                if remaining > 0:
                    self._active[order_id] = remaining
                else:
                    self._active.pop(order_id, None)

    def is_active(self, order_id: str) -> bool:
        with self._lock:
            return self._active.get(order_id, 0) > 0


class AccountIssuanceLocks:
    """Process-local serialization of account mutations and CA submission.

    The supported server has one process.  A submit holds an account lock from
    the final status/key/EAB read through the complete ADCS call sequence;
    deactivation and keyChange take the same lock around their durable mutation.
    This gives those operations a linear order without holding a SQLite write
    transaction over network I/O.

    Async routes poll a non-blocking ``threading.Lock`` acquisition rather than
    parking the event loop (or consuming a shared framework worker) while an
    enrollment is in flight.  The lock table intentionally lives for the
    process lifetime; account creation is already quota-bounded.
    """

    def __init__(self) -> None:
        self._table_lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    def _for_account(self, account_id: str) -> threading.Lock:
        with self._table_lock:
            return self._locks.setdefault(account_id, threading.Lock())

    @contextmanager
    def submitting(self, account_id: str) -> Iterator[None]:
        lock = self._for_account(account_id)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()

    @asynccontextmanager
    async def mutating(self, account_id: str) -> Any:
        lock = self._for_account(account_id)
        while not lock.acquire(blocking=False):
            await asyncio.sleep(0.01)
        try:
            yield
        finally:
            lock.release()


class IssuanceHalt:
    """A one-way latch that stops admitting new issuance.

    Set when the RA proves it can no longer record what the CA has already
    done: ``record_issuance`` failed on an UNWRITABLE store after ADCS issued
    (see ``finalize._emergency_issuance_orphan``). Every finalize admitted
    after that would orphan another live certificate the same way, so the
    second one is refused rather than issued-and-lost.

    **One way on purpose.** Clearing it means asserting the store is writable
    again, and this process cannot prove that -- a probe write that happens to
    land in free space says nothing about the next one. An operator who has
    fixed the disk restarts the service, which is what they do anyway, and the
    restart is the assertion. No admin endpoint clears it, because an endpoint
    that clears a safety latch is a way to turn the latch off under pressure.

    Not latched for a BUSY store (``database is locked``): lock contention is
    transient and ordinary, and halting issuance on it would trade a rare
    orphan for a routine self-inflicted outage. The emergency evidence is
    emitted either way -- the certificate is just as orphaned -- only the latch
    is conditional.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._reason: str | None = None

    def halt(self, reason: str) -> None:
        with self._lock:
            if self._reason is None:
                self._reason = reason

    @property
    def reason(self) -> str | None:
        with self._lock:
            return self._reason

    def __bool__(self) -> bool:
        return self.reason is not None


@dataclass
class ServerContext:
    """Dependencies shared across every request."""

    config: RAConfig
    store: Store
    policy: IssuancePolicy
    enrollment: EnrollmentLeg
    revocation: RevocationLeg
    # Order IDs with a live enrollment worker in this process. The admin
    # reclaim endpoint consults it to refuse reclaiming an in-flight
    # enrollment (which would double-issue at the CA). Process-local by
    # design; see ActiveEnrollments.
    active_enrollments: ActiveEnrollments = field(default_factory=ActiveEnrollments)
    account_issuance_locks: AccountIssuanceLocks = field(
        default_factory=AccountIssuanceLocks
    )
    enrollment_gate: EnrollmentGate = field(default_factory=EnrollmentGate)
    # Latched when a post-issuance store failure orphaned a live certificate.
    # Checked before admitting any further enrollment; see IssuanceHalt.
    issuance_halt: IssuanceHalt = field(default_factory=IssuanceHalt)
    # Dedicated, bounded, single-flight execution for CRL evidence fetches so
    # that a slow CRL host cannot queue behind — or ahead of — enrollment on
    # the shared worker pool. Closed by the app lifespan.
    crl_evidence_gate: CrlEvidenceGate = field(default_factory=CrlEvidenceGate)
    # Optional extension hook for SIEM emission (Phase 3).  Called after the
    # audit row is persisted, unconditionally, for every issuance event.
    # When None, create_app wires the default SIEM emitter from config.
    audit_hook: Callable[[dict[str, Any]], None] | None = None
    # Token bucket for the unauthenticated nonce endpoint. When None,
    # create_app builds one from config (or leaves it None if disabled).
    nonce_bucket: TokenBucket | None = None
    # Bounds durable growth from repeated account-creation denials. When
    # None, create_app builds one from config.
    denial_coalescer: DenialCoalescer | None = None


def emit_audit_hook(ctx: ServerContext, event: dict[str, Any]) -> None:
    """Fan an already-persisted audit event out to the SIEM hook.

    Fail-open by design: SIEM emission must never roll back or block an action
    whose audit row is already durable. Callers that write the audit row inside
    a larger transaction (issuance, quarantine) use this directly, after the
    commit, instead of ``_audit``.
    """
    if ctx.audit_hook is None:
        return
    try:
        ctx.audit_hook(event)
    except Exception:
        logger.warning(
            "audit hook failed for event_type=%s; continuing",
            event.get("event_type"),
            exc_info=True,
        )


def _audit(ctx: ServerContext, **kwargs: Any) -> None:
    """Persist an audit row and notify the optional SIEM hook.

    Repeated account-creation denials are folded into the window's existing row
    rather than adding one each (second daybreak rescan F4); the coalescer
    returns None in that case, and there is nothing new to fan out. Every other
    event type passes straight through, one row apiece, as before.
    """
    if ctx.denial_coalescer is not None:
        event = ctx.denial_coalescer.record(ctx.store, **kwargs)
        if event is None:
            return
    else:
        event = ctx.store.record_audit(**kwargs)
    emit_audit_hook(ctx, event)


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


def _default_nonce_bucket(config: RAConfig) -> TokenBucket | None:
    """Build the nonce token bucket from config, or None when disabled."""
    if config.nonce_rate_limit_per_second <= 0 or config.nonce_rate_limit_burst < 1:
        return None
    return TokenBucket(
        capacity=config.nonce_rate_limit_burst,
        refill_per_second=config.nonce_rate_limit_per_second,
    )


def get_context(request: Request) -> ServerContext:
    return cast(ServerContext, request.app.state.context)


def _account_url_prefix(context: ServerContext) -> str:
    """The configured prefix every account URL (and therefore every kid) shares."""
    return _url(context, "/acme/acct")


def enforce_account_usable(ctx: ServerContext, account: AccountRecord) -> None:
    """Reject a request from an account that is no longer authorized to act.

    Two independent conditions, both re-evaluated on **every** authenticated
    request rather than only at issuance time:

    * ``status`` — an account deactivated per RFC 8555 §7.3.6 can do nothing
      further, including revoking its own certificates.
    * ``eab_kid`` — the external-account credential the account was created
      under must still be in the live allowlist. Pulling a kid from
      ``eab_allowlist`` is the operator's credential-revocation action; before
      this check it stopped issuance at finalize but still left the account
      able to create orders, roll its key, and revoke its own live certs. It is
      now a complete eviction.

    Both rejections are audited: they mean someone is still holding a key the
    operator believes they have cut off, which is exactly the signal SIEM wants.
    """
    if account.status != AccountStatus.VALID:
        _audit(
            ctx,
            event_type="account-request-denied",
            account_id=account.id,
            outcome="denied",
            details={"reason": "account-not-valid", "account_status": account.status},
        )
        raise unauthorized(f"account is {account.status}")
    if account.eab_kid not in ctx.config.eab_keys_by_kid():
        _audit(
            ctx,
            event_type="account-request-denied",
            account_id=account.id,
            outcome="denied",
            details={"reason": "eab-kid-not-allowlisted", "kid": account.eab_kid},
        )
        raise unauthorized(
            "the external account credential this account was created under is "
            "no longer authorized"
        )


async def authenticate_account(
    ctx: ServerContext, request: Request, path: str
) -> tuple[dict[str, Any], dict[str, Any], AccountRecord, str]:
    """Verify a JWS; return header, payload, account, and exact key thumbprint.

    The single authenticated entry point for every account-scoped route. It
    binds the JWS to *this* RA's canonical URL for ``path`` (built from the
    configured ``base_url``, never from the inbound request) and enforces that
    the account is still usable before the route does any work.
    """
    header, payload, account_id, authenticated_thumbprint = (
        await verify_existing_account_jws(
        request,
        ctx.store,
        expected_url=_url(ctx, path),
        account_url_prefix=_account_url_prefix(ctx),
        max_body_size_bytes=ctx.config.max_jws_body_size_bytes,
        )
    )
    account = ctx.store.get_account(account_id)
    if account is None:
        raise unauthorized("account not found")
    enforce_account_usable(ctx, account)
    return header, payload, account, authenticated_thumbprint
