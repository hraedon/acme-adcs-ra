"""Audit retention: the floor, the footprint, and the gate on deletion.

Part three of the standing WI-014, after ``audit_bounds`` (row *size*) and
``audit_coalesce`` (row *count* for replayable denials). Those two bound growth
without deleting anything. This module is where deletion becomes possible, and
therefore where it has to be made hard to do by accident.

Three previous waves declined to build a pruner, and their reasoning was right:
destroying audit evidence is precisely the operation an attacker wants, so a
sweep over the system of record trades a disk problem for an evidence problem.
What changed is not the risk appetite but the architecture. With
``audit_offbox_required`` set *and demonstrated*, the local ``audit_log`` is a
**buffer** whose contents have already left the host; bounding a buffer is
capacity management, not evidence destruction. With it unset, the local table is
the only copy and this module will not delete from it at all.

So the posture is asymmetric on purpose:

* **Off-box required and healthy** — deletion is permitted, above a floor.
* **Anything else** — measure and warn, and never delete. Local-only is a
  supported deployment, not a degraded one; it simply pays for the choice in
  disk rather than in evidence. The corresponding availability trade is
  documented with the other unsafe defaults: the ``certificate-issued`` audit
  row commits in the same transaction as the certificate, so a full disk stops
  issuance rather than issuing unaudited.

**The floor.** Retention below the life of a certificate leaves a *live*
certificate with no issuance record. That is an evidence hole rather than a
capacity choice, so it is refused rather than warned about. The floor is the
longest validity this RA has actually issued plus a fixed grace period —
observed, not configured, because ADCS can issue shorter than the template asks
and the certificate is the fact. The grace term is a constant rather than a
setting: it exists so a certificate stays explainable for a while *after* it
expires, and an operator who can tune it to zero has removed the guarantee. A
fixed grace also does not collapse as certificate lifetimes shrink, which is the
direction this project is deliberately heading.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from acme_adcs_ra.config import RAConfig
    from acme_adcs_ra.siem import SiemEmitter
    from acme_adcs_ra.store import Store

logger = logging.getLogger("acme_adcs_ra.audit_retention")

# Days of retention required *beyond* the longest certificate validity. Not a
# setting: see the module docstring for why it is fixed.
RETENTION_FLOOR_GRACE_DAYS = 14


class RetentionFloorError(RuntimeError):
    """Configured retention is below the floor, so startup is refused."""


@dataclass(frozen=True)
class RetentionDecision:
    """Whether a sweep may delete, and the reason either way.

    ``reason`` is always populated — a refusal that cannot say why is
    indistinguishable from one nobody noticed.
    """

    may_prune: bool
    reason: str
    cutoff: str | None = None
    floor_days: int | None = None


def retention_floor_days(store: Store) -> int | None:
    """Minimum defensible retention in days, or ``None`` when unknowable.

    ``None`` means "at least one certificate's validity could not be
    determined", and must be treated as blocking rather than as zero.
    """
    max_validity, _unknown = store.certificate_validity_summary()
    if max_validity is None:
        return None
    return max_validity + RETENTION_FLOOR_GRACE_DAYS


def assert_retention_above_floor(config: RAConfig, store: Store) -> None:
    """Refuse startup when configured retention is below the floor.

    Only checked when retention is actually configured: leaving
    ``audit_retention_days`` at 0 keeps everything, which can never be below a
    floor. An unknowable floor is *not* a startup failure — it blocks pruning
    later, which is the fail-safe direction, and taking the RA down over a
    historical certificate with a corrupt PEM would not be.
    """
    if config.audit_retention_days <= 0:
        return
    floor = retention_floor_days(store)
    if floor is None:
        return
    if config.audit_retention_days < floor:
        raise RetentionFloorError(
            f"audit_retention_days is {config.audit_retention_days}, below the "
            f"floor of {floor} days for this deployment (longest certificate "
            f"validity observed {floor - RETENTION_FLOOR_GRACE_DAYS}d, plus "
            f"{RETENTION_FLOOR_GRACE_DAYS}d grace). Retaining for less than a "
            "certificate's own lifetime means a certificate can be valid and "
            "servable while the record of how it was issued has been deleted. "
            "Raise audit_retention_days to at least the floor, or set it to 0 "
            "to keep everything."
        )


def evaluate(
    config: RAConfig, store: Store, siem: SiemEmitter | None
) -> RetentionDecision:
    """Decide whether a retention sweep may delete anything right now.

    Every gate is checked here rather than at the call site, so that
    ``Store.delete_audit_rows_before`` stays a dumb primitive that never decides
    to destroy evidence on its own.
    """
    floor = retention_floor_days(store)

    if config.audit_retention_days <= 0:
        return RetentionDecision(
            False, "no retention window is configured; every row is kept", floor_days=floor
        )
    if not config.audit_prune_enabled:
        return RetentionDecision(
            False,
            "audit_prune_enabled is off, so retention is reported but not enforced",
            floor_days=floor,
        )
    if not config.audit_offbox_required:
        return RetentionDecision(
            False,
            "audit_offbox_required is not set, so the local audit_log is the "
            "only copy of this evidence and nothing will be deleted from it",
            floor_days=floor,
        )
    if siem is None or not siem.enabled:
        return RetentionDecision(
            False,
            "off-box audit is required but no emitter is enabled; refusing to "
            "delete the only remaining copy",
            floor_days=floor,
        )
    if floor is None:
        return RetentionDecision(
            False,
            "at least one certificate's validity could not be determined, so "
            "the retention floor is unknown and deleting could drop below it",
            floor_days=None,
        )
    if config.audit_retention_days < floor:
        return RetentionDecision(
            False,
            f"configured retention {config.audit_retention_days}d is below the "
            f"{floor}d floor",
            floor_days=floor,
        )

    # Health is proven at sweep time, not assumed from configuration. A sink
    # that was working at startup and has since died is the exact state in which
    # deleting the local copy is unrecoverable -- and until 2026-08-17 a dead
    # syslog collector reported itself healthy, so this check is only meaningful
    # because that was fixed.
    ok, detail = siem.probe_offbox_delivery()
    if not ok:
        return RetentionDecision(
            False,
            f"off-box delivery is not currently healthy ({detail}); refusing to "
            "delete local rows that may not have reached the collector",
            floor_days=floor,
        )

    cutoff = (
        datetime.now(UTC) - timedelta(days=config.audit_retention_days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return RetentionDecision(
        True,
        f"off-box audit healthy; deleting rows older than {cutoff}",
        cutoff=cutoff,
        floor_days=floor,
    )


def run_sweep(
    config: RAConfig, store: Store, siem: SiemEmitter | None
) -> tuple[int, RetentionDecision]:
    """Apply the retention window if every gate allows it.

    Returns ``(rows_deleted, decision)``. A refusal is not an error: reporting
    without deleting is the designed behaviour for most deployments.
    """
    decision = evaluate(config, store, siem)
    if not decision.may_prune or decision.cutoff is None:
        logger.info("audit retention sweep did not delete: %s", decision.reason)
        return 0, decision

    deleted = store.delete_audit_rows_before(decision.cutoff)
    # The sweep audits itself. A retention pass that leaves no trace is
    # indistinguishable from an attacker's cleanup.
    store.record_audit(
        event_type="audit-retention-swept",
        outcome="success",
        details={
            "cutoff": decision.cutoff,
            "rows_deleted": deleted,
            "retention_days": config.audit_retention_days,
            "floor_days": decision.floor_days,
        },
    )
    logger.info(
        "audit retention sweep deleted %d row(s) older than %s", deleted, decision.cutoff
    )
    return deleted, decision


def footprint_report(
    config: RAConfig, store: Store, jsonl_bytes: int = 0
) -> dict[str, Any]:
    """Measure the audit footprint and say whether it warrants attention.

    This is the half every deployment gets, including the local-only ones that
    will never delete a row. Bounding without measuring would just be hoping.
    """
    stats = store.audit_footprint()
    total = int(stats["db_bytes"]) + int(jsonl_bytes)
    warn_bytes = config.audit_store_warn_mib * 1024 * 1024
    over = bool(warn_bytes) and total > warn_bytes
    return {
        **stats,
        "jsonl_bytes": jsonl_bytes,
        "total_bytes": total,
        "warn_bytes": warn_bytes,
        "over_threshold": over,
    }


def log_footprint(config: RAConfig, store: Store, jsonl_bytes: int = 0) -> dict[str, Any]:
    """Report the footprint at startup, loudly when it is over the threshold."""
    report = footprint_report(config, store, jsonl_bytes)
    mib = report["total_bytes"] / (1024 * 1024)
    if report["over_threshold"]:
        logger.warning(
            "audit footprint is %.1f MiB across %d row(s) (threshold %d MiB, "
            "oldest %s). The certificate-issued audit row commits in the same "
            "transaction as the certificate, so exhausting this disk stops "
            "issuance. Raise capacity, or configure retention with off-box "
            "audit required so the sweep can run.",
            mib,
            report["rows"],
            config.audit_store_warn_mib,
            report["oldest"],
        )
    else:
        logger.info(
            "audit footprint: %.1f MiB across %d row(s), oldest %s",
            mib,
            report["rows"],
            report["oldest"],
        )
    return report
