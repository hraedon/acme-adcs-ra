"""Time-windowed coalescing of pre-authentication denial audit rows.

Daybreak 2026-08-15 second rescan, F4 (the standing WI-014), part two.

The finding, restated: an allowlisted peer needs no account and no valid EAB
secret to make the RA write a durable audit row. It generates its own account
key, fetches a nonce, sends a ``newAccount`` whose EAB will not verify, and one
SQLite row plus one appended JSONL record land on the issuance host's disk. Per
request. Forever.

Three previous waves declined to fix this, and their reason was right: the
remediation people usually reach for is a *pruner*, and deleting audit evidence
is precisely the operation an attacker wants. Trading a disk-space problem for
a missing-evidence problem is not a fix.

So this is not a pruner. Nothing is ever deleted, and no denial goes
unrecorded. Within a window, repeats of the same *kind* of denial are folded
into the row that is already on disk:

* The first denial of a kind opens a window and writes a normal audit row.
* Every later denial of that kind inside the window **updates that row in
  place** — bumping ``denial_count``, moving ``last_seen``, and adding the
  offered ``kid`` to a bounded set of digests.
* The next denial after the window has elapsed opens a fresh row, which also
  carries the closed window's final tally in ``previous_window``.

Durable growth therefore becomes a function of *time* — at most one row per
(reason x window) — rather than of the attacker's request rate, while the count
of attempts stays exact. Because the counter is updated on a row that is
already committed, even a hard crash cannot lose it.

The coalescing key deliberately excludes the ``kid`` and the requester. Both
are attacker-chosen; keying on them would let a peer defeat the bound by
varying one character per request. The distinct kids seen in a window are
recorded as digests instead, bounded in number and counted in full. For the
replayable *authenticated* classes added in Daybreak round 5, the key carries
the account and order ids (not attacker-chosen per request): one account's
replay storm folds, different accounts stay separable, and the row's own
``account_id``/``order_id`` columns keep the folded tally attributable.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acme_adcs_ra.store import Store, _now_iso

# Which denials are coalesced, and why exactly these.
#
# Unauthenticated, pre-authentication denials (``account-creation-denied``):
# an allowlisted peer needs no account and no valid EAB secret to make the RA
# write a durable audit row, so their volume is pure attacker choice.
#
# Replayable authenticated denials (Daybreak round 5): a *valid* credential
# replayed at line rate could grow the durable stores without bound even
# though every request is individually accountable -- accountability does not
# bound disk. These classes are replayable because each one can be re-sent
# indefinitely against unchanged server state, costing the attacker nothing:
#
# * ``account-request-denied`` -- a deactivated or EAB-evicted account key
#   still authenticates the JWS; the denial is the point.
# * ``order-rate-limited`` -- requests rejected *because* they exceed a cap
#   are unbounded by definition: the limiter does not throttle the audit row.
# * ``finalize-csr-mismatch`` / ``finalize-policy-denied`` -- cheap pre-enrollment
#   validation failures on an order that stays ``ready``, so the identical
#   failing finalize can be replayed forever.
#
# Everything else -- issuance, revocation, admin action, one-time state
# transitions -- keeps one row per event, unconditionally.
COALESCED_EVENT_TYPES = frozenset(
    {
        "account-creation-denied",
        "account-request-denied",
        "order-rate-limited",
        "finalize-csr-mismatch",
        "finalize-policy-denied",
    }
)

# Distinct offered kids sampled per window. The full number seen is counted
# regardless; this bounds only how many are named.
MAX_KID_SAMPLES = 10


def _kid_digest(kid: str) -> str:
    return "sha256:" + hashlib.sha256(kid.encode("utf-8", "surrogatepass")).hexdigest()[:16]


@dataclass
class _Window:
    """An open coalescing window and the durable row backing it."""

    audit_id: int
    opened_at: float
    first_seen: str
    last_seen: str
    # The details the row was opened with. Kept because an in-place update
    # rewrites the whole blob, and the aggregate must not overwrite the
    # original reason and kid with counters.
    base_details: dict[str, Any] = field(default_factory=dict)
    count: int = 1
    kid_samples: list[str] = field(default_factory=list)
    distinct_kids: set[str] = field(default_factory=set)

    def summary(self) -> dict[str, Any]:
        return {
            "denial_count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class DenialCoalescer:
    """Fold repeated pre-auth denials into one durable row per time window.

    ``window_seconds`` of 0 (or less) disables coalescing entirely: every
    denial gets its own row, which is the behaviour that shipped before this
    existed. Callers that want that back can set it in config.
    """

    def __init__(
        self,
        window_seconds: float,
        *,
        max_kid_samples: int = MAX_KID_SAMPLES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window_seconds = float(window_seconds)
        self._max_kid_samples = max_kid_samples
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[tuple[str, str, str, str], _Window] = {}

    @property
    def enabled(self) -> bool:
        return self._window_seconds > 0

    def record(self, store: Store, /, **kwargs: Any) -> dict[str, Any] | None:
        """Persist an audit event, coalescing it when it is a repeat denial.

        Returns the event dict when a new durable row was written — the caller
        fans that out to SIEM — or ``None`` when the event was folded into an
        open window's existing row. The SQLite row is authoritative for counts;
        the SIEM sink sees one event per window, carrying the previous window's
        final tally.
        """
        event_type = kwargs.get("event_type", "")
        if not self.enabled or event_type not in COALESCED_EVENT_TYPES:
            return store.record_audit(**kwargs)

        details = dict(kwargs.get("details") or {})
        reason = str(details.get("reason", ""))
        kid = details.get("kid")
        # The coalescing key. For pre-auth denials it is (type, reason) as
        # before -- there is no account to key on, and keying on the
        # attacker-chosen kid would let one character of variance defeat the
        # bound. For the replayable authenticated classes (round 5) the key
        # additionally carries account_id and order_id: different accounts'
        # denials stay in separate rows (each remains individually
        # accountable), while one account replaying one request folds into a
        # single window. Both key shapes tuple naturally; absent ids read as
        # "" and keep the pre-auth behaviour byte-identical.
        key = (
            event_type,
            reason,
            str(kwargs.get("account_id") or ""),
            str(kwargs.get("order_id") or ""),
        )
        now = self._clock()

        with self._lock:
            window = self._windows.get(key)
            if window is not None and (now - window.opened_at) < self._window_seconds:
                if not self._extend(store, window, kid):
                    # The durable row went away under us (an operator archived
                    # the table). Fall through and open a new window rather
                    # than counting into a record that no longer exists.
                    self._windows.pop(key, None)
                    window = None
                else:
                    return None
            closed = window.summary() if window is not None else None
            new_kwargs = dict(kwargs)
            new_details = dict(details)
            new_details["denial_count"] = 1
            new_details["coalesce_window_seconds"] = self._window_seconds
            if closed is not None:
                new_details["previous_window"] = closed
            new_kwargs["details"] = new_details
            event = store.record_audit(**new_kwargs)
            audit_id = event.get("id")
            timestamp = str(event.get("timestamp", ""))
            if isinstance(audit_id, int):
                fresh = _Window(
                    audit_id=audit_id,
                    opened_at=now,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    base_details=dict(event.get("details") or new_details),
                )
                if isinstance(kid, str):
                    digest = _kid_digest(kid)
                    fresh.distinct_kids.add(digest)
                    fresh.kid_samples.append(digest)
                self._windows[key] = fresh
            else:
                # No row id means nothing to update in place later, so do not
                # open a window: the fail-safe direction is more rows, not a
                # lost count.
                self._windows.pop(key, None)
            return event

    def _extend(self, store: Store, window: _Window, kid: Any) -> bool:
        """Fold one more denial into an open window's already-durable row.

        Returns False when the row could not be updated because it no longer
        exists, which is the caller's signal to open a fresh one.
        """
        window.count += 1
        window.last_seen = _now_iso()
        if isinstance(kid, str):
            digest = _kid_digest(kid)
            if digest not in window.distinct_kids:
                window.distinct_kids.add(digest)
                if len(window.kid_samples) < self._max_kid_samples:
                    window.kid_samples.append(digest)
        # The update rewrites the whole details blob, so start from what the
        # row already said (reason, the first offered kid) and layer the
        # aggregate on top. Nothing the first denial recorded is lost.
        details = dict(window.base_details)
        details.update(
            {
                "denial_count": window.count,
                "coalesce_window_seconds": self._window_seconds,
                "first_seen": window.first_seen,
                "last_seen": window.last_seen,
                "kid_digests": list(window.kid_samples),
                "distinct_kids": len(window.distinct_kids),
            }
        )
        return store.update_audit_details(window.audit_id, details)

    def close(self) -> None:
        """Drop every open window at shutdown.

        There is nothing to flush: each window's tally was written to its row
        on every increment, so the durable counts are already exact. This only
        clears process state, so a long-lived window cannot outlive the run it
        was measuring.
        """
        with self._lock:
            self._windows.clear()

    def open_window_count(self) -> int:
        with self._lock:
            return len(self._windows)
