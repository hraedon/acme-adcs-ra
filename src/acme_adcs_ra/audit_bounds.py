"""Bounded serialization of attacker-controlled audit detail fields.

Daybreak 2026-08-15 second rescan, F4 (the standing WI-014), part one.

Auditing a pre-authentication denial is mandatory — an RA that silently drops
evidence of people trying to talk to it is worse than one whose disk fills.
But the *size* of that evidence must not be attacker-chosen. ``newAccount``
denials copy the client's ``kid`` straight into the durable details blob, and a
peer that passes the network allowlist can make that field as long as the JWS
body limit allows, on every request, into SQLite and the JSONL mirror alike.

So the value is bounded rather than dropped: keep a readable prefix, and append
a SHA-256 of the *whole* original. Two audit rows for the same oversized kid
still compare equal, an operator can still match a row against a captured
request, and the row can no longer be inflated. Nothing an investigator needs
survives only in the discarded tail.

Part two — bounding the *number* of denial rows — lives in
``audit_coalesce``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Per-value ceiling. Comfortably longer than any legitimate kid, template name
# or reason string this RA writes, so the truncation branch is unreachable
# except for attacker-supplied values.
MAX_VALUE_CHARS = 256

# Ceiling on the serialized details object as a whole, so a *wide* dict cannot
# do what a *long* value no longer can.
MAX_DETAILS_CHARS = 4096

# Room reserved inside MAX_DETAILS_CHARS for the marker naming what was cut,
# and how many of the dropped key names that marker may list.
_MARKER_HEADROOM = 512
MAX_DROPPED_KEYS_NAMED = 10

# Depth beyond which nested structures are replaced by a placeholder rather
# than walked. Audit details are flat by convention; a deep object is either a
# bug or someone probing for one.
MAX_DEPTH = 4


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def bound_value(value: Any, *, max_chars: int = MAX_VALUE_CHARS, _depth: int = 0) -> Any:
    """Bound one detail value, preserving identity via a digest when it is cut."""
    if _depth > MAX_DEPTH:
        return "[nested too deeply for the audit log]"
    if isinstance(value, str):
        if len(value) <= max_chars:
            return value
        return (
            f"{value[:max_chars]}...[truncated: {len(value)} chars, "
            f"sha256:{_digest(value)}]"
        )
    if isinstance(value, dict):
        return {
            str(k): bound_value(v, max_chars=max_chars, _depth=_depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [bound_value(v, max_chars=max_chars, _depth=_depth + 1) for v in value]
    return value


def _serialized_length(obj: Any) -> int:
    return len(json.dumps(obj, separators=(",", ":"), default=str))


def bound_details(
    details: dict[str, Any] | None,
    *,
    max_value_chars: int = MAX_VALUE_CHARS,
    max_total_chars: int = MAX_DETAILS_CHARS,
) -> dict[str, Any]:
    """Bound every value in an audit details dict, then the dict as a whole.

    Keys are admitted in a stable order — ``reason`` first, because it is the
    field an operator reads, then alphabetically — and any key that will not
    fit is named in ``_dropped_keys`` rather than vanishing. The result is
    always JSON-serializable and always under ``max_total_chars`` plus the
    marker headroom.
    """
    bounded = {
        str(k): bound_value(v, max_chars=max_value_chars)
        for k, v in (details or {}).items()
    }
    if _serialized_length(bounded) <= max_total_chars:
        return bounded

    budget = max(max_total_chars - _MARKER_HEADROOM, 0)
    kept: dict[str, Any] = {}
    dropped: list[str] = []
    for key in sorted(bounded, key=lambda k: (k != "reason", k)):
        candidate = dict(kept)
        candidate[key] = bounded[key]
        if _serialized_length(candidate) > budget:
            dropped.append(key)
            continue
        kept = candidate
    if dropped:
        # The marker has to fit in the headroom too: naming 200 dropped keys
        # would blow the very bound it is reporting on.
        named = sorted(dropped)[:MAX_DROPPED_KEYS_NAMED]
        kept["_dropped"] = {
            "count": len(dropped),
            "keys": named,
            "reason": "audit details exceeded the size bound",
        }
    return kept
