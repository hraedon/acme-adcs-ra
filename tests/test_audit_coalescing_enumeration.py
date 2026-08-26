"""Force a coalescing decision at every audit call site (UNFILED item 13).

``COALESCED_EVENT_TYPES`` is an **allowlist**, so the default for any newly
added denial-shaped audit event is unbounded durable growth. That default is
why this class of finding has recurred in four consecutive review rounds
(2026-08-13 finding 6, round 5's replayable authenticated classes, 2026-08-17's
14a ``keyChange`` vector, and the three call sites in the 2026-08-25 scan). Each
round closed the specific call sites it happened to find and left the default
untouched, so the next round found the next three.

These tests change the default. They read the package's own source and require
every audit call site to have *made a decision* — the decision may be "coalesce
this" or "do not coalesce this, for the following reason", but it may not be
silence. A new denial-shaped event added without a decision fails here rather
than in the next review round.

Two invariants, both enforced statically because both are properties of the
call sites rather than of any single execution:

1. **Every denial-shaped event is coalesced or explicitly exempt.** Denial
   shaped means the call site declares ``outcome`` as denied, failed or noop:
   the outcomes an unauthorized or replaying caller can provoke without the
   server having done any durable work worth one row.

2. **Every coalesced call site's key is provably server-chosen.** The coalescing
   key takes ``details["reason_code"]`` when present and falls back to
   ``details["reason"]``. Whichever one is load-bearing must be a literal in the
   source, because the one time it was not — ``IssuancePolicy.evaluate``
   returning ``f"SAN out of scope for kid {kid}: {san}"`` into ``reason`` — the
   requested SAN landed in the coalescing key and one identifier of variance per
   request produced one durable row per request. That is the precise
   bound-defeating move the coalescer exists to prevent, and it shipped anyway
   because nothing checked.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from acme_adcs_ra.audit_coalesce import COALESCED_EVENT_TYPES

# Call sites that write an audit row. ``record_audit`` is the store primitive;
# ``_audit`` is the route/finalize helper that wraps it with the coalescer.
_AUDIT_CALLABLES = frozenset({"_audit", "record_audit"})

# Outcomes a caller can provoke. ``success`` is deliberately excluded: a success
# row records that the server did durable work, and the work itself is the
# bound. The two coalesced successes are read-only polls that transition
# nothing, and they carry their own justification in ``audit_coalesce``.
_DENIAL_OUTCOMES = frozenset({"denied", "failed", "noop"})

# Denial-shaped events that are deliberately NOT coalesced. Every entry states
# what bounds the row count instead, because "it is not coalesced" is only
# acceptable when something else makes it finite. Adding an entry here is a
# decision on the record; adding nothing is a test failure.
_UNCOALESCED_WITH_A_BOUND: dict[str, str] = {
    "finalize-expired-order": (
        "Written only when transition_active_to_invalid's CAS APPLIED, and that "
        "flip is one-way. A replayed finalize on the same order takes the "
        "lost-race branch and writes nothing, so this is one row per order for "
        "the life of that order, and order creation is itself rate limited."
    ),
    "key-change-stale": (
        "Reachable only by winning a TOCTOU race between outer-JWS "
        "authentication and the re-read inside the mutating lock. Replaying it "
        "means re-winning an authentication against a key that has just "
        "changed underneath the caller, which is not something a caller can "
        "pump on demand."
    ),
    "account-deactivation-stale": (
        "Same shape as key-change-stale: the thumbprint compared here is "
        "re-read inside the mutating lock after the request already "
        "authenticated, so the row records a lost race, not a rejected attempt."
    ),
    "finalize-enrollment-abandoned": (
        "Bounded by enrollments actually admitted through the concurrency gate "
        "(finalize-enrollment-admission-denied is the coalesced refusal in "
        "front of it). It is also the event the pre-pilot checklist requires a "
        "SIEM alert on, and folding it would blunt the alert it exists to "
        "raise."
    ),
    "finalize-enrollment-denied": (
        "One row per completed CA round trip. The CA call is the bound: it is "
        "gated by admission control, costs a real enrollment, and a caller who "
        "can afford to pump it can afford to pump the CA, which is the larger "
        "problem."
    ),
    "finalize-enrollment-pending": (
        "One row per completed CA round trip -- see finalize-enrollment-denied."
    ),
    "finalize-enrollment-failed": (
        "One row per completed CA round trip -- see finalize-enrollment-denied."
    ),
    "finalize-enrollment-transport-failed": (
        "One row per attempted CA round trip -- see finalize-enrollment-denied. "
        "Losing these would also hide the orphan-risk window the transport "
        "failure opens."
    ),
    "finalize-enrollment-transport-orphan": (
        "The loudest row the RA writes: a certificate may exist at the CA with "
        "no leaf in hand. It is bounded by CA round trips and must never fold, "
        "because each instance names a different possibly-orphaned request."
    ),
    "certificate-revoked": (
        "The failed-outcome branch records a revocation the RA attempted and "
        "did not complete. It needs a certificate the caller owns plus a "
        "failing revocation backend, and folding it would hide a revocation "
        "that did not happen -- the one thing the audit trail is sold on."
    ),
}


# Key expressions that are not literals at the call site but are still provably
# server-chosen, because every value they can take is a literal at the place it
# is constructed. Each entry names where that closed set lives, and
# ``test_allowlisted_key_expressions_come_from_closed_literal_sets`` reads that
# place and proves it -- so the exemption is earned on every run rather than
# asserted once. An entry whose closed set stops being closed fails there.
_SERVER_CHOSEN_KEY_EXPRESSIONS: dict[str, tuple[str, str]] = {
    "decision.reason_code": (
        "policy.py",
        (
            "IssuancePolicy.evaluate builds every PolicyDecision with a literal "
            "reason_code; decision.reason is the prose that carries the "
            "client's SAN and is deliberately NOT the key."
        ),
    ),
    "exc.scope": (
        "store.py",
        (
            "Store.create_order_with_authz raises OrderRateLimitExceeded with a "
            "literal scope on both paths."
        ),
    ),
}


def _expression_source(node: ast.expr) -> str | None:
    """Render ``a.b`` style expressions for allowlist lookup, else None."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return None


def _package_root() -> pathlib.Path:
    import acme_adcs_ra

    return pathlib.Path(acme_adcs_ra.__file__).parent


class _AuditSite:
    """One audit-writing call site, resolved as far as the source allows."""

    def __init__(
        self,
        path: pathlib.Path,
        lineno: int,
        event_type: str,
        outcome: str | None,
        details: ast.Dict | None,
        details_resolved: bool,
    ) -> None:
        self.path = path
        self.lineno = lineno
        self.event_type = event_type
        self.outcome = outcome
        self.details = details
        self.details_resolved = details_resolved

    @property
    def where(self) -> str:
        return f"{self.path.name}:{self.lineno} ({self.event_type})"

    def detail_node(self, key: str) -> ast.expr | None:
        """Return the value node for ``details[key]``, or None if absent."""
        if self.details is None:
            return None
        for k, v in zip(self.details.keys, self.details.values):
            if isinstance(k, ast.Constant) and k.value == key:
                return v
        return None


def _dict_literals_by_name(tree: ast.AST) -> dict[str, ast.Dict]:
    """Map local names assigned exactly one dict literal to that literal.

    Call sites build ``details`` as a local before passing it (orders.py does),
    so resolving one level of indirection is the difference between checking
    every site and checking only the convenient ones. Names assigned more than
    once, or assigned anything other than a dict literal, are deliberately not
    resolved -- they read as unresolved and fail the literal check loudly.
    """
    assigned: dict[str, list[ast.expr]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                assigned.setdefault(target.id, []).append(node.value)
    return {
        name: values[0]
        for name, values in assigned.items()
        if len(values) == 1 and isinstance(values[0], ast.Dict)
    }


def _collect_sites() -> list[_AuditSite]:
    sites: list[_AuditSite] = []
    seen: set[tuple[str, int]] = set()
    for path in sorted(_package_root().rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        local_dicts = _dict_literals_by_name(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name not in _AUDIT_CALLABLES:
                continue
            kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            event_type = kwargs.get("event_type")
            if not isinstance(event_type, ast.Constant):
                # A dynamic event_type is the coalescer re-recording a row it
                # already keyed, not a new decision point.
                continue
            key = (str(path), node.lineno)
            if key in seen:
                continue
            seen.add(key)
            outcome = kwargs.get("outcome")
            details_node = kwargs.get("details")
            resolved = True
            if isinstance(details_node, ast.Name):
                details_node = local_dicts.get(details_node.id)
                resolved = details_node is not None
            elif details_node is not None and not isinstance(details_node, ast.Dict):
                resolved = False
                details_node = None
            sites.append(
                _AuditSite(
                    path=path,
                    lineno=node.lineno,
                    event_type=str(event_type.value),
                    outcome=(
                        str(outcome.value)
                        if isinstance(outcome, ast.Constant)
                        else None
                    ),
                    details=details_node if isinstance(details_node, ast.Dict) else None,
                    details_resolved=resolved,
                )
            )
    return sites


@pytest.fixture(scope="module")
def audit_sites() -> list[_AuditSite]:
    sites = _collect_sites()
    # A guard against the enumeration silently finding nothing: a walker aimed
    # at the wrong tree reports zero violations just as loudly as a clean tree.
    assert len(sites) >= 30, (
        f"only {len(sites)} audit call sites found; the enumeration is probably "
        "aimed at the wrong tree, and a check whose failure mode is silence "
        "proves nothing"
    )
    return sites


def test_every_denial_shaped_event_is_coalesced_or_exempt_with_a_reason(
    audit_sites: list[_AuditSite],
) -> None:
    """The allowlist default is unbounded growth; make silence fail here."""
    undecided: list[str] = []
    for site in audit_sites:
        if site.outcome not in _DENIAL_OUTCOMES:
            continue
        if site.event_type in COALESCED_EVENT_TYPES:
            continue
        if site.event_type in _UNCOALESCED_WITH_A_BOUND:
            continue
        undecided.append(site.where)
    assert not undecided, (
        "these denial-shaped audit events are neither coalesced nor recorded as "
        "deliberately uncoalesced, so each one is unbounded durable growth by "
        "default:\n  "
        + "\n  ".join(sorted(undecided))
        + "\n\nAdd the event to COALESCED_EVENT_TYPES, or add an entry to "
        "_UNCOALESCED_WITH_A_BOUND stating what bounds the row count instead."
    )


def test_coalescing_key_is_provably_server_chosen(
    audit_sites: list[_AuditSite],
) -> None:
    """No attacker-influenced text may reach a coalescing key.

    The key uses ``reason_code`` when present and ``reason`` otherwise, so
    whichever one is load-bearing has to be a source literal.
    """
    offenders: list[str] = []
    for site in audit_sites:
        if site.event_type not in COALESCED_EVENT_TYPES:
            continue
        if not site.details_resolved:
            offenders.append(
                f"{site.where}: details could not be resolved to a dict literal, "
                "so the coalescing key cannot be shown to be server-chosen"
            )
            continue
        key_node = site.detail_node("reason_code")
        via_fallback = key_node is None
        if via_fallback:
            key_node = site.detail_node("reason")
        if key_node is None:
            # Nothing to key on: the key degrades to the empty string, which
            # folds this event into one window. Safe, and worth saying so.
            continue
        if isinstance(key_node, ast.Constant):
            continue
        if _expression_source(key_node) in _SERVER_CHOSEN_KEY_EXPRESSIONS:
            continue
        which = "the reason it falls back to" if via_fallback else "reason_code"
        offenders.append(
            f"{site.where}: {which} is the coalescing key and is neither a "
            "literal nor an allowlisted server-chosen expression -- "
            "attacker-influenced text can reach the key"
        )
    assert not offenders, (
        "coalescing keys must be provably server-chosen:\n  "
        + "\n  ".join(sorted(offenders))
    )


@pytest.mark.parametrize(
    ("expression", "keyword"),
    [("decision.reason_code", "reason_code"), ("exc.scope", "scope")],
)
def test_allowlisted_key_expressions_come_from_closed_literal_sets(
    expression: str, keyword: str
) -> None:
    """Prove the allowlist rather than trusting it.

    ``test_coalescing_key_is_provably_server_chosen`` lets two attribute
    expressions through on the promise that every value they can carry is a
    literal where it is constructed. This reads the module that constructs them
    and checks that promise, so the day someone builds one of these from
    client-supplied text the allowlist stops being true and this fails --
    rather than the exemption quietly outliving its justification.
    """
    module_name, _ = _SERVER_CHOSEN_KEY_EXPRESSIONS[expression]
    tree = ast.parse((_package_root() / module_name).read_text(encoding="utf-8"))
    constructed: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg != keyword:
                continue
            if isinstance(kw.value, ast.Constant):
                constructed.append(str(kw.value.value))
            else:
                pytest.fail(
                    f"{module_name}:{node.lineno} builds {keyword} from a "
                    f"non-literal, so {expression!r} is no longer a closed set "
                    "and must not be allowlisted as a coalescing key"
                )
    assert constructed, (
        f"no {keyword}= construction found in {module_name}; the proof is "
        "aimed at the wrong module and would pass on an empty search"
    )


def test_exemption_registry_has_no_stale_entries(
    audit_sites: list[_AuditSite],
) -> None:
    """A reason for an event that no longer exists is worse than no reason.

    It reads as a considered decision about live code while describing
    something that was deleted, which is exactly how a stale exemption
    outlives the bound it claimed.
    """
    live = {site.event_type for site in audit_sites}
    stale = sorted(set(_UNCOALESCED_WITH_A_BOUND) - live)
    assert not stale, (
        "_UNCOALESCED_WITH_A_BOUND names events with no call site: "
        + ", ".join(stale)
    )
    both = sorted(set(_UNCOALESCED_WITH_A_BOUND) & set(COALESCED_EVENT_TYPES))
    assert not both, (
        "these events are both coalesced and recorded as deliberately "
        "uncoalesced, so one of the two statements is wrong: " + ", ".join(both)
    )
