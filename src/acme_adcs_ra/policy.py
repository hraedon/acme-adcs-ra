"""Issuance policy — deterministic allow/deny for certificate requests.

Pure functions: same inputs always produce the same decision.
No LLM, no network, no time-based randomness.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class PolicyDecision:
    """Result of evaluating an issuance request against policy."""

    allowed: bool
    template: str | None
    reason: str


def _match_dns_pattern(san: str, pattern: str) -> bool:
    """Match a DNS name against an allowed pattern.

    Supports:
    - **Exact match**: ``srv01.example.com`` matches ``srv01.example.com``.
    - **Leftmost-label wildcard**: ``*.example.com`` matches
      ``foo.example.com`` but NOT ``a.b.example.com`` or ``example.com``
      (RFC 4592 single-label semantics — the wildcard absorbs exactly one
      DNS label).

    Case-insensitive per RFC 4343. Trailing dots (FQDN form) are stripped.

    Patterns containing ``*`` outside the leftmost ``*.`` position (e.g.
    ``foo*.example.com``) are treated as exact-match literals — they will
    not match any valid DNS name, which is fail-closed.
    """
    san = san.rstrip(".").lower()
    pattern = pattern.rstrip(".").lower()

    # Defense-in-depth: a SAN containing '*' is not a valid hostname.
    # Wildcard certificates (*.example.com as a SAN) are a distinct concept
    # from wildcard scope patterns and must not be authorized by a
    # *.example.com scope. The CSR gate rejects these; this is the backstop.
    if "*" in san:
        return False

    if pattern.startswith("*."):
        base = pattern[2:]
        idx = san.find(".")
        if idx <= 0:
            return False
        return san[idx + 1:] == base
    return san == pattern


class IssuancePolicy:
    """Deterministic issuance policy.

    Checks whether a given (account, SAN set) is authorised to receive a
    certificate from the configured template.  All decisions are pure —
    same inputs always yield the same ``PolicyDecision``.
    """

    def __init__(
        self,
        *,
        allowed_kids: set[str],
        san_scopes: dict[str, list[str]],
        template: str = "ACME-ServerAuth",
    ) -> None:
        self._allowed_kids = allowed_kids
        self._san_scopes = san_scopes
        self._template = template

    def evaluate(
        self,
        *,
        eab_kid: str,
        csr_subject: str,
        requested_sans: Sequence[str],
    ) -> PolicyDecision:
        """Evaluate an issuance request.  Returns a ``PolicyDecision``."""

        # csr_subject is accepted for audit logging and future subject policy,
        # but is not currently used in the allow/deny decision.

        # 1. Account must be known
        if eab_kid not in self._allowed_kids:
            return PolicyDecision(
                allowed=False,
                template=None,
                reason=f"unknown kid: {eab_kid}",
            )

        # 2. Server-auth certs must request at least one SAN.
        # A subject-only cert has a wider blast radius than intended and is not
        # useful for the RA's scoped server-authentication use case.
        if not requested_sans:
            return PolicyDecision(
                allowed=False,
                template=None,
                reason="no SANs requested; subject-only issuance is not allowed",
            )

        # 3. Every SAN must match at least one allowed pattern for this account.
        # DNS names are case-insensitive (RFC 4343); _match_dns_pattern folds
        # case. Wildcard patterns use RFC 4592 single-label semantics:
        # *.example.com matches foo.example.com but NOT a.b.example.com.
        allowed_patterns = self._san_scopes.get(eab_kid, [])
        for san in requested_sans:
            if not any(
                _match_dns_pattern(san, pat) for pat in allowed_patterns
            ):
                return PolicyDecision(
                    allowed=False,
                    template=None,
                    reason=f"SAN out of scope for kid {eab_kid}: {san}",
                )

        # 4. All checks pass
        return PolicyDecision(
            allowed=True,
            template=self._template,
            reason="allowed",
        )
