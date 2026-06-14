"""Issuance policy — deterministic allow/deny for certificate requests.

Pure functions: same inputs always produce the same decision.
No LLM, no network, no time-based randomness.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Sequence


@dataclass(frozen=True)
class PolicyDecision:
    """Result of evaluating an issuance request against policy."""

    allowed: bool
    template: str | None
    reason: str


class IssuancePolicy:
    """Deterministic issuance policy.

    Checks whether a given (account, SAN set) is authorised to receive a
    certificate from the configured template.  All decisions are pure —
    same inputs always yield the same ``PolicyDecision``.
    """

    def __init__(
        self,
        *,
        allowed_accounts: set[str],
        san_scopes: dict[str, list[str]],
        template: str = "ACME-ServerAuth",
    ) -> None:
        self._allowed_accounts = allowed_accounts
        self._san_scopes = san_scopes
        self._template = template

    def evaluate(
        self,
        *,
        account_id: str,
        csr_subject: str,
        requested_sans: Sequence[str],
    ) -> PolicyDecision:
        """Evaluate an issuance request.  Returns a ``PolicyDecision``."""

        # csr_subject is accepted for audit logging and future subject policy,
        # but is not currently used in the allow/deny decision.

        # 1. Account must be known
        if account_id not in self._allowed_accounts:
            return PolicyDecision(
                allowed=False,
                template=None,
                reason=f"unknown account: {account_id}",
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
        # DNS names are case-insensitive (RFC 4343), so fold case before matching.
        allowed_patterns = self._san_scopes.get(account_id, [])
        for san in requested_sans:
            san_lower = san.lower()
            if not any(
                fnmatch(san_lower, pat.lower()) for pat in allowed_patterns
            ):
                return PolicyDecision(
                    allowed=False,
                    template=None,
                    reason=f"SAN out of scope for account {account_id}: {san}",
                )

        # 4. All checks pass
        return PolicyDecision(
            allowed=True,
            template=self._template,
            reason="allowed",
        )
