"""Tests for acme_adcs_ra.policy — deterministic issuance policy."""

from __future__ import annotations

import pytest

from acme_adcs_ra.policy import IssuancePolicy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def policy() -> IssuancePolicy:
    """A policy with two accounts and scoped SANs."""
    return IssuancePolicy(
        allowed_kids={"acct-001", "acct-002"},
        san_scopes={
            "acct-001": ["*.internal.WORK-DOMAIN.local", "srv01.WORK-DOMAIN.local"],
            "acct-002": ["*.prod.WORK-DOMAIN.local"],
        },
        template="ACME-ServerAuth",
    )


# ---------------------------------------------------------------------------
# Allow / deny
# ---------------------------------------------------------------------------


class TestPolicyAllow:
    def test_in_scope_sans_allowed(self, policy: IssuancePolicy) -> None:
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=srv01",
            requested_sans=["srv01.WORK-DOMAIN.local"],
        )
        assert result.allowed is True
        assert result.template == "ACME-ServerAuth"
        assert result.reason == "allowed"

    def test_wildcard_pattern_match(self, policy: IssuancePolicy) -> None:
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=any",
            requested_sans=["web.internal.WORK-DOMAIN.local"],
        )
        assert result.allowed is True

    def test_second_account(self, policy: IssuancePolicy) -> None:
        result = policy.evaluate(
            eab_kid="acct-002",
            csr_subject="CN=api",
            requested_sans=["api.prod.WORK-DOMAIN.local"],
        )
        assert result.allowed is True

    def test_mixed_case_san_matches_lowercase_pattern(self, policy: IssuancePolicy) -> None:
        """DNS is case-insensitive: uppercase SAN matches lowercase pattern."""
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=srv01",
            requested_sans=["SRV01.WORK-DOMAIN.LOCAL"],
        )
        assert result.allowed is True
        assert result.template == "ACME-ServerAuth"

    def test_lowercase_san_matches_mixed_case_pattern(self) -> None:
        """Patterns may be authored in mixed case and still match."""
        policy = IssuancePolicy(
            allowed_kids={"acct-003"},
            san_scopes={"acct-003": ["*.Internal.WORK-DOMAIN.Local"]},
        )
        result = policy.evaluate(
            eab_kid="acct-003",
            csr_subject="CN=api",
            requested_sans=["api.internal.work-domain.local"],
        )
        assert result.allowed is True


class TestPolicyDeny:
    def test_out_of_scope_san_denied(self, policy: IssuancePolicy) -> None:
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=evil",
            requested_sans=["evil.other-domain.local"],
        )
        assert result.allowed is False
        assert result.template is None
        assert "out of scope" in result.reason

    def test_out_of_scope_san_case_trick_denied(self, policy: IssuancePolicy) -> None:
        """Mixed-case SANs that do not match scope are still denied."""
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=evil",
            requested_sans=["Evil.Other-Domain.Local"],
        )
        assert result.allowed is False
        assert result.template is None
        assert "out of scope" in result.reason

    def test_empty_sans_denied(self, policy: IssuancePolicy) -> None:
        """A server-auth request with no SANs is denied, not silently allowed."""
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=srv01",
            requested_sans=[],
        )
        assert result.allowed is False
        assert result.template is None
        assert "no SANs" in result.reason

    def test_unknown_account_denied(self, policy: IssuancePolicy) -> None:
        result = policy.evaluate(
            eab_kid="acct-unknown",
            csr_subject="CN=any",
            requested_sans=["any.WORK-DOMAIN.local"],
        )
        assert result.allowed is False
        assert result.template is None
        assert "unknown kid" in result.reason

    def test_mixed_sans_one_bad_denies_all(self, policy: IssuancePolicy) -> None:
        """If any SAN is out of scope the whole request is denied."""
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=mixed",
            requested_sans=[
                "srv01.WORK-DOMAIN.local",  # in scope
                "evil.other-domain.local",  # out of scope
            ],
        )
        assert result.allowed is False

    def test_account_with_no_scope_denied(self, policy: IssuancePolicy) -> None:
        """An account that is allowed but has no SAN scope cannot request any SAN."""
        policy_open = IssuancePolicy(
            allowed_kids={"acct-bare"},
            san_scopes={},  # no scopes at all
        )
        result = policy_open.evaluate(
            eab_kid="acct-bare",
            csr_subject="CN=any",
            requested_sans=["any.WORK-DOMAIN.local"],
        )
        assert result.allowed is False
        assert "out of scope" in result.reason


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestPolicyDeterminism:
    def test_same_inputs_same_decision(self, policy: IssuancePolicy) -> None:
        """Repeated calls with identical inputs must produce identical decisions."""
        kwargs = dict(
            eab_kid="acct-001",
            csr_subject="CN=srv01",
            requested_sans=["srv01.WORK-DOMAIN.local"],
        )
        d1 = policy.evaluate(**kwargs)
        d2 = policy.evaluate(**kwargs)
        assert d1 == d2

    def test_deny_deterministic(self, policy: IssuancePolicy) -> None:
        kwargs = dict(
            eab_kid="acct-999",
            csr_subject="CN=any",
            requested_sans=["any.example.com"],
        )
        d1 = policy.evaluate(**kwargs)
        d2 = policy.evaluate(**kwargs)
        assert d1 == d2
        assert d1.allowed is False
