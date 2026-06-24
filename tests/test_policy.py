"""Tests for acme_adcs_ra.policy — deterministic issuance policy."""

from __future__ import annotations

import pytest

from acme_adcs_ra.policy import IssuancePolicy, _match_dns_pattern, validate_dns_name


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
# _match_dns_pattern — RFC 4592 single-label wildcard semantics
# ---------------------------------------------------------------------------


class TestMatchDnsPattern:
    """Direct unit tests for the DNS pattern matcher.

    The critical regression: fnmatch treated ``*`` as matching any character
    sequence including dots, so ``*.example.com`` matched ``a.b.example.com``.
    RFC 4592 says a wildcard absorbs exactly one label.
    """

    # --- wildcard: single-label match (should pass) ---

    def test_wildcard_matches_single_label(self) -> None:
        assert _match_dns_pattern("foo.example.com", "*.example.com") is True

    def test_wildcard_matches_different_single_label(self) -> None:
        assert _match_dns_pattern("bar.example.com", "*.example.com") is True

    def test_wildcard_matches_single_label_deep_base(self) -> None:
        assert _match_dns_pattern("foo.sub.example.com", "*.sub.example.com") is True

    # --- wildcard: multi-label overmatch (the critical fix) ---

    def test_wildcard_rejects_multi_label_subdomain(self) -> None:
        """*.example.com must NOT match a.b.example.com (RFC 4592)."""
        assert _match_dns_pattern("a.b.example.com", "*.example.com") is False

    def test_wildcard_rejects_deeply_nested_subdomain(self) -> None:
        assert _match_dns_pattern("x.y.z.example.com", "*.example.com") is False

    def test_deep_wildcard_rejects_extra_label(self) -> None:
        """*.a.b.example.com matches foo.a.b.example.com but not bar.foo.a.b.example.com."""
        assert _match_dns_pattern("foo.a.b.example.com", "*.a.b.example.com") is True
        assert _match_dns_pattern("bar.foo.a.b.example.com", "*.a.b.example.com") is False

    # --- wildcard: apex / boundary cases ---

    def test_wildcard_rejects_apex(self) -> None:
        """*.example.com must NOT match example.com (wildcard needs ≥1 label)."""
        assert _match_dns_pattern("example.com", "*.example.com") is False

    def test_wildcard_rejects_different_base_domain(self) -> None:
        assert _match_dns_pattern("foo.other.com", "*.example.com") is False

    def test_wildcard_rejects_prefix_confusion(self) -> None:
        """fooexample.com is not a subdomain of example.com."""
        assert _match_dns_pattern("fooexample.com", "*.example.com") is False

    def test_wildcard_rejects_single_label_san(self) -> None:
        """A SAN with no dots cannot match a *.pattern."""
        assert _match_dns_pattern("localhost", "*.example.com") is False

    # --- exact match ---

    def test_exact_match(self) -> None:
        assert _match_dns_pattern("srv01.example.com", "srv01.example.com") is True

    def test_exact_match_different_host_denied(self) -> None:
        assert _match_dns_pattern("srv02.example.com", "srv01.example.com") is False

    def test_exact_match_not_substring(self) -> None:
        """Exact match must not substring-match."""
        assert _match_dns_pattern("x_srv01.example.com", "srv01.example.com") is False

    # --- case-insensitivity (RFC 4343) ---

    def test_wildcard_case_insensitive_san(self) -> None:
        assert _match_dns_pattern("FOO.EXAMPLE.COM", "*.example.com") is True

    def test_wildcard_case_insensitive_pattern(self) -> None:
        assert _match_dns_pattern("foo.example.com", "*.EXAMPLE.COM") is True

    def test_wildcard_mixed_case_both(self) -> None:
        assert _match_dns_pattern("Foo.Example.Com", "*.EXAMPLE.com") is True

    def test_exact_match_case_insensitive(self) -> None:
        assert _match_dns_pattern("SRV01.EXAMPLE.COM", "srv01.example.com") is True

    # --- trailing dot (FQDN form) ---

    def test_wildcard_san_trailing_dot_stripped(self) -> None:
        assert _match_dns_pattern("foo.example.com.", "*.example.com") is True

    def test_wildcard_pattern_trailing_dot_stripped(self) -> None:
        assert _match_dns_pattern("foo.example.com", "*.example.com.") is True

    def test_exact_match_trailing_dot_stripped(self) -> None:
        assert _match_dns_pattern("srv01.example.com.", "srv01.example.com") is True

    # --- fail-closed: non-leftmost wildcards treated as literals ---

    def test_non_leftmost_wildcard_is_literal_no_match(self) -> None:
        """foo*.example.com is treated as a literal — matches nothing real."""
        assert _match_dns_pattern("foobar.example.com", "foo*.example.com") is False

    def test_bare_star_no_dot_is_literal_no_match(self) -> None:
        """* without a dot is treated as a literal — matches nothing real."""
        assert _match_dns_pattern("anything.example.com", "*") is False

    # --- defense-in-depth: SANs containing '*' are rejected ---

    def test_wildcard_san_rejected_by_matcher(self) -> None:
        """A SAN of *.example.com must NOT match a *.example.com scope.

        A wildcard certificate request is a distinct concept from a wildcard
        scope pattern. The CSR gate rejects these; the matcher is the backstop.
        """
        assert _match_dns_pattern("*.example.com", "*.example.com") is False

    def test_partial_wildcard_san_rejected_by_matcher(self) -> None:
        """foo*.example.com must NOT match *.example.com.

        Without the guard, the suffix after the first dot would match.
        """
        assert _match_dns_pattern("foo*.example.com", "*.example.com") is False

    def test_star_in_second_label_rejected_by_matcher(self) -> None:
        """foo.*.example.com must NOT match *.example.com."""
        assert _match_dns_pattern("foo.*.example.com", "*.example.com") is False

    def test_double_wildcard_san_rejected_by_matcher(self) -> None:
        assert _match_dns_pattern("**.example.com", "*.example.com") is False


# ---------------------------------------------------------------------------
# Integration: IssuancePolicy enforces RFC 4592 wildcard semantics
# ---------------------------------------------------------------------------


class TestPolicyWildcardSemantics:
    """The critical regression test: an IssuancePolicy with *.example.com
    must deny a multi-label subdomain SAN that fnmatch would have allowed."""

    def test_multi_label_subdomain_denied(self) -> None:
        """*.internal.WORK-DOMAIN.local must NOT allow a.b.internal.WORK-DOMAIN.local.

        Under the old fnmatch, this would have been allowed — the ``*``
        matched across dots. This is the load-bearing security fix.
        """
        policy = IssuancePolicy(
            allowed_kids={"acct-001"},
            san_scopes={"acct-001": ["*.internal.WORK-DOMAIN.local"]},
        )
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=any",
            requested_sans=["a.b.internal.WORK-DOMAIN.local"],
        )
        assert result.allowed is False
        assert "out of scope" in result.reason

    def test_single_label_subdomain_still_allowed(self) -> None:
        """The fix must not break legitimate single-label subdomain matching."""
        policy = IssuancePolicy(
            allowed_kids={"acct-001"},
            san_scopes={"acct-001": ["*.internal.WORK-DOMAIN.local"]},
        )
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=any",
            requested_sans=["web.internal.WORK-DOMAIN.local"],
        )
        assert result.allowed is True

    def test_deep_wildcard_multi_label_denied(self) -> None:
        """*.prod.WORK-DOMAIN.local must deny a.b.prod.WORK-DOMAIN.local."""
        policy = IssuancePolicy(
            allowed_kids={"acct-001"},
            san_scopes={"acct-001": ["*.prod.WORK-DOMAIN.local"]},
        )
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=any",
            requested_sans=["x.y.prod.WORK-DOMAIN.local"],
        )
        assert result.allowed is False

    def test_mixed_valid_and_overmatch_san_denies_all(self) -> None:
        """If one SAN is a valid single-label match and another is an overmatch,
        the entire request is denied."""
        policy = IssuancePolicy(
            allowed_kids={"acct-001"},
            san_scopes={"acct-001": ["*.internal.WORK-DOMAIN.local"]},
        )
        result = policy.evaluate(
            eab_kid="acct-001",
            csr_subject="CN=any",
            requested_sans=[
                "web.internal.WORK-DOMAIN.local",       # valid
                "a.b.internal.WORK-DOMAIN.local",       # overmatch — must deny
            ],
        )
        assert result.allowed is False


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


# ---------------------------------------------------------------------------
# validate_dns_name — RFC 1123 / RFC 1034 label syntax validation
# ---------------------------------------------------------------------------


class TestValidateDnsNameValid:
    """Names that should pass validation."""

    @pytest.mark.parametrize("name", [
        "localhost",
        "a",
        "web.example.com",
        "srv01.example.com",
        "my-host.example.com",
        "a.b.c.d.example.com",
        "web.example.com.",
        "localhost.",
        "a.",
    ])
    def test_valid_names(self, name: str) -> None:
        validate_dns_name(name)

    def test_single_char_label(self) -> None:
        validate_dns_name("a.b")

    def test_max_label_length_63(self) -> None:
        label = "a" * 63
        validate_dns_name(f"{label}.example.com")

    def test_max_total_length_253(self) -> None:
        name = ".".join(["a" * 62] * 4) + ".c"
        assert len(name) == 253
        validate_dns_name(name)

    def test_numeric_label(self) -> None:
        validate_dns_name("123.456.example.com")

    def test_mixed_case(self) -> None:
        validate_dns_name("Web.Example.COM")


class TestValidateDnsNameInvalid:
    """Names that should be rejected."""

    @pytest.mark.parametrize("name,fragment", [
        ("", "empty"),
        (".", "empty"),
        ("foo..example.com", "empty label"),
        (".example.com", "empty label"),
        ("foo!.example.com", "invalid character"),
        ("foo_.example.com", "invalid character"),
        ("foo bar.example.com", "invalid character"),
        ("-host.example.com", "hyphen"),
        ("host-.example.com", "hyphen"),
        ("web.-example.com", "hyphen"),
        ("web.example-.com", "hyphen"),
        ("*.example.com", "invalid character"),
        ("café.example.com", "invalid character"),
        ("web@example.com", "invalid character"),
    ])
    def test_invalid_names(self, name: str, fragment: str) -> None:
        with pytest.raises(ValueError, match=fragment):
            validate_dns_name(name)

    def test_label_exceeds_63_chars(self) -> None:
        label = "a" * 64
        with pytest.raises(ValueError, match="exceeds 63"):
            validate_dns_name(f"{label}.example.com")

    def test_total_exceeds_253_chars(self) -> None:
        name = "a" * 254
        with pytest.raises(ValueError, match="exceeds 253"):
            validate_dns_name(name)

    def test_empty_string(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            validate_dns_name("")

    def test_only_dots(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            validate_dns_name("...")
