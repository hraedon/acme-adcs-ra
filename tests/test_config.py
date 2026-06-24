"""Tests for acme_adcs_ra.config — EAB credentials, validation, secrets handling."""

from __future__ import annotations

import pytest

from acme_adcs_ra.config import EABEntry, RAConfig, SANScope


class TestEABEntry:
    def test_mac_key_is_secret_str(self) -> None:
        entry = EABEntry(kid="k1", mac_key="super-secret")
        assert entry.mac_key.get_secret_value() == "super-secret"

    def test_mac_key_not_in_repr(self) -> None:
        entry = EABEntry(kid="k1", mac_key="super-secret")
        repr_text = repr(entry)
        assert "super-secret" not in repr_text


class TestRAConfig:
    def test_duplicate_eab_kid_rejected(self) -> None:
        with pytest.raises(ValueError, match="duplicate EAB kid"):
            RAConfig(
                eab_allowlist=[
                    EABEntry(kid="k1", mac_key="a"),
                    EABEntry(kid="k1", mac_key="b"),
                ]
            )

    def test_unique_eab_kids_allowed(self) -> None:
        cfg = RAConfig(
            eab_allowlist=[
                EABEntry(kid="k1", mac_key="a"),
                EABEntry(kid="k2", mac_key="b"),
            ]
        )
        assert cfg.eab_keys_by_kid() == {"k1": "a", "k2": "b"}

    def test_no_audit_emit_toggle(self) -> None:
        """Auditing is unconditional; there must be no toggle to disable it."""
        with pytest.raises(AttributeError):
            _ = RAConfig().audit_emit


class TestSANScopeValidation:
    """SANScope.dns_patterns must reject invalid wildcard patterns at config time."""

    def test_valid_wildcard_accepted(self) -> None:
        scope = SANScope(dns_patterns=["*.example.com"])
        assert scope.dns_patterns == ["*.example.com"]

    def test_valid_exact_match_accepted(self) -> None:
        scope = SANScope(dns_patterns=["srv01.example.com"])
        assert scope.dns_patterns == ["srv01.example.com"]

    def test_valid_deep_wildcard_accepted(self) -> None:
        scope = SANScope(dns_patterns=["*.sub.example.com"])
        assert scope.dns_patterns == ["*.sub.example.com"]

    def test_mixed_valid_patterns_accepted(self) -> None:
        scope = SANScope(dns_patterns=["*.example.com", "srv01.example.com"])
        assert len(scope.dns_patterns) == 2

    def test_empty_patterns_accepted(self) -> None:
        scope = SANScope(dns_patterns=[])
        assert scope.dns_patterns == []

    def test_wildcard_not_leftmost_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["foo*.example.com"])

    def test_wildcard_not_entire_label_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["*foo.example.com"])

    def test_multiple_wildcards_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["*.foo.*.example.com"])

    def test_bare_star_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["*"])

    def test_double_wildcard_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["**.example.com"])

    def test_wildcard_with_empty_base_rejected(self) -> None:
        """*.  (no domain after wildcard) must be rejected."""
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["*."])
