"""Tests for acme_adcs_ra.config — EAB credentials, validation, secrets handling."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import acme_adcs_ra
from acme_adcs_ra.config import EABEntry, RAConfig, SANScope


def test_package_version_matches_pyproject() -> None:
    """__version__ must track pyproject, not a hand-maintained literal.

    It sat at "0.1.0" from the first commit through v1.8.0 because nothing read
    it. A release artifact that misreports its own version is a trap for
    whoever eventually does.
    """
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    declared = tomllib.loads(pyproject.read_text())["project"]["version"]
    assert acme_adcs_ra.__version__ == declared


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
        # Keys must clear the MIN_EAB_MAC_KEY_BYTES floor: both decode to 32 bytes.
        k1 = "azEta2V5LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0"
        k2 = "azIta2V5LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0"
        cfg = RAConfig(
            eab_allowlist=[
                EABEntry(kid="k1", mac_key=k1),
                EABEntry(kid="k2", mac_key=k2),
            ]
        )
        assert cfg.eab_keys_by_kid() == {"k1": k1, "k2": k2}

    def test_no_audit_emit_toggle(self) -> None:
        """Auditing is unconditional; there must be no toggle to disable it."""
        with pytest.raises(AttributeError):
            _ = RAConfig().audit_emit

    def test_enrollment_total_timeout_cannot_be_below_socket_timeout(self) -> None:
        with pytest.raises(ValueError, match="total_timeout"):
            RAConfig(
                adcs_enrollment_timeout_seconds=30,
                adcs_enrollment_total_timeout_seconds=29,
            )

    def test_enrollment_admission_cannot_be_below_worker_count(self) -> None:
        with pytest.raises(ValueError, match="max_pending"):
            RAConfig(adcs_enrollment_max_workers=4, adcs_enrollment_max_pending=3)


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

    def test_wildcard_with_invalid_domain_rejected(self) -> None:
        """*.!!!.example.com — invalid characters in domain part."""
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["*.!!!.example.com"])

    def test_wildcard_with_empty_label_rejected(self) -> None:
        """*.example..com — empty label in domain part."""
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["*.example..com"])

    def test_wildcard_with_leading_hyphen_rejected(self) -> None:
        """*.-example.com — leading hyphen in domain part."""
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["*.-example.com"])

    def test_exact_pattern_with_invalid_domain_rejected(self) -> None:
        """web!.example.com — invalid characters in exact pattern."""
        with pytest.raises(ValueError, match="invalid DNS pattern"):
            SANScope(dns_patterns=["web!.example.com"])

    def test_wildcard_with_hyphenated_domain_accepted(self) -> None:
        """*.my-host.example.com — hyphens in the middle are valid."""
        scope = SANScope(dns_patterns=["*.my-host.example.com"])
        assert scope.dns_patterns == ["*.my-host.example.com"]
