"""Tests for acme_adcs_ra.config — EAB credentials, validation, secrets handling."""

from __future__ import annotations

import pytest

from acme_adcs_ra.config import EABEntry, RAConfig


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
