"""Complementary control: no signing-capable library in the dependency set.

This is the **dependency-layer backstop** to the AST guard in
``test_no_signing_key.py``.  Even if a future change hides a cert-minting
import behind dynamic dispatch (which the AST scanner may not catch), the
library must still be *installed* — and this test asserts it isn't.

Threat model: this catches a contributor adding ``pyOpenSSL`` or similar to
``pyproject.toml``.  It does NOT prevent someone from ``pip install``-ing a
signing library outside the declared deps (that is environment hardening).
"""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
PYPROJECT = ROOT / "pyproject.toml"

# Libraries that can mint/sign certificates — must NOT appear as dependencies.
# ``cryptography`` is the sole allowed crypto dep (CSR parse + JWS verify).
FORBIDDEN_DEPS: frozenset[str] = frozenset(
    {
        "pyopenssl",
        "openssl",
        "asn1crypto",
        "signxml",
        "pyasn1-modules",  # can be used for CSR/cert construction
        "pyasn1",  # low-level ASN.1 — not signing by itself but suspicious
    }
)

# Packages that must not be importable in the test environment.
FORBIDDEN_INSTALLED: frozenset[str] = frozenset(
    {
        "OpenSSL",  # pyOpenSSL top-level package
        "asn1crypto",
        "signxml",
    }
)


def _parse_dep_name(dep_spec: str) -> str:
    """Extract the canonical package name from a PEP 508 dependency string.

    Strips version specifiers, extras, environment markers, etc.
    Returns the name lowercased with hyphens (for comparison).
    """
    # Take everything up to the first marker character
    for ch in ("[", ";", " ", "<", ">", "=", "!", "~", "@"):
        dep_spec = dep_spec.split(ch, 1)[0]
    return dep_spec.strip().lower().replace("_", "-")


class TestNoSigningDependencies:
    """Assert the dependency set contains no signing-capable library."""

    def test_pyproject_has_no_signing_deps(self) -> None:
        """No cert-minting library is declared in [project] dependencies."""
        pyproject_text = PYPROJECT.read_text(encoding="utf-8")
        data = tomllib.loads(pyproject_text)
        deps: list[str] = data.get("project", {}).get("dependencies", [])

        for dep_spec in deps:
            name = _parse_dep_name(dep_spec)
            assert name not in FORBIDDEN_DEPS, (
                f"Forbidden signing dependency found in pyproject.toml: "
                f"'{dep_spec}' (normalized: '{name}'). "
                f"Only 'cryptography' is allowed for CSR parse + JWS verify."
            )

    def test_pyproject_optional_deps_have_no_signing_deps(self) -> None:
        """No cert-minting library in [project.optional-dependencies] either."""
        pyproject_text = PYPROJECT.read_text(encoding="utf-8")
        data = tomllib.loads(pyproject_text)
        opt_deps: dict[str, list[str]] = data.get("project", {}).get(
            "optional-dependencies", {}
        )

        for group_name, deps in opt_deps.items():
            for dep_spec in deps:
                name = _parse_dep_name(dep_spec)
                assert name not in FORBIDDEN_DEPS, (
                    f"Forbidden signing dependency in optional group "
                    f"'{group_name}': '{dep_spec}' (normalized: '{name}')."
                )

    @pytest.mark.parametrize("package", sorted(FORBIDDEN_INSTALLED))
    def test_signing_library_not_installed(self, package: str) -> None:
        """No signing-capable library is importable in this environment."""
        spec = importlib.util.find_spec(package)
        assert spec is None, (
            f"Forbidden signing library '{package}' is installed "
            f"(found at {spec.origin}). "
            f"Only 'cryptography' is allowed for CSR parse + JWS verify."
        )
