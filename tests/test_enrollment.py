"""Tests for acme_adcs_ra.enrollment — protocol, fake leg, platform-gated stub."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from acme_adcs_ra.enrollment import (
    CertsrvEnrollmentLeg,
    EnrollmentLeg,
    EnrollmentResult,
    FakeEnrollmentLeg,
)


# ---------------------------------------------------------------------------
# EnrollmentResult shape
# ---------------------------------------------------------------------------


class TestEnrollmentResult:
    def test_fields(self) -> None:
        r = EnrollmentResult(
            cert_pem="cert",
            chain_pem=["chain"],
            template="ACME-ServerAuth",
            requester="acct-001",
        )
        assert r.cert_pem == "cert"
        assert r.chain_pem == ["chain"]
        assert r.template == "ACME-ServerAuth"
        assert r.requester == "acct-001"
        assert r.metadata == {}

    def test_metadata(self) -> None:
        r = EnrollmentResult(
            cert_pem="c",
            chain_pem=[],
            template="t",
            requester="r",
            metadata={"source": "fake"},
        )
        assert r.metadata["source"] == "fake"

    def test_frozen(self) -> None:
        r = EnrollmentResult(
            cert_pem="c", chain_pem=[], template="t", requester="r"
        )
        with pytest.raises(AttributeError):
            r.cert_pem = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# FakeEnrollmentLeg
# ---------------------------------------------------------------------------


class TestFakeEnrollmentLeg:
    def test_returns_fixture_cert(self) -> None:
        leg = FakeEnrollmentLeg()
        result = leg.submit_csr(
            "some-csr-pem",
            account_id="acct-001",
            requested_sans=["srv.WORK-DOMAIN.local"],
        )
        assert isinstance(result, EnrollmentResult)
        assert "BEGIN CERTIFICATE" in result.cert_pem
        assert len(result.chain_pem) == 1
        assert "BEGIN CERTIFICATE" in result.chain_pem[0]
        assert result.template == "ACME-ServerAuth"
        assert result.requester == "acct-001"
        assert result.metadata["source"] == "fake"

    def test_sans_in_metadata(self) -> None:
        leg = FakeEnrollmentLeg()
        result = leg.submit_csr(
            "csr",
            account_id="a1",
            requested_sans=["a.example.com", "b.example.com"],
        )
        assert "a.example.com" in result.metadata["sans"]
        assert "b.example.com" in result.metadata["sans"]

    def test_implements_protocol(self) -> None:
        """FakeEnrollmentLeg satisfies the EnrollmentLeg protocol."""
        leg: EnrollmentLeg = FakeEnrollmentLeg()
        result = leg.submit_csr("csr", account_id="a", requested_sans=[])
        assert isinstance(result, EnrollmentResult)

    def test_default_loads_from_package_data_from_arbitrary_cwd(
        self, tmp_path: Path
    ) -> None:
        """No-arg FakeEnrollmentLeg works from any cwd via importlib.resources."""
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            leg = FakeEnrollmentLeg()
            result = leg.submit_csr(
                "csr", account_id="a", requested_sans=["x.WORK-DOMAIN.local"]
            )
            assert "BEGIN CERTIFICATE" in result.cert_pem
            assert len(result.chain_pem) == 1
            assert "BEGIN CERTIFICATE" in result.chain_pem[0]
        finally:
            os.chdir(original_cwd)


# ---------------------------------------------------------------------------
# CertsrvEnrollmentLeg (platform-gated stub)
# ---------------------------------------------------------------------------


class TestCertsrvEnrollmentLeg:
    def test_raises_not_implemented(self) -> None:
        """On any platform, submit_csr must raise NotImplementedError."""
        leg = CertsrvEnrollmentLeg()
        with pytest.raises(NotImplementedError):
            leg.submit_csr("csr", account_id="a", requested_sans=[])

    def test_importable_without_error(self) -> None:
        """The module must be importable on Linux without any ImportError."""
        # This test passes simply by reaching this point — the import at the
        # top of this file succeeded.
        assert CertsrvEnrollmentLeg is not None

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux-specific message")
    def test_linux_error_message(self) -> None:
        leg = CertsrvEnrollmentLeg()
        with pytest.raises(NotImplementedError, match="requires Windows"):
            leg.submit_csr("csr", account_id="a", requested_sans=[])
