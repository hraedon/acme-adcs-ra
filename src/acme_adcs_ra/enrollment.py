"""Enrollment leg — the interface between the RA and the certificate issuer.

Defines the ``EnrollmentLeg`` protocol, a dev/CI fake, and a platform-gated
stub for the real ADCS Web Enrollment implementation.

The RA holds **no signing key**.  The fake returns a *static, pre-generated*
fixture certificate PEM loaded from package data — it must NEVER invoke any
certificate-minting primitive at runtime.
"""

from __future__ import annotations

import importlib.resources
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrollmentResult:
    """Structured result returned by any enrollment leg."""

    cert_pem: str
    chain_pem: list[str]
    template: str
    requester: str
    metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class EnrollmentLeg(Protocol):
    """The interface any enrollment backend must satisfy."""

    def submit_csr(
        self,
        csr_pem: str,
        *,
        account_id: str,
        requested_sans: Sequence[str],
    ) -> EnrollmentResult: ...


# ---------------------------------------------------------------------------
# Fake enrollment leg (dev / CI)
# ---------------------------------------------------------------------------


def _fixture_text(name: str) -> str:
    """Load a fixture PEM from the package data.

    Using ``importlib.resources`` means this works from an editable install,
    an installed wheel, or an arbitrary working directory.
    """
    return (
        importlib.resources.files("acme_adcs_ra.fixtures")
        .joinpath(name)
        .read_text(encoding="utf-8")
    )


class FakeEnrollmentLeg:
    """Dev/CI stand-in that returns a static fixture certificate.

    **Critical constraint:** this class must NOT sign anything at runtime.
    It loads a pre-generated PEM from package data and returns it verbatim.
    The no-signing-key architecture test must stay green even with this
    class present.
    """

    def __init__(self, fixtures_dir: Path | None = None) -> None:
        self._fixtures_dir = fixtures_dir

    def _read_cert(self) -> str:
        if self._fixtures_dir is not None:
            return (self._fixtures_dir / "fake_cert.pem").read_text()
        return _fixture_text("fake_cert.pem")

    def _read_chain(self) -> str:
        if self._fixtures_dir is not None:
            return (self._fixtures_dir / "fake_chain.pem").read_text()
        return _fixture_text("fake_chain.pem")

    def submit_csr(
        self,
        csr_pem: str,
        *,
        account_id: str,
        requested_sans: Sequence[str],
    ) -> EnrollmentResult:
        cert_pem = self._read_cert()
        chain_pem = self._read_chain()
        return EnrollmentResult(
            cert_pem=cert_pem,
            chain_pem=[chain_pem],
            template="ACME-ServerAuth",
            requester=account_id,
            metadata={"source": "fake", "sans": ",".join(requested_sans)},
        )


# ---------------------------------------------------------------------------
# Real ADCS enrollment leg — platform-gated stub
# ---------------------------------------------------------------------------


class CertsrvEnrollmentLeg:
    """ADCS Web Enrollment leg via /certsrv/.

    The real implementation requires Windows SSPI/Negotiate auth
    (``requests-negotiate-sspi``) and will be filled by the
    Mode A lab spike (WI-1).  On non-Windows platforms the class is
    importable but ``submit_csr`` always raises ``NotImplementedError``.
    """

    def submit_csr(
        self,
        csr_pem: str,
        *,
        account_id: str,
        requested_sans: Sequence[str],
    ) -> EnrollmentResult:
        if sys.platform != "win32":
            raise NotImplementedError(
                "CertsrvEnrollmentLeg requires Windows (SSPI/Negotiate auth). "
                "Use FakeEnrollmentLeg for dev/CI."
            )
        # The live /certsrv/ implementation goes here (WI-1).
        # It will import requests-negotiate-sspi inside this method
        # so the import only happens on Windows at call time.
        raise NotImplementedError(
            "CertsrvEnrollmentLeg not yet implemented — "
            "filled by the Mode A spike (WI-1)"
        )
