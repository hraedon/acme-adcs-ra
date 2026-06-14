"""Revocation leg — the interface between the RA and the certificate revoker.

Defines the ``RevocationLeg`` protocol, a dev/CI fake, and a platform-gated
stub for the real ADCS Web Enrollment revocation implementation.

The RA holds **no signing key**.  Revocation is a request to the ADCS CA to
add the certificate to its CRL; the RA never signs a CRL itself.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Protocol


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RevocationResult:
    """Structured result returned by any revocation leg."""

    revoked: bool
    reason: int | None = None
    revoked_at: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class RevocationLeg(Protocol):
    """The interface any revocation backend must satisfy."""

    def revoke(
        self,
        cert_pem: str,
        reason: int | None,
    ) -> RevocationResult: ...


# ---------------------------------------------------------------------------
# Fake revocation leg (dev / CI)
# ---------------------------------------------------------------------------


class FakeRevocationLeg:
    """Dev/CI stand-in that pretends to revoke a certificate.

    Performs no network call and does not touch a real CA.  The certificate is
    marked revoked in the returned result so the server can update its store.
    """

    def revoke(
        self,
        cert_pem: str,
        reason: int | None,
    ) -> RevocationResult:
        from acme_adcs_ra.store import _now_iso

        return RevocationResult(
            revoked=True,
            reason=reason,
            revoked_at=_now_iso(),
            metadata={"source": "fake"},
        )


# ---------------------------------------------------------------------------
# Real ADCS revocation leg — platform-gated stub
# ---------------------------------------------------------------------------


class CertsrvRevocationLeg:
    """ADCS Web Enrollment revocation leg via /certsrv/certrev.asp.

    The real implementation requires Windows SSPI/Negotiate auth
    (``requests-negotiate-sspi``) and will be filled by the post-spike work.
    On non-Windows platforms the class is importable but ``revoke`` always
    raises ``NotImplementedError``.
    """

    def revoke(
        self,
        cert_pem: str,
        reason: int | None,
    ) -> RevocationResult:
        if sys.platform != "win32":
            raise NotImplementedError(
                "CertsrvRevocationLeg requires Windows (SSPI/Negotiate auth). "
                "Use FakeRevocationLeg for dev/CI."
            )
        # Live /certsrv/certrev.asp implementation goes here (post-spike).
        # It will import requests-negotiate-sspi inside this method so the
        # import only happens on Windows at call time.
        raise NotImplementedError(
            "CertsrvRevocationLeg not yet implemented — "
            "filled post-spike (POST to /certsrv/certrev.asp)"
        )
