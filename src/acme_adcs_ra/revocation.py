"""Revocation leg — the interface between the RA and the certificate revoker.

Defines the ``RevocationLeg`` protocol, a dev/CI fake, and an honest stub for
a real ADCS revocation mechanism.

The RA holds **no signing key**.  ADCS Web Enrollment (``/certsrv/``) exposes
no revocation endpoint: Microsoft Learn enumerates only request-cert /
retrieve-CA-cert / retrieve-CRL, the proven ``magnuswatn/certsrv`` reference has
no ``revoke()`` method, and ``acme2certifier`` returns "Revocation is not
supported."  The fictional ``certrev.asp`` / ``certrv.asp`` payload that was
present in an earlier draft has been removed.

The real revocation mechanism is ``certutil -revoke <serial> <reason>`` or
``ICertAdmin2::RevokeCertificate`` (COM).  Either path requires granting the
gMSA CA-officer rights ("Manage CA"), which is a security-model decision for
the operator and must be documented in ``docs/threat-model.md`` §E before it is
wired in.

The server's ``revokeCert`` endpoint remains connected to this leg, so once a
mechanism is chosen and implemented it can drop in without changing the ACME
surface.
"""

from __future__ import annotations

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
# Real ADCS revocation leg — documented gap
# ---------------------------------------------------------------------------


class CertsrvRevocationLeg:
    """Honest stub for ADCS certificate revocation.

    ADCS Web Enrollment does **not** expose a revocation endpoint; the fictional
    ``certrev.asp`` / ``certrv.asp`` form implementation was removed after
    reviewers confirmed the endpoint does not exist.  The server still routes
    ``revokeCert`` here so a real mechanism can be wired in later.

    Possible mechanisms (operator choice, each with a privilege implication):

    * ``certutil -revoke <serial> <reason>`` run by the gMSA.
    * ``ICertAdmin2::RevokeCertificate`` over COM from Python.

    Both require CA-officer ("Manage CA") rights for the gMSA — see
    ``docs/threat-model.md`` §E.
    """

    def __init__(self, *, host: str = "", ca_bundle: str | None = None, timeout: float = 30.0) -> None:
        pass

    def revoke(
        self,
        cert_pem: str,
        reason: int | None,
    ) -> RevocationResult:
        raise NotImplementedError(
            "ADCS Web Enrollment (/certsrv/) exposes no revocation endpoint. "
            "The real mechanism is `certutil -revoke <serial> <reason>` or "
            "ICertAdmin2::RevokeCertificate (COM), which requires granting the gMSA "
            "CA-officer (Manage CA) rights — a security-model decision "
            "(see docs/threat-model.md §E). Not yet implemented."
        )
