"""Revocation leg — the interface between the RA and the certificate revoker.

Defines the ``RevocationLeg`` protocol, a dev/CI fake, and the production
**out-of-band** revocation leg for ADCS.

The RA holds **no signing key** and the production gMSA holds **no CA-officer
rights**. ADCS Web Enrollment (``/certsrv/``) exposes no revocation endpoint:
Microsoft Learn enumerates only request-cert / retrieve-CA-cert / retrieve-CRL,
the proven ``magnuswatn/certsrv`` reference has no ``revoke()`` method, and
``acme2certifier`` returns "Revocation is not supported." The fictional
``certrev.asp`` / ``certrv.asp`` payload that was present in an earlier draft
has been removed.

The real revocation mechanism is ``certutil -revoke <serial> <reason>`` or
``ICertAdmin2::RevokeCertificate`` (COM). Either path requires granting the
caller CA-officer ("Manage CA") rights. The project's tightest security tenet
is that the **enrollment gMSA must not gain CA-officer rights** — that would
let a compromised RA host revoke *any* cert on the CA, not just its own, which
is a blast-radius increase the operator has explicitly declined (decision
recorded 2026-06-30, see ``docs/threat-model.md`` §E and
``plans/002-pilot-readiness.md`` Phase 2).

WI-010 therefore ships revocation as a **first-class out-of-band** capability:

* The RA's ``revokeCert`` endpoint records the revocation in the RA store
  (cert → ``revoked``, order → ``revoked``, GET cert → 410 Gone) and emits an
  honest audit event whose ``details.revocation_scope`` is ``"ra-store-only"``
  and ``details.ca_crl_updated`` is ``false``. The ACME response surfaces the
  out-of-band step so the client/operator knows the CA CRL was not written.
* ``scripts/Revoke-Cert.ps1`` is the operator-run, CA-admin credential that
  performs the actual ``certutil -revoke`` against the CA, taking the serial
  or ReqID the RA already stores. It is run by a CA officer, **not** the gMSA,
  so the standing enrollment identity never gains CA-officer power.

The server's ``revokeCert`` endpoint remains connected to this leg via the
``RevocationLeg`` protocol, so if an operator ever makes the explicit, recorded
decision to grant the gMSA CA-officer rights and wire in an in-band
``certutil``/``ICertAdmin2`` call, it can drop in without changing the ACME
surface — only this leg changes, plus the ``revocation_scope`` metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RevocationResult:
    """Structured result returned by any revocation leg.

    ``revoked`` reflects whether the *RA-store* revocation succeeded (the cert
    is marked revoked in the RA and will no longer be served). The
    ``ca_crl_updated`` flag in ``metadata`` records whether the CA-side CRL
    entry was also written — for the out-of-band leg this is ``"false"`` and
    the operator must run ``scripts/Revoke-Cert.ps1`` separately.
    """

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
            # The fake leg pretends to fully revoke (including the CA CRL), so
            # its scope is "ca-crl" and ca_crl_updated is "true". This keeps the
            # two markers consistent; the route uses them to decide whether to
            # surface the out_of_band_revocation hint.
            metadata={"source": "fake", "revocation_scope": "ca-crl", "ca_crl_updated": "true"},
        )


# ---------------------------------------------------------------------------
# Out-of-band ADCS revocation leg (WI-010)
# ---------------------------------------------------------------------------


# Revocation scope values recorded in audit ``details`` and ``RevocationResult``.
# - "ra-store-only": the RA marked the cert revoked; the CA CRL was NOT written.
#   The operator must run scripts/Revoke-Cert.ps1 out-of-band to write the CRL.
# - "ca-crl":        the CA CRL entry was also written (a future in-band leg
#   granted CA-officer rights — not the default; see docs/threat-model.md §E).
SCOPE_RA_STORE_ONLY = "ra-store-only"


def _serial_from_pem(cert_pem: str) -> str:
    """Return the uppercase hex serial for a cert PEM (the form certutil uses)."""
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    return format(cert.serial_number, "x").upper()


class CertsrvRevocationLeg:
    """Out-of-band revocation leg for ADCS (WI-010).

    The RA marks the certificate revoked in its own store and surfaces the
    out-of-band step; it does **not** call the CA. This keeps the enrollment
    gMSA least-privileged (Read+Enroll on one server-auth template only) —
    writing the CA CRL requires CA-officer ("Manage CA") rights, which is a
    blast-radius increase the operator has explicitly declined (decision
    recorded 2026-06-30; see ``docs/threat-model.md`` §E).

    The returned ``RevocationResult`` has:

    * ``revoked=True`` — the RA-store revocation succeeded, so the server
      flips the cert/order to revoked and GET cert returns 410 Gone.
    * ``metadata["revocation_scope"] = "ra-store-only"`` and
      ``metadata["ca_crl_updated"] = "false"`` — the audit event and ACME
      response carry these so the operator knows the CA CRL was **not**
      written and must run ``scripts/Revoke-Cert.ps1`` out-of-band.
    * ``metadata["serial"]`` — the uppercase hex serial the operator's
      ``Revoke-Cert.ps1`` consumes. The ADCS ReqID is **not** surfaced here
      (it is not carried on the cert); the route enriches the audit event
      and ACME response with ``req_id`` from the cert's stored RA metadata.

    If an operator ever makes the explicit, recorded decision to grant the
    gMSA CA-officer rights and call ``certutil -revoke`` / ``ICertAdmin2``
    in-band, only this leg changes (plus the scope metadata); the ACME
    surface stays the same.
    """

    def __init__(self, *, host: str = "", ca_bundle: str | None = None, timeout: float = 30.0) -> None:
        # Parameters retained for signature compatibility with the enrollment
        # leg and prior callers. The out-of-band leg makes no network call, so
        # they are not used; they are documented here so a future in-band leg
        # that does call the CA can adopt them without a constructor change.
        self._host = host
        self._ca_bundle = ca_bundle
        self._timeout = timeout

    def revoke(
        self,
        cert_pem: str,
        reason: int | None,
    ) -> RevocationResult:
        from acme_adcs_ra.store import _now_iso

        serial_hex = _serial_from_pem(cert_pem)
        metadata: dict[str, str] = {
            "revocation_scope": SCOPE_RA_STORE_ONLY,
            "ca_crl_updated": "false",
            "serial": serial_hex,
        }
        return RevocationResult(
            revoked=True,
            reason=reason,
            revoked_at=_now_iso(),
            metadata=metadata,
        )