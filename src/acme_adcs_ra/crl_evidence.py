"""Independent CRL evidence for CA-side revocation confirmations.

The RA holds no CA rights, so it cannot ask the CA "did you revoke this?".
That is why the WI-024 confirmation callback exists: the CA-side pull agent
runs ``certutil -revoke`` and then tells the RA it succeeded. The RA used to
take that entirely on faith and write ``revocation-ca-confirmed`` — an audit
event asserting an external security event it had not observed.

There is exactly one check available to the RA that does **not** depend on the
calling agent's honesty: the CRL. It is published by the CA, signed by the CA's
own key, and readable without any privilege. If a serial appears on a validly
signed CRL, the certificate really is revoked, no matter what the agent claims.

This module fetches and verifies that evidence. It is deliberately strict:

* the CRL's signature is verified against the **issuing CA certificate taken
  from the certificate's own stored chain** — not against whatever the CRL
  claims about itself, and not against a separately configured trust anchor
  that could drift from the chain the certificate was actually issued under;
* an expired CRL (``next_update`` in the past) is not evidence — a stale CRL
  is exactly what an attacker suppressing a revocation would like the RA to
  keep accepting;
* every failure returns "no evidence" rather than raising, so the caller
  decides whether missing evidence is fatal (``require_crl_evidence``) or
  merely downgrades the audit record to ``agent-asserted``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

import requests
from cryptography import x509

logger = logging.getLogger("acme_adcs_ra.crl_evidence")

# Verification outcomes recorded in the audit trail.
CRL_VERIFIED = "crl-verified"
AGENT_ASSERTED = "agent-asserted"


@dataclass(frozen=True)
class CrlEvidence:
    """The result of checking a serial against the CA's published CRL."""

    # True only when a validly signed, in-date CRL lists this serial.
    revoked: bool
    # True when a CRL was fetched and verified, whatever it said about the
    # serial. False means we learned nothing (fetch/parse/signature failure).
    checked: bool
    detail: str
    crl_number: str | None = None
    this_update: str | None = None
    next_update: str | None = None

    @property
    def verification(self) -> str:
        return CRL_VERIFIED if (self.checked and self.revoked) else AGENT_ASSERTED


def _issuer_public_key(cert_pem: str, chain_pem: list[str]) -> object | None:
    """Find the public key that signed *cert_pem*, from its own stored chain.

    The chain is what the CA returned at issuance, so it is the authoritative
    statement of which CA certificate this leaf was issued under.
    """
    try:
        leaf = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except ValueError:
        return None
    for pem in chain_pem:
        # A chain entry may itself hold several concatenated PEM certificates.
        try:
            candidates = x509.load_pem_x509_certificates(pem.encode("utf-8"))
        except ValueError:
            continue
        for candidate in candidates:
            if candidate.subject == leaf.issuer:
                return candidate.public_key()
    return None


def fetch_crl_evidence(
    *,
    crl_url: str,
    serial_number: int,
    cert_pem: str,
    chain_pem: list[str],
    timeout_seconds: float = 10.0,
    max_bytes: int = 10 * 1024 * 1024,
) -> CrlEvidence:
    """Check whether *serial_number* is on the CA's published CRL.

    Never raises: any failure is reported as ``checked=False`` with a reason.
    """
    parsed = urlparse(crl_url)
    # A CRL is signed, so plain HTTP is normal and safe for CDPs; anything
    # that is not an HTTP(S) URL (file://, etc.) is not.
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=f"CRL URL must be http(s) with a host: {crl_url!r}",
        )

    try:
        response = requests.get(crl_url, timeout=timeout_seconds, stream=True)
        response.raise_for_status()
        body = b""
        for chunk in response.iter_content(chunk_size=65536):
            body += chunk
            if len(body) > max_bytes:
                return CrlEvidence(
                    revoked=False,
                    checked=False,
                    detail=f"CRL exceeded {max_bytes} bytes",
                )
    except requests.RequestException as exc:
        return CrlEvidence(
            revoked=False, checked=False, detail=f"CRL fetch failed: {exc}"
        )

    crl: x509.CertificateRevocationList | None = None
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            crl = loader(body)
            break
        except ValueError:
            continue
    if crl is None:
        return CrlEvidence(
            revoked=False, checked=False, detail="CRL is neither valid DER nor PEM"
        )

    public_key = _issuer_public_key(cert_pem, chain_pem)
    if public_key is None:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=(
                "could not locate the issuing CA certificate in the stored "
                "chain, so the CRL signature cannot be verified"
            ),
        )
    if not crl.is_signature_valid(public_key):  # type: ignore[arg-type]
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail="CRL signature does not verify against the certificate's issuer",
        )

    this_update = crl.last_update_utc
    next_update = crl.next_update_utc
    now = datetime.now(UTC)
    if next_update is not None and next_update < now:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=f"CRL expired at {next_update.isoformat()}",
            this_update=this_update.isoformat() if this_update else None,
            next_update=next_update.isoformat(),
        )

    crl_number: str | None = None
    try:
        crl_number = str(
            crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        )
    except x509.ExtensionNotFound:
        pass

    entry = crl.get_revoked_certificate_by_serial_number(serial_number)
    return CrlEvidence(
        revoked=entry is not None,
        checked=True,
        detail=(
            "serial is listed on the CRL"
            if entry is not None
            else "serial is NOT listed on the CRL"
        ),
        crl_number=crl_number,
        this_update=this_update.isoformat() if this_update else None,
        next_update=next_update.isoformat() if next_update else None,
    )
