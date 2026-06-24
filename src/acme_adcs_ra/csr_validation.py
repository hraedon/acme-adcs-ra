"""CSR validation gates for the ACME finalize path."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acme_adcs_ra.acme_errors import bad_csr
from acme_adcs_ra.policy import validate_dns_name


def _reject_non_dns_sans(san_value: x509.SubjectAlternativeName) -> None:
    """M4: reject the CSR if it contains any non-DNSName SAN type.

    With server-auth-only scope, IPAddress/otherName/URI/RFC822Name SANs
    are an expansion risk — the ADCS template might honor them.
    """
    for gn in san_value:
        if not isinstance(gn, x509.DNSName):
            raise bad_csr(
                f"CSR contains unsupported SAN type {type(gn).__name__}; "
                f"only DNSName SANs are accepted"
            )


def _reject_wildcard_sans(san_values: list[str]) -> None:
    """Reject SAN values containing wildcard characters.

    The RA issues server-auth certs for specific hostnames, not wildcard
    certificates. A SAN like ``*.example.com`` is a wildcard cert request —
    a distinct risk profile that the SAN scope policy is not designed to
    authorize. Malformed names like ``foo*.example.com`` would also bypass
    the scope matcher (the suffix after the first dot still matches) if
    not rejected here. This is the primary gate; ``_match_dns_pattern``
    has a defense-in-depth backstop.
    """
    for san in san_values:
        if "*" in san:
            raise bad_csr(
                f"CSR SAN contains wildcard character '*': {san!r}; "
                f"wildcard certificates are not supported"
            )


def _reject_invalid_dns_sans(san_values: list[str]) -> None:
    """Reject SAN values that are not valid DNS names per RFC 1123.

    Catches malformed names — empty labels (``foo..example.com``), invalid
    characters (``foo!.example.com``), leading/trailing hyphens, excessive
    label or total length — that ``cryptography.x509.DNSName`` accepts but
    the ADCS template might honor. ``_reject_wildcard_sans`` runs first for
    the specific wildcard error; this is the general syntax gate.
    """
    for san in san_values:
        try:
            validate_dns_name(san)
        except ValueError as exc:
            raise bad_csr(f"CSR SAN is not a valid DNS name: {san!r}: {exc}")


def _validate_csr_key_strength(csr: x509.CertificateSigningRequest) -> None:
    """M5: enforce minimum key size — RSA ≥ 2048, EC over P-256/P-384/P-521."""
    pub = csr.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 2048:
            raise bad_csr(
                f"RSA key size {pub.key_size} is below the minimum of 2048 bits"
            )
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        allowed_curves: set[str] = {
            "secp256r1", "secp384r1", "secp521r1",
        }
        if pub.curve.name not in allowed_curves:
            raise bad_csr(
                f"EC curve {pub.curve.name} is not accepted; "
                f"allowed curves: P-256, P-384, P-521"
            )
    else:
        raise bad_csr(
            f"unsupported key type {type(pub).__name__}; "
            f"only RSA and EC keys are accepted"
        )
