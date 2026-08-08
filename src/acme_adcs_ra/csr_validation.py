"""CSR validation gates for the ACME finalize path."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

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


def _reject_unrequested_common_names(
    csr: x509.CertificateSigningRequest, requested_sans: list[str]
) -> None:
    """Keep the CSR subject from becoming a second, unscoped identity path.

    The ADCS template is configured to take the subject from the request.  A
    client must therefore not be able to pair an allowed SAN with an
    out-of-scope Common Name and rely on legacy CN name matching.
    """
    authorized = {name.rstrip(".").lower() for name in requested_sans}
    for attribute in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        common_name = attribute.value
        if not isinstance(common_name, str):
            raise bad_csr("CSR Common Name must be a text DNS name")
        try:
            validate_dns_name(common_name)
        except ValueError as exc:
            raise bad_csr(
                f"CSR Common Name is not a valid DNS name: {common_name!r}: {exc}"
            ) from exc
        if common_name.rstrip(".").lower() not in authorized:
            raise bad_csr(
                f"CSR Common Name {common_name!r} is not one of the requested DNS SANs"
            )


def _reject_ca_capable_csr_extensions(csr: x509.CertificateSigningRequest) -> None:
    """Reject CSR requests that ask the issuing template for CA capability."""
    try:
        basic_constraints = csr.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        if isinstance(basic_constraints, x509.BasicConstraints) and basic_constraints.ca:
            raise bad_csr("CSR requests BasicConstraints CA=true")

    try:
        key_usage = csr.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return
    if isinstance(key_usage, x509.KeyUsage) and (
        key_usage.key_cert_sign or key_usage.crl_sign
    ):
        raise bad_csr("CSR requests certificate/CRL signing key usage")
