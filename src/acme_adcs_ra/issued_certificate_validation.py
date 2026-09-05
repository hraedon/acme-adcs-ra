"""Security validation for certificates returned by ADCS.

These checks run after ADCS has issued a certificate but before the RA records
or serves it.  They are kept free of store, enrollment, and route state so the
result-validation boundary can be reviewed independently from finalization.
"""

from __future__ import annotations

from typing import cast

from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.oid import ExtensionOID

from acme_adcs_ra.acme_errors import server_internal

# SAN types that carry identity but are NOT DNS. A server-auth-only template
# driven by the CSR must never emit any of these; their presence on an issued
# cert means the template is misconfigured (or pulling from AD). The RA's CSR
# gate already rejects non-DNS SANs -- this enforces the same on the result.
_NON_DNS_SAN_TYPES: tuple[tuple[type, str], ...] = (
    (x509.RFC822Name, "RFC822Name (email)"),
    (x509.IPAddress, "IPAddress"),
    (x509.UniformResourceIdentifier, "URI"),
    (x509.OtherName, "OtherName"),
    (x509.RegisteredID, "RegisteredID"),
    (x509.DirectoryName, "DirectoryName"),
)


def issued_cert_san_violations(
    cert_pem: str, requested_sans: list[str]
) -> tuple[list[str], list[str], list[str]]:
    """Inspect the issued certificate for SANs the order did not authorize.

    Returns ``(issued_dns_sans, unauthorized_dns, non_dns_san_types)``. A cert
    with no SAN extension yields ``([], [], [])``. DNS names use the same
    case-insensitive, trailing-dot normalization as issuance policy.
    """
    try:
        issued = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive; enrollment parsed it
        raise server_internal(f"issued cert unparseable: {exc}") from exc
    try:
        san_ext = issued.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return [], [], []
    san_value = cast(x509.SubjectAlternativeName, san_ext.value)
    issued_dns = [str(v) for v in san_value.get_values_for_type(DNSName)]
    authorized = {s.rstrip(".").lower() for s in requested_sans}
    unauthorized = [
        s for s in issued_dns if s.rstrip(".").lower() not in authorized
    ]
    non_dns = [
        label
        for san_type, label in _NON_DNS_SAN_TYPES
        if san_value.get_values_for_type(san_type)
    ]
    return issued_dns, unauthorized, non_dns


# serverAuth is the ONLY EKU a server-authentication template may issue. A cert
# with no EKU is all-purpose; anyExtendedKeyUsage is likewise unbounded.
_SERVER_AUTH_EKU_OID = "1.3.6.1.5.5.7.3.1"
_EKU_OID_LABELS: dict[str, str] = {
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "2.5.29.37.0": "anyExtendedKeyUsage",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.4.1.311.20.2.2": "smartcardLogon",
    "1.3.6.1.5.2.3.3": "pkinitKDC",
    "1.3.6.1.5.2.3.4": "pkinitClientAuth",
    "1.3.6.1.5.2.3.5": "pkinitServerAuth",
}


def issued_cert_eku_violations(cert_pem: str) -> list[str]:
    """Return violations unless the issued certificate is serverAuth-only."""
    try:
        issued = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive; enrollment parsed it
        raise server_internal(f"issued cert unparseable: {exc}") from exc
    try:
        eku_ext = issued.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    except x509.ExtensionNotFound:
        return ["no Extended Key Usage extension (certificate is all-purpose)"]
    eku_value = cast(x509.ExtendedKeyUsage, eku_ext.value)
    oids = [oid.dotted_string for oid in eku_value]
    violations: list[str] = []
    non_server = [o for o in oids if o != _SERVER_AUTH_EKU_OID]
    if non_server:
        labelled = [
            f"{_EKU_OID_LABELS[o]} ({o})" if o in _EKU_OID_LABELS else o
            for o in non_server
        ]
        violations.append(f"EKU beyond serverAuth: {labelled}")
    if _SERVER_AUTH_EKU_OID not in oids:
        violations.append("serverAuth EKU (1.3.6.1.5.5.7.3.1) absent")
    return violations


def issued_cert_ca_capability_violations(cert_pem: str) -> list[str]:
    """Return violations when an issued certificate could act as a CA."""
    try:
        issued = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive; enrollment parsed it
        raise server_internal(f"issued cert unparseable: {exc}") from exc

    violations: list[str] = []
    try:
        basic_constraints = issued.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        if isinstance(basic_constraints, x509.BasicConstraints) and basic_constraints.ca:
            violations.append("BasicConstraints CA=true")

    try:
        key_usage = issued.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return violations
    if isinstance(key_usage, x509.KeyUsage):
        if key_usage.key_cert_sign:
            violations.append("KeyUsage keyCertSign=true")
        if key_usage.crl_sign:
            violations.append("KeyUsage cRLSign=true")
    return violations
