"""Regression tests for issuance identity and CA-capability boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from acme_adcs_ra.acme_errors import AcmeError
from acme_adcs_ra.csr_validation import (
    _reject_ca_capable_csr_extensions,
    _reject_unrequested_common_names,
)
from acme_adcs_ra.enrollment import (
    EnrollmentTransportError,
    _validate_issued_certificate_binding,
)
from acme_adcs_ra.finalize import _issued_cert_ca_capability_violations


def _csr(
    key: rsa.RSAPrivateKey,
    *,
    common_name: str,
    san: str,
    ca: bool = False,
) -> x509.CertificateSigningRequest:
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
    return builder.sign(key, hashes.SHA256())


def _cert(
    key: rsa.RSAPrivateKey,
    *,
    common_name: str,
    ca: bool = False,
) -> str:
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_csr_common_name_cannot_escape_san_scope() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = _csr(
        key,
        common_name="dc01.out-of-scope.example",
        san="allowed.example",
    )
    with pytest.raises(AcmeError, match="not one of the requested DNS SANs"):
        _reject_unrequested_common_names(csr, ["allowed.example"])


def test_ca_capable_csr_is_rejected_before_enrollment() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = _csr(key, common_name="allowed.example", san="allowed.example", ca=True)
    with pytest.raises(AcmeError, match="CA=true"):
        _reject_ca_capable_csr_extensions(csr)


def test_ca_capable_issued_certificate_is_rejected() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    violations = _issued_cert_ca_capability_violations(
        _cert(key, common_name="allowed.example", ca=True)
    )
    assert "BasicConstraints CA=true" in violations


def test_certsrv_response_must_match_csr_public_key() -> None:
    csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = _csr(
        csr_key,
        common_name="allowed.example",
        san="allowed.example",
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    with pytest.raises(EnrollmentTransportError, match="public key does not match"):
        _validate_issued_certificate_binding(
            _cert(wrong_key, common_name="allowed.example"),
            csr_pem,
            ["allowed.example"],
        )


def test_certsrv_response_common_name_stays_in_scope() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = _csr(key, common_name="allowed.example", san="allowed.example")
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    with pytest.raises(EnrollmentTransportError, match="out-of-scope"):
        _validate_issued_certificate_binding(
            _cert(key, common_name="other.example"),
            csr_pem,
            ["allowed.example"],
        )
