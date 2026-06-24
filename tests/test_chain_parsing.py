"""The certnew.p7b chain parser must survive ADCS's format quirks — in
particular a PKCS7 SignedData returned under -----BEGIN CERTIFICATE----- markers
with a text/html content-type, as observed against a live CA.

Extended coverage (WI-008): CMS markers, raw-base64 fallback, multiple blocks,
mixed marker types, HTML-wrapped responses, and the failure path.
"""

from __future__ import annotations

import base64
import datetime

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from acme_adcs_ra.enrollment import EnrollmentTransportError, _parse_pkcs7_chain


def _cert(cn: str) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


def _wrap(der: bytes, marker: str) -> bytes:
    b64 = base64.b64encode(der).decode("ascii")
    lines = "\r\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {marker}-----\r\n{lines}\r\n-----END {marker}-----\r\n".encode("ascii")


def test_pkcs7_wrapped_in_certificate_markers() -> None:
    # The live failure mode: a PKCS7 bundle mislabeled with CERTIFICATE markers.
    der = pkcs7.serialize_certificates(
        [_cert("leaf"), _cert("ca"), _cert("root")], serialization.Encoding.DER
    )
    assert len(_parse_pkcs7_chain(_wrap(der, "CERTIFICATE"))) == 3


def test_pkcs7_wrapped_in_pkcs7_markers() -> None:
    der = pkcs7.serialize_certificates([_cert("ca"), _cert("root")], serialization.Encoding.DER)
    assert len(_parse_pkcs7_chain(_wrap(der, "PKCS7"))) == 2


def test_single_der_certificate_block() -> None:
    der = _cert("only").public_bytes(serialization.Encoding.DER)
    pems = _parse_pkcs7_chain(_wrap(der, "CERTIFICATE"))
    assert len(pems) == 1
    assert pems[0].startswith("-----BEGIN CERTIFICATE-----")


def test_pkcs7_wrapped_in_cms_markers() -> None:
    """CMS is a valid standard PEM type (RFC 7468). The regex [A-Z0-9 ]+ must
    match it, not just CERTIFICATE and PKCS7."""
    der = pkcs7.serialize_certificates(
        [_cert("leaf"), _cert("ca")], serialization.Encoding.DER
    )
    assert len(_parse_pkcs7_chain(_wrap(der, "CMS"))) == 2


def test_raw_base64_no_pem_wrapper() -> None:
    """The fallback path (lines 391-395): when no PEM markers are present,
    the entire body is treated as raw base64."""
    der = pkcs7.serialize_certificates(
        [_cert("ca"), _cert("root")], serialization.Encoding.DER
    )
    raw_b64 = base64.b64encode(der)
    assert len(_parse_pkcs7_chain(raw_b64)) == 2


def test_multiple_pem_blocks() -> None:
    """Multiple PEM blocks in one response — re.finditer must collect all."""
    der1 = _cert("cert-a").public_bytes(serialization.Encoding.DER)
    der2 = _cert("cert-b").public_bytes(serialization.Encoding.DER)
    body = _wrap(der1, "CERTIFICATE") + _wrap(der2, "CERTIFICATE")
    pems = _parse_pkcs7_chain(body)
    assert len(pems) == 2


def test_mixed_marker_types() -> None:
    """A single DER cert in a CERTIFICATE block + a PKCS7 bundle in a PKCS7
    block — both must be extracted and parsed."""
    single_der = _cert("standalone").public_bytes(serialization.Encoding.DER)
    p7b_der = pkcs7.serialize_certificates(
        [_cert("chain-ca"), _cert("chain-root")], serialization.Encoding.DER
    )
    body = _wrap(single_der, "CERTIFICATE") + _wrap(p7b_der, "PKCS7")
    pems = _parse_pkcs7_chain(body)
    assert len(pems) == 3


def test_pem_block_embedded_in_html() -> None:
    """ADCS certnew.p7b returns text/html wrapping the PEM payload.
    The regex must find the PEM block within surrounding HTML."""
    der = pkcs7.serialize_certificates(
        [_cert("leaf"), _cert("ca"), _cert("root")], serialization.Encoding.DER
    )
    pem_block = _wrap(der, "CERTIFICATE")
    html = (
        b"<html><head><title>Certificate Chain</title></head>"
        b"<body><pre>" + pem_block + b"</pre></body></html>"
    )
    assert len(_parse_pkcs7_chain(html)) == 3


def test_empty_body_raises_transport_error() -> None:
    with pytest.raises(EnrollmentTransportError, match="did not contain a parseable chain"):
        _parse_pkcs7_chain(b"")
