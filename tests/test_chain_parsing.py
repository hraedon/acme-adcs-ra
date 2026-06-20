"""The certnew.p7b chain parser must survive ADCS's format quirks — in
particular a PKCS7 SignedData returned under -----BEGIN CERTIFICATE----- markers
with a text/html content-type, as observed against a live CA."""

from __future__ import annotations

import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from acme_adcs_ra.enrollment import _parse_pkcs7_chain


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
