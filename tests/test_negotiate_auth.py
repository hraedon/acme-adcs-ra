"""Tests for the in-tree Negotiate auth (the parts that don't need live SSPI):
RFC 5929 tls-server-end-point channel binding + challenge-token parsing."""

from __future__ import annotations

import base64
import datetime
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acme_adcs_ra.negotiate_auth import NegotiateAuth, tls_server_end_point_digest


def _self_signed(hash_alg: hashes.HashAlgorithm) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hash_alg)
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_cbt_sha256_signed_hashes_with_sha256() -> None:
    der = _self_signed(hashes.SHA256())
    assert tls_server_end_point_digest(der) == b"tls-server-end-point:" + hashlib.sha256(der).digest()


def test_cbt_sha384_signed_hashes_with_sha384() -> None:
    der = _self_signed(hashes.SHA384())
    assert tls_server_end_point_digest(der) == b"tls-server-end-point:" + hashlib.sha384(der).digest()


def test_cbt_sha1_signed_upgrades_to_sha256() -> None:
    try:
        der = _self_signed(hashes.SHA1())
    except Exception:  # pragma: no cover - some cryptography builds refuse SHA1
        pytest.skip("SHA1 signing unavailable in this cryptography build")
    # RFC 5929: SHA-1/MD5 signature algorithms are upgraded to SHA-256.
    assert tls_server_end_point_digest(der) == b"tls-server-end-point:" + hashlib.sha256(der).digest()


def test_challenge_token_parsing() -> None:
    tok = base64.b64encode(b"server-token").decode("ascii")
    assert NegotiateAuth._challenge_token(f"Negotiate {tok}") == b"server-token"
    assert NegotiateAuth._challenge_token("Negotiate") is None
    assert NegotiateAuth._challenge_token("NTLM abc") is None
    assert NegotiateAuth._challenge_token("") is None
