"""Unit tests for acme_adcs_ra.jws — JWS and EAB verification only (no signing)."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from acme_adcs_ra.jws import (
    JWSValidationError,
    UnsupportedAlgorithmError,
    verify_eab_jws,
    verify_flattened_jws,
    _base64url_encode,
    _public_key_from_jwk,
)


def _b64url_encode_dict(obj: dict) -> str:
    return _base64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _make_jws_payload(payload: dict) -> str:
    return _b64url_encode_dict(payload)


@pytest.fixture()
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


class TestJWSVerify:
    def test_valid_rs256(self, rsa_key: rsa.RSAPrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "RS256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = rsa_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature),
        }
        result = verify_flattened_jws(jws, rsa_key.public_key())
        assert json.loads(result) == payload

    def test_valid_es256(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "ES256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        # cryptography returns DER; our verifier expects raw R||S.
        der_sig = ec_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        raw_sig = _der_to_raw(der_sig, 32)
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(raw_sig),
        }
        result = verify_flattened_jws(jws, ec_key.public_key())
        assert json.loads(result) == payload

    def test_invalid_signature_rs256(self, rsa_key: rsa.RSAPrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "RS256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = rsa_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature + b"\x00"),
        }
        with pytest.raises(JWSValidationError, match="signature verification failed"):
            verify_flattened_jws(jws, rsa_key.public_key())

    def test_wrong_alg_rs256_vs_es256(self, rsa_key: rsa.RSAPrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "ES256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        # Sign as RS256 but claim ES256.
        signature = rsa_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature),
        }
        with pytest.raises(JWSValidationError):
            verify_flattened_jws(jws, rsa_key.public_key())

    def test_unsupported_alg(self, rsa_key: rsa.RSAPrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "PS256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = rsa_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature),
        }
        with pytest.raises(UnsupportedAlgorithmError):
            verify_flattened_jws(jws, rsa_key.public_key())

    def test_public_key_from_jwk_rsa(self, rsa_key: rsa.RSAPrivateKey) -> None:
        pub = rsa_key.public_key()
        numbers = pub.public_numbers()
        jwk = {
            "kty": "RSA",
            "n": _base64url_encode(
                numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
            ),
            "e": _base64url_encode(
                numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
            ),
        }
        rebuilt = _public_key_from_jwk(jwk)
        assert isinstance(rebuilt, rsa.RSAPublicKey)
        assert rebuilt.public_numbers() == numbers

    def test_public_key_from_jwk_ec(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        pub = ec_key.public_key()
        numbers = pub.public_numbers()
        coordinate_len = (pub.curve.key_size + 7) // 8
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url_encode(numbers.x.to_bytes(coordinate_len, "big")),
            "y": _base64url_encode(numbers.y.to_bytes(coordinate_len, "big")),
        }
        rebuilt = _public_key_from_jwk(jwk)
        assert isinstance(rebuilt, ec.EllipticCurvePublicKey)


class TestEABVerify:
    def test_valid_eab_hs256(self, rsa_key: rsa.RSAPrivateKey) -> None:
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        eab_jws = _make_eab_jws(account_jwk, "kid-001", mac_key)
        assert verify_eab_jws(eab_jws, account_jwk, mac_key) == "kid-001"

    def test_unknown_alg_rejected(self, rsa_key: rsa.RSAPrivateKey) -> None:
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        protected_b64 = _b64url_encode_dict({"alg": "HS128", "kid": "kid-001"})
        payload_b64 = _b64url_encode_dict(account_jwk)
        eab_jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(b"bogus"),
        }
        with pytest.raises(JWSValidationError, match="unsupported EAB algorithm"):
            verify_eab_jws(eab_jws, account_jwk, mac_key)

    def test_wrong_mac_rejected(self, rsa_key: rsa.RSAPrivateKey) -> None:
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        eab_jws = _make_eab_jws(account_jwk, "kid-001", mac_key)
        with pytest.raises(JWSValidationError, match="MAC verification failed"):
            verify_eab_jws(eab_jws, account_jwk, b"wrong-key-32-bytes-long!!!!!!!")

    def test_payload_mismatch_rejected(self, rsa_key: rsa.RSAPrivateKey) -> None:
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        eab_jws = _make_eab_jws(account_jwk, "kid-001", mac_key)
        other_jwk = dict(account_jwk)
        other_jwk["n"] = other_jwk["n"][:-1] + "X"
        with pytest.raises(JWSValidationError, match="does not match"):
            verify_eab_jws(eab_jws, other_jwk, mac_key)

    def test_jwks_differing_only_in_alg_are_equal(self, rsa_key: rsa.RSAPrivateKey) -> None:
        """M1: JWKs that differ only in the optional 'alg' field must be treated as equal.

        Per ACME §7.1.3, 'alg' is optional in the JWK; its presence/absence
        must not flip the comparison result.
        """
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        # EAB JWS payload contains the bare JWK (no alg).
        eab_jws = _make_eab_jws(account_jwk, "kid-001", mac_key)
        # account_jwk_with_alg has an extra 'alg' field — must still match.
        account_jwk_with_alg = dict(account_jwk, alg="RS256")
        result = verify_eab_jws(eab_jws, account_jwk_with_alg, mac_key)
        assert result == "kid-001"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _jwk(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> dict[str, object]:
    pub = key.public_key()
    if isinstance(key, rsa.RSAPrivateKey):
        numbers = pub.public_numbers()
        return {
            "kty": "RSA",
            "n": _base64url_encode(
                numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
            ),
            "e": _base64url_encode(
                numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
            ),
        }
    numbers = pub.public_numbers()
    coordinate_len = (pub.curve.key_size + 7) // 8
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _base64url_encode(numbers.x.to_bytes(coordinate_len, "big")),
        "y": _base64url_encode(numbers.y.to_bytes(coordinate_len, "big")),
    }


def _make_eab_jws(
    account_jwk: dict[str, object],
    kid: str,
    mac_key: bytes,
    alg: str = "HS256",
) -> dict[str, str]:
    import hmac

    protected_b64 = _b64url_encode_dict({"alg": alg, "kid": kid})
    payload_b64 = _b64url_encode_dict(account_jwk)
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    hash_name = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}[alg]
    mac = hmac.new(mac_key, signing_input, hash_name).digest()
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": _base64url_encode(mac),
    }


def _der_to_raw(der_sig: bytes, coordinate_len: int) -> bytes:
    if der_sig[0] != 0x30:
        raise ValueError("not a sequence")
    seq_len = der_sig[1]
    offset = 2
    if seq_len & 0x80:
        len_bytes = seq_len & 0x7F
        seq_len = int.from_bytes(der_sig[offset : offset + len_bytes], "big")
        offset += len_bytes

    def _parse_int() -> int:
        nonlocal offset
        if der_sig[offset] != 0x02:
            raise ValueError("expected INTEGER")
        int_len = der_sig[offset + 1]
        offset += 2
        value = int.from_bytes(der_sig[offset : offset + int_len], "big")
        offset += int_len
        return value

    r = _parse_int()
    s = _parse_int()
    return r.to_bytes(coordinate_len, "big") + s.to_bytes(coordinate_len, "big")
