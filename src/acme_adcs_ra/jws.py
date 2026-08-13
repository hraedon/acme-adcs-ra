"""JWS verification helpers (RFC 7515 + RFC 8555 §6.2).

This module only **verifies** signatures; it never signs anything.
Supported account-key algorithms: RS256, RS384, RS512, ES256, ES384, ES512.
Supported EAB algorithms: HS256, HS384, HS512.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

# RSA account-key bounds, enforced in _public_key_from_jwk before the key is
# built or any signature is verified. The minimum blocks factorable legacy
# keys (possession of the public JWK would otherwise become eventual account
# takeover). The maximum modulus and the exponent allowlist bound the cost of
# the *unauthenticated* newAccount public-key operation: newAccount verifies an
# attacker-chosen n/e before it reads any EAB credential, and the 64 KiB JWS
# body cap does not bound compute (a 64 KiB body still admits a ~290 kbit
# modulus). The installed OpenSSL happens to reject oversized moduli and
# short-circuit huge exponents today, but that is incidental to the backend;
# enforcing the bound here keeps the guarantee in our own code.
_RSA_MIN_MODULUS_BITS = 2048
_RSA_MAX_MODULUS_BITS = 16384
# 65537 is what every ACME client generates; 3 is retained as a deliberate
# compatibility choice and is equally cost-safe (a tiny exponent). Both are far
# below any DoS threshold — the allowlist exists to reject the *large* exponent,
# not the small one.
_RSA_ALLOWED_EXPONENTS = frozenset({3, 65537})


class JWSValidationError(Exception):
    """Raised when a JWS fails structural or cryptographic validation."""


class UnsupportedAlgorithmError(JWSValidationError):
    """Raised when the JWS uses an algorithm we do not support."""


def _base64url_encode(data: bytes) -> str:
    """Base64url-encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Base64url-decode a string, tolerating missing padding."""
    padding_needed = (-len(data)) % 4
    return base64.urlsafe_b64decode(data + ("=" * padding_needed))


def _integer_to_der_bytes(value: int) -> bytes:
    """Encode a non-negative integer as a DER INTEGER (minimal, unsigned)."""
    byte_length = (value.bit_length() + 8) // 8
    if byte_length == 0:
        byte_length = 1
    raw = value.to_bytes(byte_length, "big")
    # If the high bit is set, prepend a zero byte so it is interpreted as positive.
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _length_bytes(len(raw)) + raw


def _length_bytes(length: int) -> bytes:
    """DER length octets for a definite-length short/long form."""
    if length < 0x80:
        return bytes([length])
    encoded: list[int] = []
    temp = length
    while temp:
        encoded.insert(0, temp & 0xFF)
        temp >>= 8
    return bytes([0x80 | len(encoded)] + encoded)


def _raw_ecdsa_to_der(signature: bytes, coordinate_byte_length: int) -> bytes:
    """Convert a raw R||S ECDSA signature to ASN.1 DER."""
    if len(signature) != 2 * coordinate_byte_length:
        raise JWSValidationError(
            f"invalid raw ECDSA signature length: {len(signature)} "
            f"(expected {2 * coordinate_byte_length})"
        )
    r = int.from_bytes(signature[:coordinate_byte_length], "big")
    s = int.from_bytes(signature[coordinate_byte_length:], "big")
    seq_body = _integer_to_der_bytes(r) + _integer_to_der_bytes(s)
    return b"\x30" + _length_bytes(len(seq_body)) + seq_body


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Return the RFC 7638 SHA-256 thumbprint of a JWK (base64url, no padding).

    This is the canonical, key-order-independent identity of an account key —
    used to deduplicate accounts (RFC 8555 §7.3). Hashing only; never signs.
    """
    kty = jwk.get("kty")
    if kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    else:
        raise UnsupportedAlgorithmError(f"cannot thumbprint JWK kty: {kty}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("ascii")
    return _base64url_encode(hashlib.sha256(canonical).digest())


def _public_key_from_jwk(jwk: dict[str, Any]) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
    """Build a cryptography public key from a JWK dictionary."""
    if not isinstance(jwk, dict):
        raise JWSValidationError("JWK must be a JSON object")
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(_base64url_decode(cast(str, jwk["n"])), "big")
        e = int.from_bytes(_base64url_decode(cast(str, jwk["e"])), "big")
        # Bound the public-key operation on the decoded integers, BEFORE
        # constructing the key or verifying a signature — this runs on
        # unauthenticated, attacker-chosen n/e ahead of any EAB check. See the
        # _RSA_* constants above for the rationale behind each bound.
        modulus_bits = n.bit_length()
        if modulus_bits < _RSA_MIN_MODULUS_BITS:
            raise JWSValidationError(
                f"RSA account key size {modulus_bits} is below the "
                f"{_RSA_MIN_MODULUS_BITS}-bit minimum"
            )
        if modulus_bits > _RSA_MAX_MODULUS_BITS:
            raise JWSValidationError(
                f"RSA account key size {modulus_bits} exceeds the "
                f"{_RSA_MAX_MODULUS_BITS}-bit maximum"
            )
        if e not in _RSA_ALLOWED_EXPONENTS:
            raise JWSValidationError(
                f"RSA public exponent {e} is not a supported value "
                f"(supported: {sorted(_RSA_ALLOWED_EXPONENTS)})"
            )
        return rsa.RSAPublicNumbers(e=e, n=n).public_key()
    if kty == "EC":
        crv = cast(str, jwk.get("crv"))
        curve_map: dict[str, ec.EllipticCurve] = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
        }
        curve = curve_map.get(crv)
        if curve is None:
            raise UnsupportedAlgorithmError(f"unsupported EC curve: {crv}")
        x = int.from_bytes(_base64url_decode(cast(str, jwk["x"])), "big")
        y = int.from_bytes(_base64url_decode(cast(str, jwk["y"])), "big")
        return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve).public_key()
    raise UnsupportedAlgorithmError(f"unsupported JWK kty: {kty}")


def _hash_for_alg(alg: str) -> hashes.HashAlgorithm:
    """Return the hash algorithm implied by an HS/RS/ES algorithm identifier."""
    if alg.endswith("256"):
        return hashes.SHA256()
    if alg.endswith("384"):
        return hashes.SHA384()
    if alg.endswith("512"):
        return hashes.SHA512()
    raise UnsupportedAlgorithmError(f"cannot infer hash for algorithm: {alg}")


def _hashlib_callable_for_alg(alg: str) -> Any:
    """Return a hashlib constructor for the algorithm suffix."""
    if alg.endswith("256"):
        return hashlib.sha256
    if alg.endswith("384"):
        return hashlib.sha384
    if alg.endswith("512"):
        return hashlib.sha512
    raise UnsupportedAlgorithmError(f"unsupported HMAC algorithm: {alg}")


def _coordinate_length_for_curve(curve: ec.EllipticCurve) -> int:
    """Byte length of an EC coordinate for supported curves."""
    return (curve.key_size + 7) // 8


def _verify_hmac(
    protected_b64: str,
    payload_b64: str,
    signature: bytes,
    mac_key: bytes,
    alg: str,
) -> bool:
    """Verify an HMAC over the JWS signing input."""
    try:
        hash_callable = _hashlib_callable_for_alg(alg)
    except UnsupportedAlgorithmError:
        return False
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    mac = hmac.new(mac_key, signing_input, hash_callable).digest()
    return hmac.compare_digest(mac, signature)


def verify_flattened_jws(
    jws: dict[str, Any],
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
) -> bytes:
    """Verify a flattened JSON JWS and return the decoded payload bytes.

    Raises JWSValidationError on structural, algorithmic, or signature failure.
    """
    protected_b64 = jws.get("protected")
    payload_b64 = jws.get("payload")
    signature_b64 = jws.get("signature")
    if not all(isinstance(v, str) for v in (protected_b64, payload_b64, signature_b64)):
        raise JWSValidationError("JWS missing protected, payload, or signature")

    protected_b64 = cast(str, protected_b64)
    payload_b64 = cast(str, payload_b64)
    signature_b64 = cast(str, signature_b64)

    try:
        protected_bytes = _base64url_decode(protected_b64)
        signature = _base64url_decode(signature_b64)
        payload = _base64url_decode(payload_b64)
    except Exception as exc:
        raise JWSValidationError(f"invalid base64url encoding: {exc}") from exc

    try:
        header = json.loads(protected_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JWSValidationError(f"protected header is not valid JSON: {exc}") from exc

    if not isinstance(header, dict):
        raise JWSValidationError("protected header must be a JSON object")

    alg = header.get("alg")
    if not isinstance(alg, str):
        raise JWSValidationError("protected header missing alg")

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")

    try:
        if alg in ("RS256", "RS384", "RS512"):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise JWSValidationError("RS* algorithm requires an RSA public key")
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                _hash_for_alg(alg),
            )
        elif alg in ("ES256", "ES384", "ES512"):
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise JWSValidationError("ES* algorithm requires an EC public key")
            expected_alg = {
                "secp256r1": "ES256",
                "secp384r1": "ES384",
                "secp521r1": "ES512",
            }.get(public_key.curve.name)
            if alg != expected_alg:
                raise JWSValidationError(
                    f"{alg} is not valid for EC curve {public_key.curve.name} "
                    f"(expected {expected_alg})"
                )
            coordinate_len = _coordinate_length_for_curve(public_key.curve)
            der_signature = _raw_ecdsa_to_der(signature, coordinate_len)
            public_key.verify(der_signature, signing_input, ec.ECDSA(_hash_for_alg(alg)))
        else:
            raise UnsupportedAlgorithmError(f"unsupported JWS alg: {alg}")
    except InvalidSignature as exc:
        raise JWSValidationError("JWS signature verification failed") from exc
    except UnsupportedAlgorithmError:
        raise
    except Exception as exc:
        raise JWSValidationError(f"signature verification error: {exc}") from exc

    return payload


def verify_eab_jws(
    eab_jws: dict[str, Any],
    account_jwk: dict[str, Any],
    mac_key: bytes,
    *,
    expected_url: str | None = None,
) -> str:
    """Verify an externalAccountBinding JWS and return the EAB kid.

    The EAB JWS payload must equal the account JWK.  The MAC key is looked up
    by the kid in the protected header.
    """
    protected_b64 = eab_jws.get("protected")
    payload_b64 = eab_jws.get("payload")
    signature_b64 = eab_jws.get("signature")
    if not all(isinstance(v, str) for v in (protected_b64, payload_b64, signature_b64)):
        raise JWSValidationError("EAB JWS missing protected, payload, or signature")

    protected_b64 = cast(str, protected_b64)
    payload_b64 = cast(str, payload_b64)
    signature_b64 = cast(str, signature_b64)

    try:
        header = json.loads(_base64url_decode(protected_b64))
    except Exception as exc:
        raise JWSValidationError(f"invalid EAB protected header: {exc}") from exc

    if not isinstance(header, dict):
        raise JWSValidationError("EAB protected header must be a JSON object")

    alg = header.get("alg")
    if alg not in ("HS256", "HS384", "HS512"):
        raise JWSValidationError(f"unsupported EAB algorithm: {alg}")
    alg = cast(str, alg)

    kid = header.get("kid")
    if not kid:
        raise JWSValidationError("EAB protected header missing kid")
    kid = cast(str, kid)

    if expected_url is not None and header.get("url") != expected_url:
        raise JWSValidationError(
            "EAB protected-header url does not match the newAccount endpoint"
        )

    try:
        eab_payload = _base64url_decode(payload_b64)
    except Exception as exc:
        raise JWSValidationError(f"invalid EAB payload encoding: {exc}") from exc

    try:
        decoded_jwk = json.loads(eab_payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JWSValidationError(f"EAB payload is not valid JSON: {exc}") from exc

    if not isinstance(decoded_jwk, dict):
        raise JWSValidationError("EAB payload JWK must be a JSON object")

    # Canonical JWK comparison: drop the optional 'alg' field per ACME §7.1.3
    # and compare sorted key-value pairs, so a present/absent 'alg' does not
    # flip the result (M1).
    def _canonical_jwk(jwk: dict[str, Any]) -> list[tuple[str, str]]:
        return sorted(
            (k, v) for k, v in jwk.items() if k != "alg"
        )

    if _canonical_jwk(decoded_jwk) != _canonical_jwk(account_jwk):
        raise JWSValidationError("EAB payload does not match account JWK")

    try:
        signature = _base64url_decode(signature_b64)
    except Exception as exc:
        raise JWSValidationError(f"invalid EAB signature encoding: {exc}") from exc

    if not _verify_hmac(protected_b64, payload_b64, signature, mac_key, alg):
        raise JWSValidationError("EAB MAC verification failed")

    return kid
