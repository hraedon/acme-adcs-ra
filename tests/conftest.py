"""Shared test helpers.

The only thing here is a placeholder-JWK builder. Plenty of tests need a
handful of *distinct* account keys and do not care what they contain — the
store just needs different thumbprints. They used to spell those inline as
``{"kty": "RSA", "n": "x1", "e": "AQAB"}``.

That stopped working when ``jwk_thumbprint`` began enforcing canonical member
encodings (2026-08-18 F5): a key with several accepted spellings is a key with
several accounts, and deactivating the observed one leaves its twin usable. The
enforcement is the point, so the fixtures move rather than the rule.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def placeholder_rsa_jwk(label: str) -> dict[str, Any]:
    """A canonical, distinct RSA JWK derived from *label*.

    Not a real key — nothing here signs or verifies with it. The modulus is a
    hash of the label so distinct labels give distinct thumbprints, with the top
    bit forced on so the octet string carries no leading zero (RFC 7518 §2
    requires the minimal representation).
    """
    modulus = bytearray(hashlib.sha256(label.encode("utf-8")).digest())
    modulus[0] |= 0x80
    return {"kty": "RSA", "n": _b64u(bytes(modulus)), "e": "AQAB"}


def placeholder_ec_jwk(label: str) -> dict[str, Any]:
    """A canonical, distinct P-256 JWK derived from *label*.

    Coordinates are full 32-byte width, which RFC 7518 §6.2.1.2 requires and
    which the thumbprint now checks — a stripped or over-padded coordinate is
    a second spelling of the same key.
    """
    x = hashlib.sha256(f"{label}:x".encode()).digest()
    y = hashlib.sha256(f"{label}:y".encode()).digest()
    return {"kty": "EC", "crv": "P-256", "x": _b64u(x), "y": _b64u(y)}
