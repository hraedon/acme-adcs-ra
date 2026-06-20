"""In-tree Negotiate (SPNEGO) auth for ``requests``, with Extended Protection
(channel binding) support.

Replaces ``requests-negotiate-sspi`` — a single-maintainer package (a provenance
concern already noted in the threat model) that additionally *broke on Python
3.14*: its error handler subscripts a ``pywintypes.error`` that is no longer
subscriptable, masking every real SSPI error behind a ``TypeError``.

This handler instead uses **pyspnego**, which:

- authenticates as the process's ambient identity (the **gMSA**) via SSPI with
  **no stored password** (``spnego.client(...)`` with no explicit credentials
  uses the current Windows logon session); and
- binds the token to the TLS channel (RFC 5929 ``tls-server-end-point``), so it
  works against an ADCS ``/certsrv/`` hardened with **EPA = Require** — the
  secure posture — rather than forcing it down to ``EPA = Accept``.

``spnego`` is imported lazily inside the auth flow so this module and the
deterministic channel-binding helper import cleanly on non-Windows CI, where
pyspnego is not installed (it is ``sys_platform == 'win32'``-gated).
"""

from __future__ import annotations

import base64
import socket
import ssl
from typing import Any

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes

_TLS_SERVER_END_POINT = b"tls-server-end-point:"


def tls_server_end_point_digest(cert_der: bytes) -> bytes:
    """RFC 5929 ``tls-server-end-point`` channel-binding application data.

    The server certificate is hashed with its own signature hash algorithm,
    except that MD5/SHA-1 signatures are upgraded to SHA-256 (per the RFC).
    """
    cert = x509.load_der_x509_certificate(cert_der)
    sig_hash = cert.signature_hash_algorithm
    if sig_hash is None or isinstance(sig_hash, (hashes.MD5, hashes.SHA1)):
        algorithm: hashes.HashAlgorithm = hashes.SHA256()
    else:
        algorithm = sig_hash
    digest = hashes.Hash(algorithm)
    digest.update(cert_der)
    return _TLS_SERVER_END_POINT + digest.finalize()


class NegotiateAuth(requests.auth.AuthBase):
    """SPNEGO/Negotiate as the ambient identity, channel-bound to the server's
    TLS certificate (works with ``EPA = Require``)."""

    def __init__(
        self,
        host: str,
        *,
        port: int = 443,
        ca_bundle: str | None = None,
        service: str = "HTTP",
    ) -> None:
        self._host = host
        self._port = port
        self._ca_bundle = ca_bundle
        self._service = service
        self._app_data: bytes | None = None

    def _server_cert_der(self) -> bytes:
        # The CBT is over the server's certificate (stable for the host), so a
        # side TLS probe with the same SNI yields the same cert the auth
        # connection uses. Verify it with the same trust anchor as the leg.
        ctx = (
            ssl.create_default_context(cafile=self._ca_bundle)
            if self._ca_bundle
            else ssl.create_default_context()
        )
        with socket.create_connection((self._host, self._port), timeout=30) as sock:
            with ctx.wrap_socket(sock, server_hostname=self._host) as tls:
                der = tls.getpeercert(binary_form=True)
        if der is None:  # pragma: no cover - defensive
            raise RuntimeError(f"no server certificate from {self._host}:{self._port}")
        return der

    def _channel_binding_app_data(self) -> bytes:
        if self._app_data is None:
            self._app_data = tls_server_end_point_digest(self._server_cert_der())
        return self._app_data

    @staticmethod
    def _challenge_token(www_authenticate: str) -> bytes | None:
        for part in www_authenticate.split(","):
            part = part.strip()
            if part[:9].lower() == "negotiate":
                token = part[9:].strip()
                if token:
                    return base64.b64decode(token)
        return None

    def _authenticate(self, response: requests.Response, **kwargs: Any) -> requests.Response:
        if response.status_code != 401:
            return response
        if "negotiate" not in response.headers.get("WWW-Authenticate", "").lower():
            return response

        import spnego  # type: ignore[import-not-found]  # lazy: win32-only dependency
        from spnego.channel_bindings import GssChannelBindings  # type: ignore[import-not-found]

        cbt = GssChannelBindings(application_data=self._channel_binding_app_data())
        client = spnego.client(
            hostname=self._host,
            service=self._service,
            channel_bindings=cbt,
            protocol="negotiate",
        )

        in_token: bytes | None = None
        current = response
        while True:
            out_token = client.step(in_token)
            if not out_token:
                return current
            current.content  # drain so the underlying connection can be reused
            request = current.request.copy()
            request.headers["Authorization"] = (
                "Negotiate " + base64.b64encode(out_token).decode("ascii")
            )
            cookie = current.headers.get("set-cookie")
            if cookie:
                request.headers["Cookie"] = cookie
            nxt = current.connection.send(request, **kwargs)
            nxt.history.append(current)
            if nxt.status_code != 401:
                return nxt
            in_token = self._challenge_token(nxt.headers.get("WWW-Authenticate", ""))
            current = nxt
            if in_token is None:
                return nxt

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        r.headers["Connection"] = "Keep-Alive"
        r.register_hook("response", self._authenticate)  # type: ignore[no-untyped-call]
        return r
