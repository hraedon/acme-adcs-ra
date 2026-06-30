"""Enrollment leg — the interface between the RA and the certificate issuer.

Defines the ``EnrollmentLeg`` protocol, a dev/CI fake, and a platform-gated
stub for the real ADCS Web Enrollment implementation.

The RA holds **no signing key**.  The fake returns a *static, pre-generated*
fixture certificate PEM loaded from package data — it must NEVER invoke any
certificate-minting primitive at runtime.
"""

from __future__ import annotations

import base64
import binascii
import importlib.resources
import logging
import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrollmentResult:
    """Structured result returned by any enrollment leg."""

    cert_pem: str
    chain_pem: list[str]
    template: str
    requester: str
    metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Enrollment error types (M2 — distinct so the real leg + audit can
# distinguish ADCS policy denial from transport error)
# ---------------------------------------------------------------------------


class EnrollmentDenied(Exception):
    """The ADCS CA explicitly denied the request (policy violation)."""


class EnrollmentTransportError(Exception):
    """A transport / connectivity error when contacting the ADCS CA."""


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class EnrollmentLeg(Protocol):
    """The interface any enrollment backend must satisfy."""

    def submit_csr(
        self,
        csr_pem: str,
        *,
        account_id: str,
        requested_sans: Sequence[str],
    ) -> EnrollmentResult: ...


# ---------------------------------------------------------------------------
# Fake enrollment leg (dev / CI)
# ---------------------------------------------------------------------------


def _fixture_text(name: str) -> str:
    """Load a fixture PEM from the package data.

    Using ``importlib.resources`` means this works from an editable install,
    an installed wheel, or an arbitrary working directory.
    """
    return (
        importlib.resources.files("acme_adcs_ra.fixtures")
        .joinpath(name)
        .read_text(encoding="utf-8")
    )


class FakeEnrollmentLeg:
    """Dev/CI stand-in that returns a static fixture certificate.

    **Critical constraint:** this class must NOT sign anything at runtime.
    It loads a pre-generated PEM from package data and returns it verbatim.
    The no-signing-key architecture test must stay green even with this
    class present.
    """

    def __init__(self, fixtures_dir: Path | None = None) -> None:
        self._fixtures_dir = fixtures_dir

    def _read_cert(self) -> str:
        if self._fixtures_dir is not None:
            return (self._fixtures_dir / "fake_cert.pem").read_text()
        return _fixture_text("fake_cert.pem")

    def _read_chain(self) -> str:
        if self._fixtures_dir is not None:
            return (self._fixtures_dir / "fake_chain.pem").read_text()
        return _fixture_text("fake_chain.pem")

    def submit_csr(
        self,
        csr_pem: str,
        *,
        account_id: str,
        requested_sans: Sequence[str],
    ) -> EnrollmentResult:
        cert_pem = self._read_cert()
        chain_pem = self._read_chain()
        return EnrollmentResult(
            cert_pem=cert_pem,
            chain_pem=[chain_pem],
            template="ACME-ServerAuth",
            requester=account_id,
            metadata={"source": "fake", "sans": ",".join(requested_sans)},
        )


# ---------------------------------------------------------------------------
# HTTP session Protocols (enable dependency-injection for unit tests)
# ---------------------------------------------------------------------------


class HttpResponse(Protocol):
    """Minimal view of an HTTP response (satisfied by ``requests.Response``)."""

    status_code: int
    text: str
    content: bytes
    headers: Mapping[str, str]

    def raise_for_status(self) -> None: ...


class HttpSession(Protocol):
    """Minimal HTTP session (satisfied by ``requests.Session`` on win32).

    Duck-typed so a test fake can stand in for ``requests.Session`` without
    the win32-only ``requests``/``requests-negotiate-sspi`` deps being
    installed.  ``requests`` is *only* imported inside ``_build_session``
    (the win32 default-session path), never at module top level.
    """

    def post(
        self, url: str, *, data: Mapping[str, str], timeout: float
    ) -> HttpResponse: ...

    def get(
        self, url: str, *, params: Mapping[str, str], timeout: float
    ) -> HttpResponse: ...


# ---------------------------------------------------------------------------
# Real ADCS enrollment leg — /certsrv/ via Negotiate/SSPI (Mode A)
# ---------------------------------------------------------------------------

# certfnsh.asp payload borrowed from magnuswatn/certsrv (the proven reference
# cited in docs/architecture.md) and mirrored in lab/spike_mode_a.py:
#   https://github.com/magnuswatn/certsrv/blob/master/certsrv.py
_CERTFNSH_USER_AGENT = "acme-adcs-ra/0.1-enroll (Mode A)"


class CertsrvEnrollmentLeg:
    """ADCS Web Enrollment leg via ``/certsrv/`` (Mode A).

    The real implementation authenticates to the ADCS Web Enrollment surface
    as the process's ambient **gMSA** identity using Negotiate/SSPI
    (``requests-negotiate-sspi``) — no stored password.  It POSTs the CSR to
    ``certfnsh.asp``, then fetches the issued certificate and the CA chain.

    On non-Windows platforms the class is importable but ``submit_csr`` raises
    ``NotImplementedError`` *unless* a ``session_factory`` is injected (which is
    how the full logic is unit-tested on Linux without a live CA).

    The RA holds **no signing key**; this leg only *forwards* the client's CSR
    and *parses* the ADCS-issued certificate/chain.  It never builds or signs
    a certificate (the pkcs7 *builder* is never used; only the loaders are).
    """

    def __init__(
        self,
        *,
        host: str,
        template: str,
        ca_name: str | None = None,
        ca_bundle: str | None = None,
        timeout: float = 30.0,
        session_factory: Callable[[], HttpSession] | None = None,
    ) -> None:
        self._host = host
        self._template = template
        self._ca_name = ca_name
        self._ca_bundle = ca_bundle
        self._timeout = timeout
        self._session_factory = session_factory

    def _build_session(self) -> HttpSession:
        """Build the live ADCS session: SPNEGO/Negotiate as the ambient gMSA,
        channel-bound to the CA's TLS cert (works with ``/certsrv/`` EPA=Require).

        ``pyspnego`` is ``sys_platform == 'win32'``-gated; ``NegotiateAuth``
        imports it lazily so the Linux env stays clean. No password is ever
        stored or read — the current Windows logon (the gMSA) is used.
        """
        import requests

        from acme_adcs_ra.negotiate_auth import NegotiateAuth

        session = requests.Session()
        session.auth = NegotiateAuth(self._host, ca_bundle=self._ca_bundle)
        session.headers.update({"User-agent": _CERTFNSH_USER_AGENT})
        session.verify = self._ca_bundle if self._ca_bundle else True
        return cast(HttpSession, session)

    def _requester(self) -> str:
        """Best-effort capture of the ambient enrollment identity (the gMSA)."""
        domain = os.environ.get("USERDOMAIN", "")
        user = os.environ.get("USERNAME", "?")
        return f"{domain}\\{user}" if domain else user

    def submit_csr(
        self,
        csr_pem: str,
        *,
        account_id: str,
        requested_sans: Sequence[str],
    ) -> EnrollmentResult:
        # Linux guard preserved: without an injected session the live
        # Negotiate/SSPI path is unavailable on non-Windows platforms.  When a
        # session_factory is injected (tests) the full logic runs regardless of
        # platform so it is unit-testable on Linux without a live CA.
        if sys.platform != "win32" and self._session_factory is None:
            raise NotImplementedError(
                "CertsrvEnrollmentLeg requires Windows (SSPI/Negotiate auth). "
                "Use FakeEnrollmentLeg for dev/CI."
            )

        session = (
            self._session_factory()
            if self._session_factory is not None
            else self._build_session()
        )
        base = f"https://{self._host}/certsrv"
        timeout = self._timeout

        try:
            # 1. Submit the CSR to certfnsh.asp (payload per magnuswatn/certsrv).
            form = {
                "Mode": "newreq",
                "CertRequest": csr_pem,
                "CertAttrib": f"CertificateTemplate:{self._template}\r\n",
                "FriendlyType": "Saved-Request Certificate",
                "TargetStoreFlags": "0",
                "SaveCert": "yes",
            }
            resp = session.post(f"{base}/certfnsh.asp", data=form, timeout=timeout)
            resp.raise_for_status()
            disposition, detail = _parse_certfnsh_disposition(
                resp.text, resp.status_code
            )
            if disposition == "pending":
                raise EnrollmentTransportError(
                    f"certificate pending or not issued (ReqID={detail}); "
                    "check the CA — manager approval may be on, "
                    "or the template policy denied the request"
                )
            if disposition == "denied":
                raise EnrollmentDenied(f"CA denied the request: {detail}")
            if disposition != "issued":
                raise EnrollmentTransportError(detail)
            req_id = detail

            # 2. Fetch the issued certificate (base64 or PEM).
            cert_resp = session.get(
                f"{base}/certnew.cer",
                params={"ReqID": req_id, "Enc": "b64"},
                timeout=timeout,
            )
            cert_resp.raise_for_status()
            # ADCS Web Enrollment is inconsistent about the certnew.cer
            # content-type (observed live: text/html wrapping an Enc=b64 PEM
            # body). Don't gate on the header — parse the body as a certificate
            # and fail only if that fails, surfacing a snippet for diagnosis.
            try:
                cert_pem = _parse_cert_body(cert_resp.content)
            except Exception as exc:
                ct = cert_resp.headers.get("Content-Type")
                snippet = " ".join(cert_resp.text[:400].split())
                raise EnrollmentTransportError(
                    f"certnew.cer did not return a parseable certificate "
                    f"(content-type {ct!r}): {exc}; body: {snippet}"
                ) from exc

            # 3. Fetch the CA chain (PKCS#7).  First scrape nRenewals from
            #    certcarc.asp, then GET certnew.p7b (mirrors spike_mode_a.py).
            arc_resp = session.get(f"{base}/certcarc.asp", params={}, timeout=timeout)
            arc_resp.raise_for_status()
            nren = re.search(r"var nRenewals=(\d+);", arc_resp.text)
            renewals = nren.group(1) if nren else "0"
            chain_resp = session.get(
                f"{base}/certnew.p7b",
                params={"ReqID": "CACert", "Renewal": renewals, "Enc": "b64"},
                timeout=timeout,
            )
            chain_resp.raise_for_status()
            chain_pem = _parse_pkcs7_chain(chain_resp.content)
        except EnrollmentDenied:
            raise
        except EnrollmentTransportError:
            raise
        except Exception as exc:
            # Preserve the stack for diagnosis — the wrapped message alone loses
            # where in the request/parse flow an unexpected error originated.
            _log.exception("certsrv enrollment failed (unexpected error)")
            raise EnrollmentTransportError(
                f"ADCS enrollment transport error: {exc}"
            ) from exc

        metadata: dict[str, str] = {
            "req_id": req_id,
            "host": self._host,
            "source": "certsrv",
        }
        if self._ca_name:
            metadata["ca_name"] = self._ca_name

        return EnrollmentResult(
            cert_pem=cert_pem,
            chain_pem=chain_pem,
            template=self._template,
            requester=self._requester(),
            metadata=metadata,
        )


def _parse_certfnsh_disposition(body: str, status_code: int) -> tuple[str, str]:
    """Parse a ``certfnsh.asp`` response body into a disposition.

    WI-007: prefers locale-independent structured signals over English
    prose strings. The signals, in priority order:

    1. **Issued** — ``certnew.cer?ReqID=<n>&`` (a download URL; the ``&``
       after the ReqID distinguishes it from a status-only link). URLs are
       locale-independent.
    2. **Denied** — a quoted disposition message preceded by a word and
       whitespace (e.g. ``is "Denied by policy"`` or ``lautet "Abgelehnt"``).
       The quoting and the word+space prefix are locale-independent; the
       word is typically a verb like "is"/"lautet"/"est". HTML attributes
       (``href="…"``) are excluded because they have no space before the
       quote.
    3. **Pending** — ``ReqID=<n>`` as a query/form parameter (the request
       was submitted and assigned a ReqID, but no download link and no
       denial message are present). Locale-independent — ``ReqID`` is a
       URL parameter name, not prose.
    4. **English fallback** — ``"Certificate Pending"`` and
       ``'The disposition message is "…"'`` (backward compatibility for
       English-locale ADCS).
    5. **Unrecognized** — surfaces a body snippet so the operator can see
       what the CA returned, rather than silently misreading a non-English
       locale as a generic transport error.

    Returns ``(disposition, detail)`` where disposition is one of
    ``"issued"``, ``"pending"``, ``"denied"``, ``"unknown"`` and detail
    is the ReqID (issued/pending), the denial message (denied), or a
    diagnostic snippet (unknown).
    """
    # 1. Issued: download link with ReqID=<n>& (the & precedes Enc=).
    m = re.search(r"certnew\.cer\?ReqID=(\d+)&", body)
    if m:
        return ("issued", m.group(1))

    # 2. Denied: a quoted message preceded by word+space (locale-independent).
    #    Strip <script> blocks first to avoid matching JavaScript string
    #    literals (e.g. return "...", var s = "..."). Filters out URL-like
    #    strings (JavaScript redirects, href values).
    noscript = re.sub(r"<script\b[^>]*>.*?</script>", "", body, flags=re.DOTALL | re.IGNORECASE)
    for match in re.finditer(r'\b\w+\s+"([^"]{5,})"', noscript):
        candidate = match.group(1)
        if "://" not in candidate and "certnew.cer" not in candidate.lower():
            return ("denied", candidate)

    # 3. Pending: ReqID= as a query/form parameter, no download link, no
    #    denial message. Locale-independent — ReqID is a URL parameter name.
    rid = re.search(r"ReqID=(\d+)", body)
    if rid:
        return ("pending", rid.group(1))

    # 4. English-locale fallback (backward compatibility).
    if re.search(r"Certificate Pending", body, re.IGNORECASE):
        rid = re.search(r"Your Request Id is (\d+)", body)
        return ("pending", rid.group(1) if rid else "?")

    msg = re.search(r'The disposition message is "([^"]+)', body)
    if msg:
        return ("denied", msg.group(1))

    # 5. Unrecognized: surface the body for diagnosis (not silent).
    snippet = " ".join(body[:400].split())
    return ("unknown", f"unrecognized certfnsh.asp response (HTTP {status_code}); body: {snippet}")


def _parse_cert_body(body: bytes) -> str:
    """Parse a ``certnew.cer`` response into a PEM string.

    ADCS with ``Enc=b64`` may return either a PEM block or a raw base64-encoded
    DER blob; handle both robustly.  This is a read/parse operation — no signing
    primitive is involved.
    """
    if body.lstrip().startswith(b"-----BEGIN CERTIFICATE"):
        return body.strip().decode("ascii")
    cleaned = body.replace(b"\n", b"").replace(b"\r", b"").replace(b" ", b"")
    der = base64.b64decode(cleaned, validate=True)
    cert = x509.load_der_x509_certificate(der)
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _parse_pkcs7_chain(body: bytes) -> list[str]:
    """Parse a ``certnew.p7b`` PKCS#7 response into a list of PEM cert strings.

    Per spec: try ``load_der_pkcs7_certificates`` after base64-decoding, falling
    back to ``load_pem_pkcs7_certificates``.  This is a read/parse operation —
    no signing primitive is involved (the pkcs7 *builder* is never used).
    """
    text = body.decode("latin-1", errors="replace")
    # The PEM markers ADCS uses here are unreliable: this surface returns a PKCS7
    # SignedData wrapped in -----BEGIN CERTIFICATE----- markers (text/html
    # content-type). So collect the DER blob from any PEM block (or the whole
    # body as raw base64), then try to read each blob as a PKCS7 bundle first and
    # a single DER certificate second.
    blobs: list[bytes] = []
    for match in re.finditer(r"-----BEGIN [A-Z0-9 ]+-----(.*?)-----END [A-Z0-9 ]+-----", text, re.DOTALL):
        try:
            blobs.append(base64.b64decode(re.sub(r"\s+", "", match.group(1))))
        except (binascii.Error, ValueError):
            continue
    if not blobs:
        try:
            blobs.append(base64.b64decode(re.sub(rb"\s+", b"", body)))
        except (binascii.Error, ValueError):
            pass

    certs: list[x509.Certificate] = []
    for der in blobs:
        try:
            certs.extend(pkcs7.load_der_pkcs7_certificates(der))
            continue
        except (ValueError, TypeError):
            pass
        try:
            certs.append(x509.load_der_x509_certificate(der))
        except (ValueError, TypeError):
            pass

    if not certs:
        snippet = " ".join(text[:300].split())
        raise EnrollmentTransportError(
            f"certnew.p7b did not contain a parseable chain (len={len(body)}); body: {snippet}"
        )
    return [c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs]
