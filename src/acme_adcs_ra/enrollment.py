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
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

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


class EnrollmentPending(Exception):
    """The CA accepted the request but has not decided it yet.

    ``certfnsh.asp`` returns a "pending" disposition — with a **ReqID** — when
    the template requires manager approval, or when CA policy defers. The
    request now exists in the CA database and may become an issued, live,
    domain-trusted certificate at any later moment, at an officer's discretion.

    This used to be raised as a plain :class:`EnrollmentTransportError` with the
    ReqID left in the message string (2026-08-18 F4). That put it in the same
    bucket as "the CA was unreachable", so ``ca_issued`` was false, nothing
    durable recorded which request was outstanding, and administrative recovery
    could reopen the order on an operator's "no certificate was issued"
    assertion — an assertion that is *true at the time it is made* and becomes
    false when the officer approves. The retry then submits a second request and
    the order ends up with two live certificates, which is precisely the
    invariant the lifecycle exists to hold.

    Distinct type, ReqID carried structurally: the finalize path persists it on
    the order, and reclaim refuses to reopen until that exact request is
    accounted for.
    """

    def __init__(self, message: str, *, req_id: str) -> None:
        super().__init__(message)
        self.req_id = req_id


class EnrollmentTransportError(Exception):
    """A transport / connectivity error when contacting the ADCS CA.

    ``req_id`` and ``cert_pem`` are set when the failure happened **after the
    CA had already issued**. That window is real: ``certfnsh.asp`` returns an
    "issued" disposition with a ReqID, and only then does the leg fetch the
    certificate, fetch the PKCS#7 chain, and validate that the chain binds to
    the leaf. A failure in any of those steps leaves a live, domain-trusted
    certificate at the CA — with a serial and a CA database row — while the RA
    is about to return 503.

    Carrying the identifiers out with the exception is what lets the finalize
    path quarantine it instead of orphaning it. Without them the RA recorded
    only ``{"error": ...}``, and the operator had a timestamp with which to go
    hunting in the CA database. See ``finalize._quarantine_transport_orphan``.
    """

    def __init__(
        self,
        message: str,
        *,
        req_id: str | None = None,
        cert_pem: str | None = None,
        chain_pem: Sequence[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.req_id = req_id
        self.cert_pem = cert_pem
        self.chain_pem = list(chain_pem) if chain_pem is not None else []

    @property
    def ca_issued(self) -> bool:
        """True when the CA issued before this failure — the dangerous case."""
        return self.req_id is not None


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


class _NoRedirectSession:
    """Wraps a live ``requests.Session`` so it never follows a redirect.

    ``requests`` strips the ``Authorization`` header when a redirect crosses to
    another host — but that protection does **not** apply here, because
    ``NegotiateAuth`` does not set a static header. It registers a *response
    hook* that fires on any 401 and builds a fresh Kerberos token, so a redirect
    to an attacker-controlled host that answers 401 Negotiate would draw a
    freshly minted ticket for the gMSA out of the RA, with a channel-binding
    token derived from the real CA's TLS certificate — the shape of a relay.

    Nothing in the ``/certsrv/`` flow legitimately redirects: every URL is
    constructed from the configured host. So refusing outright costs nothing
    and removes the whole class. Applied in the production session factory
    rather than at each call site, so a new call cannot forget it, and so the
    ``HttpSession`` protocol (and every test fake) stays unchanged.
    """

    def __init__(self, session: Any) -> None:
        self._session = session

    def post(self, url: str, *, data: Mapping[str, str], timeout: float) -> Any:
        return self._session.post(
            url, data=data, timeout=timeout, allow_redirects=False
        )

    def get(self, url: str, *, params: Mapping[str, str], timeout: float) -> Any:
        return self._session.get(
            url, params=params, timeout=timeout, allow_redirects=False
        )


def _reject_redirect(resp: HttpResponse, what: str) -> None:
    """Refuse a 3xx. ``raise_for_status`` treats redirects as success.

    With redirects disabled the redirect itself arrives as the response, so
    without this check the flow would try to parse a redirect body as a
    disposition, a certificate, or a PKCS#7 chain.
    """
    if 300 <= resp.status_code < 400:
        location = resp.headers.get("Location", "<none>")
        raise EnrollmentTransportError(
            f"{what} returned HTTP {resp.status_code} redirecting to "
            f"{location!r}; /certsrv/ must not redirect and the RA will not "
            "follow one while carrying the gMSA's Kerberos identity"
        )


def _capped_body(resp: HttpResponse, max_bytes: int, what: str) -> None:
    """Refuse an oversized enrollment response before it is parsed.

    The certificate, disposition, and PKCS#7 bodies were read with no size
    limit at all, so a compromised or simply malfunctioning ``/certsrv/`` could
    hand the RA an arbitrarily large body to buffer and parse on the issuance
    path.

    *Residual, stated because it is not obvious:* ``requests`` has already
    buffered the body by the time this runs, so this bounds *parsing*, and
    bounds *buffering* only for a response that declares an honest
    ``Content-Length``. Fully bounding a chunked response would require
    streaming reads through the ``HttpSession`` protocol. Given the transport
    is mutually authenticated to the CA with channel binding, that trade is
    deliberate rather than overlooked.
    """
    declared = resp.headers.get("Content-Length")
    if declared is not None:
        try:
            if int(declared) > max_bytes:
                raise EnrollmentTransportError(
                    f"{what} declared {declared} bytes, over the "
                    f"{max_bytes}-byte limit"
                )
        except ValueError:
            pass
    if len(resp.content) > max_bytes:
        raise EnrollmentTransportError(
            f"{what} returned {len(resp.content)} bytes, over the "
            f"{max_bytes}-byte limit"
        )


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
        locale: str = "en",
        max_response_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        self._host = host
        self._template = template
        self._ca_name = ca_name
        self._ca_bundle = ca_bundle
        self._timeout = timeout
        self._session_factory = session_factory
        self._locale = locale
        self._max_response_bytes = max_response_bytes

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
        return cast(HttpSession, _NoRedirectSession(session))

    def _requester(self) -> str:
        """Best-effort capture of the ambient enrollment identity (the gMSA).

        **This is a hint, not an attestation.** It reads the process
        environment, which is inherited from whatever launched the worker — it
        is not derived from the Kerberos token that actually authenticated to
        ``/certsrv/``. The authoritative record of who enrolled is the ADCS CA
        database's ``Request.RequesterName``, which is what
        ``scripts/Revoke-Cert.ps1`` checks. Audit events carry
        ``requester_source`` so a reader can tell which one they are looking at.
        """
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

        # Everything the CA has already committed to, tracked outside the try
        # so the handlers below can hand it to the caller. Once `issued_req_id`
        # is set, a live certificate exists at the CA no matter how this call
        # ends, and the RA owes it a quarantine row rather than a bare 503.
        issued_req_id: str | None = None
        issued_cert_pem: str | None = None
        issued_chain_pem: list[str] = []

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
            _reject_redirect(resp, "certfnsh.asp")
            resp.raise_for_status()
            _capped_body(resp, self._max_response_bytes, "certfnsh.asp")
            disposition, detail = _parse_certfnsh_disposition(
                resp.text, resp.status_code, locale=self._locale
            )
            if disposition == "pending":
                # The ReqID travels as a field, not just inside the message:
                # the order cannot be safely reopened without it (F4).
                raise EnrollmentPending(
                    f"certificate pending at the CA (ReqID={detail}); "
                    "check the CA — manager approval may be on, "
                    "or the template policy deferred the request",
                    req_id=detail,
                )
            if disposition == "denied":
                raise EnrollmentDenied(f"CA denied the request: {detail}")
            if disposition != "issued":
                raise EnrollmentTransportError(detail)
            req_id = detail
            # From here on the CA has issued. Record it before the first call
            # that can fail.
            issued_req_id = req_id

            # 2. Fetch the issued certificate (base64 or PEM).
            cert_resp = session.get(
                f"{base}/certnew.cer",
                params={"ReqID": req_id, "Enc": "b64"},
                timeout=timeout,
            )
            _reject_redirect(cert_resp, "certnew.cer")
            cert_resp.raise_for_status()
            _capped_body(cert_resp, self._max_response_bytes, "certnew.cer")
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
                    f"(content-type {ct!r}): {exc}; body: {snippet}",
                    req_id=req_id,
                ) from exc
            # The bytes are in hand: every later failure can now quarantine a
            # fully identified certificate rather than just a ReqID.
            issued_cert_pem = cert_pem

            # The production finalize path always supplies a parsed, valid
            # CSR.  A few transport-only unit fakes intentionally use a
            # non-parseable placeholder; keep those focused on HTTP parsing.
            # Any real (parseable) CSR, including through an injected session,
            # receives the binding check.
            try:
                x509.load_pem_x509_csr(csr_pem.encode("ascii"))
            except (TypeError, ValueError):
                if self._session_factory is None:
                    raise EnrollmentTransportError(
                        "enrollment leg received an invalid CSR from the finalize path"
                    )
            else:
                _validate_issued_certificate_binding(
                    cert_pem,
                    csr_pem,
                    requested_sans,
                )

            # 3. Fetch the CA chain (PKCS#7).  First scrape nRenewals from
            #    certcarc.asp, then GET certnew.p7b (mirrors spike_mode_a.py).
            arc_resp = session.get(f"{base}/certcarc.asp", params={}, timeout=timeout)
            _reject_redirect(arc_resp, "certcarc.asp")
            arc_resp.raise_for_status()
            _capped_body(arc_resp, self._max_response_bytes, "certcarc.asp")
            nren = re.search(r"var nRenewals=(\d+);", arc_resp.text)
            renewals = nren.group(1) if nren else "0"
            chain_resp = session.get(
                f"{base}/certnew.p7b",
                params={"ReqID": "CACert", "Renewal": renewals, "Enc": "b64"},
                timeout=timeout,
            )
            _reject_redirect(chain_resp, "certnew.p7b")
            chain_resp.raise_for_status()
            _capped_body(chain_resp, self._max_response_bytes, "certnew.p7b")
            chain_pem = _parse_pkcs7_chain(chain_resp.content)
            issued_chain_pem = list(chain_pem)
            _validate_chain_binds_to_leaf(cert_pem, chain_pem)
        except EnrollmentDenied:
            raise
        except EnrollmentPending:
            # Must pass through untouched. The catch-all below re-wraps
            # unexpected exceptions as EnrollmentTransportError, which would
            # strip the ReqID off and put a pending CA request straight back
            # into the bucket that lets recovery retry it (F4). Nothing has been
            # issued at this point, so there is nothing to attach either.
            raise
        except EnrollmentTransportError as exc:
            # Attach what the CA already issued, unless a raise site already
            # did. A transport error raised after issuance is the orphan case.
            if exc.req_id is None and issued_req_id is not None:
                exc.req_id = issued_req_id
                exc.cert_pem = issued_cert_pem
                exc.chain_pem = issued_chain_pem
            raise
        except Exception as exc:
            # Preserve the stack for diagnosis — the wrapped message alone loses
            # where in the request/parse flow an unexpected error originated.
            _log.exception("certsrv enrollment failed (unexpected error)")
            raise EnrollmentTransportError(
                f"ADCS enrollment transport error: {exc}",
                req_id=issued_req_id,
                cert_pem=issued_cert_pem,
                chain_pem=issued_chain_pem,
            ) from exc

        metadata: dict[str, str] = {
            "req_id": req_id,
            "host": self._host,
            "source": "certsrv",
            # See _requester(): the recorded requester is the worker's process
            # identity, not a token-derived attestation. The CA DB is authoritative.
            "requester_source": "process-environment",
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


def _parse_certfnsh_disposition(
    body: str, status_code: int, *, locale: str = "en"
) -> tuple[str, str]:
    """Parse a ``certfnsh.asp`` response body into a disposition.

    WI-007/WI-020: prefers locale-independent structured signals over
    English prose strings. The signals, in priority order:

    1. **Issued** — ``certnew.cer?ReqID=<n>&`` (a download URL; the ``&``
       after the ReqID distinguishes it from a status-only link). URLs are
       locale-independent.
    2. **Explicit denial** — high-confidence structural markers
       (``'The disposition message is "…"'`` / ``"your certificate request
       was denied"``). Checked *before* pending so a request denied *after*
       a ReqID was assigned (a manager denial) is not misread as pending.
       **WI-020:** these markers are English-specific and are only checked
       when ``locale == "en"``. A non-English locale skips them and relies
       on the locale-independent signals + the loose denial fallback.
    3. **Pending** — a request was accepted but not yet issued: ``ReqID=<n>``
       (locale-independent), ``"Certificate Pending"`` or ``"Your Request Id
       is <n>"`` (English chrome, ``locale == "en"`` only), with no download
       link and no explicit denial. Runs *before* the loose quoted-message
       heuristic so innocent quoted prose on a pending page is not misread
       as a denial — that would be a hard ``400`` on a still-processing
       request, the unsafe direction.
    4. **Loose denial fallback** — a quoted disposition message preceded by
       a word and whitespace (``is "Denied by policy"`` / ``lautet
       "Abgelehnt"``), for *non-English* denials that lack the explicit
       markers and carry no ReqID (real ADCS policy denials have no ReqID).
       A non-English denial that *does* carry a ReqID is read as pending in
       (3) — the fail-safe direction (the client polls) rather than a hard
       ``400``.
    5. **Unrecognized** — surfaces a body snippet so the operator can see
       what the CA returned, rather than silently misreading a non-English
       locale as a generic transport error. **WI-020:** when
       ``locale != "en"``, the message explicitly names the locale
       assumption so the operator knows to verify it.

    Returns ``(disposition, detail)`` where disposition is one of
    ``"issued"``, ``"pending"``, ``"denied"``, ``"unknown"`` and detail
    is the ReqID (issued/pending), the denial message (denied), or a
    diagnostic snippet (unknown).
    """
    is_english = locale == "en"
    # Strip <script> blocks AND <!-- comments --> before any prose heuristic:
    # neither a JavaScript string literal nor commented-out markup may
    # masquerade as a disposition message. (Real ADCS pages contain both.)
    clean = re.sub(r"<script\b[^>]*>.*?</script>", "", body, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<!--.*?-->", "", clean, flags=re.DOTALL)

    # 1. Issued: download link with ReqID=<n>& (the & precedes Enc=). LOW-1:
    #    match against the script/comment-stripped ``clean`` body, not the raw
    #    body, so a <script> literal containing a certnew.cer URL cannot
    #    false-positive as "issued". (Failure mode if missed: safe — the cert
    #    fetch would fail — but inconsistent with the denial/pending checks.)
    m = re.search(r"certnew\.cer\?ReqID=(\d+)&", clean)
    if m:
        return ("issued", m.group(1))

    # 2. Explicit denial — wins even when a ReqID is present.
    #    WI-020: English-specific markers are skipped for non-English locales.
    if is_english:
        msg = re.search(r'The disposition message is "([^"]+)', clean)
        if msg:
            return ("denied", msg.group(1))
        if re.search(r"your certificate request was denied", clean, re.IGNORECASE):
            return ("denied", "the CA denied the request")

    # 3. Pending: a ReqID assigned (locale-independent) or English pending
    #    chrome (English only) with no download link and no explicit denial.
    #    Matched against ``clean``, not the raw body, for the same reason as
    #    steps 1/2/4: a ReqID inside a <script> literal or an HTML comment is
    #    page chrome, not a disposition. (Raw-body matching here would read a
    #    denial page carrying a commented-out ReqID as pending — the safe
    #    direction, but inconsistent with every other signal in this parser.)
    rid = re.search(r"ReqID=(\d+)", clean)
    if rid:
        return ("pending", rid.group(1))
    if is_english:
        pending_id = re.search(r"Your Request Id is (\d+)", clean, re.IGNORECASE)
        if pending_id or re.search(r"Certificate Pending", clean, re.IGNORECASE):
            return ("pending", pending_id.group(1) if pending_id else "?")

    # 4. Loose denial fallback (locale-independent — works for non-English
    #    denials without a ReqID). WI-020: only runs for non-English locales
    #    where the English-specific markers in step 2 were skipped. For
    #    English, the explicit markers in step 2 already caught structured
    #    denials, so the loose heuristic is unnecessary and risks false
    #    positives on innocent quoted prose.
    if not is_english:
        for match in re.finditer(r'\b\w+\s+"([^"]{5,})"', clean):
            candidate = match.group(1)
            if "://" not in candidate and "certnew.cer" not in candidate.lower():
                return ("denied", candidate)

    # 5. Unrecognized: surface the body for diagnosis (not silent).
    snippet = " ".join(body[:400].split())
    if is_english:
        return ("unknown", f"unrecognized certfnsh.asp response (HTTP {status_code}); body: {snippet}")
    return (
        "unknown",
        (
            f"unrecognized certfnsh.asp response (HTTP {status_code}, locale={locale!r}); "
            f"no locale-independent signal matched — check CA locale setting. body: {snippet}"
        ),
    )


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


def _validate_issued_certificate_binding(
    cert_pem: str,
    csr_pem: str,
    requested_sans: Sequence[str],
) -> None:
    """Bind the certsrv response to the CSR key and authorized subject names."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    except (TypeError, ValueError) as exc:
        raise EnrollmentTransportError(
            f"unable to validate issued certificate against CSR: {exc}"
        ) from exc

    cert_spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    csr_spki = csr.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_spki != csr_spki:
        raise EnrollmentTransportError(
            "certnew.cer returned a certificate whose public key does not match the CSR"
        )

    authorized = {name.rstrip(".").lower() for name in requested_sans}
    for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        common_name = attribute.value
        if not isinstance(common_name, str):
            raise EnrollmentTransportError(
                "certnew.cer returned a non-text subject Common Name"
            )
        if common_name.rstrip(".").lower() not in authorized:
            raise EnrollmentTransportError(
                "certnew.cer returned an out-of-scope subject Common Name: "
                f"{common_name!r}"
            )


def _validate_chain_binds_to_leaf(cert_pem: str, chain_pem: Sequence[str]) -> None:
    """Verify the fetched chain actually issued the leaf we are about to serve.

    ``certnew.p7b`` is fetched with ``ReqID=CACert`` — a *separate* request from
    the one that produced the leaf, and one whose response the RA previously
    stored and served without checking any relationship to the certificate it
    accompanies. The leaf itself gets three independent post-issuance verifiers
    (SAN, EKU, CA-capability); the chain got none, so a CA that had been
    re-keyed, or a ``certcarc.asp`` renewal-index scrape that picked the wrong
    generation, would ship every client a chain that does not verify.

    The check: some certificate in the chain must both match the leaf's issuer
    name and actually verify the leaf's signature. Signature verification is
    what makes this meaningful — issuer-name equality alone is forgeable and,
    more to the point, does not distinguish CA generations after a re-key.
    """
    try:
        leaf = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
        chain = [x509.load_pem_x509_certificate(c.encode("ascii")) for c in chain_pem]
    except (TypeError, ValueError) as exc:
        raise EnrollmentTransportError(
            f"unable to parse the issued certificate or its chain: {exc}"
        ) from exc

    for candidate in chain:
        if candidate.subject != leaf.issuer:
            continue
        try:
            leaf.verify_directly_issued_by(candidate)
        except (ValueError, TypeError, InvalidSignature):
            continue
        return

    raise EnrollmentTransportError(
        "certnew.p7b returned a chain that does not issue the certificate just "
        f"issued (leaf issuer {leaf.issuer.rfc4514_string()!r}; chain subjects "
        f"{[c.subject.rfc4514_string() for c in chain]}). The CA may have been "
        "re-keyed, or certcarc.asp reported the wrong renewal generation."
    )


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
