"""Tests for acme_adcs_ra.enrollment — protocol, fake leg, /certsrv/ leg."""

from __future__ import annotations

import base64
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from acme_adcs_ra.enrollment import (
    CertsrvEnrollmentLeg,
    EnrollmentDenied,
    EnrollmentLeg,
    EnrollmentResult,
    EnrollmentTransportError,
    FakeEnrollmentLeg,
    _parse_certfnsh_disposition,
)


# ---------------------------------------------------------------------------
# EnrollmentResult shape
# ---------------------------------------------------------------------------


class TestEnrollmentResult:
    def test_fields(self) -> None:
        r = EnrollmentResult(
            cert_pem="cert",
            chain_pem=["chain"],
            template="ACME-ServerAuth",
            requester="acct-001",
        )
        assert r.cert_pem == "cert"
        assert r.chain_pem == ["chain"]
        assert r.template == "ACME-ServerAuth"
        assert r.requester == "acct-001"
        assert r.metadata == {}

    def test_metadata(self) -> None:
        r = EnrollmentResult(
            cert_pem="c",
            chain_pem=[],
            template="t",
            requester="r",
            metadata={"source": "fake"},
        )
        assert r.metadata["source"] == "fake"

    def test_frozen(self) -> None:
        r = EnrollmentResult(
            cert_pem="c", chain_pem=[], template="t", requester="r"
        )
        with pytest.raises(AttributeError):
            r.cert_pem = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# FakeEnrollmentLeg
# ---------------------------------------------------------------------------


class TestFakeEnrollmentLeg:
    def test_returns_fixture_cert(self) -> None:
        leg = FakeEnrollmentLeg()
        result = leg.submit_csr(
            "some-csr-pem",
            account_id="acct-001",
            requested_sans=["srv.WORK-DOMAIN.local"],
        )
        assert isinstance(result, EnrollmentResult)
        assert "BEGIN CERTIFICATE" in result.cert_pem
        assert len(result.chain_pem) == 1
        assert "BEGIN CERTIFICATE" in result.chain_pem[0]
        assert result.template == "ACME-ServerAuth"
        assert result.requester == "acct-001"
        assert result.metadata["source"] == "fake"

    def test_sans_in_metadata(self) -> None:
        leg = FakeEnrollmentLeg()
        result = leg.submit_csr(
            "csr",
            account_id="a1",
            requested_sans=["a.example.com", "b.example.com"],
        )
        assert "a.example.com" in result.metadata["sans"]
        assert "b.example.com" in result.metadata["sans"]

    def test_implements_protocol(self) -> None:
        """FakeEnrollmentLeg satisfies the EnrollmentLeg protocol."""
        leg: EnrollmentLeg = FakeEnrollmentLeg()
        result = leg.submit_csr("csr", account_id="a", requested_sans=[])
        assert isinstance(result, EnrollmentResult)

    def test_default_loads_from_package_data_from_arbitrary_cwd(
        self, tmp_path: Path
    ) -> None:
        """No-arg FakeEnrollmentLeg works from any cwd via importlib.resources."""
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            leg = FakeEnrollmentLeg()
            result = leg.submit_csr(
                "csr", account_id="a", requested_sans=["x.WORK-DOMAIN.local"]
            )
            assert "BEGIN CERTIFICATE" in result.cert_pem
            assert len(result.chain_pem) == 1
            assert "BEGIN CERTIFICATE" in result.chain_pem[0]
        finally:
            os.chdir(original_cwd)


# ---------------------------------------------------------------------------
# CertsrvEnrollmentLeg — Linux guard + DI-driven /certsrv/ flow
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Minimal HttpResponse stand-in for /certsrv/ tests."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        text: str = "",
        content: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.content = content
        self.headers: Mapping[str, str] = headers if headers is not None else {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeSession:
    """Recording fake HttpSession that routes by URL substring.

    ``routes`` maps a URL substring (e.g. ``"certfnsh.asp"``) to either a
    ``_FakeResponse`` or a callable[[], _FakeResponse].  Every POST/GET is
    captured in ``posts``/``gets`` so the payload-correctness test can assert
    on the exact form data sent to certfnsh.asp.
    """

    def __init__(self, routes: Mapping[str, object]) -> None:
        self._routes = routes
        self.posts: list[tuple[str, dict[str, str]]] = []
        self.gets: list[tuple[str, dict[str, str]]] = []

    def post(self, url: str, *, data: Mapping[str, str], timeout: float) -> _FakeResponse:
        self.posts.append((url, dict(data)))
        return self._route(url)

    def get(
        self, url: str, *, params: Mapping[str, str], timeout: float
    ) -> _FakeResponse:
        self.gets.append((url, dict(params)))
        return self._route(url)

    def _route(self, url: str) -> _FakeResponse:
        for key, resp in self._routes.items():
            if key in url:
                return resp() if callable(resp) else resp  # type: ignore[operator]
        return _FakeResponse(status_code=404, text=f"no route for {url}")


def _build_leaf_cert_and_chain() -> tuple[str, bytes, str]:
    """Build a leaf cert + a certificates-only PKCS#7 chain for tests.

    Tests/ are outside the ``src/`` no-signing-key architecture scan, so
    signing here is permitted (precedent: tests/hand_rolled_acme_client.py).
    Returns (leaf_pem, leaf_der, p7b_base64).
    """
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA01-CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(ca_key, hashes.SHA256())
    )
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    # Certificates-only PKCS#7 containing the CA cert (the "chain").
    p7b_der = pkcs7.serialize_certificates([ca_cert], serialization.Encoding.DER)
    p7b_b64 = base64.b64encode(p7b_der).decode("ascii")
    return leaf_pem, leaf_der, p7b_b64


_CSR_PEM = (
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "fake-csr-for-payload-test\n"
    "-----END CERTIFICATE REQUEST-----\n"
)
_HOST = "CA01.WORK-DOMAIN.local"
_TEMPLATE = "ACME-ServerAuth"


class TestCertsrvEnrollmentLeg:
    """CertsrvEnrollmentLeg: Linux guard + DI-driven /certsrv/ flow tests."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux-only guard")
    def test_linux_guard_raises_not_implemented(self) -> None:
        """Without an injected session, non-Windows raises NotImplementedError."""
        leg = CertsrvEnrollmentLeg(host=_HOST, template=_TEMPLATE)
        with pytest.raises(NotImplementedError, match="requires Windows"):
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])

    def test_importable_without_error(self) -> None:
        """The module must be importable on Linux without any ImportError."""
        assert CertsrvEnrollmentLeg is not None

    def test_success_returns_cert_and_chain(self) -> None:
        leaf_pem, leaf_der, p7b_b64 = _build_leaf_cert_and_chain()
        cert_b64 = base64.b64encode(leaf_der).decode("ascii")
        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text='<html>... <a href="certnew.cer?ReqID=42&Enc=b64">...</a></html>'
                ),
                "certnew.cer": _FakeResponse(
                    text=cert_b64,
                    content=cert_b64.encode("ascii"),
                    headers={"Content-Type": "application/pkix-cert"},
                ),
                "certcarc.asp": _FakeResponse(text="... var nRenewals=0; ..."),
                "certnew.p7b": _FakeResponse(content=p7b_b64.encode("ascii")),
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST, template=_TEMPLATE, session_factory=lambda: fake
        )
        result = leg.submit_csr(_CSR_PEM, account_id="acct-1", requested_sans=["srv01.WORK-DOMAIN.local"])

        assert isinstance(result, EnrollmentResult)
        assert "BEGIN CERTIFICATE" in result.cert_pem
        assert len(result.chain_pem) >= 1
        assert "BEGIN CERTIFICATE" in result.chain_pem[0]
        assert result.metadata["req_id"] == "42"
        assert result.metadata["source"] == "certsrv"
        assert result.metadata["host"] == _HOST
        assert result.template == _TEMPLATE
        assert result.requester  # non-empty

    def test_pending_raises_transport_error(self) -> None:
        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text="... Certificate Pending ... Your Request Id is 7 ..."
                ),
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST, template=_TEMPLATE, session_factory=lambda: fake
        )
        with pytest.raises(EnrollmentTransportError, match="manager approval"):
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])

    def test_denied_raises_enrollment_denied(self) -> None:
        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text='... The disposition message is "Denied by policy" ...'
                ),
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST, template=_TEMPLATE, session_factory=lambda: fake
        )
        with pytest.raises(EnrollmentDenied, match="Denied by policy"):
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])

    def test_connection_error_wrapped_as_transport(self) -> None:
        class _ConnErrorSession:
            def post(self, url: str, *, data: Mapping[str, str], timeout: float) -> _FakeResponse:
                raise ConnectionError("connection refused")

            def get(
                self, url: str, *, params: Mapping[str, str], timeout: float
            ) -> _FakeResponse:
                raise ConnectionError("connection refused")

        leg = CertsrvEnrollmentLeg(
            host=_HOST, template=_TEMPLATE, session_factory=lambda: _ConnErrorSession()
        )
        with pytest.raises(EnrollmentTransportError, match="connection refused"):
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])

    def test_certfnsh_payload_correctness(self) -> None:
        leaf_pem, leaf_der, p7b_b64 = _build_leaf_cert_and_chain()
        cert_b64 = base64.b64encode(leaf_der).decode("ascii")
        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text='<a href="certnew.cer?ReqID=99&Enc=b64">cert</a>'
                ),
                "certnew.cer": _FakeResponse(
                    text=cert_b64,
                    content=cert_b64.encode("ascii"),
                    headers={"Content-Type": "application/pkix-cert"},
                ),
                "certcarc.asp": _FakeResponse(text="var nRenewals=0;"),
                "certnew.p7b": _FakeResponse(content=p7b_b64.encode("ascii")),
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST, template=_TEMPLATE, session_factory=lambda: fake
        )
        leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])

        assert fake.posts, "expected a POST to certfnsh.asp"
        url, data = fake.posts[0]
        assert "certfnsh.asp" in url
        assert data["Mode"] == "newreq"
        assert data["CertRequest"] == _CSR_PEM
        assert f"CertificateTemplate:{_TEMPLATE}" in data["CertAttrib"]
        assert data["FriendlyType"] == "Saved-Request Certificate"
        assert data["TargetStoreFlags"] == "0"
        assert data["SaveCert"] == "yes"

    def test_certfnsh_http_error_raises_transport_error(self) -> None:
        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(status_code=401, text="Unauthorized"),
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST, template=_TEMPLATE, session_factory=lambda: fake
        )
        with pytest.raises(EnrollmentTransportError, match="HTTP 401"):
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])

    def test_malformed_p7b_raises_transport_error(self) -> None:
        leaf_pem, leaf_der, _p7b_b64 = _build_leaf_cert_and_chain()
        cert_b64 = base64.b64encode(leaf_der).decode("ascii")
        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text='<a href="certnew.cer?ReqID=42&Enc=b64">cert</a>'
                ),
                "certnew.cer": _FakeResponse(
                    text=cert_b64,
                    content=cert_b64.encode("ascii"),
                    headers={"Content-Type": "application/pkix-cert"},
                ),
                "certcarc.asp": _FakeResponse(text="var nRenewals=0;"),
                "certnew.p7b": _FakeResponse(content=b"not-a-pkcs7"),
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST, template=_TEMPLATE, session_factory=lambda: fake
        )
        with pytest.raises(EnrollmentTransportError):
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])

    def test_multi_cert_chain_propagates(self) -> None:
        now = datetime.now(timezone.utc)
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root-CA")])
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(root_key, hashes.SHA256())
        )
        int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sub-CA")])
        int_cert = (
            x509.CertificateBuilder()
            .subject_name(int_name)
            .issuer_name(root_name)
            .public_key(int_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(root_key, hashes.SHA256())
        )
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")])
            )
            .issuer_name(int_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .sign(int_key, hashes.SHA256())
        )
        leaf_b64 = base64.b64encode(
            leaf_cert.public_bytes(serialization.Encoding.DER)
        ).decode("ascii")
        p7b_der = pkcs7.serialize_certificates([root_cert, int_cert], serialization.Encoding.DER)
        p7b_b64 = base64.b64encode(p7b_der).decode("ascii")

        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text='<a href="certnew.cer?ReqID=42&Enc=b64">cert</a>'
                ),
                "certnew.cer": _FakeResponse(
                    text=leaf_b64,
                    content=leaf_b64.encode("ascii"),
                    headers={"Content-Type": "application/pkix-cert"},
                ),
                "certcarc.asp": _FakeResponse(text="var nRenewals=0;"),
                "certnew.p7b": _FakeResponse(content=p7b_b64.encode("ascii")),
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST, template=_TEMPLATE, session_factory=lambda: fake
        )
        result = leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])
        assert isinstance(result, EnrollmentResult)
        assert len(result.chain_pem) == 2
        for pem in result.chain_pem:
            assert "BEGIN CERTIFICATE" in pem


# ---------------------------------------------------------------------------
# WI-007: locale-independent certfnsh.asp disposition parsing
# ---------------------------------------------------------------------------


class TestCertfnshDispositionParsing:
    """WI-007: certfnsh.asp disposition parsing must not depend on OS locale.

    The success signal (certnew.cer?ReqID=<n>&) is a URL and is locale-
    independent. For non-success, structured tokens (ReqID= query param,
    quoted disposition message) are preferred over English prose strings.
    English strings remain as a backward-compatibility fallback.
    """

    def test_issued_extracts_req_id(self) -> None:
        body = '<a href="certnew.cer?ReqID=42&Enc=b64">Download</a>'
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "issued"
        assert detail == "42"

    def test_pending_via_req_id_query_param(self) -> None:
        """A ReqID= query param without a download link means pending."""
        body = (
            '<html><body>'
            '<a href="certnew.cer?ReqID=7">Check status</a>'
            '</body></html>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "pending"
        assert detail == "7"

    def test_pending_english_fallback(self) -> None:
        body = "... Certificate Pending ... Your Request Id is 7 ..."
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "pending"
        assert detail == "7"

    def test_pending_english_fallback_no_req_id(self) -> None:
        body = "... Certificate Pending ..."
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "pending"
        assert detail == "?"

    def test_denied_english(self) -> None:
        body = '... The disposition message is "Denied by policy" ...'
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "denied"
        assert detail == "Denied by policy"

    def test_denied_non_english_locale(self) -> None:
        """A non-English denied page must be detected via the quoted message.

        The disposition message is in quotes regardless of locale; the
        word+space prefix before the quote distinguishes it from HTML
        attributes (href=\"...\").
        """
        body = (
            '<html><body>'
            '<h2>Anforderung abgelehnt</h2>'
            'Die Dispositionsnachricht lautet "Richtlinie verweigert"'
            '</body></html>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "denied"
        assert "Richtlinie verweigert" in detail

    def test_pending_non_english_locale(self) -> None:
        """A non-English pending page must be detected via ReqID= query param."""
        body = (
            '<html><body>'
            '<h2>Zertifikat ausstehend</h2>'
            'Ihre Anforderungs-ID lautet 42.'
            '<br><a href="certnew.cer?ReqID=42">Status abrufen</a>'
            '</body></html>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "pending"
        assert detail == "42"

    def test_issued_with_quoted_message_still_issued(self) -> None:
        """The issued check runs first — a download link wins over any
        quoted message in the body."""
        body = (
            '<a href="certnew.cer?ReqID=99&Enc=b64">Download</a>'
            '<p>The disposition message is "Issued"</p>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "issued"
        assert detail == "99"

    def test_denied_quoted_message_excludes_urls(self) -> None:
        """A quoted JavaScript string must not be mistaken for a disposition
        message — the word+space prefix distinguishes text quotes from
        assignment quotes (``= \"…\"``)."""
        body = (
            '<script>var title = "Certificate Services Page"</script>'
            '<p>is "Denied by policy"</p>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "denied"
        assert detail == "Denied by policy"

    def test_denied_regex_ignores_script_blocks(self) -> None:
        """JavaScript return/string literals inside <script> blocks must
        not false-positive as a denied disposition message."""
        body = (
            '<script>function check() { return "Certificate Pending"; }</script>'
            '<body>Die Nachricht lautet "Abgelehnt"</body>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "denied"
        assert detail == "Abgelehnt"

    def test_denied_colon_separated_falls_through(self) -> None:
        """A denied page with a colon-separated disposition (not word+space)
        is not matched by the locale-independent denied regex — it falls
        through to the English fallback or 'unknown'. Documents a known
        limitation: the live re-proof should capture real non-English
        certfnsh.asp bodies to validate the heuristic."""
        body = '<p>Disposition: "Refusé par la politique"</p>'
        disposition, _detail = _parse_certfnsh_disposition(body, 200)
        # No word+space before the quote (it's `: "..."`), and no ReqID=,
        # and no English strings → unknown (visible, not silent).
        assert disposition == "unknown"

    def test_unrecognized_surfaces_body_snippet(self) -> None:
        """An unrecognized response must surface a body snippet, not a
        generic error (WI-007: no silent misreading)."""
        body = "<html><body>Something completely unexpected</body></html>"
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "unknown"
        assert "HTTP 200" in detail
        assert "Something completely unexpected" in detail

    # -- Real ADCS bodies captured live (lab re-proof, 2026-06-30) --------
    # issued_real / denied_real / pending_real are REAL certfnsh.asp responses
    # captured from a live ADCS CA (CA common name scrubbed to CONTOSO-CA01).
    # The pending body was captured via a throwaway PEND_ALL_REQUESTS template.
    # They lock the parser against actual ADCS output, not hand-written HTML.

    def _fixture(self, name: str) -> str:
        from pathlib import Path

        return (Path(__file__).parent / "fixtures" / "certfnsh" / name).read_text(
            encoding="utf-8"
        )

    def test_real_issued_body_parses_as_issued(self) -> None:
        disposition, detail = _parse_certfnsh_disposition(
            self._fixture("issued_real.html"), 200
        )
        assert disposition == "issued"
        assert detail.isdigit()  # the ReqID

    def test_real_denied_body_parses_as_denied(self) -> None:
        disposition, detail = _parse_certfnsh_disposition(
            self._fixture("denied_real.html"), 200
        )
        assert disposition == "denied"
        # The real ADCS policy-module denial message is surfaced.
        assert "Denied by Policy Module" in detail

    def test_real_pending_body_parses_as_pending(self) -> None:
        disposition, detail = _parse_certfnsh_disposition(
            self._fixture("pending_real.html"), 200
        )
        assert disposition == "pending"
        assert detail == "89"  # the ReqID assigned to the pending request

    def test_pending_with_quoted_prose_is_not_denied(self) -> None:
        """Regression guard (fixed 2026-06-30): a pending page (a Request Id
        assigned, no download link, no explicit denial) that happens to
        contain a word+space+quoted string must classify as pending, not
        denied. The pending check now runs before the loose quoted-message
        heuristic, so innocent quoted prose no longer triggers a hard ACME
        400 on a still-processing request (the unsafe misclassification
        direction)."""
        body = (
            "<html><body>"
            '<p>The request status is "received and queued for the operator"</p>'
            "Your Request Id is 85."
            "</body></html>"
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "pending"
        assert detail == "85"

    def test_html_comment_with_quoted_prose_is_not_denied(self) -> None:
        """An HTML comment containing a word+space+quoted string must not be
        read as a denial — comments are stripped alongside <script> before the
        loose heuristic (real ADCS pages carry boilerplate comments)."""
        body = (
            "<html><body>"
            '<!-- template note: the "ACME-ServerAuth" policy applies here -->'
            "Your Request Id is 90."
            "</body></html>"
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "pending"
        assert detail == "90"
