"""Tests for acme_adcs_ra.enrollment — protocol, fake leg, /certsrv/ leg."""

from __future__ import annotations

import asyncio
import base64
import os
import sys
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from acme_adcs_ra.enrollment import (
    CertsrvEnrollmentLeg,
    EnrollmentDenied,
    EnrollmentGate,
    EnrollmentGateBusy,
    EnrollmentLeg,
    EnrollmentPending,
    EnrollmentResult,
    EnrollmentTransportError,
    FakeEnrollmentLeg,
    _abort_enrollment_transfer,
    _LiveEnrollmentTransfer,
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
        # A real response derives one from the other; this fake let them drift,
        # so a test that set only `text` had an empty `content`. That was
        # invisible while the leg read `.text` for prose bodies and `.content`
        # for binary ones, and surfaced the moment the bounded reader started
        # taking bytes for both (2026-08-18 wave 3 F4). Keep them consistent.
        self.content = content if content else text.encode("utf-8")
        self.headers: Mapping[str, str] = headers if headers is not None else {}
        self.closed = False

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def close(self) -> None:
        self.closed = True


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
        self.timeouts: list[float] = []

    def post(self, url: str, *, data: Mapping[str, str], timeout: float) -> _FakeResponse:
        self.timeouts.append(timeout)
        self.posts.append((url, dict(data)))
        return self._route(url)

    def get(
        self, url: str, *, params: Mapping[str, str], timeout: float
    ) -> _FakeResponse:
        self.timeouts.append(timeout)
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
    now = datetime.now(UTC)
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
        _leaf_pem, leaf_der, p7b_b64 = _build_leaf_cert_and_chain()
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

    def test_all_four_requests_clamp_timeout_to_one_decreasing_deadline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _leaf_pem, leaf_der, p7b_b64 = _build_leaf_cert_and_chain()
        cert_b64 = base64.b64encode(leaf_der).decode("ascii")
        clock = {"now": 100.0}
        monkeypatch.setattr(
            "acme_adcs_ra.enrollment.time.monotonic", lambda: clock["now"]
        )

        class _AdvancingSession(_FakeSession):
            def _route(self, url: str) -> _FakeResponse:
                # Deterministic elapsed time: every completed HTTP exchange
                # consumes exactly 0.25s of the one deadline. A mutation that
                # resets the deadline per request records 2.0 four times and
                # fails the exact timeout assertion below.
                clock["now"] += 0.25
                return super()._route(url)

        fake = _AdvancingSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text='<a href="certnew.cer?ReqID=42&Enc=b64">cert</a>'
                ),
                "certnew.cer": _FakeResponse(content=cert_b64.encode("ascii")),
                "certcarc.asp": _FakeResponse(text="var nRenewals=0;"),
                "certnew.p7b": _FakeResponse(content=p7b_b64.encode("ascii")),
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST,
            template=_TEMPLATE,
            timeout=5.0,
            total_timeout=2.0,
            session_factory=lambda: fake,
        )

        leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])

        assert fake.timeouts == pytest.approx([2.0, 1.75, 1.5, 1.25])

    def test_pending_raises_enrollment_pending_carrying_the_req_id(self) -> None:
        """Pending is its own type, and the ReqID travels as a field.

        It used to be an `EnrollmentTransportError` with the ReqID buried in the
        message — the same bucket as "the CA was unreachable" — so nothing
        durable recorded which CA request was outstanding and administrative
        recovery could reopen the order into a second issuance (2026-08-18 F4).
        """
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
        with pytest.raises(EnrollmentPending, match="manager approval") as caught:
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])
        assert caught.value.req_id == "7"
        # Not a transport error: the two are handled differently downstream.
        assert not isinstance(caught.value, EnrollmentTransportError)

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

    def test_one_deadline_aborts_stream_and_preserves_issued_req_id(self) -> None:
        """A trickling post-issuance body cannot outlive the total deadline."""

        class _Socket:
            def __init__(self) -> None:
                self.aborted = threading.Event()

            def shutdown(self, _how: int) -> None:
                self.aborted.set()

            def close(self) -> None:
                self.aborted.set()

        class _Raw:
            def __init__(self) -> None:
                self._connection = type("Connection", (), {"sock": _Socket()})()

            def read1(self, _size: int, *, decode_content: bool) -> bytes:
                del decode_content
                assert self._connection.sock.aborted.wait(1.0)
                raise OSError("socket aborted")

        blocked = _FakeResponse()
        blocked.raw = _Raw()  # type: ignore[attr-defined]
        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text='<a href="certnew.cer?ReqID=42&Enc=b64">cert</a>'
                ),
                "certnew.cer": blocked,
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST,
            template=_TEMPLATE,
            timeout=5.0,
            # 0.5s, not the 0.05s this used to be. The budget has to survive
            # the certfnsh POST *and* the ReqID parse, because the property
            # under test is that a deadline expiring DURING THE STREAM still
            # reports the ReqID the CA already issued. At 50ms a loaded runner
            # spent the whole budget before the parse, the deadline fired with
            # no ReqID attached, and the assertion below failed for a reason
            # that had nothing to do with the behaviour: observed on CI
            # 2026-08-27, where the same commit passed one run and failed the
            # other. The blocked read waits up to 1.0s, so 0.5s still expires
            # inside the stream, which is what keeps the test meaningful.
            #
            # This widens the race rather than removing it. The real fix is an
            # injectable clock on CertsrvEnrollmentLeg so the deadline is not
            # wall-clock at all; that touches the issuance path and wants its
            # own round. See docs/UNFILED-WORK-ITEMS.md item 18.
            total_timeout=0.5,
            session_factory=lambda: fake,
        )

        started = time.monotonic()
        with pytest.raises(EnrollmentTransportError, match="deadline") as caught:
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])
        # Scaled with the budget above. Still far below the 5.0s per-operation
        # timeout, so this continues to prove the TOTAL deadline is what fired
        # rather than the per-read one.
        assert time.monotonic() - started < 2.0
        assert caught.value.req_id == "42"
        assert caught.value.ca_issued is True
        assert blocked.closed is True

    def test_deadline_closes_the_socket_on_windows(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Socket:
            def __init__(self) -> None:
                self.shutdown_called = False
                self.close_called = False

            def shutdown(self, _how: int) -> None:
                self.shutdown_called = True

            def close(self) -> None:
                self.close_called = True

        sock = _Socket()
        response = _FakeResponse()
        response.raw = type(  # type: ignore[attr-defined]
            "Raw", (), {"_connection": type("Connection", (), {"sock": sock})()}
        )()
        live = _LiveEnrollmentTransfer()
        live.response = response
        timed_out = threading.Event()
        monkeypatch.setattr("acme_adcs_ra.enrollment.sys.platform", "win32")

        _abort_enrollment_transfer(live, timed_out)

        assert timed_out.is_set()
        assert sock.shutdown_called is True
        assert sock.close_called is True

    def test_windows_close_still_runs_when_socket_shutdown_raises_type_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Socket:
            def __init__(self) -> None:
                self.close_called = False

            def shutdown(self, _how: int) -> None:
                raise TypeError("changed wrapper signature")

            def close(self) -> None:
                self.close_called = True

        sock = _Socket()
        response = _FakeResponse()
        response.raw = type(  # type: ignore[attr-defined]
            "Raw", (), {"_connection": type("Connection", (), {"sock": sock})()}
        )()
        live = _LiveEnrollmentTransfer()
        live.response = response
        timed_out = threading.Event()
        monkeypatch.setattr("acme_adcs_ra.enrollment.sys.platform", "win32")

        # A Timer callback has nowhere useful to propagate an exception. This
        # must return normally and still execute the Windows closesocket path.
        _abort_enrollment_transfer(live, timed_out)

        assert timed_out.is_set()
        assert sock.close_called is True

    def test_dedicated_gate_sheds_instead_of_queueing_without_bound(self) -> None:
        async def scenario() -> None:
            gate = EnrollmentGate(max_workers=1, max_pending=1)
            entered = threading.Event()
            release = threading.Event()

            def blocked() -> str:
                entered.set()
                assert release.wait(2.0)
                return threading.current_thread().name

            first = asyncio.create_task(gate.run(blocked))
            assert await asyncio.to_thread(entered.wait, 1.0)
            with pytest.raises(EnrollmentGateBusy):
                await gate.run(blocked)
            release.set()
            assert (await first).startswith("ra-adcs-enrollment")
            gate.close()

        asyncio.run(scenario())

    def test_dedicated_gate_does_not_abandon_admitted_work_on_cancellation(
        self,
    ) -> None:
        async def scenario() -> None:
            gate = EnrollmentGate(max_workers=1, max_pending=1)
            entered = threading.Event()
            release = threading.Event()

            def blocked() -> str:
                entered.set()
                assert release.wait(2.0)
                return "issued-result"

            admitted = asyncio.create_task(gate.run(blocked))
            assert await asyncio.to_thread(entered.wait, 1.0)
            admitted.cancel()
            await asyncio.sleep(0)
            assert admitted.done() is False
            release.set()
            assert await admitted == "issued-result"
            gate.close()

        asyncio.run(scenario())

    def test_gate_close_drains_running_and_queued_admitted_work(self) -> None:
        """Shutdown refuses new work but never cancels already-admitted issuance."""

        async def scenario() -> None:
            gate = EnrollmentGate(max_workers=1, max_pending=2)
            first_entered = threading.Event()
            release_first = threading.Event()
            second_ran = threading.Event()

            def first() -> str:
                first_entered.set()
                assert release_first.wait(2.0)
                return "first-complete"

            def second() -> str:
                second_ran.set()
                return "second-complete"

            running = asyncio.create_task(gate.run(first))
            assert await asyncio.to_thread(first_entered.wait, 1.0)
            queued = asyncio.create_task(gate.run(second))
            await asyncio.sleep(0)

            gate.close()
            with pytest.raises(RuntimeError, match="closed"):
                await gate.run(lambda: "not-admitted")

            release_first.set()
            assert await asyncio.wait_for(running, timeout=1.0) == "first-complete"
            assert await asyncio.wait_for(queued, timeout=1.0) == "second-complete"
            assert second_ran.is_set()

        asyncio.run(scenario())

    def test_direct_body_deadline_error_keeps_issued_orphan_metadata(self) -> None:
        """The EnrollmentTransportError branch preserves ReqID, not only catch-all."""

        class _Socket:
            def __init__(self) -> None:
                self.aborted = threading.Event()

            def shutdown(self, _how: int) -> None:
                self.aborted.set()

            def close(self) -> None:
                self.aborted.set()

        class _Raw:
            def __init__(self) -> None:
                self._connection = type("Connection", (), {"sock": _Socket()})()

            def read1(self, _size: int, *, decode_content: bool) -> bytes:
                del decode_content
                # Return normally after watchdog abort. _read_capped_body then
                # sees timed_out itself and raises EnrollmentTransportError
                # directly, exercising that exception branch.
                assert self._connection.sock.aborted.wait(1.0)
                return b"x"

        blocked = _FakeResponse()
        blocked.raw = _Raw()  # type: ignore[attr-defined]
        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text='<a href="certnew.cer?ReqID=73&Enc=b64">cert</a>'
                ),
                "certnew.cer": blocked,
            }
        )
        leg = CertsrvEnrollmentLeg(
            host=_HOST,
            template=_TEMPLATE,
            timeout=5.0,
            # 0.5s, not the 0.05s this used to be. The budget has to survive
            # the certfnsh POST *and* the ReqID parse, because the property
            # under test is that a deadline expiring DURING THE STREAM still
            # reports the ReqID the CA already issued. At 50ms a loaded runner
            # spent the whole budget before the parse, the deadline fired with
            # no ReqID attached, and the assertion below failed for a reason
            # that had nothing to do with the behaviour: observed on CI
            # 2026-08-27, where the same commit passed one run and failed the
            # other. The blocked read waits up to 1.0s, so 0.5s still expires
            # inside the stream, which is what keeps the test meaningful.
            #
            # This widens the race rather than removing it. The real fix is an
            # injectable clock on CertsrvEnrollmentLeg so the deadline is not
            # wall-clock at all; that touches the issuance path and wants its
            # own round. See docs/UNFILED-WORK-ITEMS.md item 18.
            total_timeout=0.5,
            session_factory=lambda: fake,
        )

        with pytest.raises(
            EnrollmentTransportError, match="total deadline expired"
        ) as caught:
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])

        assert caught.value.req_id == "73"
        assert caught.value.cert_pem is None
        assert caught.value.chain_pem == []
        assert caught.value.ca_issued is True
        assert blocked.closed is True

    def test_certfnsh_payload_correctness(self) -> None:
        _leaf_pem, leaf_der, p7b_b64 = _build_leaf_cert_and_chain()
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
        _leaf_pem, leaf_der, _p7b_b64 = _build_leaf_cert_and_chain()
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
        now = datetime.now(UTC)
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
        disposition, detail = _parse_certfnsh_disposition(body, 200, locale="de")
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

    def test_issued_regex_ignores_script_blocks(self) -> None:
        """LOW-1: a ``certnew.cer?ReqID=N&`` URL appearing only inside a
        ``<script>`` literal of a PENDING page must not false-positive as
        'issued'. The issued check now runs against the script/comment-stripped
        body, consistent with the denied/pending checks. A pending ReqID in the
        page chrome (without the download link) still classifies as pending."""
        body = (
            '<script>var link = "certnew.cer?ReqID=77&Enc=b64";</script>'
            '<body>Your Request Id is 77</body>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "pending"
        assert detail == "77"

    def test_denied_quoted_message_excludes_urls(self) -> None:
        """A quoted JavaScript string must not be mistaken for a disposition
        message — the word+space prefix distinguishes text quotes from
        assignment quotes (``= \"…\"``)."""
        body = (
            '<script>var title = "Certificate Services Page"</script>'
            '<p>is "Denied by policy"</p>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200, locale="de")
        assert disposition == "denied"
        assert detail == "Denied by policy"

    def test_denied_regex_ignores_script_blocks(self) -> None:
        """JavaScript return/string literals inside <script> blocks must
        not false-positive as a denied disposition message."""
        body = (
            '<script>function check() { return "Certificate Pending"; }</script>'
            '<body>Die Nachricht lautet "Abgelehnt"</body>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200, locale="de")
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


class TestLocaleRobustDisposition:
    """WI-020: locale-robust certfnsh.asp disposition parsing."""

    def test_english_locale_default(self) -> None:
        body = (
            '<html><body>'
            'The disposition message is "Denied by policy".'
            '</body></html>'
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "denied"
        assert "Denied by policy" in detail

    def test_non_english_locale_skips_english_denial_markers(self) -> None:
        body = (
            "<html><body>"
            "Your certificate request was denied."
            "</body></html>"
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200, locale="de")
        assert disposition == "unknown"
        assert "locale='de'" in detail

    def test_non_english_locale_issued_via_locale_independent_signal(self) -> None:
        body = (
            '<html><body><a href="certnew.cer?ReqID=42&Enc=b64">Download</a>'
            "</body></html>"
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200, locale="de")
        assert disposition == "issued"
        assert detail == "42"

    def test_non_english_locale_pending_via_reqid(self) -> None:
        body = "<html><body>ReqID=77</body></html>"
        disposition, detail = _parse_certfnsh_disposition(body, 200, locale="de")
        assert disposition == "pending"
        assert detail == "77"

    def test_non_english_locale_denied_via_loose_fallback(self) -> None:
        body = (
            "<html><body>"
            'Die Disposition lautet "Abgelehnt durch Richtlinie".'
            "</body></html>"
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200, locale="de")
        assert disposition == "denied"
        assert "Abgelehnt" in detail

    def test_non_english_locale_unrecognized_fails_loudly(self) -> None:
        body = "<html><body>Some completely unknown response format</body></html>"
        disposition, detail = _parse_certfnsh_disposition(body, 200, locale="fr")
        assert disposition == "unknown"
        assert "locale='fr'" in detail
        assert "check CA locale" in detail

    def test_english_locale_unrecognized_does_not_mention_locale(self) -> None:
        body = "<html><body>Some completely unknown response format</body></html>"
        disposition, detail = _parse_certfnsh_disposition(body, 200, locale="en")
        assert disposition == "unknown"
        assert "locale" not in detail

    def test_existing_english_fixtures_pass_with_default_locale(self) -> None:
        body = (
            '<html><body>'
            'The disposition message is "Denied by policy".'
            '</body></html>'
        )
        d1, _ = _parse_certfnsh_disposition(body, 200)
        d2, _ = _parse_certfnsh_disposition(body, 200, locale="en")
        assert d1 == d2 == "denied"

    def test_locale_parameter_does_not_break_issued(self) -> None:
        body = (
            '<html><body><a href="certnew.cer?ReqID=99&Enc=b64">Download</a>'
            "</body></html>"
        )
        for loc in ("en", "de", "fr", "ja"):
            disposition, detail = _parse_certfnsh_disposition(body, 200, locale=loc)
            assert disposition == "issued"
            assert detail == "99"

    def test_locale_parameter_does_not_break_pending_reqid(self) -> None:
        body = "<html><body>ReqID=55</body></html>"
        for loc in ("en", "de", "fr", "ja"):
            disposition, detail = _parse_certfnsh_disposition(body, 200, locale=loc)
            assert disposition == "pending"
            assert detail == "55"
