"""Regression tests for the 2026-08-17 scan (findings 2 and 3).

The scan of `38f2638` closed three of the four preceding findings and reported
the CRL work as only partially done. One medium and three low:

* F1 — the elevated installer ran an unverified MSI. PowerShell; covered by
  `tests/pester/InstallVerify.Tests.ps1`.
* F2 — the confirmation route buffered an unbounded request body. Here.
* F3 — serial aliases, unbounded admission, and a **non-chunked** trickle all
  slipped past the CRL resource controls added the round before. Here.
* F4 — one failed RA callback wedged automated reconciliation for ever.
  PowerShell; covered by `tests/pester/Sync.Tests.ps1`.

Each test here was mutation-checked: the fix was reverted in turn and the test
confirmed to fail. See docs/security-review-2026-08-17.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from acme_adcs_ra.crl_evidence import (
    CrlEvidenceGate,
    CrlEvidenceGateBusy,
    fetch_crl_evidence,
)
from acme_adcs_ra.store import CertStatus

# The 2026-08-13 suite already builds a client whose confirm token is set and a
# revoked certificate in its store — exactly this route's preconditions.
from .test_security_review_2026_08_13 import (
    STRONG_ADMIN_TOKEN,
    STRONG_CONFIRM_TOKEN,
    _client,
    _config,
    _revoked_cert,
)

CONFIRM_AUTH = {"Authorization": f"Bearer {STRONG_CONFIRM_TOKEN}"}


# ---------------------------------------------------------------------------
# Finding 2 (low) — the confirmation body was unbounded
# ---------------------------------------------------------------------------


class TestConfirmationBodyIsBounded:
    """The route consumes one boolean and buffered as much as you sent.

    `request.json()` goes through Starlette's `Request.body()`, which appends
    every chunk of the stream and joins them before decoding. Every other
    attacker-reachable body in this codebase is read through a streaming cap;
    this one — reachable with the scoped confirmation credential — was not.
    """

    def _client_and_serial(self, tmp_path: Path) -> tuple[TestClient, str]:
        client = _client(
            tmp_path, revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN)
        )
        store = client.app.state.context.store  # type: ignore[attr-defined]
        cert = _revoked_cert(store)
        return client, str(cert.serial_number)

    def test_an_oversized_declared_body_is_rejected(self, tmp_path: Path) -> None:
        client, serial = self._client_and_serial(tmp_path)
        resp = client.post(
            f"/acme/admin/revocations/{serial}/confirm",
            headers=CONFIRM_AUTH,
            content=b"x" * 100_000,
        )
        assert resp.status_code == 400
        assert "too large" in resp.text

    def test_a_rejected_body_does_not_confirm_the_revocation(
        self, tmp_path: Path
    ) -> None:
        """Rejection is total: the serial stays pending for the next sweep."""
        client, serial = self._client_and_serial(tmp_path)
        store = client.app.state.context.store  # type: ignore[attr-defined]
        resp = client.post(
            f"/acme/admin/revocations/{serial}/confirm",
            headers=CONFIRM_AUTH,
            content=b"x" * 100_000,
        )
        assert resp.status_code == 400
        assert len(store.list_revoked_certificates()) == 1

    def test_a_lying_content_length_is_still_bounded(self, tmp_path: Path) -> None:
        """The declared length is a claim; the streamed count is the control."""
        client, serial = self._client_and_serial(tmp_path)

        def oversized_chunks() -> Any:
            for _ in range(50):
                yield b"x" * 2048

        resp = client.post(
            f"/acme/admin/revocations/{serial}/confirm",
            headers=CONFIRM_AUTH,
            content=oversized_chunks(),
        )
        assert resp.status_code == 400
        assert "too large" in resp.text

    def test_the_ordinary_confirmation_body_still_works(
        self, tmp_path: Path
    ) -> None:
        client, serial = self._client_and_serial(tmp_path)
        store = client.app.state.context.store  # type: ignore[attr-defined]
        resp = client.post(
            f"/acme/admin/revocations/{serial}/confirm",
            headers=CONFIRM_AUTH,
            json={"ca_crl_updated": True, "crl_published": True},
        )
        assert resp.status_code == 200
        assert store.list_revoked_certificates() == []

    def test_an_absent_body_still_works(self, tmp_path: Path) -> None:
        """The body is optional, and absent means crl_published=False."""
        client, serial = self._client_and_serial(tmp_path)
        resp = client.post(
            f"/acme/admin/revocations/{serial}/confirm", headers=CONFIRM_AUTH
        )
        assert resp.status_code == 200

    def test_an_unparseable_body_is_still_treated_as_no(
        self, tmp_path: Path
    ) -> None:
        """Preserved behaviour: garbage means "not published", not a 500."""
        client, serial = self._client_and_serial(tmp_path)
        resp = client.post(
            f"/acme/admin/revocations/{serial}/confirm",
            headers=CONFIRM_AUTH,
            content=b"{not json at all",
        )
        assert resp.status_code == 200

    def test_the_body_bound_is_configurable_and_validated(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ValidationError, match="max_admin_body_size_bytes"):
            _config(tmp_path, max_admin_body_size_bytes=0)


# ---------------------------------------------------------------------------
# Finding 3 (low), part 1 — serial aliases defeated the single-flight key
# ---------------------------------------------------------------------------


class TestSerialAliasesAreCanonicalized:
    """`A`, `0A` and `00A` are one certificate; they were three gate keys.

    The store canonicalizes inside its lookup (leading zeros stripped), so all
    three aliases select the same row. The route kept its own half-normalized
    spelling — uppercased, `0x` stripped, leading zeros **not** stripped — and
    used that as the single-flight key, so the aliases of one certificate each
    started their own CRL retrieval. The fix canonicalizes at route entry and
    keys the gate by the certificate row id, which cannot be spelled two ways.
    """

    def _client_and_serial(self, tmp_path: Path) -> tuple[TestClient, str]:
        client = _client(
            tmp_path, revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN)
        )
        store = client.app.state.context.store  # type: ignore[attr-defined]
        cert = _revoked_cert(store)
        return client, str(cert.serial_number)

    @pytest.mark.parametrize("prefix", ["", "0", "00", "000", "0x", "0X00"])
    def test_every_alias_reaches_the_same_certificate(
        self, tmp_path: Path, prefix: str
    ) -> None:
        client, serial = self._client_and_serial(tmp_path)
        store = client.app.state.context.store  # type: ignore[attr-defined]
        resp = client.post(
            f"/acme/admin/revocations/{prefix}{serial}/confirm",
            headers=CONFIRM_AUTH,
        )
        assert resp.status_code == 200
        # Confirmed, so it drains off the pending feed — proving the alias
        # resolved to the real row rather than 404ing or confirming nothing.
        assert store.list_revoked_certificates() == []

    def test_the_audit_records_one_canonical_spelling(
        self, tmp_path: Path
    ) -> None:
        """Aliases must not turn one certificate into several audit identities."""
        client, serial = self._client_and_serial(tmp_path)
        store = client.app.state.context.store  # type: ignore[attr-defined]
        resp = client.post(
            f"/acme/admin/revocations/000{serial}/confirm", headers=CONFIRM_AUTH
        )
        assert resp.status_code == 200
        events = [
            e
            for e in store.list_audit_events(limit=100)
            if e["event_type"] == "revocation-ca-confirmed"
        ]
        assert events, "expected a confirmation audit event"
        assert events[0]["details"]["serial"] == serial

    @pytest.mark.parametrize("bad", ["zzz", "12g4", "0x", "..%2f"])
    def test_a_non_hexadecimal_serial_is_refused(
        self, tmp_path: Path, bad: str
    ) -> None:
        """Hex-validate at entry rather than passing path text onward."""
        client, _serial = self._client_and_serial(tmp_path)
        resp = client.post(
            f"/acme/admin/revocations/{bad}/confirm", headers=CONFIRM_AUTH
        )
        assert resp.status_code in (400, 404)
        if resp.status_code == 400:
            assert "hexadecimal" in resp.text or "must not be empty" in resp.text

    def test_the_gate_is_keyed_by_certificate_id_not_by_serial(
        self, tmp_path: Path
    ) -> None:
        """Directly assert the key, since aliasing is what the key controls."""
        client = _client(
            tmp_path,
            revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN),
            revocation_confirm_crl_url="http://127.0.0.1:1/none.crl",
        )
        ctx = client.app.state.context  # type: ignore[attr-defined]
        cert = _revoked_cert(ctx.store)

        seen: list[str] = []
        real_run = ctx.crl_evidence_gate.run

        async def recording_run(key: str, fn: Any, *args: Any) -> Any:
            seen.append(key)
            return await real_run(key, fn, *args)

        ctx.crl_evidence_gate.run = recording_run  # type: ignore[method-assign]
        resp = client.post(
            f"/acme/admin/revocations/00{cert.serial_number}/confirm",
            headers=CONFIRM_AUTH,
        )
        assert resp.status_code == 200
        assert seen == [cert.id]


# ---------------------------------------------------------------------------
# Finding 3 (low), part 2 — admission was unbounded
# ---------------------------------------------------------------------------


class TestGateAdmissionControl:
    """`max_workers` bounds what runs, not what is accepted.

    `ThreadPoolExecutor`'s work queue is an unbounded `SimpleQueue`, and each
    waiting caller also pins a suspended request task. Distinct serials arriving
    faster than they complete therefore grew memory without limit even though
    only two retrievals ran at a time.
    """

    def test_distinct_keys_are_shed_at_the_ceiling(self) -> None:
        gate = CrlEvidenceGate(max_workers=1, max_pending=3)
        release = threading.Event()

        def blocked() -> str:
            release.wait(5)
            return "evidence"

        async def scenario() -> None:
            accepted = [
                asyncio.ensure_future(gate.run(f"KEY-{i}", blocked)) for i in range(3)
            ]
            await asyncio.sleep(0.05)
            assert gate.inflight == 3
            with pytest.raises(CrlEvidenceGateBusy):
                await gate.run("KEY-OVERFLOW", blocked)
            release.set()
            await asyncio.gather(*accepted)

        try:
            asyncio.run(scenario())
        finally:
            release.set()
            gate.close()

    def test_joining_an_existing_flight_is_never_shed(self) -> None:
        """A second caller for an in-flight key costs nothing new to admit."""
        gate = CrlEvidenceGate(max_workers=1, max_pending=1)
        release = threading.Event()
        entered = threading.Semaphore(0)

        def blocked() -> str:
            entered.release()
            release.wait(5)
            return "evidence"

        async def scenario() -> list[str]:
            first = asyncio.ensure_future(gate.run("KEY-A", blocked))
            await asyncio.to_thread(entered.acquire)
            # At the ceiling (1 in flight), but this is the SAME key.
            second = asyncio.ensure_future(gate.run("KEY-A", blocked))
            await asyncio.sleep(0.05)
            release.set()
            return await asyncio.gather(first, second)

        try:
            assert asyncio.run(scenario()) == ["evidence", "evidence"]
        finally:
            release.set()
            gate.close()

    def test_capacity_is_released_as_flights_complete(self) -> None:
        gate = CrlEvidenceGate(max_workers=2, max_pending=2)

        async def scenario() -> None:
            for i in range(6):
                assert await gate.run(f"KEY-{i}", lambda: "evidence") == "evidence"
            assert gate.inflight == 0

        try:
            asyncio.run(scenario())
        finally:
            gate.close()

    def test_the_route_sheds_with_a_retryable_status(self, tmp_path: Path) -> None:
        """429 + Retry-After, not "no evidence".

        Being too busy to look says nothing about whether the certificate is
        revoked, so it must not be recorded as absent evidence — under
        `require_crl_evidence` that would be a false statement in the audit
        trail. The serial stays pending and the next sweep retries.
        """
        client = _client(
            tmp_path,
            revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN),
            revocation_confirm_crl_url="http://127.0.0.1:1/none.crl",
        )
        ctx = client.app.state.context  # type: ignore[attr-defined]
        cert = _revoked_cert(ctx.store)

        async def always_busy(key: str, fn: Any, *args: Any) -> Any:
            raise CrlEvidenceGateBusy("99 CRL evidence retrievals already in progress")

        ctx.crl_evidence_gate.run = always_busy  # type: ignore[method-assign]
        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers=CONFIRM_AUTH,
        )
        assert resp.status_code == 429
        assert resp.headers.get("Retry-After")
        # Not confirmed: still pending for the next sweep.
        assert len(ctx.store.list_revoked_certificates()) == 1

    def test_the_ceiling_is_validated_against_the_pool_size(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ValidationError, match="max_pending"):
            _config(tmp_path, revocation_confirm_crl_max_pending=0)
        with pytest.raises(ValidationError, match="below"):
            _config(
                tmp_path,
                revocation_confirm_crl_max_workers=8,
                revocation_confirm_crl_max_pending=4,
            )


# ---------------------------------------------------------------------------
# Finding 3 (low), part 3 — a non-chunked trickle never reached the deadline
# ---------------------------------------------------------------------------


def _serve_content_length_trickle(
    *, declared: int = 1_000_000, interval: float = 0.02
) -> tuple[str, Any]:
    """A server that declares a large Content-Length and dribbles bytes.

    This is the shape the previous fix missed. With no chunked encoding, the
    underlying read waits for the full 64 KiB `iter_content` chunk; a byte
    arriving before each socket-read timeout keeps resetting that timeout while
    never delivering enough to yield a chunk, so the loop body — and the
    deadline check that lived in it — was never reached at all.
    """
    stop = threading.Event()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=dribble, args=(conn,), daemon=True).start()

    def dribble(conn: socket.socket) -> None:
        try:
            conn.recv(4096)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % declared
            )
            while not stop.is_set():
                conn.sendall(b"A")
                time.sleep(interval)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    threading.Thread(target=serve, daemon=True).start()

    def shutdown() -> None:
        stop.set()
        with contextlib.suppress(OSError):
            srv.close()

    return f"http://127.0.0.1:{port}/ca.crl", shutdown


class TestNonChunkedTrickleHitsTheDeadline:
    def test_a_content_length_trickle_is_cut_off(self) -> None:
        url, shutdown = _serve_content_length_trickle()
        try:
            started = time.monotonic()
            evidence = fetch_crl_evidence(
                crl_url=url,
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                timeout_seconds=5.0,
                total_timeout_seconds=0.5,
            )
            elapsed = time.monotonic() - started
        finally:
            shutdown()

        assert evidence.checked is False
        assert "total deadline" in evidence.detail
        # Before the fix this ran until an external timeout killed it. The
        # per-read timeout is 5s and would never fire against this server, so
        # anything under it proves the total deadline is what stopped it.
        assert elapsed < 3.0

    def test_the_deadline_is_reported_as_a_deadline_not_a_read_error(self) -> None:
        """Aborting the transport must not be mistaken for a transport fault.

        Tearing the socket down surfaces as `IncompleteRead`/`ProtocolError` on
        a Content-Length response. Reporting that as "CRL fetch failed" would
        send an operator looking at the CRL host instead of at the deadline.
        """
        url, shutdown = _serve_content_length_trickle()
        try:
            evidence = fetch_crl_evidence(
                crl_url=url,
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                timeout_seconds=5.0,
                total_timeout_seconds=0.4,
            )
        finally:
            shutdown()
        assert "total deadline" in evidence.detail
        assert "fetch failed" not in evidence.detail
        assert "read failed" not in evidence.detail

    def test_concurrent_trickles_all_terminate(self) -> None:
        """The bound is per-retrieval, so a fleet of them still all end."""
        url, shutdown = _serve_content_length_trickle()
        results: list[Any] = []

        def one() -> None:
            results.append(
                fetch_crl_evidence(
                    crl_url=url,
                    serial_number=0x1234,
                    cert_pem="",
                    chain_pem=[],
                    timeout_seconds=5.0,
                    total_timeout_seconds=0.5,
                )
            )

        try:
            started = time.monotonic()
            threads = [threading.Thread(target=one) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
            elapsed = time.monotonic() - started
        finally:
            shutdown()

        assert all(not t.is_alive() for t in threads)
        assert len(results) == 4
        assert all("total deadline" in r.detail for r in results)
        assert elapsed < 5.0

    def test_a_peer_that_goes_silent_is_cut_at_the_total_deadline(self) -> None:
        """The case only the watchdog covers.

        A peer that sends headers and then nothing does eventually trip the
        per-read timeout — but that timeout is the wrong bound. With a 0.5s
        total deadline and an 8s per-read timeout, the in-loop clock check
        cannot run (the read is parked), so without something that interrupts
        the read from outside, the total deadline overshoots by 16x and the
        result is reported as a transport fault rather than as a deadline.
        Measured before the fix: 8.01s, "CRL read failed".
        """
        stop = threading.Event()
        held: list[socket.socket] = []
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def serve() -> None:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with contextlib.suppress(OSError):
                conn.recv(4096)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"
                )
            # Then nothing, ever. Held open so the socket is not closed, which
            # would give the reader a clean EOF and defeat the point.
            held.append(conn)
            stop.wait(10)

        threading.Thread(target=serve, daemon=True).start()
        try:
            started = time.monotonic()
            evidence = fetch_crl_evidence(
                crl_url=f"http://127.0.0.1:{srv.getsockname()[1]}/ca.crl",
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                timeout_seconds=8.0,
                total_timeout_seconds=0.5,
            )
            elapsed = time.monotonic() - started
        finally:
            stop.set()
            for conn in held:
                with contextlib.suppress(OSError):
                    conn.close()
            with contextlib.suppress(OSError):
                srv.close()

        assert evidence.checked is False
        assert "total deadline" in evidence.detail
        # Well under the 8s per-read timeout: the total deadline is what fired.
        assert elapsed < 4.0

    def test_a_prompt_response_is_unaffected(self) -> None:
        """The watchdog must not disturb a healthy fetch."""
        import http.server

        body = b"not a crl at all"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"http://127.0.0.1:{server.server_address[1]}/ca.crl",
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                total_timeout_seconds=30.0,
            )
        finally:
            server.shutdown()

        # It got the whole body and rejected it on content, not on time.
        assert evidence.checked is False
        assert "neither valid DER nor PEM" in evidence.detail


def test_the_confirm_route_still_requires_its_own_token(tmp_path: Path) -> None:
    """Guard rail: the body/serial/admission changes touched the route's top."""
    client = _client(
        tmp_path, revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN)
    )
    store = client.app.state.context.store  # type: ignore[attr-defined]
    cert = _revoked_cert(store, status=CertStatus.REVOKED)
    resp = client.post(
        f"/acme/admin/revocations/{cert.serial_number}/confirm",
        headers={"Authorization": f"Bearer {STRONG_ADMIN_TOKEN}"},
        content=b"x" * 100_000,
    )
    # 401, not 400: authority is checked before the body is even read.
    assert resp.status_code == 401
    assert len(store.list_revoked_certificates()) == 1
