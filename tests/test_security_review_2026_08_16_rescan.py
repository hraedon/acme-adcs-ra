"""Regression tests for the 2026-08-16 rescan (findings 1-4).

The rescan of `fb3a14e` confirmed the four 2026-08-16 fixes and found four
more: one medium (legacy certificate rows carry no serial, so they cannot be
revoked through ACME after an upgrade) and three low (unbounded CRL retrieval
sharing the enrollment worker pool, caller-supplied SANs reaching the
revocation audit, and a revocation script claiming a CRL publication it
skipped).

Finding 2 is PowerShell and is covered by `tests/pester/Revocation.Tests.ps1`
(`Get-RevocationCompletionMessage`); there is nothing for pytest to assert.

Each test here was mutation-checked: the fix was reverted in turn and the test
confirmed to fail. See docs/security-review-2026-08-16-rescan.md.
"""

from __future__ import annotations

import asyncio
import datetime
import http.server
import json
import sqlite3
import threading
import time
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.crl_evidence import CrlEvidenceGate, fetch_crl_evidence
from acme_adcs_ra.routes.revocation import _dns_sans
from acme_adcs_ra.store import Store, StoreMigrationError, _serial_from_pem

# The app/client/config fixtures come from the revocation suite verbatim —
# these tests exercise the same surface and there is nothing to vary.
from .test_revocation import (
    _issue_cert,
    _make_test_config,
    account_key,
    app,
    client,
    test_config,
)

__all__ = ["account_key", "app", "client", "test_config"]


def _audit_events(db_path: Any, event_type: str) -> list[sqlite3.Row]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM audit_log WHERE event_type = ? ORDER BY id",
            (event_type,),
        ).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Finding 1 (medium) — legacy certificate rows are unrevokable
# ---------------------------------------------------------------------------


class TestLegacySerialBackfill:
    """`serial_number` is the ONLY key revokeCert resolves a certificate by.

    The migration that introduced the column added it with `ALTER TABLE ... ADD
    COLUMN`, which gives every existing row NULL, and nothing ever derived a
    value. SQL equality against NULL never matches, so on any deployment
    upgraded across that point every pre-existing certificate answered its
    owner's revocation request with 404 — the certificate stayed trusted until
    expiry, and the pending-revocation feed skipped it too, so nothing said so.
    """

    @staticmethod
    def _make_legacy(db_path: Any) -> str:
        """Blank the serial on the one certificate row, as the ALTER did."""
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("UPDATE certificates SET serial_number = NULL")
            conn.commit()
            row = conn.execute("SELECT id FROM certificates").fetchone()
            assert row is not None
            return str(row[0])
        finally:
            conn.close()

    def test_upgraded_database_can_still_revoke_a_legacy_certificate(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """The headline case: upgrade a pre-migration DB, then revoke."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        self._make_legacy(test_config.db_path)

        # Opening a Store is what runs the migration — this is the upgrade.
        Store(test_config.db_path)

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200

    def test_backfill_derives_the_serial_from_the_stored_pem(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """And it derives the *right* one, in the store's canonical form."""
        _ac, cert_der = _issue_cert(client, test_config, account_key)
        self._make_legacy(test_config.db_path)
        Store(test_config.db_path)

        expected = _serial_from_pem(
            x509.load_der_x509_certificate(cert_der)
            .public_bytes(serialization.Encoding.PEM)
            .decode("utf-8")
        )
        conn = sqlite3.connect(str(test_config.db_path))
        try:
            stored = conn.execute("SELECT serial_number FROM certificates").fetchone()[0]
        finally:
            conn.close()
        assert stored == expected

    def test_repeated_startup_is_a_no_op(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """The invariant check must not trip on an already-backfilled store."""
        _issue_cert(client, test_config, account_key)
        self._make_legacy(test_config.db_path)
        Store(test_config.db_path)
        Store(test_config.db_path)
        Store(test_config.db_path)

    def test_unparseable_legacy_row_fails_startup(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """Fail loudly rather than come up with an unrevokable certificate.

        A row whose PEM will not parse has no derivable serial, so it would sit
        in the store permanently unreachable by revocation. That is precisely
        the state this finding is about, so the RA refuses to start.
        """
        _issue_cert(client, test_config, account_key)
        conn = sqlite3.connect(str(test_config.db_path))
        try:
            conn.execute(
                "UPDATE certificates SET serial_number = NULL, cert_pem = ?",
                ("-----BEGIN CERTIFICATE-----\nnot a certificate\n",),
            )
            conn.commit()
        finally:
            conn.close()

        with pytest.raises(StoreMigrationError) as exc:
            Store(test_config.db_path)
        assert "does not parse" in str(exc.value)

    def test_conflicting_legacy_rows_fail_startup(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """Two rows deriving one serial for one account cannot both be the
        answer to that account's revocation request, so the migration stops."""
        _issue_cert(client, test_config, account_key)
        conn = sqlite3.connect(str(test_config.db_path))
        try:
            row = conn.execute("SELECT * FROM certificates").fetchone()
            columns = [d[0] for d in conn.execute("SELECT * FROM certificates").description]
            twin = dict(zip(columns, row, strict=True))
            twin["id"] = "cert-twin"
            twin["order_id"] = "order-twin"
            twin["serial_number"] = None
            conn.execute("UPDATE certificates SET serial_number = NULL")
            conn.execute(
                f"INSERT INTO certificates ({','.join(twin)}) "
                f"VALUES ({','.join('?' * len(twin))})",
                tuple(twin.values()),
            )
            conn.commit()
        finally:
            conn.close()

        with pytest.raises(StoreMigrationError) as exc:
            Store(test_config.db_path)
        assert "conflicting serial" in str(exc.value)

    def test_failed_migration_rolls_back(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """A refused startup must not leave a half-backfilled store behind."""
        _issue_cert(client, test_config, account_key)
        conn = sqlite3.connect(str(test_config.db_path))
        try:
            conn.execute(
                "UPDATE certificates SET serial_number = NULL, cert_pem = ?",
                ("garbage",),
            )
            conn.commit()
        finally:
            conn.close()

        with pytest.raises(StoreMigrationError):
            Store(test_config.db_path)

        conn = sqlite3.connect(str(test_config.db_path))
        try:
            serial = conn.execute("SELECT serial_number FROM certificates").fetchone()[0]
        finally:
            conn.close()
        assert serial is None


# ---------------------------------------------------------------------------
# Finding 3 (low) — caller-supplied SANs reached the revocation audit
# ---------------------------------------------------------------------------


def _self_signed(sans: list[str], serial: int | None = None) -> bytes:
    """A throwaway self-signed certificate in DER, with the given dNSNames."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    common_name = sans[0] if sans else "no-san.example.invalid"
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _forge_same_serial(cert_der: bytes, sans: list[str]) -> bytes:
    """A self-signed certificate carrying *cert_der*'s serial and other SANs.

    This is what an owner submits to revokeCert to test the binding: the serial
    matches, so the (serial, account) lookup still finds the authoritative row.
    """
    genuine = x509.load_der_x509_certificate(cert_der)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])])
    forged = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(genuine.issuer)
        .public_key(key.public_key())
        .serial_number(genuine.serial_number)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return forged.public_bytes(serialization.Encoding.DER)


class TestRevocationAuditSansAreAuthoritative:
    """The audit trail is the record of a containment action.

    revokeCert binds the request to stored state by (serial, account_id) only.
    An owner could therefore submit a self-signed certificate with the same
    serial and any SANs it liked: the correct certificate was revoked, and the
    mandatory `certificate-revoked` event recorded the attacker's SAN list as
    though it were the issued one.
    """

    def test_forged_same_serial_certificate_is_rejected(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        forged = _forge_same_serial(cert_der, ["evil.example.invalid"])

        resp = ac.revoke_certificate(forged, reason=0)
        assert resp.status_code == 400
        assert "does not match" in resp.text

    def test_a_rejected_forgery_does_not_revoke_anything(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """Rejection must be total: the certificate stays valid and no
        `certificate-revoked` event is written for the attempt."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        forged = _forge_same_serial(cert_der, ["evil.example.invalid"])
        assert ac.revoke_certificate(forged, reason=0).status_code == 400

        assert _audit_events(test_config.db_path, "certificate-revoked") == []
        # The genuine certificate is untouched, so the real revocation still works.
        assert ac.revoke_certificate(cert_der, reason=0).status_code == 200

    def test_audit_records_the_stored_certificates_sans(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """The ordinary path audits the SANs of the row the RA holds.

        Computed here from the stored PEM, independently of the route, so this
        asserts the source of the value rather than restating it. (The CI
        enrollment fixture carries no SAN extension, which is why the expected
        list is empty — the point is that it comes from the store.)
        """
        ac, cert_der = _issue_cert(client, test_config, account_key)
        assert ac.revoke_certificate(cert_der, reason=1).status_code == 200

        conn = sqlite3.connect(str(test_config.db_path))
        try:
            stored_pem = conn.execute("SELECT cert_pem FROM certificates").fetchone()[0]
        finally:
            conn.close()
        expected = _dns_sans(
            x509.load_pem_x509_certificate(stored_pem.encode("utf-8"))
        )

        events = _audit_events(test_config.db_path, "certificate-revoked")
        assert len(events) == 1
        assert json.loads(events[0]["sans"]) == expected

    def test_dns_sans_reads_the_certificates_own_names(self) -> None:
        """The helper the audit path uses, on both shapes of certificate."""
        with_sans = x509.load_der_x509_certificate(
            _self_signed(["a.example.invalid", "b.example.invalid"])
        )
        assert _dns_sans(with_sans) == ["a.example.invalid", "b.example.invalid"]

        without = x509.load_der_x509_certificate(_self_signed([]))
        assert _dns_sans(without) == []


# ---------------------------------------------------------------------------
# Finding 4 (low) — trickling CRL requests could exhaust the enrollment pool
# ---------------------------------------------------------------------------


def _serve_trickle(interval: float = 0.02) -> tuple[str, Any]:
    """An HTTP server that dribbles bytes for ever without ever timing out.

    This is the shape that defeats a `requests` timeout: the timeout is
    per-read, so a byte arriving before each one keeps resetting it and the
    transfer never ends.
    """
    stop = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                while not stop.is_set():
                    self.wfile.write(b"1\r\nA\r\n")
                    self.wfile.flush()
                    time.sleep(interval)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        def log_message(self, *_args: Any) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def shutdown() -> None:
        stop.set()
        server.shutdown()

    return f"http://127.0.0.1:{server.server_address[1]}/ca.crl", shutdown


class TestCrlRetrievalHasATotalDeadline:
    def test_a_trickling_server_is_cut_off_at_the_total_deadline(self) -> None:
        """Per-read timeouts do not bound a transfer; this one does."""
        url, shutdown = _serve_trickle()
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
        # Generously above the 0.5s deadline and far below the 5s per-read
        # timeout the trickle would otherwise keep resetting for ever.
        assert elapsed < 3.0

    def test_the_deadline_does_not_disturb_a_healthy_fetch(self) -> None:
        """A prompt (if unusable) response still returns its own verdict."""
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

        assert evidence.checked is False
        assert "total deadline" not in evidence.detail


class TestCrlEvidenceGate:
    """Confirmations run on the RA's own bounded pool, one flight per serial."""

    def test_concurrent_confirmations_for_one_serial_fetch_once(self) -> None:
        gate = CrlEvidenceGate(max_workers=2)
        calls = threading.Semaphore(0)
        release = threading.Event()
        started = []

        def slow_fetch() -> str:
            started.append(1)
            calls.release()
            release.wait(5)
            return "evidence"

        async def scenario() -> list[str]:
            first = asyncio.ensure_future(gate.run("SERIAL-A", slow_fetch))
            # Let the first submission reach the worker before the others queue.
            await asyncio.to_thread(calls.acquire)
            others = [asyncio.ensure_future(gate.run("SERIAL-A", slow_fetch)) for _ in range(8)]
            await asyncio.sleep(0.05)
            release.set()
            return await asyncio.gather(first, *others)

        try:
            results = asyncio.run(scenario())
        finally:
            release.set()
            gate.close()

        assert results == ["evidence"] * 9
        assert sum(started) == 1

    def test_distinct_serials_are_not_single_flighted(self) -> None:
        gate = CrlEvidenceGate(max_workers=4)

        async def scenario() -> list[str]:
            return await asyncio.gather(
                *(gate.run(f"SERIAL-{i}", lambda i=i: f"evidence-{i}") for i in range(4))
            )

        try:
            results = asyncio.run(scenario())
        finally:
            gate.close()
        assert sorted(results) == [f"evidence-{i}" for i in range(4)]

    def test_a_completed_flight_does_not_block_the_next_one(self) -> None:
        """The in-flight entry is cleared, or one confirmation per serial would
        be all the RA ever performs."""
        gate = CrlEvidenceGate(max_workers=1)
        counter = [0]

        def count() -> int:
            counter[0] += 1
            return counter[0]

        async def scenario() -> list[int]:
            return [await gate.run("SERIAL-A", count) for _ in range(3)]

        try:
            assert asyncio.run(scenario()) == [1, 2, 3]
        finally:
            gate.close()

    def test_work_runs_on_the_ras_own_threads_not_starlettes(self) -> None:
        """Pool isolation is the point: a stalled CRL must not consume the
        workers that ADCS enrollment draws from."""
        gate = CrlEvidenceGate(max_workers=2)

        async def scenario() -> str:
            return await gate.run("SERIAL-A", lambda: threading.current_thread().name)

        try:
            name = asyncio.run(scenario())
        finally:
            gate.close()
        assert name.startswith("ra-crl-evidence")

    def test_a_cancelled_caller_does_not_cancel_the_shared_flight(self) -> None:
        """A client disconnect must not abort the retrieval other callers are
        still waiting on."""
        gate = CrlEvidenceGate(max_workers=2)
        release = threading.Event()
        entered = threading.Semaphore(0)

        def slow_fetch() -> str:
            entered.release()
            release.wait(5)
            return "evidence"

        async def scenario() -> str:
            first = asyncio.ensure_future(gate.run("SERIAL-A", slow_fetch))
            await asyncio.to_thread(entered.acquire)
            second = asyncio.ensure_future(gate.run("SERIAL-A", slow_fetch))
            await asyncio.sleep(0.05)
            first.cancel()
            release.set()
            return await second

        try:
            assert asyncio.run(scenario()) == "evidence"
        finally:
            release.set()
            gate.close()

    def test_a_closed_gate_refuses_work(self) -> None:
        gate = CrlEvidenceGate()
        gate.close()

        async def scenario() -> None:
            await gate.run("SERIAL-A", lambda: "evidence")

        with pytest.raises(RuntimeError):
            asyncio.run(scenario())


class TestCrlTimeoutConfiguration:
    def test_total_below_per_read_is_refused_at_load(self, tmp_path: Any) -> None:
        """A total deadline under the per-read timeout would abort healthy
        fetches — and under require_crl_evidence, wedge confirmation."""
        base = _make_test_config(tmp_path).model_dump()
        base["revocation_confirm_crl_timeout_seconds"] = 10.0
        base["revocation_confirm_crl_total_timeout_seconds"] = 5.0
        with pytest.raises(ValueError, match="below"):
            RAConfig(**base)

    def test_zero_workers_is_refused_at_load(self, tmp_path: Any) -> None:
        base = _make_test_config(tmp_path).model_dump()
        base["revocation_confirm_crl_max_workers"] = 0
        with pytest.raises(ValueError, match="at least 1"):
            RAConfig(**base)
