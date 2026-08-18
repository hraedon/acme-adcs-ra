"""Regression tests for the third 2026-08-18 review wave (of `d26b892`).

Seven findings, of which **two were already closed** at HEAD by the rescan
commit (`83abd62`) — that scan and the rescan looked at the same commit in
parallel, so its F5 (CRL redirect origin) and F7 (twin migration) are covered by
`test_security_review_2026_08_18_rescan.py`. The five genuinely new ones:

* F1 (medium) — ADCS disposition 21 was read as proof of revocation, but the
  repo's own lab notes record that reason 8 (removeFromCRL) leaves disposition
  21 while the certificate is off the CRL and **valid**.
* F2 (medium) — `audit_offbox_required` asserted that a SIEM emitter had been
  *constructed*, not that anything reached it.
* F4 (low) — the certsrv response cap ran after `requests` had buffered.
* F6 (low) — `ca_crl_updated` committed before its audit event, on a separate
  connection.
* F3 (low) — unbounded audit growth from unauthenticated denials. **Deliberately
  not fixed this wave**; see docs/security-review-2026-08-18-wave3.md.

Each test here was mutation-checked. See docs/security-review-2026-08-18-wave3.md.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, ClassVar

import pytest

from acme_adcs_ra.enrollment import EnrollmentTransportError, _read_capped_body
from acme_adcs_ra.siem import SiemConfig, SiemEmitter
from acme_adcs_ra.store import CertStatus, Store

_RECONCILE = Path(__file__).resolve().parent.parent / "scripts" / "reconcile_revocation.py"


# ---------------------------------------------------------------------------
# Finding 1 (medium) — disposition 21 is not proof of revocation
# ---------------------------------------------------------------------------


def _seed_cert(db_path: Path, serial_hex: str, status: str) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO certificates (id, order_id, account_id, cert_pem, "
            "chain_pem, template, requester, metadata, issued_at, status, "
            "serial_number) VALUES (?, ?, ?, '', '[]', 't', 'r', '{}', ?, ?, ?)",
            (
                f"cert-{serial_hex}",
                f"order-{serial_hex}",
                "acct-1",
                "2026-08-18T00:00:00+00:00",
                status,
                serial_hex,
            ),
        )


def _reconcile(db_path: Path, export: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    export_path = tmp_path / "ca-export.txt"
    export_path.write_text(export)
    return subprocess.run(
        [
            sys.executable, str(_RECONCILE),
            "--db", str(db_path),
            "--ca-export", str(export_path),
            "--json",
        ],
        capture_output=True, text=True, check=False,
    )


def _row(serial: str, disposition: int, reason: int | None = None) -> str:
    lines = [
        "Row Index: 1",
        "  Request ID: 1",
        f"  Serial Number: {serial}",
        f"  Disposition: {disposition}",
    ]
    if reason is not None:
        lines.append(f"  Revocation Reason: 0x{reason:x} ({reason})")
    return "\n".join(lines) + "\n\n"


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    Store(tmp_path / "ra.db")
    return tmp_path / "ra.db"


class TestRemoveFromCrlIsNotRevocation:
    """`scripts/lib/RevocationLib.ps1` records the lab finding this rests on:

        a certificate placed on hold and then given reason 8 ends up "off the
        CRL and valid" while ADCS keeps its DB Disposition at 21.

    The RA already refuses reason 8 as *CRL* evidence and refuses to emit it on
    the ACME route. The CA-side tooling did not: both the sync agent and the
    reconciler read disposition alone, so an un-revoked certificate produced a
    containment PASS while relying parties still accepted it.
    """

    def test_reason_8_at_disposition_21_is_drift_not_in_sync(
        self, db: Path, tmp_path: Path
    ) -> None:
        _seed_cert(db, "AABBCCDD", "revoked")
        result = _reconcile(db, _row("AABBCCDD", 21, reason=8), tmp_path)

        assert result.returncode == 1
        body = json.loads(result.stdout)
        assert body["revoked_in_ra_active_at_ca"] == ["AABBCCDD"]
        assert body["in_sync"] == []

    def test_an_ordinary_revocation_reason_is_still_in_sync(
        self, db: Path, tmp_path: Path
    ) -> None:
        """Only reason 8 is the un-revoke; the rest must not become drift."""
        _seed_cert(db, "AABBCCDD", "revoked")
        result = _reconcile(db, _row("AABBCCDD", 21, reason=1), tmp_path)

        assert result.returncode == 0
        assert json.loads(result.stdout)["in_sync"] == ["AABBCCDD"]

    def test_a_disposition_21_row_with_no_reason_is_still_revoked(
        self, db: Path, tmp_path: Path
    ) -> None:
        """An export without the reason column must not silently become drift.

        Reason is absent on an older export or a CA that does not surface the
        column; treating that as reason 8 would invent drift for every revoked
        certificate in the estate.
        """
        _seed_cert(db, "AABBCCDD", "revoked")
        result = _reconcile(db, _row("AABBCCDD", 21), tmp_path)

        assert result.returncode == 0
        assert json.loads(result.stdout)["in_sync"] == ["AABBCCDD"]

    def test_a_quarantined_certificate_unrevoked_at_the_ca_is_drift(
        self, db: Path, tmp_path: Path
    ) -> None:
        _seed_cert(db, "CAFEBABE", "quarantined")
        result = _reconcile(db, _row("CAFEBABE", 21, reason=8), tmp_path)

        assert result.returncode == 1
        assert json.loads(result.stdout)["revoked_in_ra_active_at_ca"] == ["CAFEBABE"]

    @pytest.mark.parametrize(
        "line",
        [
            "  Revocation Reason: 0x8 (8)",
            "  Revocation Reason: 8",
            "  Request.RevokedReason: 8",
        ],
    )
    def test_the_reason_line_is_parsed_in_the_shapes_certutil_emits(
        self, db: Path, tmp_path: Path, line: str
    ) -> None:
        _seed_cert(db, "AABBCCDD", "revoked")
        export = (
            "Row Index: 1\n  Request ID: 1\n  Serial Number: AABBCCDD\n"
            f"  Disposition: 21\n{line}\n\n"
        )
        result = _reconcile(db, export, tmp_path)
        assert result.returncode == 1, f"{line!r} was not recognised as reason 8"


# ---------------------------------------------------------------------------
# Finding 2 (medium) — required off-box audit must prove delivery
# ---------------------------------------------------------------------------


class TestOffboxDeliveryIsProven:
    """"Required" has to mean demonstrated, not configured.

    The gate asserted the emitter had been *constructed* from syntactically
    valid config. A revoked token, a wrong index, or an endpoint answering 403
    to everything passed it, and the RA issued certificates believing an
    off-box trail was in force — the trail whose whole purpose is to survive a
    compromise of this host.
    """

    def test_a_probe_against_an_unreachable_hec_fails(self) -> None:
        emitter = SiemEmitter(
            SiemConfig(
                sink="hec",
                hec_url="https://hec.invalid.example/services/collector",
                hec_token="t",
            )
        )
        assert emitter.enabled is True, "construction succeeds — that is the point"
        ok, detail = emitter.probe_offbox_delivery()
        assert ok is False
        assert "HEC rejected the startup probe" in detail
        emitter.close()

    def test_a_probe_over_tcp_syslog_succeeds_against_a_listener(self) -> None:
        import socket

        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        accepted: list[socket.socket] = []

        def serve() -> None:
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                accepted.append(conn)

        threading.Thread(target=serve, daemon=True).start()
        emitter = None
        try:
            emitter = SiemEmitter(
                SiemConfig(
                    sink="syslog",
                    syslog_host="127.0.0.1",
                    syslog_port=listener.getsockname()[1],
                    syslog_proto="tcp",
                )
            )
            ok, detail = emitter.probe_offbox_delivery()
            assert ok is True, detail
            assert "TCP" in detail
        finally:
            if emitter is not None:
                emitter.close()
            for conn in accepted:
                with contextlib.suppress(OSError):
                    conn.close()
            with contextlib.suppress(OSError):
                listener.close()

    def test_a_udp_syslog_probe_fails_rather_than_explaining_itself(self) -> None:
        """UDP cannot acknowledge, so it cannot pass — SUPERSEDED 2026-08-18.

        This wave's fix made the probe *honest*: it returned True with a detail
        string saying in as many words that reachability was NOT proven. The
        2026-08-18 Codex scan (item 8) pointed out that the caller gates startup
        on the boolean and never reads the detail, so `audit_offbox_required`
        still refused nothing over UDP. The candour was real and useless. What
        this wave was reaching for is now expressed where it has effect.

        Kept rather than deleted because it is the regression that matters: a
        future refactor that restores "True with a caveat" would reopen the
        hole. Full coverage in `tests/test_codex_scan_2026_08_18.py`.
        """
        emitter = SiemEmitter(
            SiemConfig(
                sink="syslog",
                syslog_host="127.0.0.1",
                syslog_port=15514,
                syslog_proto="udp",
            )
        )
        try:
            ok, detail = emitter.probe_offbox_delivery()
            assert ok is False
            assert "fire-and-forget" in detail
            assert "syslog_proto=tcp" in detail
        finally:
            emitter.close()

    def test_a_disabled_emitter_never_passes_the_probe(self) -> None:
        emitter = SiemEmitter(SiemConfig(sink="hec", hec_url="", hec_token=""))
        assert emitter.enabled is False
        ok, detail = emitter.probe_offbox_delivery()
        assert ok is False
        assert "disabled" in detail

    def test_delivery_failures_are_counted_not_just_logged(self) -> None:
        """A sustained rejection used to be indistinguishable from a quiet period."""
        emitter = SiemEmitter(
            SiemConfig(
                sink="hec",
                hec_url="https://hec.invalid.example/services/collector",
                hec_token="t",
            )
        )
        try:
            assert emitter.offbox_failures == 0
            emitter.probe_offbox_delivery()
            emitter.probe_offbox_delivery()
            assert emitter.offbox_failures == 2
            assert emitter.offbox_last_error is not None
            assert emitter.offbox_delivered == 0
        finally:
            emitter.close()


# ---------------------------------------------------------------------------
# Finding 4 (low) — certsrv responses were capped only after buffering
# ---------------------------------------------------------------------------


class _StreamingRaw:
    """Stands in for ``response.raw``: hands out bytes in chunks, on demand."""

    def __init__(self, total: int, chunk: int = 4096) -> None:
        self._remaining = total
        self._chunk = chunk
        self.delivered = 0

    def read1(self, size: int, decode_content: bool = True) -> bytes:
        if self._remaining <= 0:
            return b""
        n = min(size, self._chunk, self._remaining)
        self._remaining -= n
        self.delivered += n
        return b"x" * n


class _StreamingResponse:
    def __init__(self, total: int, headers: dict[str, str] | None = None) -> None:
        self.status_code = 200
        self.headers = headers or {}
        self.raw = _StreamingRaw(total)
        self.encoding = "utf-8"

    @property
    def content(self) -> bytes:  # pragma: no cover - must not be reached
        raise AssertionError(
            "the bounded reader must not fall back to .content on a streamed "
            "response; that is what buffers the whole body"
        )

    def raise_for_status(self) -> None:
        return None


class TestCertsrvBodiesAreBoundedBeforeBuffering:
    """The cap ran after `requests` had already buffered the body.

    So it bounded *parsing* and never *memory*: a chunked reply from a
    malfunctioning or compromised certsrv was fully resident before anything
    checked its size, on the issuance path.
    """

    def test_an_oversized_stream_stops_near_the_cap(self) -> None:
        resp = _StreamingResponse(total=10 * 1024 * 1024)
        with pytest.raises(EnrollmentTransportError, match="limit"):
            _read_capped_body(resp, 64 * 1024, "certnew.cer")  # type: ignore[arg-type]
        # The load-bearing assertion: it stopped reading, rather than taking the
        # whole 10 MiB and complaining afterwards.
        assert resp.raw.delivered < 64 * 1024 + 8192

    def test_a_body_within_the_cap_is_returned_whole(self) -> None:
        resp = _StreamingResponse(total=1000)
        body = _read_capped_body(resp, 64 * 1024, "certnew.cer")  # type: ignore[arg-type]
        assert body == b"x" * 1000

    def test_a_declared_length_over_the_cap_is_refused_before_reading(self) -> None:
        resp = _StreamingResponse(
            total=10 * 1024 * 1024, headers={"Content-Length": str(10 * 1024 * 1024)}
        )
        with pytest.raises(EnrollmentTransportError, match="declared"):
            _read_capped_body(resp, 64 * 1024, "certnew.cer")  # type: ignore[arg-type]
        assert resp.raw.delivered == 0, "not one byte should have been read"

    def test_a_non_streaming_response_still_works(self) -> None:
        """Transport-only unit fakes have no `.raw`; they must keep working."""

        class _Buffered:
            status_code = 200
            headers: ClassVar[dict[str, str]] = {}
            content = b"hello"
            encoding = "utf-8"

            def raise_for_status(self) -> None:
                return None

        assert _read_capped_body(_Buffered(), 1024, "x") == b"hello"  # type: ignore[arg-type]

    def test_the_production_session_streams(self) -> None:
        """`stream=True` is applied in the factory, not at each call site."""
        import inspect

        from acme_adcs_ra.enrollment import _NoRedirectSession

        for method in (_NoRedirectSession.post, _NoRedirectSession.get):
            assert "stream=True" in inspect.getsource(method)


# ---------------------------------------------------------------------------
# Finding 6 (low) — the confirmation flag and its audit must commit together
# ---------------------------------------------------------------------------


class TestConfirmAndAuditAreAtomic:
    """`ca_crl_updated` is what removes a serial from the retry feed.

    Committing it before the audit event meant a crash in between dropped the
    certificate off the feed with no `revocation-ca-confirmed` recorded — and
    the route's idempotence check returns early on that same flag, so no retry
    could repair it. The evidence that a CA-side revocation was confirmed was
    permanently absent.
    """

    def _revoked_store(self, tmp_path: Path) -> tuple[Store, str]:
        store = Store(tmp_path / "ra.db")
        _seed_cert(tmp_path / "ra.db", "AABBCCDD", CertStatus.REVOKED)
        return store, "AABBCCDD"

    def test_a_failing_audit_insert_rolls_back_the_flag(self, tmp_path: Path) -> None:
        store, serial = self._revoked_store(tmp_path)

        def boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise sqlite3.OperationalError("disk I/O error")

        store._record_audit_in_conn = boom  # type: ignore[method-assign]
        with pytest.raises(sqlite3.OperationalError):
            store.confirm_ca_revocation_with_audit(
                serial, event_type="revocation-ca-confirmed", outcome="success"
            )

        # The serial must still be pending, so the next sweep retries it.
        del store._record_audit_in_conn  # type: ignore[attr-defined]
        reopened = Store(tmp_path / "ra.db")
        pending = [c.serial_number for c in reopened.list_revoked_certificates()]
        assert serial in pending, "the flag committed without its audit event"

    def test_a_successful_confirm_writes_both(self, tmp_path: Path) -> None:
        store, serial = self._revoked_store(tmp_path)
        won, event = store.confirm_ca_revocation_with_audit(
            serial,
            event_type="revocation-ca-confirmed",
            outcome="success",
            details={"serial": serial},
        )
        assert won is True
        assert event is not None and event["event_type"] == "revocation-ca-confirmed"
        assert store.list_revoked_certificates() == []
        with sqlite3.connect(str(tmp_path / "ra.db")) as conn:
            rows = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE event_type = ?",
                ("revocation-ca-confirmed",),
            ).fetchone()[0]
        assert rows == 1

    def test_a_second_confirm_is_idempotent_and_does_not_double_audit(
        self, tmp_path: Path
    ) -> None:
        store, serial = self._revoked_store(tmp_path)
        store.confirm_ca_revocation_with_audit(
            serial, event_type="revocation-ca-confirmed", outcome="success"
        )
        won, event = store.confirm_ca_revocation_with_audit(
            serial, event_type="revocation-ca-confirmed", outcome="success"
        )
        assert won is False
        assert event is None
        with sqlite3.connect(str(tmp_path / "ra.db")) as conn:
            rows = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE event_type = ?",
                ("revocation-ca-confirmed",),
            ).fetchone()[0]
        assert rows == 1
