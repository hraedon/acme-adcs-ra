"""Tests for read-only revocation reconciliation (WI-017)."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acme_adcs_ra.store import Store

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "reconcile_revocation.py"


def _jwk(idx: int) -> dict[str, Any]:
    return {
        "kty": "RSA",
        "n": f"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4-{idx}",
        "e": "AQAB",
    }


def _make_cert_pem(serial_hex: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv.WORK-DOMAIN.local")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(int(serial_hex, 16))
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _create_account_and_order(store: Store, idx: int) -> tuple[str, str]:
    account = store.create_account(jwk=_jwk(idx), eab_kid=f"kid-{idx:03d}")
    order = store.create_order_with_authz(
        account_id=account.id,
        identifiers=[{"type": "dns", "value": f"srv{idx}.WORK-DOMAIN.local"}],
        challenge_url_fn=lambda cid: f"http://test/acme/chall/{cid}",
        authz_url_fn=lambda aid: f"http://test/acme/authz/{aid}",
        finalize_url_fn=lambda oid: f"http://test/acme/order/{oid}/finalize",
    )
    return account.id, order.id


def _insert_cert(
    store: Store,
    order_id: str,
    account_id: str,
    serial_hex: str,
    *,
    revoked: bool = False,
) -> None:
    cert_pem = _make_cert_pem(serial_hex)
    record = store.create_certificate(
        order_id=order_id,
        account_id=account_id,
        cert_pem=cert_pem,
        chain_pem=[cert_pem],
        template="ACME-ServerAuth",
        requester="test",
        metadata={},
    )
    if revoked:
        update = store.revoke_certificate(record.id, reason=1)
        assert update.record is not None
        assert update.record.status == "revoked"
        assert update.won_cas is True


def _load_ra_state(db_path: Path) -> dict[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT serial_number, status FROM certificates WHERE serial_number IS NOT NULL"
        ).fetchall()
    return {row[0]: row[1] for row in rows}


def _run_reconcile(
    db_path: Path,
    ca_export_path: Path,
    *,
    use_json: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(_SCRIPT), "--db", str(db_path), "--ca-export", str(ca_export_path)]
    if use_json:
        cmd.append("--json")
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(_SCRIPT.parent.parent),
    )


def _ca_export_text(rows: list[tuple[int, str, int]]) -> str:
    lines: list[str] = []
    for idx, (request_id, serial, disposition) in enumerate(rows, start=1):
        label = "Revoked" if disposition == 21 else "Issued"
        lines.append(f"Row Index: {idx}")
        lines.append(f"  Request ID: {request_id}")
        lines.append(f"  Serial Number: {serial}")
        lines.append(f"  Disposition: {disposition} -- {label}")
        lines.append("")
    return "\n".join(lines)


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "ra.db")


class TestReconciliationBuckets:
    def test_revoked_in_both_is_in_sync(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_id, order_id = _create_account_and_order(store, 1)
        _insert_cert(store, order_id, account_id, "AABBCCDD", revoked=True)
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(1, "aabbccdd", 21)]))

        result = _run_reconcile(store._db_path, export_path)

        assert result.returncode == 0
        assert "In sync: 1" in result.stdout
        assert "Revoked at CA, valid in RA: 0" in result.stdout
        assert "Revoked in RA, active at CA: 0" in result.stdout

    def test_active_in_both_is_in_sync(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_id, order_id = _create_account_and_order(store, 2)
        _insert_cert(store, order_id, account_id, "11223344", revoked=False)
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(2, "11223344", 3)]))

        result = _run_reconcile(store._db_path, export_path)

        assert result.returncode == 0
        assert "In sync: 1" in result.stdout
        assert "PASS: revocation state is in sync." in result.stdout

    def test_revoked_at_ca_valid_in_ra_is_drift(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_id, order_id = _create_account_and_order(store, 3)
        _insert_cert(store, order_id, account_id, "DEADBEEF", revoked=False)
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(3, "DEADBEEF", 21)]))

        result = _run_reconcile(store._db_path, export_path)

        assert result.returncode == 1
        assert "Revoked at CA, valid in RA: 1" in result.stdout
        assert "DEADBEEF" in result.stdout

    def test_revoked_in_ra_active_at_ca_is_drift(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_id, order_id = _create_account_and_order(store, 4)
        _insert_cert(store, order_id, account_id, "CAFEBABE", revoked=True)
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(4, "CAFEBABE", 3)]))

        result = _run_reconcile(store._db_path, export_path)

        assert result.returncode == 1
        assert "Revoked in RA, active at CA: 1" in result.stdout
        assert "CAFEBABE" in result.stdout


class TestReconciliationRobustness:
    def test_lowercase_and_whitespace_serials_are_normalized(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_id, order_id = _create_account_and_order(store, 5)
        _insert_cert(store, order_id, account_id, "AABBCCDD", revoked=True)
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(5, "  aa bb cc dd  ", 21)]))

        result = _run_reconcile(store._db_path, export_path)

        assert result.returncode == 0
        assert "In sync: 1" in result.stdout

    def test_unknown_ca_disposition_is_skipped(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_id, order_id = _create_account_and_order(store, 6)
        _insert_cert(store, order_id, account_id, "AABBCCDD", revoked=False)
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(6, "AABBCCDD", 20)]))

        result = _run_reconcile(store._db_path, export_path)

        assert result.returncode == 0
        assert "In sync: 0" in result.stdout


class TestReconciliationModes:
    def test_json_output_reports_all_buckets(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_ids: list[str] = []
        order_ids: list[str] = []
        for idx in range(1, 5):
            account_id, order_id = _create_account_and_order(store, idx)
            account_ids.append(account_id)
            order_ids.append(order_id)

        _insert_cert(store, order_ids[0], account_ids[0], "B00B0001", revoked=True)
        _insert_cert(store, order_ids[1], account_ids[1], "B00B0002", revoked=False)
        _insert_cert(store, order_ids[2], account_ids[2], "CA000001", revoked=False)
        _insert_cert(store, order_ids[3], account_ids[3], "CA000002", revoked=True)

        export_path = tmp_path / "ca.txt"
        export_path.write_text(
            _ca_export_text([
                (1, "B00B0001", 21),
                (2, "B00B0002", 3),
                (3, "CA000001", 21),
                (4, "CA000002", 3),
            ])
        )

        result = _run_reconcile(store._db_path, export_path, use_json=True)

        assert result.returncode == 1
        body = json.loads(result.stdout)
        assert body["compared_serials"] == 4
        assert body["drift_count"] == 2
        assert set(body["in_sync"]) == {"B00B0001", "B00B0002"}
        assert body["revoked_at_ca_valid_in_ra"] == ["CA000001"]
        assert body["revoked_in_ra_active_at_ca"] == ["CA000002"]

    def test_tool_is_read_only(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_id, order_id = _create_account_and_order(store, 7)
        _insert_cert(store, order_id, account_id, "F00DBABE", revoked=True)
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(1, "F00DBABE", 21)]))

        before = _load_ra_state(store._db_path)
        result = _run_reconcile(store._db_path, export_path)
        after = _load_ra_state(store._db_path)

        assert result.returncode == 0
        assert before == after


class TestReconciliationExitCodes:
    def test_exit_code_zero_when_all_in_sync(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_id, order_id = _create_account_and_order(store, 8)
        _insert_cert(store, order_id, account_id, "BAD0C0DE", revoked=False)
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(1, "BAD0C0DE", 3)]))

        result = _run_reconcile(store._db_path, export_path)

        assert result.returncode == 0

    def test_exit_code_one_when_drift_present(
        self,
        store: Store,
        tmp_path: Path,
    ) -> None:
        account_id, order_id = _create_account_and_order(store, 9)
        _insert_cert(store, order_id, account_id, "C0FFEE00", revoked=True)
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(1, "C0FFEE00", 3)]))

        result = _run_reconcile(store._db_path, export_path)

        assert result.returncode == 1

    def test_exit_code_two_on_missing_db(
        self,
        tmp_path: Path,
    ) -> None:
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export_text([(1, "NOSUCHDB", 3)]))

        result = _run_reconcile(tmp_path / "does-not-exist.db", export_path)

        assert result.returncode == 2
        assert "ERROR:" in result.stderr
