"""Audit retention: the floor, the gates on deletion, and the footprint.

WI-014 part three. Parts one and two (``audit_bounds``, ``audit_coalesce``)
bounded growth without deleting anything; this is where deletion becomes
possible, so most of what is asserted here is that it *does not* happen.
"""

from __future__ import annotations

import base64
import datetime as dt
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acme_adcs_ra.audit_retention import (
    RETENTION_FLOOR_GRACE_DAYS,
    RetentionFloorError,
    assert_retention_above_floor,
    evaluate,
    footprint_report,
    retention_floor_days,
    run_sweep,
)
from acme_adcs_ra.store import Store


def _cert_pem(validity_days: int) -> str:
    """A self-signed certificate with a chosen validity, for the floor maths."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "floor.example")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=validity_days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


class _Config:
    """Only the fields the retention code reads."""

    def __init__(self, **kw: Any) -> None:
        self.audit_retention_days = kw.get("audit_retention_days", 0)
        self.audit_prune_enabled = kw.get("audit_prune_enabled", False)
        self.audit_offbox_required = kw.get("audit_offbox_required", False)
        self.audit_store_warn_mib = kw.get("audit_store_warn_mib", 1024)


class _Siem:
    def __init__(self, enabled: bool = True, healthy: bool = True) -> None:
        self.enabled = enabled
        self._healthy = healthy
        self.probes = 0

    def probe_offbox_delivery(self) -> tuple[bool, str]:
        self.probes += 1
        return (True, "healthy") if self._healthy else (False, "collector is dead")


def _jwk(idx: int) -> dict[str, Any]:
    # Canonical unpadded base64url, no leading zero octet -- jwk_thumbprint
    # enforces that. The store only needs these distinct, not real moduli.
    modulus = bytes([0x80]) + b"x" * 30 + bytes([idx])
    return {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(modulus).rstrip(b"=").decode("ascii"),
        "e": "AQAB",
    }


def _issue(store: Store, validity_days: int, idx: int = 1) -> None:
    account = store.create_account(jwk=_jwk(idx), eab_kid=f"kid-{idx:03d}")
    order = store.create_order_with_authz(
        account_id=account.id,
        identifiers=[{"type": "dns", "value": f"srv{idx}.example"}],
        challenge_url_fn=lambda cid: f"http://test/acme/chall/{cid}",
        authz_url_fn=lambda aid: f"http://test/acme/authz/{aid}",
        finalize_url_fn=lambda oid: f"http://test/acme/order/{oid}/finalize",
    )
    pem = _cert_pem(validity_days)
    store.create_certificate(
        order_id=order.id,
        account_id=account.id,
        cert_pem=pem,
        chain_pem=[pem],
        template="T",
        requester="r",
    )


def _store_with_cert_at(db: Path, validity_days: int) -> Store:
    store = Store(db)
    _issue(store, validity_days, idx=1)
    return store


def _store_with_cert(tmp_path: Path, validity_days: int) -> Store:
    return _store_with_cert_at(tmp_path / "ra.db", validity_days)


# ---------------------------------------------------------------------------
# The floor
# ---------------------------------------------------------------------------


class TestRetentionFloor:
    def test_floor_is_observed_validity_plus_grace(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        assert retention_floor_days(store) == 90 + RETENTION_FLOOR_GRACE_DAYS

    def test_floor_tracks_the_longest_certificate_not_the_latest(
        self, tmp_path: Path
    ) -> None:
        """A short-lived cert issued later must not lower the floor."""
        store = _store_with_cert(tmp_path, validity_days=90)
        _issue(store, validity_days=7, idx=2)
        assert retention_floor_days(store) == 90 + RETENTION_FLOOR_GRACE_DAYS

    def test_floor_is_unknown_with_no_certificates(self, tmp_path: Path) -> None:
        assert retention_floor_days(Store(tmp_path / "ra.db")) is None

    def test_floor_is_unknown_when_a_validity_could_not_be_derived(
        self, tmp_path: Path
    ) -> None:
        """Unknown must read as blocking, never as zero."""
        store = _store_with_cert(tmp_path, validity_days=30)
        with store._connect() as conn:  # simulate a row that predates the columns
            conn.execute("UPDATE certificates SET not_after = NULL")
        assert retention_floor_days(store) is None

    def test_startup_refuses_retention_below_the_floor(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        cfg = _Config(audit_retention_days=30)
        with pytest.raises(RetentionFloorError) as exc:
            assert_retention_above_floor(cfg, store)
        assert "below the floor" in str(exc.value)

    def test_startup_accepts_retention_at_the_floor(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        assert_retention_above_floor(
            _Config(audit_retention_days=90 + RETENTION_FLOOR_GRACE_DAYS), store
        )

    def test_zero_retention_is_never_below_the_floor(self, tmp_path: Path) -> None:
        """0 means keep everything, which cannot violate a minimum."""
        store = _store_with_cert(tmp_path, validity_days=3650)
        assert_retention_above_floor(_Config(audit_retention_days=0), store)

    def test_unknown_floor_does_not_block_startup(self, tmp_path: Path) -> None:
        """A corrupt historical PEM must not take the RA down; it blocks pruning."""
        store = _store_with_cert(tmp_path, validity_days=30)
        with store._connect() as conn:
            conn.execute("UPDATE certificates SET not_after = NULL")
        assert_retention_above_floor(_Config(audit_retention_days=1), store)


# ---------------------------------------------------------------------------
# The gates. Every one of these is a refusal to delete.
# ---------------------------------------------------------------------------


class TestPruneGates:
    def _ready(self, **kw: Any) -> _Config:
        base = {
            "audit_retention_days": 200,
            "audit_prune_enabled": True,
            "audit_offbox_required": True,
        }
        base.update(kw)
        return _Config(**base)

    def test_permitted_when_every_gate_is_satisfied(self, tmp_path: Path) -> None:
        """The control: without this passing, the refusals below prove nothing."""
        store = _store_with_cert(tmp_path, validity_days=90)
        decision = evaluate(self._ready(), store, _Siem())
        assert decision.may_prune is True
        assert decision.cutoff is not None

    def test_refuses_without_a_retention_window(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        d = evaluate(self._ready(audit_retention_days=0), store, _Siem())
        assert d.may_prune is False
        assert "no retention window" in d.reason

    def test_refuses_when_pruning_is_not_armed(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        d = evaluate(self._ready(audit_prune_enabled=False), store, _Siem())
        assert d.may_prune is False
        assert "not enforced" in d.reason

    def test_refuses_in_local_only_mode(self, tmp_path: Path) -> None:
        """The load-bearing gate: no off-box copy means no deletion, ever."""
        store = _store_with_cert(tmp_path, validity_days=90)
        d = evaluate(self._ready(audit_offbox_required=False), store, _Siem())
        assert d.may_prune is False
        assert "only copy" in d.reason

    def test_refuses_when_the_emitter_is_disabled(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        d = evaluate(self._ready(), store, _Siem(enabled=False))
        assert d.may_prune is False

    def test_refuses_when_offbox_delivery_is_unhealthy(self, tmp_path: Path) -> None:
        """Health is proven at sweep time, not assumed from configuration."""
        store = _store_with_cert(tmp_path, validity_days=90)
        siem = _Siem(healthy=False)
        d = evaluate(self._ready(), store, siem)
        assert d.may_prune is False
        assert "not currently healthy" in d.reason
        assert siem.probes == 1, "the sweep must actively probe, not trust config"

    def test_refuses_when_the_floor_is_unknown(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        with store._connect() as conn:
            conn.execute("UPDATE certificates SET not_after = NULL")
        d = evaluate(self._ready(), store, _Siem())
        assert d.may_prune is False
        assert "floor is unknown" in d.reason

    def test_refuses_when_retention_drifted_below_the_floor(
        self, tmp_path: Path
    ) -> None:
        """The floor is re-checked at sweep time, not only at startup.

        A longer certificate issued after start raises the floor under a
        running process, so the startup check alone is not sufficient.
        """
        store = _store_with_cert(tmp_path, validity_days=90)
        d = evaluate(self._ready(audit_retention_days=30), store, _Siem())
        assert d.may_prune is False
        assert "below the" in d.reason


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------


class TestSweep:
    def _aged_rows(self, store: Store, count: int, days_ago: int) -> None:
        stamp = (dt.datetime.now(dt.UTC) - dt.timedelta(days=days_ago)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        for i in range(count):
            store.record_audit(event_type="old", outcome="denied", details={"n": i})
        with store._connect() as conn:
            conn.execute("UPDATE audit_log SET timestamp = ? WHERE event_type = 'old'", (stamp,))

    def test_deletes_only_rows_older_than_the_window(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        self._aged_rows(store, 5, days_ago=400)
        store.record_audit(event_type="recent", outcome="success", details={})
        cfg = _Config(
            audit_retention_days=200, audit_prune_enabled=True, audit_offbox_required=True
        )
        deleted, decision = run_sweep(cfg, store, _Siem())
        assert decision.may_prune is True
        assert deleted == 5
        remaining = {e["event_type"] for e in store.list_audit_events(limit=100)}
        assert "old" not in remaining
        assert "recent" in remaining

    def test_sweep_audits_itself(self, tmp_path: Path) -> None:
        """A retention pass that leaves no trace looks like an attacker's cleanup."""
        store = _store_with_cert(tmp_path, validity_days=90)
        self._aged_rows(store, 3, days_ago=400)
        cfg = _Config(
            audit_retention_days=200, audit_prune_enabled=True, audit_offbox_required=True
        )
        run_sweep(cfg, store, _Siem())
        events = store.list_audit_events(limit=100)
        swept = [e for e in events if e["event_type"] == "audit-retention-swept"]
        assert len(swept) == 1
        assert swept[0]["details"]["rows_deleted"] == 3

    def test_refused_sweep_deletes_nothing(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        self._aged_rows(store, 4, days_ago=400)
        before = len(store.list_audit_events(limit=500))
        cfg = _Config(
            audit_retention_days=200,
            audit_prune_enabled=True,
            audit_offbox_required=False,  # local-only
        )
        deleted, decision = run_sweep(cfg, store, _Siem())
        assert deleted == 0
        assert decision.may_prune is False
        assert len(store.list_audit_events(limit=500)) == before


# ---------------------------------------------------------------------------
# Footprint
# ---------------------------------------------------------------------------


class TestFootprint:
    def test_reports_rows_span_and_bytes(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        for i in range(10):
            store.record_audit(event_type="e", outcome="success", details={"n": i})
        report = footprint_report(_Config(), store, jsonl_bytes=2048)
        assert report["rows"] >= 10
        assert report["oldest"] is not None and report["newest"] is not None
        assert report["db_bytes"] > 0
        assert report["total_bytes"] == report["db_bytes"] + 2048

    def test_flags_when_over_the_threshold(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        store.record_audit(event_type="e", outcome="success", details={})
        assert footprint_report(_Config(audit_store_warn_mib=1), store)["over_threshold"] is False
        big = footprint_report(_Config(audit_store_warn_mib=1), store, jsonl_bytes=8 * 1024 * 1024)
        assert big["over_threshold"] is True

    def test_zero_threshold_disables_the_warning(self, tmp_path: Path) -> None:
        store = _store_with_cert(tmp_path, validity_days=90)
        report = footprint_report(
            _Config(audit_store_warn_mib=0), store, jsonl_bytes=100 * 1024 * 1024
        )
        assert report["over_threshold"] is False


class TestValidityBackfill:
    """The migration path, which is what an existing deployment actually runs.

    Fresh-database tests never execute the backfill, so on their own they would
    prove nothing about an upgrade.
    """

    def test_backfills_validity_for_rows_that_predate_the_columns(
        self, tmp_path: Path
    ) -> None:
        db = tmp_path / "ra.db"
        store = _store_with_cert_at(db, validity_days=45)
        with store._connect() as conn:  # simulate rows written before the columns
            conn.execute("UPDATE certificates SET not_before = NULL, not_after = NULL")
        assert retention_floor_days(store) is None

        reopened = Store(db)  # re-running the migration is what an upgrade does
        assert retention_floor_days(reopened) == 45 + RETENTION_FLOOR_GRACE_DAYS

    def test_unparseable_pem_warns_but_does_not_refuse_startup(
        self, tmp_path: Path, caplog: Any
    ) -> None:
        """A corrupt historical row costs the deployment pruning, not uptime."""
        db = tmp_path / "ra.db"
        store = _store_with_cert_at(db, validity_days=45)
        with store._connect() as conn:
            conn.execute(
                "UPDATE certificates SET not_before = NULL, not_after = NULL, "
                "cert_pem = '-----BEGIN CERTIFICATE-----\nnope\n"
                "-----END CERTIFICATE-----'"
            )
        with caplog.at_level("WARNING", logger="acme_adcs_ra.store"):
            reopened = Store(db)  # must not raise
        assert "could not derive validity" in caplog.text
        # ...and the unknown must block pruning rather than read as zero.
        assert retention_floor_days(reopened) is None
        decision = evaluate(
            _Config(
                audit_retention_days=200,
                audit_prune_enabled=True,
                audit_offbox_required=True,
            ),
            reopened,
            _Siem(),
        )
        assert decision.may_prune is False
