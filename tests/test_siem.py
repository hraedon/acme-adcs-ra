"""Tests for SIEM audit emission (Phase 3)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.siem import SiemConfig, SiemEmitter, build_siem_config, default_jsonl_path
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import HandRolledAcmeClient


def _make_test_config(tmp_path: Path) -> RAConfig:
    mac_key_b64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[
            EABEntry(kid="kid-001", mac_key=mac_key_b64),
        ],
        san_scopes={
            "kid-001": {"dns_patterns": ["*.WORK-DOMAIN.local", "srv01.WORK-DOMAIN.local"]},
        },
        adcs_template="ACME-ServerAuth",
    )


def _eab_mac_key(config: RAConfig, kid: str) -> bytes:
    raw = config.eab_key_bytes(kid)
    assert raw is not None
    return raw


def _make_csr(sans: list[str]) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, sans[0])])
    san = x509.SubjectAlternativeName([x509.DNSName(name) for name in sans])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


def _make_app(config: RAConfig, audit_hook: Any = None) -> Any:
    store = Store(config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(config.eab_keys_by_kid().keys()),
        san_scopes={
            kid: scope.dns_patterns for kid, scope in config.san_scopes.items()
        },
        template=config.adcs_template,
    )
    context = ServerContext(
        config=config,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
        audit_hook=audit_hook,
    )
    return create_app(context)


# ---------------------------------------------------------------------------
# SiemEmitter unit behavior
# ---------------------------------------------------------------------------


class TestSiemEmitter:
    def test_jsonl_sink_appends_events(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        emitter = SiemEmitter(SiemConfig(sink="jsonl", jsonl_path=path))
        emitter.export({"event_type": "test", "outcome": "success"})
        emitter.close()

        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["event_type"] == "test"
        assert event["outcome"] == "success"
        assert event["schema_version"] == "acme-adcs-ra-audit/1"
        assert "instance" in event

    def test_export_is_fail_open(self, tmp_path: Path) -> None:
        # A path under a non-existent parent that cannot be created as a file.
        path = tmp_path / "not-a-dir" / "events.jsonl"
        path.mkdir(parents=True)
        emitter = SiemEmitter(SiemConfig(sink="jsonl", jsonl_path=path))
        # Should not raise even though *path* is a directory.
        emitter.export({"event_type": "test", "outcome": "success"})
        emitter.close()

    def test_disabled_when_no_config(self) -> None:
        emitter = SiemEmitter(SiemConfig(sink="syslog"))
        assert emitter.enabled is False
        # Export must be a no-op, not an error.
        emitter.export({"event_type": "test"})


# ---------------------------------------------------------------------------
# Default config wiring
# ---------------------------------------------------------------------------


class TestDefaultSiemWiring:
    def test_default_config_wires_jsonl_sink(self, tmp_path: Path) -> None:
        config = _make_test_config(tmp_path)
        config.siem_jsonl_path = None
        app = _make_app(config)
        assert app.state.context.audit_hook is not None

    def test_default_jsonl_path_derived_from_db(self, tmp_path: Path) -> None:
        db_path = tmp_path / "ra.db"
        assert default_jsonl_path(db_path) == tmp_path / "ra.siem.jsonl"

    def test_build_siem_config_reads_ra_config(self, tmp_path: Path) -> None:
        config = _make_test_config(tmp_path)
        siem_config = build_siem_config(config)
        assert siem_config.sink == "jsonl"
        assert siem_config.jsonl_path == tmp_path / "test_ra.siem.jsonl"
        assert siem_config.hec_token == ""


# ---------------------------------------------------------------------------
# Every audited event produces a SIEM event
# ---------------------------------------------------------------------------


class TestSiemAuditEvents:
    def test_account_created_emits_to_siem(
        self,
        tmp_path: Path,
    ) -> None:
        config = _make_test_config(tmp_path)
        client = TestClient(_make_app(config))
        account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        resp = ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        assert resp.status_code == 201

        lines = config.siem_jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        events = [json.loads(line) for line in lines]
        assert any(
            e["event_type"] == "account-created" and e["outcome"] == "success"
            for e in events
        )

    def test_order_created_and_certificate_issued_emit_to_siem(
        self,
        tmp_path: Path,
    ) -> None:
        config = _make_test_config(tmp_path)
        client = TestClient(_make_app(config))
        account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order_resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
        assert order_resp.status_code == 201
        order = order_resp.json()
        for authz_url in order["authorizations"]:
            authz = ac.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                ac.validate_challenge(challenge["url"])

        csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
        finalize_resp = ac.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200

        lines = config.siem_jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        events = [json.loads(line) for line in lines]
        assert any(e["event_type"] == "order-created" for e in events)
        assert any(
            e["event_type"] == "certificate-issued" and e["outcome"] == "success"
            for e in events
        )

        # Schema fields present on the issuance event.
        issued = next(e for e in events if e["event_type"] == "certificate-issued")
        assert issued["schema_version"] == "acme-adcs-ra-audit/1"
        assert "timestamp" in issued
        assert "account_id" in issued
        assert "order_id" in issued
        assert "sans" in issued
        assert "template" in issued
        assert "requester" in issued
        assert "outcome" in issued
        assert "details" in issued
        assert "instance" in issued

    def test_failing_siem_sink_does_not_abort_issuance(
        self,
        tmp_path: Path,
    ) -> None:
        config = _make_test_config(tmp_path)

        def exploding_hook(event: dict[str, Any]) -> None:
            raise RuntimeError("SIEM is down")

        client = TestClient(_make_app(config, audit_hook=exploding_hook))
        account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order_resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
        order = order_resp.json()
        for authz_url in order["authorizations"]:
            authz = ac.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                ac.validate_challenge(challenge["url"])

        csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
        finalize_resp = ac.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200
        assert finalize_resp.json()["status"] == "valid"


# ---------------------------------------------------------------------------
# C-2: SIEM startup probe
# ---------------------------------------------------------------------------


class TestSiemStartupProbe:
    def test_unwritable_jsonl_path_disables_emitter(self, tmp_path: Path) -> None:
        """C-2: An unwritable jsonl path sets enabled=False at init time."""
        # Create a directory where the jsonl file would be — open() will fail
        # with IsADirectoryError during the startup probe.
        path = tmp_path / "blocked" / "events.jsonl"
        path.mkdir(parents=True)
        emitter = SiemEmitter(SiemConfig(sink="jsonl", jsonl_path=path))
        assert emitter.enabled is False
        emitter.close()

    def test_unwritable_jsonl_path_logs_error(self, tmp_path: Path, caplog: Any) -> None:
        """C-2: An unwritable path causes an ERROR-level log."""
        path = tmp_path / "blocked" / "events.jsonl"
        path.mkdir(parents=True)
        with caplog.at_level(logging.ERROR, logger="acme_adcs_ra.siem"):
            emitter = SiemEmitter(SiemConfig(sink="jsonl", jsonl_path=path))
        assert any(
            "startup probe failed" in rec.message
            for rec in caplog.records
            if rec.levelno >= logging.ERROR
        )
        emitter.close()

    def test_unwritable_siem_still_allows_issuance(self, tmp_path: Path) -> None:
        """C-2: Fail-open — a broken SIEM sink does not abort issuance.
        The RA-store row is still written."""
        # Point SIEM at an unwritable path.
        unwritable = tmp_path / "no-access" / "dir-as-file"
        unwritable.mkdir(parents=True)
        config = _make_test_config(tmp_path)
        config.siem_jsonl_path = unwritable

        client = TestClient(_make_app(config))
        account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order_resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
        order = order_resp.json()
        for authz_url in order["authorizations"]:
            authz = ac.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                ac.validate_challenge(challenge["url"])

        csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
        finalize_resp = ac.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200

        # The RA-store row exists (fail-open — issuance proceeds).
        store = Store(config.db_path)
        account_id = ac.account_url.split("/")[-1]
        events = store.list_audit_events(account_id=account_id, event_type="certificate-issued")
        assert any(e["outcome"] == "success" for e in events)

    def test_hec_missing_url_disables(self, caplog: Any) -> None:
        """C-2: HEC sink with empty hec_url is disabled at init."""
        with caplog.at_level(logging.ERROR, logger="acme_adcs_ra.siem"):
            emitter = SiemEmitter(SiemConfig(sink="hec", hec_url="", hec_token="tok"))
        assert emitter.enabled is False
        emitter.close()

    def test_syslog_missing_host_disables(self, caplog: Any) -> None:
        """C-2: syslog sink with empty syslog_host is disabled at init."""
        with caplog.at_level(logging.ERROR, logger="acme_adcs_ra.siem"):
            emitter = SiemEmitter(SiemConfig(sink="syslog", syslog_host=""))
        assert emitter.enabled is False
