"""Regression tests for the 2026-08-13 security review findings.

Each test here was written against a *reproduced* defect: the behaviour it
asserts is the one that was missing, and every test in this file was confirmed
to fail against the pre-fix code. See docs/security-review-2026-08-13.md.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.crl_evidence import AGENT_ASSERTED, CRL_VERIFIED, CrlEvidence
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.siem import SiemConfig, SiemEmitter, build_siem_config
from acme_adcs_ra.store import CertStatus, Store

from .hand_rolled_acme_client import b64url_encode, jwk_from_private_key, sign_jws

STRONG_ADMIN_TOKEN = "test-admin-token-0123456789abcdef-32+"
STRONG_CONFIRM_TOKEN = "test-confirm-token-0123456789abcdef-32+"
# Decodes to exactly 32 bytes.
STRONG_MAC_KEY = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"


def _config(tmp_path: Path, **overrides: Any) -> RAConfig:
    overrides.setdefault("base_url", "http://testserver")
    overrides.setdefault("admin_token", SecretStr(STRONG_ADMIN_TOKEN))
    return RAConfig(
        db_path=tmp_path / "ra.db",
        siem_jsonl_path=tmp_path / "ra.siem.jsonl",
        **overrides,
    )


def _client(tmp_path: Path, **overrides: Any) -> TestClient:
    cfg = _config(tmp_path, **overrides)
    ctx = ServerContext(
        config=cfg,
        store=Store(cfg.db_path),
        policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    return TestClient(create_app(ctx), raise_server_exceptions=False)


def _new_account_body(client: TestClient, eab: Any) -> dict[str, Any]:
    """Build a signed newAccount JWS carrying the supplied EAB object."""
    nonce = client.head("/acme/new-nonce").headers["Replay-Nonce"]
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwk_from_private_key(key)
    return sign_jws(
        {"externalAccountBinding": eab},
        key,
        {
            "alg": "ES256",
            "nonce": nonce,
            "url": "http://testserver/acme/new-acct",
            "jwk": jwk,
        },
    )


def _post_jose(client: TestClient, path: str, body: dict[str, Any]) -> Any:
    return client.post(
        path,
        content=json.dumps(body),
        headers={"Content-Type": "application/jose+json"},
    )


# ---------------------------------------------------------------------------
# Finding 10 — malformed JWS/EAB member types must be 4xx, never 500
# ---------------------------------------------------------------------------


class TestMalformedJwsTypes:
    def test_eab_protected_header_that_is_a_json_array(self, tmp_path: Path) -> None:
        """A decoded EAB protected header that is not an object reached ``.get``."""
        client = _client(tmp_path)
        eab = {
            "protected": b64url_encode(json.dumps(["not", "an", "object"]).encode()),
            "payload": b64url_encode(b"{}"),
            "signature": b64url_encode(b"x" * 32),
        }
        resp = _post_jose(client, "/acme/new-acct", _new_account_body(client, eab))
        assert resp.status_code == 400
        assert resp.json()["type"].endswith("badExternalAccountBinding")

    def test_eab_members_that_are_not_strings(self, tmp_path: Path) -> None:
        client = _client(tmp_path)
        eab = {"protected": 42, "payload": {"a": 1}, "signature": None}
        resp = _post_jose(client, "/acme/new-acct", _new_account_body(client, eab))
        assert resp.status_code == 400

    def test_non_ascii_eab_payload_on_the_unknown_kid_path(
        self, tmp_path: Path
    ) -> None:
        """_dummy_hmac ASCII-encoded attacker input before any signature check."""
        client = _client(tmp_path)
        eab = {
            "protected": b64url_encode(
                json.dumps({"alg": "HS256", "kid": "no-such-kid"}).encode()
            ),
            "payload": "üüü",
            "signature": "abc",
        }
        resp = _post_jose(client, "/acme/new-acct", _new_account_body(client, eab))
        assert resp.status_code == 400

    @pytest.mark.parametrize("bad_nonce", [{"a": 1}, ["x"], 42])
    def test_non_string_nonce_is_bad_nonce_not_500(
        self, tmp_path: Path, bad_nonce: Any
    ) -> None:
        """A truthy non-string nonce reached SQLite parameter binding."""
        client = _client(tmp_path)
        key = ec.generate_private_key(ec.SECP256R1())
        jwk = jwk_from_private_key(key)
        body = sign_jws(
            {},
            key,
            {
                "alg": "ES256",
                "nonce": bad_nonce,
                "url": "http://testserver/acme/new-acct",
                "jwk": jwk,
            },
        )
        resp = _post_jose(client, "/acme/new-acct", body)
        assert resp.status_code == 400
        assert resp.json()["type"].endswith("badNonce")

    def test_store_rejects_a_non_string_nonce_defensively(
        self, tmp_path: Path
    ) -> None:
        store = Store(tmp_path / "ra.db")
        assert store.consume_nonce({"a": 1}) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Finding 7 — an invalid nonce must not take the SQLite write lock
# ---------------------------------------------------------------------------


def test_invalid_nonce_does_not_contend_for_the_write_lock(tmp_path: Path) -> None:
    """Rejecting a bogus nonce must be a read.

    Pre-fix, ``consume_nonce`` issued an unconditional DELETE, so a nonce that
    could not possibly match still queued behind the single writer: with a
    concurrent write transaction open it blocked for the full 5s busy_timeout
    and then raised "database is locked" (a 500, not a 400 badNonce).
    """
    db = tmp_path / "ra.db"
    store = Store(db)

    blocker = sqlite3.connect(str(db))
    blocker.execute("PRAGMA journal_mode=WAL")
    blocker.execute("BEGIN IMMEDIATE")
    blocker.execute(
        "INSERT INTO nonces (nonce, created_at) VALUES ('blk','2000-01-01T00:00:00Z')"
    )
    try:
        start = time.monotonic()
        assert store.consume_nonce("this-nonce-never-existed") is False
        elapsed = time.monotonic() - start
    finally:
        blocker.rollback()
        blocker.close()

    assert elapsed < 1.0, (
        f"rejecting an invalid nonce took {elapsed:.2f}s — it is contending "
        "for the SQLite write lock instead of failing on a read"
    )


def test_a_valid_nonce_is_still_single_use(tmp_path: Path) -> None:
    """The read fast path must not weaken replay protection."""
    store = Store(tmp_path / "ra.db")
    nonce = store.create_nonce()
    assert store.consume_nonce(nonce) is True
    assert store.consume_nonce(nonce) is False


# ---------------------------------------------------------------------------
# Finding 9 — credential strength floors
# ---------------------------------------------------------------------------


class TestCredentialStrength:
    def test_short_admin_token_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="admin_token is 1 characters"):
            _config(tmp_path, admin_token=SecretStr("x"))

    def test_short_eab_mac_key_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="decodes to 1 bytes"):
            _config(tmp_path, eab_allowlist=[{"kid": "k", "mac_key": "AQ"}])

    def test_empty_eab_mac_key_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="decodes to 0 bytes"):
            _config(tmp_path, eab_allowlist=[{"kid": "k", "mac_key": ""}])

    def test_non_base64url_eab_mac_key_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="not valid base64url"):
            _config(tmp_path, eab_allowlist=[{"kid": "k", "mac_key": "a"}])

    def test_short_confirm_token_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="revocation_confirm_token"):
            _config(tmp_path, revocation_confirm_token=SecretStr("short"))

    def test_strong_credentials_are_accepted(self, tmp_path: Path) -> None:
        cfg = _config(
            tmp_path, eab_allowlist=[{"kid": "k", "mac_key": STRONG_MAC_KEY}]
        )
        assert cfg.eab_key_bytes("k") is not None

    def test_the_opt_out_is_explicit(self, tmp_path: Path) -> None:
        """A lab may opt out, but only by saying so."""
        cfg = _config(
            tmp_path,
            admin_token=SecretStr("x"),
            eab_allowlist=[{"kid": "k", "mac_key": "AQ"}],
            allow_weak_credentials=True,
        )
        assert cfg.admin_token.get_secret_value() == "x"


# ---------------------------------------------------------------------------
# Finding 5 — required off-box audit must fail startup on a disabled emitter
# ---------------------------------------------------------------------------


class TestOffboxAuditGate:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"siem_sink": "hec", "siem_hec_url": "", "siem_hec_token": SecretStr("t")},
            {
                "siem_sink": "hec",
                "siem_hec_url": "https://hec.example/x",
                "siem_hec_token": SecretStr(""),
            },
            {
                # Not https — the emitter refuses to carry a token in clear.
                "siem_sink": "hec",
                "siem_hec_url": "http://hec.example/x",
                "siem_hec_token": SecretStr("t"),
            },
            {"siem_sink": "syslog", "siem_syslog_host": ""},
        ],
    )
    def test_startup_fails_when_the_required_emitter_is_disabled(
        self, tmp_path: Path, overrides: dict[str, Any]
    ) -> None:
        cfg = _config(tmp_path, audit_offbox_required=True, **overrides)
        assert SiemEmitter(build_siem_config(cfg)).enabled is False
        ctx = ServerContext(
            config=cfg,
            store=Store(cfg.db_path),
            policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        with pytest.raises(RuntimeError, match="audit_offbox_required"):
            create_app(ctx)

    def test_startup_succeeds_when_the_required_emitter_is_enabled(
        self, tmp_path: Path
    ) -> None:
        cfg = _config(
            tmp_path,
            audit_offbox_required=True,
            siem_sink="hec",
            siem_hec_url="https://hec.example/services/collector",
            siem_hec_token=SecretStr("hec-token"),
        )
        ctx = ServerContext(
            config=cfg,
            store=Store(cfg.db_path),
            policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        assert create_app(ctx) is not None


# ---------------------------------------------------------------------------
# Finding 2 — the HEC delivery queue must be bounded
# ---------------------------------------------------------------------------


class TestHecQueueBound:
    def test_queue_is_bounded_and_drops_are_counted(self) -> None:
        """A dead HEC endpoint must not let audit events accumulate forever.

        The workers are pinned with an explicit barrier rather than by pointing
        at an unresolvable host. Relying on ``.invalid`` to *stall* was flaky:
        a resolver that returns NXDOMAIN quickly lets workers drain, so more
        than ``hec_queue_max`` events get accepted and the drop count comes in
        under what the test expected. Blocking the workers outright makes the
        bound exact and the assertion meaningful on any machine.
        """
        import threading

        release = threading.Event()
        emitter = SiemEmitter(
            SiemConfig(
                sink="hec",
                hec_url="https://hec.invalid/services/collector",
                hec_token="tok",
                hec_queue_max=25,
            )
        )
        # Pin every worker so nothing can leave the queue during the probe.
        emitter._hec_post_inner = lambda event: release.wait(30)  # type: ignore[method-assign]
        try:
            assert emitter.enabled
            for i in range(2000):
                emitter.export({"event_type": "probe", "n": i})
            # The bound holds exactly, and everything past it is counted.
            assert emitter._hec_inflight <= 25
            assert emitter.hec_dropped == 2000 - 25
        finally:
            release.set()
            emitter.close()

    def test_local_audit_row_survives_hec_backpressure(self, tmp_path: Path) -> None:
        """Dropping is from the HEC sink only; the durable trail is the table."""
        cfg = _config(
            tmp_path,
            siem_sink="hec",
            siem_hec_url="https://hec.invalid/services/collector",
            siem_hec_token=SecretStr("tok"),
            siem_hec_queue_max=1,
        )
        store = Store(cfg.db_path)
        ctx = ServerContext(
            config=cfg,
            store=store,
            policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        client = TestClient(create_app(ctx), raise_server_exceptions=False)
        for _ in range(20):
            client.request(
                "DELETE",
                "/acme/admin/nonces",
                headers={"Authorization": f"Bearer {STRONG_ADMIN_TOKEN}"},
            )
        events = store.list_audit_events(event_type="admin-nonce-cleanup", limit=50)
        assert len(events) == 20


# ---------------------------------------------------------------------------
# Finding 3 — issuance and its audit row commit together
# ---------------------------------------------------------------------------


def test_issuance_and_its_audit_row_are_atomic(tmp_path: Path) -> None:
    """A certificate row must never exist without its issuance audit event.

    Pre-fix the two were separate commits, so injecting a failure between them
    left one certificate row and zero ``certificate-issued`` events.
    """
    store = Store(tmp_path / "ra.db")
    account = store.create_account(
        jwk={"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
        eab_kid="k",
        status="valid",
        contact=[],
    )
    order = store.create_order_with_authz(
        account_id=account.id,
        identifiers=[{"type": "dns", "value": "a.example.com"}],
        challenge_url_fn=lambda i: f"http://t/acme/challenge/{i}",
        authz_url_fn=lambda i: f"http://t/acme/authz/{i}",
        finalize_url_fn=lambda i: f"http://t/acme/finalize/{i}",
    )
    store.transition_pending_to_ready(order.id)
    store.transition_order_to_processing(order.id)

    from importlib import resources

    cert_pem = (
        resources.files("acme_adcs_ra.fixtures").joinpath("fake_cert.pem").read_text()
    )

    record, applied, event = store.record_issuance(
        order_id=order.id,
        account_id=account.id,
        cert_pem=cert_pem,
        chain_pem=[],
        template="ACME-ServerAuth",
        requester="CONTOSO\\gMSA-acme-ra$",
        metadata={"req_id": "77"},
        certificate_url_fn=lambda cid: f"http://t/acme/cert/{cid}",
        sans=["a.example.com"],
        csr_subject="CN=a.example.com",
    )
    assert applied is True
    assert event["event_type"] == "certificate-issued"

    certs = store._connect().execute("SELECT id FROM certificates").fetchall()
    issued = store.list_audit_events(event_type="certificate-issued")
    assert len(certs) == 1
    assert len(issued) == 1
    assert issued[0]["details"]["certificate_id"] == record.id
    # The serial is on the issuance event, not only on the certificate row.
    assert issued[0]["details"]["serial"] == record.serial_number


def test_a_failed_audit_write_rolls_back_the_certificate_row(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The atomicity claim, tested the only way that proves it: inject a fault."""
    store = Store(tmp_path / "ra.db")
    account = store.create_account(
        jwk={"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
        eab_kid="k",
        status="valid",
        contact=[],
    )
    order = store.create_order_with_authz(
        account_id=account.id,
        identifiers=[{"type": "dns", "value": "a.example.com"}],
        challenge_url_fn=lambda i: f"http://t/acme/challenge/{i}",
        authz_url_fn=lambda i: f"http://t/acme/authz/{i}",
        finalize_url_fn=lambda i: f"http://t/acme/finalize/{i}",
    )
    store.transition_pending_to_ready(order.id)
    store.transition_order_to_processing(order.id)

    from importlib import resources

    cert_pem = (
        resources.files("acme_adcs_ra.fixtures").joinpath("fake_cert.pem").read_text()
    )

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated crash writing the audit row")

    monkeypatch.setattr(store, "_record_audit_in_conn", boom)

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.record_issuance(
            order_id=order.id,
            account_id=account.id,
            cert_pem=cert_pem,
            chain_pem=[],
            template="ACME-ServerAuth",
            requester="CONTOSO\\gMSA-acme-ra$",
            metadata={},
            certificate_url_fn=lambda cid: f"http://t/acme/cert/{cid}",
            sans=["a.example.com"],
            csr_subject="CN=a.example.com",
        )

    certs = store._connect().execute("SELECT id FROM certificates").fetchall()
    assert certs == [], (
        "the certificate row was committed without its issuance audit row"
    )
    assert store.get_order(order.id).status == "processing"  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Finding 1 — CA revocation confirmations
# ---------------------------------------------------------------------------


def _revoked_cert(store: Store, status: str = CertStatus.REVOKED) -> Any:
    from importlib import resources

    cert_pem = (
        resources.files("acme_adcs_ra.fixtures").joinpath("fake_cert.pem").read_text()
    )
    account = store.create_account(
        jwk={"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
        eab_kid="k",
        status="valid",
        contact=[],
    )
    order = store.create_order_with_authz(
        account_id=account.id,
        identifiers=[{"type": "dns", "value": "a.example.com"}],
        challenge_url_fn=lambda i: f"http://t/acme/challenge/{i}",
        authz_url_fn=lambda i: f"http://t/acme/authz/{i}",
        finalize_url_fn=lambda i: f"http://t/acme/finalize/{i}",
    )
    record = store.create_certificate(
        order_id=order.id,
        account_id=account.id,
        cert_pem=cert_pem,
        chain_pem=[],
        template="ACME-ServerAuth",
        requester="CONTOSO\\gMSA-acme-ra$",
        metadata={"req_id": "42"},
    )
    if status == CertStatus.REVOKED:
        store.revoke_certificate(record.id, reason=1)
    return record


class TestRevocationConfirmAuthority:
    def test_the_general_admin_token_cannot_confirm(self, tmp_path: Path) -> None:
        """The core of finding 1: maintenance authority != revoker authority."""
        client = _client(
            tmp_path, revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN)
        )
        store = client.app.state.context.store  # type: ignore[attr-defined]
        cert = _revoked_cert(store)
        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": f"Bearer {STRONG_ADMIN_TOKEN}"},
        )
        assert resp.status_code == 401
        # And the serial is still on the pending list — not silently drained.
        assert len(store.list_revoked_certificates()) == 1

    def test_the_confirm_token_works(self, tmp_path: Path) -> None:
        client = _client(
            tmp_path, revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN)
        )
        store = client.app.state.context.store  # type: ignore[attr-defined]
        cert = _revoked_cert(store)
        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": f"Bearer {STRONG_CONFIRM_TOKEN}"},
        )
        assert resp.status_code == 200
        assert store.list_revoked_certificates() == []

    def test_confirm_is_disabled_when_no_confirm_token_is_configured(
        self, tmp_path: Path
    ) -> None:
        """Fail closed: an unset credential disables the endpoint."""
        client = _client(tmp_path)
        store = client.app.state.context.store  # type: ignore[attr-defined]
        cert = _revoked_cert(store)
        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": f"Bearer {STRONG_ADMIN_TOKEN}"},
        )
        assert resp.status_code == 401
        assert len(store.list_revoked_certificates()) == 1

    def test_an_unverified_confirmation_is_labelled_agent_asserted(
        self, tmp_path: Path
    ) -> None:
        """The audit trail must not claim the RA observed the CA revoke."""
        client = _client(
            tmp_path, revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN)
        )
        store = client.app.state.context.store  # type: ignore[attr-defined]
        cert = _revoked_cert(store)
        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": f"Bearer {STRONG_CONFIRM_TOKEN}"},
        )
        assert resp.json()["verification"] == AGENT_ASSERTED
        event = store.list_audit_events(event_type="revocation-ca-confirmed")[0]
        assert event["details"]["verification"] == AGENT_ASSERTED

    def test_required_crl_evidence_refuses_an_unproven_confirmation(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        client = _client(
            tmp_path,
            revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN),
            revocation_confirm_crl_url="http://crl.invalid/ca.crl",
            revocation_confirm_require_crl_evidence=True,
        )
        store = client.app.state.context.store  # type: ignore[attr-defined]
        cert = _revoked_cert(store)
        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": f"Bearer {STRONG_CONFIRM_TOKEN}"},
        )
        assert resp.status_code == 400
        assert "CRL evidence is required" in resp.json()["detail"]
        # Still pending: an unproven claim must not drain the queue.
        assert len(store.list_revoked_certificates()) == 1
        denied = store.list_audit_events(
            event_type="admin-revocation-confirm-denied"
        )
        assert denied[0]["details"]["reason"] == "crl-evidence-required-but-absent"

    def test_crl_verified_confirmation_is_labelled_as_such(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        client = _client(
            tmp_path,
            revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN),
            revocation_confirm_crl_url="http://crl.example/ca.crl",
            revocation_confirm_require_crl_evidence=True,
        )
        store = client.app.state.context.store  # type: ignore[attr-defined]
        cert = _revoked_cert(store)

        monkeypatch.setattr(
            "acme_adcs_ra.routes.admin.fetch_crl_evidence",
            lambda **_kw: CrlEvidence(
                revoked=True,
                checked=True,
                detail="serial is listed on the CRL",
                crl_number="12",
            ),
        )
        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": f"Bearer {STRONG_CONFIRM_TOKEN}"},
        )
        assert resp.status_code == 200
        assert resp.json()["verification"] == CRL_VERIFIED
        event = store.list_audit_events(event_type="revocation-ca-confirmed")[0]
        assert event["details"]["verification"] == CRL_VERIFIED
        assert event["details"]["crl_number"] == "12"

    def test_requiring_evidence_without_a_crl_url_is_a_config_error(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ValidationError, match="revocation_confirm_crl_url"):
            _config(tmp_path, revocation_confirm_require_crl_evidence=True)


class TestCrlEvidenceSemantics:
    def test_unchecked_evidence_is_never_crl_verified(self) -> None:
        assert (
            CrlEvidence(revoked=False, checked=False, detail="x").verification
            == AGENT_ASSERTED
        )

    def test_checked_but_absent_serial_is_not_crl_verified(self) -> None:
        """A CRL that does NOT list the serial is not proof of revocation."""
        assert (
            CrlEvidence(revoked=False, checked=True, detail="x").verification
            == AGENT_ASSERTED
        )

    def test_checked_and_listed_is_crl_verified(self) -> None:
        assert (
            CrlEvidence(revoked=True, checked=True, detail="x").verification
            == CRL_VERIFIED
        )

    def test_a_non_http_crl_url_is_refused_without_a_fetch(self) -> None:
        from acme_adcs_ra.crl_evidence import fetch_crl_evidence

        evidence = fetch_crl_evidence(
            crl_url="file:///etc/passwd",
            serial_number=1,
            cert_pem="",
            chain_pem=[],
        )
        assert evidence.checked is False
        assert "http(s)" in evidence.detail


# ---------------------------------------------------------------------------
# Finding 6 — quarantined certificates are never servable
# ---------------------------------------------------------------------------


class TestQuarantineIsNotServable:
    def _quarantined(self, tmp_path: Path) -> tuple[Store, Any]:
        from importlib import resources

        store = Store(tmp_path / "ra.db")
        cert_pem = (
            resources.files("acme_adcs_ra.fixtures")
            .joinpath("fake_cert.pem")
            .read_text()
        )
        account = store.create_account(
            jwk={"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
            eab_kid="k",
            status="valid",
            contact=[],
        )
        order = store.create_order_with_authz(
            account_id=account.id,
            identifiers=[{"type": "dns", "value": "a.example.com"}],
            challenge_url_fn=lambda i: f"http://t/acme/challenge/{i}",
            authz_url_fn=lambda i: f"http://t/acme/authz/{i}",
            finalize_url_fn=lambda i: f"http://t/acme/finalize/{i}",
        )
        store.transition_pending_to_ready(order.id)
        store.transition_order_to_processing(order.id)
        record, _event = store.quarantine_certificate(
            order_id=order.id,
            account_id=account.id,
            cert_pem=cert_pem,
            chain_pem=[],
            template="ACME-ServerAuth",
            requester="CONTOSO\\gMSA-acme-ra$",
            metadata={"req_id": "99"},
            event_type="finalize-issued-cert-eku-mismatch",
            violations=["clientAuth (1.3.6.1.5.5.7.3.2)"],
            reason="not serverAuth-only",
            sans=["a.example.com"],
        )
        return store, record

    def test_quarantined_cert_is_not_returned_as_the_order_certificate(
        self, tmp_path: Path
    ) -> None:
        """A retried finalize must not be able to pick it up and serve it."""
        store, record = self._quarantined(tmp_path)
        assert store.get_certificate_by_order(record.order_id) is None

    def test_quarantine_makes_the_order_terminal(self, tmp_path: Path) -> None:
        store, record = self._quarantined(tmp_path)
        assert store.get_order(record.order_id).status == "invalid"  # type: ignore[union-attr]

    def test_quarantined_cert_is_queued_for_ca_side_revocation(
        self, tmp_path: Path
    ) -> None:
        store, record = self._quarantined(tmp_path)
        pending = store.list_revoked_certificates()
        assert [c.serial_number for c in pending] == [record.serial_number]
        assert pending[0].status == CertStatus.QUARANTINED

    def test_the_http_certificate_route_refuses_to_serve_it(
        self, tmp_path: Path
    ) -> None:
        store, record = self._quarantined(tmp_path)
        cfg = _config(tmp_path)
        ctx = ServerContext(
            config=cfg,
            store=store,
            policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        client = TestClient(create_app(ctx), raise_server_exceptions=False)
        # The plain unauthenticated GET form was removed (2026-08-15 review,
        # finding 4), so there is no unauthenticated path a quarantined cert
        # could leak through: only POST is registered, so a GET is 405. The
        # quarantine→410 refusal itself lives on the account-scoped POST-as-GET
        # path (_certificate_response, shared by both).
        resp = client.get(f"/acme/cert/{record.id}")
        assert resp.status_code == 405

    def test_confirming_a_quarantined_serial_clears_it(self, tmp_path: Path) -> None:
        """The quarantine drains through the normal pull-agent loop."""
        store, record = self._quarantined(tmp_path)
        cfg = _config(
            tmp_path, revocation_confirm_token=SecretStr(STRONG_CONFIRM_TOKEN)
        )
        ctx = ServerContext(
            config=cfg,
            store=store,
            policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        client = TestClient(create_app(ctx), raise_server_exceptions=False)
        resp = client.post(
            f"/acme/admin/revocations/{record.serial_number}/confirm",
            headers={"Authorization": f"Bearer {STRONG_CONFIRM_TOKEN}"},
        )
        assert resp.status_code == 200
        assert store.list_revoked_certificates() == []

    def test_the_pending_list_distinguishes_quarantine_from_revocation(
        self, tmp_path: Path
    ) -> None:
        store, _record = self._quarantined(tmp_path)
        cfg = _config(tmp_path)
        ctx = ServerContext(
            config=cfg,
            store=store,
            policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        client = TestClient(create_app(ctx), raise_server_exceptions=False)
        resp = client.get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": f"Bearer {STRONG_ADMIN_TOKEN}"},
        )
        entry = resp.json()["pending_revocations"][0]
        assert entry["status"] == CertStatus.QUARANTINED
        assert entry["req_id"] == "99"


# ---------------------------------------------------------------------------
# Finding 1 — the CRL evidence path against real, signed CRLs
# ---------------------------------------------------------------------------


class TestCrlEvidenceAgainstRealCrls:
    """Exercise ``fetch_crl_evidence`` end-to-end over real HTTP.

    The CRL check is the only part of the confirmation path that can turn an
    agent's claim into evidence, so it is tested against genuinely signed CRLs
    served by a real socket — not by stubbing the parser. These are synthetic
    CAs, not ADCS: see the proof gaps in docs/security-review-2026-08-13.md.
    """

    @staticmethod
    def _fixture() -> Any:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        now = datetime.datetime.now(datetime.UTC)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "CONTOSO-CA01-CA")]
        )
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_serial = 0x1A2B3C4D
        leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv01.example")])
            )
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(leaf_serial)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(ca_key, hashes.SHA256())
        )

        def build_crl(
            serials: list[int],
            *,
            next_update_days: int = 7,
            crl_number: int = 12,
            signer: Any = ca_key,
        ) -> bytes:
            last = now - datetime.timedelta(minutes=5)
            nxt = now + datetime.timedelta(days=next_update_days)
            if nxt <= last:
                last = nxt - datetime.timedelta(days=1)
            builder = (
                x509.CertificateRevocationListBuilder()
                .issuer_name(ca_name)
                .last_update(last)
                .next_update(nxt)
                .add_extension(x509.CRLNumber(crl_number), critical=False)
            )
            for s in serials:
                builder = builder.add_revoked_certificate(
                    x509.RevokedCertificateBuilder()
                    .serial_number(s)
                    .revocation_date(last)
                    .build()
                )
            return builder.sign(signer, hashes.SHA256()).public_bytes(
                serialization.Encoding.DER
            )

        return {
            "leaf_pem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
            "chain": [ca_cert.public_bytes(serialization.Encoding.PEM).decode()],
            "serial": leaf_serial,
            "build_crl": build_crl,
            "other_key": rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            ),
            "pem_of": lambda der: x509.load_der_x509_crl(der).public_bytes(
                serialization.Encoding.PEM
            ),
        }

    @staticmethod
    def _serve(body: bytes) -> Any:
        """Serve one body over loopback HTTP; returns (url, shutdown)."""
        import http.server
        import threading

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
        return f"http://127.0.0.1:{server.server_address[1]}/ca.crl", server.shutdown

    def _check(self, body: bytes, **overrides: Any) -> Any:
        from acme_adcs_ra.crl_evidence import fetch_crl_evidence

        fx = overrides.pop("fixture")
        url, shutdown = self._serve(body)
        try:
            return fetch_crl_evidence(
                crl_url=url,
                serial_number=overrides.get("serial", fx["serial"]),
                cert_pem=overrides.get("cert_pem", fx["leaf_pem"]),
                chain_pem=overrides.get("chain_pem", fx["chain"]),
            )
        finally:
            shutdown()

    def test_der_crl_listing_the_serial_is_evidence(self) -> None:
        fx = self._fixture()
        ev = self._check(fx["build_crl"]([fx["serial"]]), fixture=fx)
        assert (ev.revoked, ev.checked) == (True, True)
        assert ev.verification == CRL_VERIFIED
        assert ev.crl_number == "12"

    def test_pem_crl_is_also_accepted(self) -> None:
        fx = self._fixture()
        der = fx["build_crl"]([fx["serial"]])
        ev = self._check(fx["pem_of"](der), fixture=fx)
        assert ev.verification == CRL_VERIFIED

    def test_a_crl_not_listing_the_serial_is_not_evidence(self) -> None:
        """The check ran and said 'no' — that must not confirm a revocation."""
        fx = self._fixture()
        ev = self._check(fx["build_crl"]([0x999]), fixture=fx)
        assert (ev.revoked, ev.checked) == (False, True)
        assert ev.verification == AGENT_ASSERTED

    def test_an_expired_crl_is_not_evidence(self) -> None:
        """A stale CRL is exactly what a suppressed revocation looks like."""
        fx = self._fixture()
        ev = self._check(
            fx["build_crl"]([fx["serial"]], next_update_days=-1), fixture=fx
        )
        assert ev.checked is False
        assert "expired" in ev.detail

    def test_a_crl_signed_by_the_wrong_key_is_not_evidence(self) -> None:
        fx = self._fixture()
        ev = self._check(
            fx["build_crl"]([fx["serial"]], signer=fx["other_key"]), fixture=fx
        )
        assert ev.checked is False
        assert "signature does not verify" in ev.detail

    def test_without_the_issuer_in_the_chain_nothing_can_be_verified(self) -> None:
        fx = self._fixture()
        ev = self._check(fx["build_crl"]([fx["serial"]]), fixture=fx, chain_pem=[])
        assert ev.checked is False
        assert "issuing CA certificate" in ev.detail

    def test_a_garbage_body_is_not_evidence(self) -> None:
        fx = self._fixture()
        ev = self._check(b"not a crl at all", fixture=fx)
        assert ev.checked is False
        assert "neither valid DER nor PEM" in ev.detail
