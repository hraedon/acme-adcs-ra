"""Tests for revokeCert passthrough (RFC 8555 §7.6)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import (
    CertsrvRevocationLeg,
    FakeRevocationLeg,
    RevocationLeg,
    RevocationResult,
)
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import HandRolledAcmeClient


def _make_test_config(tmp_path: Any) -> RAConfig:
    mac_key_b64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[
            EABEntry(kid="kid-001", mac_key=mac_key_b64),
            EABEntry(kid="kid-002", mac_key="YW5vdGhlci0zMi1ieXRlLW1hYy1rZXktZm9yLXRlc3Rz"),
        ],
        san_scopes={
            "kid-001": {"dns_patterns": ["*.WORK-DOMAIN.local", "srv01.WORK-DOMAIN.local"]},
            "kid-002": {"dns_patterns": ["*.prod.WORK-DOMAIN.local"]},
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


def _issue_cert(
    client: TestClient,
    config: RAConfig,
    account_key: rsa.RSAPrivateKey,
    kid: str = "kid-001",
) -> tuple[HandRolledAcmeClient, bytes]:
    """Return an ACME client and the DER bytes of the issued certificate."""
    ac = HandRolledAcmeClient(client, config.base_url, account_key)
    resp = ac.new_account(kid, _eab_mac_key(config, kid))
    assert resp.status_code == 201

    resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
    assert resp.status_code == 201
    order = resp.json()
    for authz_url in order["authorizations"]:
        authz = ac.get_authorization(authz_url).json()
        for challenge in authz["challenges"]:
            assert ac.validate_challenge(challenge["url"]).status_code == 200

    csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
    resp = ac.finalize_order(order["finalize"], csr_der)
    assert resp.status_code == 200
    finalized = resp.json()
    cert_resp = ac.get_certificate(finalized["certificate"])
    assert cert_resp.status_code == 200

    # Extract the first certificate DER from the PEM-chain response.
    first_pem = cert_resp.text.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----"
    cert_der = x509.load_pem_x509_certificate(first_pem.encode("utf-8")).public_bytes(
        serialization.Encoding.DER
    )
    return ac, cert_der


@pytest.fixture()
def test_config(tmp_path: Any) -> RAConfig:
    return _make_test_config(tmp_path)


@pytest.fixture()
def app(test_config: RAConfig) -> Any:
    store = Store(test_config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(test_config.eab_keys_by_kid().keys()),
        san_scopes={
            kid: scope.dns_patterns for kid, scope in test_config.san_scopes.items()
        },
        template=test_config.adcs_template,
    )
    context = ServerContext(
        config=test_config,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    return create_app(context)


@pytest.fixture()
def client(app: Any) -> TestClient:
    return TestClient(app)


@pytest.fixture()
def account_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ---------------------------------------------------------------------------
# Authorization and basic behavior
# ---------------------------------------------------------------------------


class TestRevokeCertAuthorization:
    def test_issuing_account_can_revoke(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_different_account_cannot_revoke(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """C-1: a different account gets 404 (not 401) when trying to revoke
        a cert it doesn't own — no information leak about ownership."""
        ac1, cert_der = _issue_cert(client, test_config, account_key, kid="kid-001")

        # Create a second account on the same server.
        account_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac2 = HandRolledAcmeClient(client, test_config.base_url, account_key2)
        resp = ac2.new_account("kid-002", _eab_mac_key(test_config, "kid-002"))
        assert resp.status_code == 201

        resp = ac2.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 404
        assert resp.json()["type"] == "urn:ietf:params:acme:error:notFound"

    def test_unknown_cert_returns_not_found(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac = HandRolledAcmeClient(client, test_config.base_url, account_key)
        ac.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))

        # A self-signed cert that was never issued by the RA.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime_now())
            .not_valid_after(datetime_now(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 404
        assert resp.json()["type"] == "urn:ietf:params:acme:error:notFound"

    def test_already_revoked_returns_200_ok(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """H-4: RFC 8555 §7.6 — re-revoking an already-revoked cert returns 200 OK."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        assert ac.revoke_certificate(cert_der, reason=0).status_code == 200
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Reason-code validation
# ---------------------------------------------------------------------------


class TestRevokeCertReasonValidation:
    @pytest.mark.parametrize("reason", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    def test_valid_reason_codes_accepted(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
        reason: int,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=reason)
        assert resp.status_code == 200

    @pytest.mark.parametrize("reason", [-1, 11, 128, "not-an-int"])
    def test_invalid_reason_codes_rejected(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
        reason: Any,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=reason)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badRevocationReason"


# ---------------------------------------------------------------------------
# Store + audit + SIEM
# ---------------------------------------------------------------------------


class TestRevokeCertStoreAndAudit:
    def test_store_reflects_revoked_status(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        resp = ac.revoke_certificate(cert_der, reason=1)
        assert resp.status_code == 200

        store = Store(test_config.db_path)
        record = store.get_certificate_by_serial(serial_hex)
        assert record is not None
        assert record.status == "revoked"
        assert record.revocation_reason == 1
        assert record.revoked_at is not None

    def test_revocation_produces_audit_and_siem_event(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200

        # Audit row
        account_id = ac.account_url.split("/")[-1]
        store = Store(test_config.db_path)
        events = store.list_audit_events(account_id=account_id, event_type="certificate-revoked")
        assert any(
            e["event_type"] == "certificate-revoked"
            and e["outcome"] == "success"
            and e["details"].get("serial") == serial_hex
            for e in events
        )

        # SIEM event
        siem_lines = test_config.siem_jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        siem_events = [json.loads(line) for line in siem_lines]
        assert any(
            e.get("event_type") == "certificate-revoked"
            and e.get("outcome") == "success"
            and e.get("details", {}).get("serial") == serial_hex
            and e.get("schema_version") == "acme-adcs-ra-audit/1"
            for e in siem_events
        )


# ---------------------------------------------------------------------------
# RevocationLeg protocol and platform-gated stub
# ---------------------------------------------------------------------------


class TestRevocationLeg:
    def test_fake_leg_returns_revoked_result(self) -> None:
        leg: RevocationLeg = FakeRevocationLeg()
        result = leg.revoke("pem", reason=1)
        assert isinstance(result, RevocationResult)
        assert result.revoked is True
        assert result.reason == 1
        assert result.revoked_at is not None

    def test_certsrv_stub_raises_not_implemented(self) -> None:
        leg = CertsrvRevocationLeg()
        with pytest.raises(NotImplementedError):
            leg.revoke("pem", reason=0)


# ---------------------------------------------------------------------------
# C-1: serial-scoped revocation lookup (no cross-account serial collision)
# ---------------------------------------------------------------------------


class TestSerialCollisionSafety:
    def test_accounts_with_same_serial_isolated(self, test_config: RAConfig, account_key: rsa.RSAPrivateKey) -> None:
        """C-1: Two accounts each issue a cert (both share the FakeEnrollmentLeg
        static serial).  Revocation by one account never touches the other's row.

        With the old (unscoped) serial lookup, fetchone() could return A's row
        when B requests revocation, silently revoking A's cert.  The scoped
        lookup (serial_number, account_id) prevents this.
        """
        store = Store(test_config.db_path)
        policy = IssuancePolicy(
            allowed_kids=set(test_config.eab_keys_by_kid().keys()),
            san_scopes={
                kid: scope.dns_patterns for kid, scope in test_config.san_scopes.items()
            },
            template=test_config.adcs_template,
        )
        context = ServerContext(
            config=test_config,
            store=store,
            policy=policy,
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        client = TestClient(create_app(context))

        # Account A issues a cert (kid-001).
        ac_a = HandRolledAcmeClient(client, test_config.base_url, account_key)
        resp_a = ac_a.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert resp_a.status_code == 201
        order_a = ac_a.new_order(["srv01.WORK-DOMAIN.local"]).json()
        for authz_url in order_a["authorizations"]:
            authz = ac_a.get_authorization(authz_url).json()
            for ch in authz["challenges"]:
                ac_a.validate_challenge(ch["url"])
        csr_der_a = _make_csr(["srv01.WORK-DOMAIN.local"])
        fin_a = ac_a.finalize_order(order_a["finalize"], csr_der_a)
        assert fin_a.status_code == 200
        cert_url_a = fin_a.json()["certificate"]
        # Extract DER for the cert to use in revocation.
        cert_pem_a = ac_a.get_certificate(cert_url_a).text
        first_pem = cert_pem_a.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----"
        cert_der = x509.load_pem_x509_certificate(first_pem.encode("utf-8")).public_bytes(
            serialization.Encoding.DER
        )

        # Account B issues a cert (kid-002) — same static serial from FakeEnrollmentLeg.
        key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac_b = HandRolledAcmeClient(client, test_config.base_url, key_b)
        resp_b = ac_b.new_account("kid-002", _eab_mac_key(test_config, "kid-002"))
        assert resp_b.status_code == 201
        order_b = ac_b.new_order(["web.prod.WORK-DOMAIN.local"]).json()
        for authz_url in order_b["authorizations"]:
            authz = ac_b.get_authorization(authz_url).json()
            for ch in authz["challenges"]:
                ac_b.validate_challenge(ch["url"])
        csr_der_b = _make_csr(["web.prod.WORK-DOMAIN.local"])
        fin_b = ac_b.finalize_order(order_b["finalize"], csr_der_b)
        assert fin_b.status_code == 200

        # (a) Account B revokes using the shared cert DER — should succeed
        #     (scoped to B's cert row, not A's).
        resp_revoke_b = ac_b.revoke_certificate(cert_der, reason=0)
        assert resp_revoke_b.status_code == 200

        # (b) Account A's cert is still valid in the store.
        cert_id_a = cert_url_a.rsplit("/", 1)[-1]
        cert_a_record = store.get_certificate(cert_id_a)
        assert cert_a_record is not None
        assert cert_a_record.status == "valid"

        # (c) A second revocation by B returns 200 (already revoked, H-4)
        #     but crucially does NOT revoke A's cert.
        resp_revoke_b2 = ac_b.revoke_certificate(cert_der, reason=0)
        assert resp_revoke_b2.status_code == 200  # already-revoked is idempotent

        # A's cert is STILL valid — the old bug would have revoked it.
        cert_a_record2 = store.get_certificate(cert_id_a)
        assert cert_a_record2 is not None
        assert cert_a_record2.status == "valid"

        # (d) Account B cannot revoke A's cert via the scoped lookup —
        #     B's cert is already revoked, so another attempt returns 200.
        #     But A can still revoke A's own cert.
        resp_revoke_a = ac_a.revoke_certificate(cert_der, reason=0)
        assert resp_revoke_a.status_code == 200

        cert_a_record3 = store.get_certificate(cert_id_a)
        assert cert_a_record3 is not None
        assert cert_a_record3.status == "revoked"


# ---------------------------------------------------------------------------
# H-1: Revoked certs are not served; order status reflects revoked
# ---------------------------------------------------------------------------


class TestRevokedCertNotServed:
    def test_get_cert_returns_410_after_revoke(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """H-1: After revocation, GET on the cert URL returns 410 Gone."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)

        # Get the cert URL from the order.
        serial_hex = format(cert.serial_number, "x").upper()
        store = Store(test_config.db_path)
        cert_record = store.get_certificate_by_serial(serial_hex)
        assert cert_record is not None

        # Revoke.
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200

        # GET the cert URL → 410 Gone.
        cert_url = f"/acme/cert/{cert_record.id}"
        cert_resp = client.get(cert_url)
        assert cert_resp.status_code == 410

    def test_order_status_reflects_revoked(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """H-1: After revocation, the order status is 'revoked'."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)

        serial_hex = format(cert.serial_number, "x").upper()
        store = Store(test_config.db_path)
        cert_record = store.get_certificate_by_serial(serial_hex)
        assert cert_record is not None

        # Revoke.
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200

        # Order should be revoked.
        order = store.get_order(cert_record.order_id)
        assert order is not None
        assert order.status == "revoked"


# Helper imports placed at the bottom to avoid shadowing module-level imports.
from datetime import datetime, timedelta, timezone  # noqa: E402


def datetime_now(*, days: int = 0) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)
