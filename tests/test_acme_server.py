"""Integration tests for the ACME server endpoints and round-trip flow."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import NONCE_TTL_SECONDS, Store

from .hand_rolled_acme_client import HandRolledAcmeClient


# ---------------------------------------------------------------------------
# Test config and fixtures
# ---------------------------------------------------------------------------


def _make_test_config(tmp_path: Path) -> RAConfig:
    # 32-byte base64url-encoded key.
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


@pytest.fixture()
def test_config(tmp_path: Path) -> RAConfig:
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


@pytest.fixture()
def acme_client(
    client: TestClient,
    account_key: rsa.RSAPrivateKey,
) -> HandRolledAcmeClient:
    return HandRolledAcmeClient(
        http_client=client,
        base_url="http://testserver",
        account_key=account_key,
    )


def _eab_mac_key(config: RAConfig, kid: str) -> bytes:
    raw = config.eab_key_bytes(kid)
    assert raw is not None
    return raw


def _make_csr(sans: list[str]) -> bytes:
    """Build a self-signed CSR with the given DNS SANs (test code may sign)."""
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


# ---------------------------------------------------------------------------
# Endpoint smoke tests
# ---------------------------------------------------------------------------


class TestDirectory:
    def test_directory_shape(self, client: TestClient) -> None:
        resp = client.get("/directory")
        assert resp.status_code == 200
        body = resp.json()
        assert body["newNonce"].endswith("/acme/new-nonce")
        assert body["newAccount"].endswith("/acme/new-acct")
        assert body["newOrder"].endswith("/acme/new-order")
        assert body["revokeCert"].endswith("/acme/revoke-cert")
        assert body["meta"]["externalAccountRequired"] is True


class TestNonce:
    def test_new_nonce_head(self, client: TestClient) -> None:
        resp = client.head("/acme/new-nonce")
        assert resp.status_code == 204
        assert "Replay-Nonce" in resp.headers
        assert resp.headers["Cache-Control"] == "no-store"

    def test_new_nonce_get(self, client: TestClient) -> None:
        resp = client.get("/acme/new-nonce")
        assert resp.status_code == 204
        assert "Replay-Nonce" in resp.headers


# ---------------------------------------------------------------------------
# newAccount + EAB
# ---------------------------------------------------------------------------


class TestNewAccount:
    def test_new_account_success(self, acme_client: HandRolledAcmeClient, test_config: RAConfig) -> None:
        resp = acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "valid"
        assert "Location" in resp.headers
        assert resp.headers["Location"].startswith("http://testserver/acme/acct/")

    def test_new_account_requires_eab(self, acme_client: HandRolledAcmeClient) -> None:
        url = f"{acme_client.base_url}/acme/new-acct"
        from .hand_rolled_acme_client import sign_jws

        protected = {
            "alg": "RS256",
            "nonce": acme_client._fresh_nonce(),
            "url": url,
            "jwk": acme_client.account_jwk,
        }
        body = sign_jws({"termsOfServiceAgreed": True}, acme_client.account_key, protected)
        resp = acme_client.http.post(url, json=body)
        assert resp.status_code == 400
        assert "externalAccountBinding" in resp.json()["detail"]

    def test_new_account_unknown_kid_rejected(
        self, acme_client: HandRolledAcmeClient, test_config: RAConfig
    ) -> None:
        resp = acme_client.new_account("kid-unknown", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badExternalAccountBinding"

    def test_new_account_wrong_mac_rejected(
        self, acme_client: HandRolledAcmeClient
    ) -> None:
        bad_key = b"wrong-key-32-bytes-long!!!!!!!!!"
        resp = acme_client.new_account("kid-001", bad_key)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badExternalAccountBinding"

    def test_replayed_nonce_rejected(self, acme_client: HandRolledAcmeClient, test_config: RAConfig) -> None:
        url = f"{acme_client.base_url}/acme/new-acct"
        from .hand_rolled_acme_client import make_eab_jws, sign_jws

        nonce = acme_client._fresh_nonce()
        eab_jws = make_eab_jws(
            acme_client.account_jwk,
            "kid-001",
            _eab_mac_key(test_config, "kid-001"),
            url=url,
        )
        protected = {
            "alg": "RS256",
            "nonce": nonce,
            "url": url,
            "jwk": acme_client.account_jwk,
        }
        body = sign_jws(
            {"externalAccountBinding": eab_jws, "termsOfServiceAgreed": True},
            acme_client.account_key,
            protected,
        )
        resp1 = acme_client.http.post(url, json=body)
        assert resp1.status_code == 201
        resp2 = acme_client.http.post(url, json=body)
        assert resp2.status_code == 400
        assert resp2.json()["type"] == "urn:ietf:params:acme:error:badNonce"


# ---------------------------------------------------------------------------
# M-2: Failed account-creation attempts are audited
# ---------------------------------------------------------------------------


class TestAccountCreationDeniedAudit:
    def test_unknown_kid_produces_audit_row(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """M-2: An unknown-kid newAccount attempt produces an account-creation-denied audit row."""
        store = Store(test_config.db_path)
        before = store.list_audit_events(event_type="account-creation-denied")
        resp = acme_client.new_account("kid-unknown", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 400
        after = store.list_audit_events(event_type="account-creation-denied")
        assert len(after) == len(before) + 1
        assert after[0]["outcome"] == "failed"
        assert after[0]["details"]["reason"] == "unknown EAB kid"
        assert after[0]["details"]["kid"] == "kid-unknown"

    def test_wrong_mac_produces_audit_row(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """M-2: A bad-MAC newAccount attempt produces an account-creation-denied audit row."""
        store = Store(test_config.db_path)
        before = store.list_audit_events(event_type="account-creation-denied")
        bad_key = b"wrong-key-32-bytes-long!!!!!!!!!"
        resp = acme_client.new_account("kid-001", bad_key)
        assert resp.status_code == 400
        after = store.list_audit_events(event_type="account-creation-denied")
        assert len(after) == len(before) + 1
        assert after[0]["outcome"] == "failed"
        assert "EAB MAC verification failed" in after[0]["details"]["reason"]
        # The MAC key itself must NOT appear in the audit row.
        details_str = json.dumps(after[0]["details"])
        assert "wrong-key" not in details_str


# ---------------------------------------------------------------------------
# newOrder / finalize / policy
# ---------------------------------------------------------------------------


class TestPolicyViaFinalize:
    def test_in_scope_san_issues_certificate(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        resp = acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 201

        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        assert resp.status_code == 201
        order = resp.json()
        assert order["status"] == "pending"
        assert len(order["authorizations"]) == 1

        # Walk authz -> challenge -> valid.
        authz_url = order["authorizations"][0]
        authz_resp = acme_client.get_authorization(authz_url)
        assert authz_resp.status_code == 200
        challenge = authz_resp.json()["challenges"][0]
        assert challenge["status"] == "pending"
        challenge_resp = acme_client.validate_challenge(challenge["url"])
        assert challenge_resp.status_code == 200
        assert challenge_resp.json()["status"] == "valid"

        # Finalize with a CSR matching the identifier.
        csr_der = _make_csr(["web.WORK-DOMAIN.local"])
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200
        finalized_order = finalize_resp.json()
        assert finalized_order["status"] == "valid"
        assert "certificate" in finalized_order

        cert_resp = acme_client.get_certificate(finalized_order["certificate"])
        assert cert_resp.status_code == 200
        assert cert_resp.headers["Content-Type"] == "application/pem-certificate-chain"
        assert "BEGIN CERTIFICATE" in cert_resp.text

    def test_out_of_scope_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["evil.other-domain.local"])
        assert resp.status_code == 201
        order = resp.json()

        authz_url = order["authorizations"][0]
        authz_resp = acme_client.get_authorization(authz_url)
        challenge = authz_resp.json()["challenges"][0]
        acme_client.validate_challenge(challenge["url"])

        csr_der = _make_csr(["evil.other-domain.local"])
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:rejectedIdentifier"

    def test_empty_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["srv01.WORK-DOMAIN.local"])
        order = resp.json()

        authz_url = order["authorizations"][0]
        authz_resp = acme_client.get_authorization(authz_url)
        challenge = authz_resp.json()["challenges"][0]
        acme_client.validate_challenge(challenge["url"])

        # CSR with only a subject CN and no SAN extension.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")])
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
        csr_der = csr.public_bytes(serialization.Encoding.DER)

        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:rejectedIdentifier"
        assert "no SANs" in finalize_resp.json()["detail"]

    def test_wrong_account_kid_rejected(self, acme_client: HandRolledAcmeClient, test_config: RAConfig) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        # Send a newOrder signed with a bogus account URL.
        acme_client.account_url = "http://testserver/acme/acct/00000000000000000000000000000000"
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        assert resp.status_code == 401
        assert resp.json()["type"] == "urn:ietf:params:acme:error:unauthorized"


# ---------------------------------------------------------------------------
# Full round trip
# ---------------------------------------------------------------------------


class TestFullRoundTrip:
    def test_certify_the_web_like_flow(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        # 1. EAB-bound newAccount.
        resp = acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 201

        # 2. newOrder for an in-scope SAN.
        resp = acme_client.new_order(["srv01.WORK-DOMAIN.local"])
        assert resp.status_code == 201
        order = resp.json()
        assert order["status"] == "pending"

        # 3. Walk each authorization to valid.
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                val_resp = acme_client.validate_challenge(challenge["url"])
                assert val_resp.json()["status"] == "valid"

        # 4. Finalize with CSR.
        csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
        resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert resp.status_code == 200
        finalized = resp.json()
        assert finalized["status"] == "valid"
        assert "certificate" in finalized

        # 5. Retrieve certificate.
        cert_resp = acme_client.get_certificate(finalized["certificate"])
        assert cert_resp.status_code == 200
        assert cert_resp.headers["Content-Type"] == "application/pem-certificate-chain"
        pem_text = cert_resp.text
        assert "BEGIN CERTIFICATE" in pem_text
        cert_count = pem_text.count("BEGIN CERTIFICATE")
        assert cert_count >= 1

        # 6. Audit row exists.
        store = Store(test_config.db_path)
        assert acme_client.account_url is not None
        account_id = acme_client.account_url.split("/")[-1]
        events = store.list_audit_events(account_id=account_id)
        assert any(e["event_type"] == "certificate-issued" for e in events)


# ---------------------------------------------------------------------------
# Audit hook
# ---------------------------------------------------------------------------


class TestAuditHook:
    def test_hook_called_for_account_created(
        self,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        events: list[dict[str, Any]] = []

        def hook(event: dict[str, Any]) -> None:
            events.append(event)

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
            audit_hook=hook,
        )
        client = TestClient(create_app(context))
        ac = HandRolledAcmeClient(client, "http://testserver", account_key)
        resp = ac.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 201
        assert any(e["event_type"] == "account-created" and e["outcome"] == "success" for e in events)


# ---------------------------------------------------------------------------
# Nonce garbage collection
# ---------------------------------------------------------------------------


class TestNonceGarbageCollection:
    def test_cleanup_expired_nonces(self, tmp_path: Path) -> None:
        """Expired nonces are removed by cleanup_expired_nonces."""
        store = Store(tmp_path / "test_gc.db")
        now = datetime.now(timezone.utc)
        old_ts = (now - timedelta(seconds=NONCE_TTL_SECONDS + 60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with store._connect() as conn:
            conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", ("old-nonce-1", old_ts))
            conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", ("old-nonce-2", old_ts))
            conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", ("fresh-nonce", now.strftime("%Y-%m-%dT%H:%M:%SZ")))
        deleted = store.cleanup_expired_nonces()
        assert deleted == 2
        with store._connect() as conn:
            row = conn.execute("SELECT COUNT(*) as c FROM nonces").fetchone()
            assert row["c"] == 1


# ---------------------------------------------------------------------------
# H2: Full-URL binding (scheme + host + path + query)
# ---------------------------------------------------------------------------


class TestFullUrlBinding:
    def test_jws_with_wrong_host_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A JWS whose protected url has a different host must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        # Forge a JWS with a wrong host in the url.
        url = f"{acme_client.base_url}/acme/new-order"
        from .hand_rolled_acme_client import sign_jws

        protected = {
            "alg": "RS256",
            "nonce": acme_client._fresh_nonce(),
            "url": "http://evil-host/acme/new-order",  # wrong host
            "kid": acme_client.account_url,
        }
        payload = {
            "identifiers": [{"type": "dns", "value": "test.WORK-DOMAIN.local"}],
        }
        body = sign_jws(payload, acme_client.account_key, protected)
        resp = acme_client.http.post(url, json=body)
        assert resp.status_code == 400
        assert "host mismatch" in resp.json()["detail"]

    def test_jws_with_correct_full_url_accepted(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A JWS whose protected url matches scheme+host+path works."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        assert resp.status_code == 201

    def test_jws_with_relative_url_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A relative url (no scheme/host) must be rejected - otherwise a stolen
        JWS could replay against any host at the same path."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        url = f"{acme_client.base_url}/acme/new-order"
        from .hand_rolled_acme_client import sign_jws

        protected = {
            "alg": "RS256",
            "nonce": acme_client._fresh_nonce(),
            "url": "/acme/new-order",  # relative - must be rejected
            "kid": acme_client.account_url,
        }
        payload = {"identifiers": [{"type": "dns", "value": "test.WORK-DOMAIN.local"}]}
        body = sign_jws(payload, acme_client.account_key, protected)
        resp = acme_client.http.post(url, json=body)
        assert resp.status_code == 400
        assert "absolute URL" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# H3: Challenge payload must be {}
# ---------------------------------------------------------------------------


class TestChallengePayloadValidation:
    def test_non_empty_payload_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A challenge POST with non-empty payload must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        authz_url = order["authorizations"][0]
        authz = acme_client.get_authorization(authz_url).json()
        challenge = authz["challenges"][0]

        # Send a challenge POST with a non-empty payload.
        url = challenge["url"]
        from .hand_rolled_acme_client import sign_jws

        protected = {
            "alg": "RS256",
            "nonce": acme_client._fresh_nonce(),
            "url": url,
            "kid": acme_client.account_url,
        }
        body = sign_jws({"keyAuthorization": "bogus"}, acme_client.account_key, protected)
        resp = acme_client.http.post(url, json=body)
        assert resp.status_code == 400
        assert "empty object" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# M3: Processing state + double-finalize guard
# ---------------------------------------------------------------------------


class TestDoubleFinalizeGuard:
    def test_double_finalize_returns_existing_cert(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """Finalizing an already-finalized order returns the existing cert."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()

        # Walk to valid.
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        # First finalize.
        csr_der = _make_csr(["web.WORK-DOMAIN.local"])
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200
        first_cert_url = finalize_resp.json().get("certificate")

        # Second finalize with same order — should return existing cert, not error.
        finalize_resp2 = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp2.status_code == 200
        second_cert_url = finalize_resp2.json().get("certificate")
        assert first_cert_url == second_cert_url

    def test_finalize_on_processing_order_does_not_re_enroll(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """An order at 'processing' (mid-flight, no cert yet) must NOT be
        re-enrolled - the server returns it for polling. Prevents double
        issuance on a concurrent/retried finalize."""
        config = _make_test_config(tmp_path)
        store = Store(config.db_path)
        policy = IssuancePolicy(
            allowed_kids=set(config.eab_keys_by_kid().keys()),
            san_scopes={k: s.dns_patterns for k, s in config.san_scopes.items()},
            template=config.adcs_template,
        )
        app = create_app(
            ServerContext(
                config=config,
                store=store,
                policy=policy,
                enrollment=FakeEnrollmentLeg(),
                revocation=FakeRevocationLeg(),
            )
        )
        client = TestClient(app)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = ac.new_order(["web.WORK-DOMAIN.local"]).json()
        for authz_url in order["authorizations"]:
            authz = ac.get_authorization(authz_url).json()
            for ch in authz["challenges"]:
                ac.validate_challenge(ch["url"])

        order_id = order["finalize"].split("/")[-1]
        # Simulate a first finalize that crashed mid-enrollment: order is
        # 'processing', no cert stored yet.
        assert store.transition_order_to_processing(order_id) is True
        assert store.get_certificate_by_order(order_id) is None

        resp = ac.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        # Must NOT have re-enrolled: no cert stored, order still processing,
        # client told to retry.
        assert resp.status_code == 200
        assert resp.json()["status"] == "processing"
        assert resp.headers.get("retry-after") is not None
        assert store.get_certificate_by_order(order_id) is None


# ---------------------------------------------------------------------------
# M4: CSR with non-DNS SAN types rejected
# ---------------------------------------------------------------------------


class TestCsrSanTypeValidation:
    def test_csr_with_ip_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A CSR with an IPAddress SAN must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        # CSR with both DNS and IP SANs.
        import ipaddress
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "web.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([
            x509.DNSName("web.WORK-DOMAIN.local"),
            x509.IPAddress(ipaddress.IPv4Address("10.0.0.1")),
        ])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:badCSR"
        assert "IPAddress" in finalize_resp.json()["detail"]

    def test_csr_with_uri_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A CSR with a URI SAN must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "web.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([
            x509.DNSName("web.WORK-DOMAIN.local"),
            x509.UniformResourceIdentifier("https://example.com"),
        ])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert "UniformResourceIdentifier" in finalize_resp.json()["detail"]


# ---------------------------------------------------------------------------
# M5: Minimum key strength
# ---------------------------------------------------------------------------


class TestMinimumKeyStrength:
    def test_rsa_1024_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        tmp_path: Path,
    ) -> None:
        """An RSA-1024 CSR must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "web.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([x509.DNSName("web.WORK-DOMAIN.local")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:badCSR"
        assert "1024" in finalize_resp.json()["detail"]

    def test_ec_p256_accepted(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """An EC P-256 CSR must be accepted."""
        # Create an ACME client with an EC key.
        ec_key = ec.generate_private_key(ec.SECP256R1())
        from .hand_rolled_acme_client import HandRolledAcmeClient as HRC
        ec_client = HRC(
            http_client=acme_client.http,
            base_url=acme_client.base_url,
            account_key=ec_key,
        )
        ec_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = ec_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = ec_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                ec_client.validate_challenge(challenge["url"])

        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "web.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([x509.DNSName("web.WORK-DOMAIN.local")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = ec_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200
