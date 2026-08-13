"""Regression tests for the 2026-08-14 security review.

Each test is named for the finding it pins. Every one was mutation-checked:
the fix was reverted in turn and the test confirmed to fail.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509

from acme_adcs_ra.enrollment import (
    EnrollmentResult,
    EnrollmentTransportError,
    FakeEnrollmentLeg,
)
from acme_adcs_ra.store import CertStatus, Store


class _IssuedThenFailedLeg:
    """An enrollment leg where the CA issues and the RA then fails.

    This is the window the review named: ``certfnsh.asp`` has already returned
    an "issued" disposition with a ReqID, so a live, domain-trusted certificate
    exists at the CA, and only then does the chain fetch or the
    chain-binds-to-leaf check blow up.
    """

    def __init__(self, *, with_cert: bool) -> None:
        self._with_cert = with_cert
        self.cert_pem = FakeEnrollmentLeg()._read_cert() if with_cert else None

    def submit_csr(
        self,
        csr_pem: str,
        *,
        account_id: str,
        requested_sans: Sequence[str],
    ) -> EnrollmentResult:
        raise EnrollmentTransportError(
            "PKCS#7 chain does not bind to the issued leaf",
            req_id="4242",
            cert_pem=self.cert_pem,
            chain_pem=[],
        )


class TestTransportOrphanQuarantine:
    """F14 — a CA-issued certificate must never be silently orphaned.

    Before the fix the finalize handler recorded ``{"error": ...}`` and
    returned 503: no certificate row, no serial anywhere in the RA, and the
    order left in ``processing``. That is the same orphan class the
    post-issuance verifiers were fixed for in the 2026-08-13 review, on a path
    that review did not reach.
    """

    def test_the_transport_error_carries_what_the_ca_already_issued(self) -> None:
        """The identifiers must survive the exception, or nothing downstream
        can act on them."""
        leg = _IssuedThenFailedLeg(with_cert=True)
        with pytest.raises(EnrollmentTransportError) as caught:
            leg.submit_csr("csr", account_id="acct", requested_sans=["a.example.com"])
        assert caught.value.ca_issued is True
        assert caught.value.req_id == "4242"
        assert caught.value.cert_pem is not None

    def test_a_pre_issuance_transport_error_is_not_flagged_as_issued(self) -> None:
        """The negative control. Without it, every transport failure would
        look like an orphan and the signal would be worthless."""
        exc = EnrollmentTransportError("connection refused")
        assert exc.ca_issued is False
        assert exc.req_id is None

    def _orphaned(self, tmp_path: Path, *, with_cert: bool) -> tuple[Store, Any]:
        return _app_with_leg(tmp_path, _IssuedThenFailedLeg(with_cert=with_cert))

    def test_the_orphan_is_quarantined_with_its_serial(self, tmp_path: Path) -> None:
        """With the leaf in hand the RA can identify the certificate exactly,
        so it must land in the store rather than only in a log line."""
        store, _client = self._orphaned(tmp_path, with_cert=True)
        leg = _IssuedThenFailedLeg(with_cert=True)
        assert leg.cert_pem is not None
        cert = x509.load_pem_x509_certificate(leg.cert_pem.encode())
        expected_serial = format(cert.serial_number, "x").upper()


        # Drive the handler directly: the HTTP path needs a full authorized
        # order, and what is under test is the orphan handling itself.
        order_id, account_id = _seed_processing_order(store)
        exc = EnrollmentTransportError(
            "chain does not bind", req_id="4242", cert_pem=leg.cert_pem, chain_pem=[]
        )
        _run_orphan_handler(store, order_id, account_id, exc)

        pending = store.list_revoked_certificates()
        assert [c.serial_number for c in pending] == [expected_serial]
        assert pending[0].status == CertStatus.QUARANTINED
        assert pending[0].metadata["req_id"] == "4242"

    def test_the_order_goes_terminal_so_finalize_cannot_re_enroll(
        self, tmp_path: Path
    ) -> None:
        """The CA has already satisfied this request. A retried finalize that
        re-enrolled would issue a second certificate for one order."""
        store, _client = self._orphaned(tmp_path, with_cert=True)
        order_id, account_id = _seed_processing_order(store)
        leg = _IssuedThenFailedLeg(with_cert=True)
        exc = EnrollmentTransportError(
            "chain does not bind", req_id="4242", cert_pem=leg.cert_pem, chain_pem=[]
        )
        _run_orphan_handler(store, order_id, account_id, exc)
        order = store.get_order(order_id)
        assert order is not None
        assert order.status == "invalid"

    def test_finalize_routes_an_issued_orphan_to_quarantine(
        self, tmp_path: Path
    ) -> None:
        """The dispatch itself, driven through the real finalize handler.

        The unit tests above call the orphan handler directly, so they pass
        even if ``_finalize_submit_enrollment``'s ``except`` never routes to
        it — a mutation confirmed exactly that. This drives a full authorized
        order through HTTP so the branch is genuinely covered.
        """
        store, client = self._orphaned(tmp_path, with_cert=True)
        resp = _drive_order_to_finalize(client)
        # The CA issued; the RA refuses to honour it and says so with a 500,
        # not the 503 "try again" that would invite a re-enrollment.
        assert resp.status_code == 500, resp.text

        pending = store.list_revoked_certificates()
        assert len(pending) == 1
        assert pending[0].status == CertStatus.QUARANTINED
        assert pending[0].metadata["req_id"] == "4242"

    def test_a_pre_issuance_transport_failure_still_returns_503(
        self, tmp_path: Path
    ) -> None:
        """The negative control for the dispatch: a failure *before* issuance
        must keep the old retryable behaviour and quarantine nothing."""
        store, client = self._orphaned_preissuance(tmp_path / "preissuance")
        resp = _drive_order_to_finalize(client)
        assert resp.status_code == 503, resp.text
        assert store.list_revoked_certificates() == []

    def _orphaned_preissuance(self, tmp_path: Path) -> tuple[Store, Any]:
        class _PreIssuanceFailure:
            def submit_csr(
                self, csr_pem: str, *, account_id: str, requested_sans: Sequence[str]
            ) -> EnrollmentResult:
                raise EnrollmentTransportError("connection refused")

        tmp_path.mkdir(parents=True, exist_ok=True)
        return _app_with_leg(tmp_path, _PreIssuanceFailure())

    def test_a_retrieval_failure_still_records_the_reqid(
        self, tmp_path: Path
    ) -> None:
        """When the leaf itself could not be fetched there are no bytes to
        store, so the ReqID is the only handle the operator has. It must be in
        the audit trail — previously the event carried only an error string."""
        store, _client = self._orphaned(tmp_path, with_cert=False)
        order_id, account_id = _seed_processing_order(store)
        exc = EnrollmentTransportError(
            "certnew.cer did not return a parseable certificate", req_id="4242"
        )
        _run_orphan_handler(store, order_id, account_id, exc)

        events = _audit_events(store, "finalize-enrollment-transport-orphan")
        assert len(events) == 1
        assert events[0]["details"]["req_id"] == "4242"
        assert events[0]["details"]["ca_issued"] is True
        assert events[0]["details"]["quarantined"] is False

    def test_a_retrieval_failure_still_makes_the_order_terminal(
        self, tmp_path: Path
    ) -> None:
        """The ReqID-only branch writes no certificate row, so nothing else
        flips the order — this is the one path where the explicit terminal
        transition is load-bearing. Without it the order stays ``processing``
        and a client can poll it forever against a request the CA already
        satisfied.
        """
        store, _client = self._orphaned(tmp_path, with_cert=False)
        order_id, account_id = _seed_processing_order(store)
        exc = EnrollmentTransportError(
            "certnew.cer did not return a parseable certificate", req_id="4242"
        )
        _run_orphan_handler(store, order_id, account_id, exc)
        order = store.get_order(order_id)
        assert order is not None
        assert order.status == "invalid"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _app_with_leg(tmp_path: Path, leg: Any) -> tuple[Store, Any]:
    """An app whose issuance policy actually permits an order to be driven.

    Reuses test_revocation's config (real EAB kids and SAN scopes) rather than
    the empty-policy one, because these tests must reach the enrollment leg.
    """
    from fastapi.testclient import TestClient

    from acme_adcs_ra.app_state import ServerContext
    from acme_adcs_ra.policy import IssuancePolicy
    from acme_adcs_ra.revocation import FakeRevocationLeg
    from acme_adcs_ra.server import create_app

    from .test_revocation import _make_test_config

    tmp_path.mkdir(parents=True, exist_ok=True)
    cfg = _make_test_config(tmp_path)
    store = Store(cfg.db_path)
    ctx = ServerContext(
        config=cfg,
        store=store,
        policy=IssuancePolicy(
            allowed_kids=set(cfg.eab_keys_by_kid().keys()),
            san_scopes={
                kid: scope.dns_patterns for kid, scope in cfg.san_scopes.items()
            },
            template=cfg.adcs_template,
        ),
        enrollment=leg,
        revocation=FakeRevocationLeg(),
    )
    return store, TestClient(create_app(ctx), raise_server_exceptions=False)


def _drive_order_to_finalize(client: Any) -> Any:
    """New account -> order -> challenge -> finalize, returning the finalize
    response. The enrollment leg is what decides how finalize ends."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from .hand_rolled_acme_client import HandRolledAcmeClient
    from .test_revocation import _eab_mac_key, _make_csr, _make_test_config

    cfg = _make_test_config(Path("/nonexistent"))  # only for the MAC key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ac = HandRolledAcmeClient(client, "http://testserver", key)
    assert ac.new_account("kid-001", _eab_mac_key(cfg, "kid-001")).status_code == 201

    resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
    assert resp.status_code == 201
    order = resp.json()
    for authz_url in order["authorizations"]:
        authz = ac.get_authorization(authz_url).json()
        for challenge in authz["challenges"]:
            assert ac.validate_challenge(challenge["url"]).status_code == 200

    return ac.finalize_order(order["finalize"], _make_csr(["srv01.WORK-DOMAIN.local"]))


def _seed_processing_order(store: Store) -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric import ec

    from .hand_rolled_acme_client import jwk_from_private_key

    account = store.create_account(
        jwk=jwk_from_private_key(ec.generate_private_key(ec.SECP256R1())),
        eab_kid="kid-1",
    )
    order = store.create_order_with_authz(
        account_id=account.id,
        identifiers=[{"type": "dns", "value": "a.example.com"}],
        challenge_url_fn=lambda i: f"http://testserver/acme/chall/{i}",
        authz_url_fn=lambda i: f"http://testserver/acme/authz/{i}",
        finalize_url_fn=lambda i: f"http://testserver/acme/finalize/{i}",
    )
    store.transition_pending_to_ready(order.id)
    store.transition_order_to_processing(order.id)
    return order.id, account.id


def _run_orphan_handler(
    store: Store, order_id: str, account_id: str, exc: EnrollmentTransportError
) -> None:
    from acme_adcs_ra.app_state import ServerContext
    from acme_adcs_ra.config import RAConfig
    from acme_adcs_ra.finalize import _quarantine_transport_orphan
    from acme_adcs_ra.policy import IssuancePolicy
    from acme_adcs_ra.revocation import FakeRevocationLeg

    ctx = ServerContext(
        config=RAConfig(db_path=store._db_path, base_url="http://testserver"),
        store=store,
        policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    _quarantine_transport_orphan(
        ctx,
        order_id=order_id,
        account_id=account_id,
        requested_sans=["a.example.com"],
        template="ACME-ServerAuth",
        exc=exc,
    )


def _audit_events(store: Store, event_type: str) -> list[dict[str, Any]]:
    import json
    import sqlite3

    conn = sqlite3.connect(str(store._db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE event_type = ?", (event_type,)
    ).fetchall()
    conn.close()
    return [{**dict(r), "details": json.loads(r["details"])} for r in rows]
