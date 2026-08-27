"""The monotonic CRL watermark (UNFILED item 23).

The control this replaces was an age ceiling, and the reason it had to be
replaced is worth restating because it is what these tests are shaped around: to
bind against replay the ceiling has to sit *below* the CA's published window,
and to avoid refusing healthy CRLs it has to sit *above* the maximum age the CDP
actually serves. Whether any value satisfies both is **still open** — it turns
on the CA's publication overlap, and UNFILED item 24 has a sampler running to
settle it. Four derivations have been spent on that question already.

The point of monotonicity is that it does not depend on the answer. RFC 5280
§5.2.3 already requires the CRL Number to increase per CA, so the property is
the CA's to maintain rather than the operator's to derive: no calibration, and
so no fifth derivation to get wrong.

**Mutation-proved.** Each fix was reverted in turn and the suite re-run; each
kills exactly the tests that claim it, and nothing else:

* the ``verdict == WATERMARK_OLDER`` refusal in ``fetch_crl_evidence`` →
  ``TestRegressionRefusal`` (2 tests);
* the compare-and-set in ``Store._advance_crl_watermark_in_conn``, reduced to an
  unconditional upsert → ``test_advance_moves_forward_and_refuses_to_move_back``;
* the SPKI in ``_watermark_key``, leaving the DN alone →
  ``test_key_rollover_produces_a_distinct_watermark``;
* CRL-Number precedence in ``compare_to_watermark`` → ``TestComparison``
  (3 tests).

A test that cannot fail manufactures confidence in the next reviewer.
"""

from __future__ import annotations

import datetime
import http.server
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acme_adcs_ra.crl_evidence import (
    CRL_EVIDENCE_REGRESSED,
    WATERMARK_EQUAL,
    WATERMARK_FIRST,
    WATERMARK_INDETERMINATE,
    WATERMARK_NEWER,
    WATERMARK_OLDER,
    CrlWatermark,
    compare_to_watermark,
    crl_watermark_key,
    fetch_crl_evidence,
)
from acme_adcs_ra.store import Store

_NOW = datetime.datetime.now(datetime.UTC)


# ---------------------------------------------------------------------------
# Fixtures: a CA, a leaf, and CRLs whose number and vintage are dialable
# ---------------------------------------------------------------------------


def _ca(common_name: str = "CONTOSO-CA01-CA") -> tuple[Any, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


class Fixture:
    """A CA, a leaf it issued, and a CRL factory."""

    def __init__(self, common_name: str = "CONTOSO-CA01-CA") -> None:
        self.ca_key, self.ca_cert = _ca(common_name)
        self.ca_name = self.ca_cert.subject
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.serial = 0x1A2B3C4D
        self.leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv01.example")])
            )
            .issuer_name(self.ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(self.serial)
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=30))
            .sign(self.ca_key, hashes.SHA256())
        )

    @property
    def leaf_pem(self) -> str:
        return self.leaf.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def chain(self) -> list[str]:
        return [self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()]

    def crl(
        self,
        *,
        number: int | None,
        age_minutes: int = 5,
        serials: list[int] | None = None,
        reason: x509.ReasonFlags | None = None,
    ) -> bytes:
        last = _NOW - datetime.timedelta(minutes=age_minutes)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_name)
            .last_update(last)
            .next_update(_NOW + datetime.timedelta(days=7))
        )
        if number is not None:
            builder = builder.add_extension(x509.CRLNumber(number), critical=False)
        for serial in serials or []:
            entry = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(last)
            )
            if reason is not None:
                entry = entry.add_extension(x509.CRLReason(reason), critical=False)
            builder = builder.add_revoked_certificate(entry.build())
        return builder.sign(self.ca_key, hashes.SHA256()).public_bytes(
            serialization.Encoding.DER
        )


def _serve(body: bytes) -> tuple[str, Any]:
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


def _check(
    fx: Fixture,
    body: bytes,
    *,
    watermark: CrlWatermark | None = None,
    enforce: bool = True,
) -> Any:
    url, shutdown = _serve(body)
    try:
        return fetch_crl_evidence(
            crl_url=url,
            serial_number=fx.serial,
            cert_pem=fx.leaf_pem,
            chain_pem=fx.chain,
            watermark=watermark,
            enforce_monotonic=enforce,
        )
    finally:
        shutdown()


@pytest.fixture
def fx() -> Fixture:
    return Fixture()


# ---------------------------------------------------------------------------
# The comparison itself
# ---------------------------------------------------------------------------


class TestComparison:
    def test_first_observation_is_trust_on_first_use(self) -> None:
        """Named, not hidden: the first document seen protects nothing."""
        assert (
            compare_to_watermark(None, crl_number="7", this_update=_NOW.isoformat())
            == WATERMARK_FIRST
        )

    def test_a_higher_crl_number_advances(self) -> None:
        mark = CrlWatermark(issuer_key="k", crl_number="7", this_update=_NOW.isoformat())
        assert compare_to_watermark(mark, crl_number="8", this_update=_NOW.isoformat()) == WATERMARK_NEWER

    def test_the_same_document_is_equal_not_a_regression(self) -> None:
        """A CDP re-serving the current CRL is the normal case, not an attack."""
        stamp = _NOW.isoformat()
        mark = CrlWatermark(issuer_key="k", crl_number="7", this_update=stamp)
        assert compare_to_watermark(mark, crl_number="7", this_update=stamp) == WATERMARK_EQUAL

    def test_a_lower_crl_number_regresses(self) -> None:
        mark = CrlWatermark(issuer_key="k", crl_number="7", this_update=_NOW.isoformat())
        assert compare_to_watermark(mark, crl_number="6", this_update=_NOW.isoformat()) == WATERMARK_OLDER

    def test_crl_number_beats_this_update(self) -> None:
        """Precedence, in the one case where the two disagree.

        A replayed document with a *newer* timestamp and a *lower* number is
        the shape a CA clock adjustment produces, and the shape an attacker
        would choose if timestamps were authoritative. RFC 5280 makes the
        number the monotonic quantity, so the number decides.
        """
        mark = CrlWatermark(
            issuer_key="k",
            crl_number="7",
            this_update=(_NOW - datetime.timedelta(hours=1)).isoformat(),
        )
        verdict = compare_to_watermark(
            mark, crl_number="6", this_update=_NOW.isoformat()
        )
        assert verdict == WATERMARK_OLDER, (
            "a newer timestamp overrode a lower CRL Number; the timestamp is "
            "not the monotonic quantity"
        )

    def test_falls_back_to_this_update_when_either_side_lacks_a_number(self) -> None:
        """A missing CRL Number is the CA's doing, not tampering.

        The extension is covered by the CA's signature, so whoever answers the
        CDP cannot strip it. Refusing outright would break every CA that omits
        it; the timestamp is the honest fallback.
        """
        mark = CrlWatermark(
            issuer_key="k",
            crl_number=None,
            this_update=(_NOW - datetime.timedelta(hours=1)).isoformat(),
        )
        assert compare_to_watermark(mark, crl_number="9", this_update=_NOW.isoformat()) == WATERMARK_NEWER
        assert (
            compare_to_watermark(
                mark,
                crl_number="9",
                this_update=(_NOW - datetime.timedelta(hours=2)).isoformat(),
            )
            == WATERMARK_OLDER
        )

    def test_nothing_comparable_is_indeterminate_not_newer(self) -> None:
        """Absence of a comparison must not read as a passed one."""
        mark = CrlWatermark(issuer_key="k", crl_number=None, this_update=None)
        assert compare_to_watermark(mark, crl_number=None, this_update=None) == WATERMARK_INDETERMINATE


# ---------------------------------------------------------------------------
# The identity the watermark is keyed on
# ---------------------------------------------------------------------------


class TestIssuerKey:
    def test_key_rollover_produces_a_distinct_watermark(self) -> None:
        """Same DN, new key ⇒ new watermark, by construction.

        ADCS renews a CA key while keeping the subject DN, and CRL Number
        sequences are per key. Sharing a watermark across generations would
        make the older generation's legitimately lower-numbered CRLs read as
        replays — the control refusing valid evidence, which is how a control
        gets switched off.
        """
        first = Fixture("CONTOSO-CA01-CA")
        second = Fixture("CONTOSO-CA01-CA")
        assert first.ca_cert.subject == second.ca_cert.subject
        key_one = crl_watermark_key(first.leaf_pem, first.chain)
        key_two = crl_watermark_key(second.leaf_pem, second.chain)
        assert key_one is not None and key_two is not None
        assert key_one != key_two, (
            "two CA generations sharing a DN collapsed onto one watermark; the "
            "SPKI is not in the key"
        )

    def test_the_key_is_derived_from_the_chain_and_matches_the_fetch(
        self, fx: Fixture
    ) -> None:
        """The pre-fetch lookup and the post-fetch evidence must agree.

        The route reads the watermark *before* going to the network, keyed off
        the stored chain. If that key differed from the one the fetch reports,
        every comparison would silently be against an empty watermark — a
        control that always says "first observation" and never refuses
        anything.
        """
        evidence = _check(fx, fx.crl(number=5))
        assert evidence.checked is True
        assert evidence.issuer_key == crl_watermark_key(fx.leaf_pem, fx.chain)

    def test_no_chain_means_no_key_rather_than_a_guess(self) -> None:
        """An unresolvable issuer yields None, not a key over the leaf itself."""
        fx = Fixture()
        assert crl_watermark_key(fx.leaf_pem, []) is None


# ---------------------------------------------------------------------------
# The refusal, end to end through the real fetch path
# ---------------------------------------------------------------------------


class TestRegressionRefusal:
    def test_a_regressed_crl_is_refused_as_no_evidence(self, fx: Fixture) -> None:
        """The wrong-accept this closes is a hold→unhold replay.

        A certificate put on hold (reason 6) and later released with reason 8
        (`removeFromCRL`) is still listed as revoked on the older CRL. Replay
        that document and the RA confirms a revocation for a certificate that
        is currently valid — the one direction an age ceiling never protected,
        because a stale CRL that *lacks* the serial already fails closed.
        """
        mark = CrlWatermark(
            issuer_key=crl_watermark_key(fx.leaf_pem, fx.chain) or "",
            crl_number="9",
            this_update=(_NOW - datetime.timedelta(minutes=1)).isoformat(),
        )
        evidence = _check(fx, fx.crl(number=4, serials=[fx.serial]), watermark=mark)
        assert evidence.revoked is False
        assert evidence.checked is False, (
            "a regressed CRL was accepted as evidence; the replay it enables is "
            "a confirmation for a certificate that came off hold"
        )
        assert evidence.regressed is True
        assert CRL_EVIDENCE_REGRESSED in evidence.detail

    def test_refusal_is_no_evidence_not_counter_evidence(self, fx: Fixture) -> None:
        """`checked=False` is what makes `require_crl_evidence` fail closed.

        Reporting `checked=True, revoked=False` would be a *claim* about the
        certificate drawn from a document the RA has just decided not to trust.
        """
        mark = CrlWatermark(
            issuer_key=crl_watermark_key(fx.leaf_pem, fx.chain) or "",
            crl_number="9",
            this_update=_NOW.isoformat(),
        )
        evidence = _check(fx, fx.crl(number=4, serials=[fx.serial]), watermark=mark)
        assert (evidence.checked, evidence.revoked) == (False, False)

    def test_advisory_mode_reports_the_verdict_without_refusing(
        self, fx: Fixture
    ) -> None:
        """`enforce_monotonic=False` is for a knowingly-lagging CDP estate.

        The measurement has to survive the exemption, or an operator turning
        enforcement on later is doing it blind.
        """
        mark = CrlWatermark(
            issuer_key=crl_watermark_key(fx.leaf_pem, fx.chain) or "",
            crl_number="9",
            this_update=_NOW.isoformat(),
        )
        evidence = _check(
            fx, fx.crl(number=4, serials=[fx.serial]), watermark=mark, enforce=False
        )
        assert evidence.checked is True
        assert evidence.revoked is True
        assert evidence.watermark_verdict == WATERMARK_OLDER

    def test_an_advancing_crl_is_accepted_and_reports_newer(self, fx: Fixture) -> None:
        mark = CrlWatermark(
            issuer_key=crl_watermark_key(fx.leaf_pem, fx.chain) or "",
            crl_number="4",
            this_update=(_NOW - datetime.timedelta(hours=2)).isoformat(),
        )
        evidence = _check(fx, fx.crl(number=9, serials=[fx.serial]), watermark=mark)
        assert (evidence.checked, evidence.revoked) == (True, True)
        assert evidence.watermark_verdict == WATERMARK_NEWER

    def test_a_freshness_failure_is_not_reported_as_a_regression(
        self, fx: Fixture
    ) -> None:
        """Document-level checks run first; only survivors are compared.

        A CRL refused for staleness must not also advance or be blamed on the
        watermark — the two failures need different operator responses (one is
        the CA's publication pipeline, the other is the CDP serving backwards).
        """
        evidence = _check(fx, fx.crl(number=9), watermark=None)
        assert evidence.watermark_verdict == WATERMARK_FIRST
        expired = fetch_crl_evidence(
            crl_url="http://127.0.0.1:1/nope.crl",
            serial_number=fx.serial,
            cert_pem=fx.leaf_pem,
            chain_pem=fx.chain,
        )
        assert expired.checked is False
        assert expired.watermark_verdict is None
        assert expired.regressed is False


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class TestStoreWatermark:
    def test_first_read_is_none(self, tmp_path: Path) -> None:
        store = Store(tmp_path / "ra.db")
        assert store.read_crl_watermark("nothing-here") is None

    def test_advance_moves_forward_and_refuses_to_move_back(
        self, tmp_path: Path
    ) -> None:
        """The compare-and-set is what survives a lost race.

        The route reads the watermark before it fetches and writes it after, so
        a concurrent confirmation can advance the row in between. A plain
        upsert would then walk the watermark *backwards* to this request's
        older document — turning the control off precisely under the
        concurrency an attacker can generate.
        """
        store = Store(tmp_path / "ra.db")
        older = (_NOW - datetime.timedelta(hours=2)).isoformat()
        newer = _NOW.isoformat()
        with store._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            assert store._advance_crl_watermark_in_conn(
                conn, issuer_key="ca", crl_number="7", this_update=older,
                source_url="http://cdp/ca.crl",
            )
        with store._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            assert store._advance_crl_watermark_in_conn(
                conn, issuer_key="ca", crl_number="9", this_update=newer,
                source_url="http://cdp/ca.crl",
            )
        with store._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            assert not store._advance_crl_watermark_in_conn(
                conn, issuer_key="ca", crl_number="8", this_update=newer,
                source_url="http://cdp/ca.crl",
            ), "the watermark went backwards"
        mark = store.read_crl_watermark("ca")
        assert mark is not None and mark.crl_number == "9"

    def test_watermarks_are_per_ca(self, tmp_path: Path) -> None:
        store = Store(tmp_path / "ra.db")
        stamp = _NOW.isoformat()
        for issuer in ("ca-one", "ca-two"):
            with store._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                store._advance_crl_watermark_in_conn(
                    conn, issuer_key=issuer, crl_number="5", this_update=stamp,
                    source_url=None,
                )
        with store._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            store._advance_crl_watermark_in_conn(
                conn, issuer_key="ca-one", crl_number="6", this_update=stamp,
                source_url=None,
            )
        one = store.read_crl_watermark("ca-one")
        two = store.read_crl_watermark("ca-two")
        assert one is not None and one.crl_number == "6"
        assert two is not None and two.crl_number == "5"

    def test_reset_is_available_and_takes_effect(self, tmp_path: Path) -> None:
        """The recovery path for a CA restored from backup.

        Deliberately an operator action with no automatic caller: wiring
        "the number went backwards, so clear the watermark" would hand the
        attacker the exact sequence that defeats the control.
        """
        store = Store(tmp_path / "ra.db")
        with store._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            store._advance_crl_watermark_in_conn(
                conn, issuer_key="ca", crl_number="120",
                this_update=_NOW.isoformat(), source_url=None,
            )
        assert store.reset_crl_watermark("ca") is True
        assert store.read_crl_watermark("ca") is None
        assert store.reset_crl_watermark("ca") is False

    def test_a_confirmation_that_changes_nothing_does_not_advance(
        self, tmp_path: Path
    ) -> None:
        """The advance belongs to the confirm's transaction, not to the fetch.

        An unknown serial takes the early return before any watermark write, so
        a request that confirmed nothing must leave the watermark alone — if it
        did not, an attacker could ratchet the watermark (and wedge every real
        confirmation) without owning a single certificate.
        """
        store = Store(tmp_path / "ra.db")
        flipped, event = store.confirm_ca_revocation_with_audit(
            "00DEADBEEF",
            event_type="revocation-ca-confirmed",
            outcome="success",
            watermark_advance=CrlWatermark(
                issuer_key="ca", crl_number="99", this_update=_NOW.isoformat()
            ),
            watermark_source_url="http://cdp/ca.crl",
        )
        assert (flipped, event) == (False, None)
        assert store.read_crl_watermark("ca") is None

    def test_the_audit_literal_matches_the_constant(self) -> None:
        """The route spells the reason code as a literal, on purpose.

        The coalescing-key guard requires it to be provably server-chosen
        *syntactically*, and relaxing that guard to accept a name would be the
        fourth call-site patch to it (UNFILED item 13). This pins the literal
        to the constant so the two cannot drift in silence.
        """
        source = (
            Path(__file__).resolve().parents[1]
            / "src" / "acme_adcs_ra" / "routes" / "admin.py"
        ).read_text(encoding="utf-8")
        assert f'"reason_code": "{CRL_EVIDENCE_REGRESSED}"' in source


class TestAdvisoryModeDoesNotMislabelDenials:
    """A regression that was not acted on must not be blamed for the denial.

    In advisory mode (`enforce_monotonic=False`) the verdict is recorded and the
    document is still used. If the confirmation is then denied because the
    serial is genuinely absent from the CRL, calling that `crl-evidence-regressed`
    would send whoever reads the audit trail after a CDP fault that is not the
    reason anything failed.
    """

    def test_the_denial_reason_requires_the_evidence_to_have_been_refused(
        self, fx: Fixture
    ) -> None:
        mark = CrlWatermark(
            issuer_key=crl_watermark_key(fx.leaf_pem, fx.chain) or "",
            crl_number="9",
            this_update=_NOW.isoformat(),
        )
        advisory = _check(fx, fx.crl(number=4), watermark=mark, enforce=False)
        # Regressed, but used: this is not the shape that should be labelled a
        # regression denial.
        assert (advisory.regressed, advisory.checked) == (True, True)

        enforced = _check(fx, fx.crl(number=4), watermark=mark, enforce=True)
        assert (enforced.regressed, enforced.checked) == (True, False)


class TestTheConfirmPathNeverRaises:
    """`_crl_evidence_for` promises a CRL problem never becomes a 500.

    Reading the watermark added a store touch to that function, and a store
    read is exactly the kind of thing that raises on a full disk or a locked
    database. If it escaped, a CDP-adjacent fault would take down the
    revocation-confirmation route — the route whose whole job is to keep the RA
    and the CA from drifting apart.
    """

    def test_a_failing_watermark_read_is_reported_not_raised(
        self, fx: Fixture
    ) -> None:
        from acme_adcs_ra.routes import admin

        class ExplodingStore:
            def read_crl_watermark(self, issuer_key: str) -> Any:
                raise sqlite3.OperationalError("database is locked")

        class Config:
            revocation_confirm_crl_url = "http://127.0.0.1:1/ca.crl"
            revocation_confirm_crl_timeout_seconds = 1.0
            revocation_confirm_crl_max_bytes = 1024
            revocation_confirm_crl_max_age_seconds = 7 * 24 * 3600
            revocation_confirm_crl_total_timeout_seconds = 2.0
            revocation_confirm_crl_follow_redirects = False
            revocation_confirm_crl_require_monotonic = True

        class Ctx:
            config = Config()
            store = ExplodingStore()

        class Cert:
            serial_number = f"{fx.serial:X}"
            cert_pem = fx.leaf_pem
            chain_pem = fx.chain

        evidence = admin._crl_evidence_for(Ctx(), Cert())  # type: ignore[arg-type]
        assert evidence is not None
        assert evidence.checked is False
        assert "CRL check error" in evidence.detail
