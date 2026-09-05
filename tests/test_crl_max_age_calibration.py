"""The CRL age ceiling's calibration, and the independence of the three bounds.

WI-052 / UNFILED item 24, resolved 2026-09-05 by measurement rather than by a
fifth paper derivation.

Four derivations argued that no age ceiling could be both binding and free of
false refusals. They all took the ceiling's *floor* from the CRL's published
validity window. That is the wrong quantity. Two different numbers constrain the
ceiling:

* the **floor** is the maximum age an honest CDP actually **serves** -- below it
  the ceiling refuses healthy evidence. No document carries this number; it has
  to be sampled.
* the **roof** is the published window ``nextUpdate - thisUpdate`` -- at or above
  it the ceiling sits behind the CRL's own expiry and can never fire first.

On a CA that publishes with overlap those differ by exactly the overlap, so a
band exists. ``scripts/sample_crl_age.py`` measured it on the lab CA: 399
samples over 8.3 days covering one complete publication cycle.

These tests pin the number against the measurement and, separately, prove that
expiry, configured age and monotonicity are three independent refusals rather
than one check wearing three names -- because the argument above is only sound
if a ceiling at or above the roof really is redundant with expiry.
"""

from __future__ import annotations

import datetime
import http.server
import threading
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.crl_evidence import (
    DEFAULT_CRL_MAX_AGE_SECONDS,
    CrlWatermark,
    fetch_crl_evidence,
)

# ---------------------------------------------------------------------------
# The measurement, as literals.
#
# Deliberately NOT derived from the constant under test: a fixture built from
# the number it checks cannot detect a change to that number.
# ---------------------------------------------------------------------------

#: Largest age the lab CDP was observed serving (last sample of CRL 127).
OBSERVED_MAX_SERVED_AGE = 603654
#: Upper bound on the true maximum: the observation above plus one 1800s
#: sampling interval, since the real changeover is unobservable at that cadence.
SERVED_AGE_UPPER_BOUND = 605454
#: ``nextUpdate - thisUpdate`` on every one of the 399 samples.
PUBLISHED_WINDOW = 649200
#: The value this observation period supports for a weekly CA with ADCS's
#: computed 12h overlap. Not a universal bound -- measure your own CA.
MEASURED_CEILING = 626400


class TestCalibration:
    def test_the_shipped_default_is_the_measured_value(self) -> None:
        assert DEFAULT_CRL_MAX_AGE_SECONDS == MEASURED_CEILING

    def test_the_config_default_cannot_drift_from_the_library_default(self) -> None:
        """One number, two places it is read from.

        Production always passes the config value explicitly, so a divergence
        here would stay invisible until some script or test omitted the
        argument and silently got a different bound.
        """
        field = RAConfig.model_fields["revocation_confirm_crl_max_age_seconds"]
        assert field.default == DEFAULT_CRL_MAX_AGE_SECONDS == MEASURED_CEILING

    def test_the_default_clears_the_measured_floor(self) -> None:
        """Above the floor, or it refuses CRLs the CA is healthily serving."""
        assert MEASURED_CEILING > SERVED_AGE_UPPER_BOUND
        assert MEASURED_CEILING - SERVED_AGE_UPPER_BOUND == 20946  # ~5h49m

    def test_the_default_stays_under_the_roof_and_therefore_binds(self) -> None:
        """Below the window, or it never fires before ``nextUpdate`` does."""
        assert MEASURED_CEILING < PUBLISHED_WINDOW
        assert PUBLISHED_WINDOW - MEASURED_CEILING == 22800  # ~6h20m

    def test_the_superseded_recommendation_was_outside_the_band(self) -> None:
        """649800 was published as a floor and is above the roof.

        Kept as a test so the number cannot quietly come back: any ceiling at
        or above the window is redundant with the expiry check, which
        ``test_a_ceiling_above_the_window_is_redundant_with_expiry`` proves
        against the implementation rather than on paper.
        """
        assert 649800 > PUBLISHED_WINDOW

    def test_the_previous_default_could_not_be_shown_safe(self) -> None:
        """604800 sat inside the uncertainty band on the served age.

        It cleared the observed maximum by 1146s but not the upper bound, so on
        the measured cycle it could have refused a genuinely healthy CRL in the
        minutes before republication.
        """
        assert OBSERVED_MAX_SERVED_AGE < 604800 < SERVED_AGE_UPPER_BOUND


# ---------------------------------------------------------------------------
# Independence of the three bounds.
# ---------------------------------------------------------------------------

_NOW = datetime.datetime.now(datetime.UTC)


class _Fixture:
    """A CA, a leaf, and CRLs whose window and age are set independently."""

    def __init__(self) -> None:
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "CONTOSO-CA01-CA")]
        )
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(self.ca_name)
            .issuer_name(self.ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=800))
            .not_valid_after(_NOW + datetime.timedelta(days=800))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(self.ca_key, hashes.SHA256())
        )
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.serial = 0x6C0000005E
        self.leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "host.example")])
            )
            .issuer_name(self.ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(self.serial)
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=90))
            .sign(self.ca_key, hashes.SHA256())
        )

    @property
    def leaf_pem(self) -> str:
        return self.leaf.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def chain(self) -> list[str]:
        return [self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()]

    def crl(self, *, age_seconds: int, window_seconds: int, number: int) -> bytes:
        this_update = _NOW - datetime.timedelta(seconds=age_seconds)
        return (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_name)
            .last_update(this_update)
            .next_update(this_update + datetime.timedelta(seconds=window_seconds))
            .add_extension(x509.CRLNumber(number), critical=False)
            .add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(self.serial)
                .revocation_date(this_update)
                .build()
            )
            .sign(self.ca_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
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


def _check(fx: _Fixture, body: bytes, **kwargs: Any) -> Any:
    url, shutdown = _serve(body)
    try:
        return fetch_crl_evidence(
            crl_url=url,
            serial_number=fx.serial,
            cert_pem=fx.leaf_pem,
            chain_pem=fx.chain,
            **kwargs,
        )
    finally:
        shutdown()


@pytest.fixture(scope="module")
def fx() -> _Fixture:
    return _Fixture()


class TestTheThreeBoundsAreIndependent:
    """Expiry, configured age and monotonicity each refuse on their own.

    Each test satisfies the other two conditions, so the refusal it observes
    can only have come from the bound it names.
    """

    def test_expiry_refuses_on_its_own(self, fx: _Fixture) -> None:
        """Age ceiling wide open, no watermark: only nextUpdate can refuse."""
        body = fx.crl(age_seconds=700_000, window_seconds=600_000, number=200)
        ev = _check(fx, body, max_age_seconds=10**9, enforce_monotonic=False)
        assert ev.checked is False
        assert ev.revoked is False
        assert "expired at" in ev.detail

    def test_the_configured_age_refuses_on_its_own(self, fx: _Fixture) -> None:
        """Unexpired and non-regressed: only the ceiling can refuse."""
        body = fx.crl(age_seconds=630_000, window_seconds=PUBLISHED_WINDOW, number=200)
        ev = _check(
            fx, body, max_age_seconds=MEASURED_CEILING, enforce_monotonic=False
        )
        assert ev.checked is False
        assert "freshness limit" in ev.detail
        assert "expired" not in ev.detail

    def test_monotonicity_refuses_on_its_own(self, fx: _Fixture) -> None:
        """Unexpired and well inside the ceiling: only the watermark can refuse."""
        body = fx.crl(age_seconds=60, window_seconds=PUBLISHED_WINDOW, number=128)
        ev = _check(
            fx,
            body,
            max_age_seconds=MEASURED_CEILING,
            watermark=CrlWatermark(
                issuer_key="k", crl_number="129", this_update=_NOW.isoformat()
            ),
            enforce_monotonic=True,
        )
        assert ev.checked is False
        assert ev.regressed is True
        assert "regressed" in ev.detail

    def test_the_same_crl_passes_all_three_when_none_is_violated(
        self, fx: _Fixture
    ) -> None:
        """The control. Without it the three tests above pass vacuously."""
        body = fx.crl(age_seconds=60, window_seconds=PUBLISHED_WINDOW, number=130)
        ev = _check(
            fx,
            body,
            max_age_seconds=MEASURED_CEILING,
            watermark=CrlWatermark(
                issuer_key="k", crl_number="129", this_update=_NOW.isoformat()
            ),
            enforce_monotonic=True,
        )
        assert ev.checked is True
        assert ev.revoked is True

    def test_a_ceiling_above_the_window_is_redundant_with_expiry(
        self, fx: _Fixture
    ) -> None:
        """Why 649800 bounds nothing, proved against the implementation.

        With the ceiling set at or above the published window, any CRL old
        enough to exceed it has already passed its own ``nextUpdate`` -- so the
        expiry check answers first and the ceiling never gets to speak. This is
        the claim four paper derivations turned on; it is cheap to just run.
        """
        too_old = fx.crl(
            age_seconds=PUBLISHED_WINDOW + 600,
            window_seconds=PUBLISHED_WINDOW,
            number=200,
        )
        ev = _check(fx, too_old, max_age_seconds=649_800, enforce_monotonic=False)
        assert ev.checked is False
        # Expiry, not freshness: the ceiling was never reached.
        assert "expired at" in ev.detail
        assert "freshness limit" not in ev.detail
