"""``scripts/sample_crl_age.py`` — the measurement WI-052 never had.

The item survived four derivations and three live validation rounds because the
number it needed could not be obtained: the RA records ``crl_this_update`` on
every confirmation, and the lab teardown restores the store to its pre-run
fingerprint, so each session produced exactly the evidence required and then
deleted it. The sampler exists to put that measurement somewhere a teardown
does not reach.

What is worth testing about a sampler is not that it can read a good CRL. It is
that it keeps recording when things go wrong — a sampler that drops its
failures measures only the CA's good days and produces a maximum observed age
that is quietly a lower bound. Both properties below were mutation-proved.
"""

from __future__ import annotations

import datetime
import http.server
import importlib.util
import json
import threading
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

REPO_ROOT = Path(__file__).resolve().parent.parent
_SAMPLE_TIME = datetime.datetime(2026, 8, 29, 12, 0, tzinfo=datetime.UTC)


@pytest.fixture(scope="module")
def sampler() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "sample_crl_age_under_test", REPO_ROOT / "scripts" / "sample_crl_age.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _crl(
    *,
    sampled_at: datetime.datetime,
    number: int | None = 42,
    age_minutes: int = 90,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CONTOSO-CA01-CA")])
    last = sampled_at - datetime.timedelta(minutes=age_minutes)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(last)
        .next_update(last + datetime.timedelta(seconds=649200))
    )
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _serve(body: bytes, status: int = 200) -> tuple[str, Any]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}/ca.crl", server.shutdown


class TestSampling:
    def test_a_good_crl_yields_the_three_numbers_that_matter(
        self, sampler: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Age, window and CRL Number: a ceiling, a bound and a watermark."""
        class FixedDatetime(datetime.datetime):
            @classmethod
            def now(cls, tz: datetime.tzinfo | None = None) -> datetime.datetime:
                return _SAMPLE_TIME if tz is not None else _SAMPLE_TIME.replace(tzinfo=None)

        # Keep fixture construction and fetch time on an explicit clock. This
        # remains exact even when the full suite reaches this test long after
        # the module was imported.
        monkeypatch.setattr(sampler, "datetime", FixedDatetime)
        url, shutdown = _serve(
            _crl(sampled_at=_SAMPLE_TIME, number=127, age_minutes=90)
        )
        try:
            row = sampler.sample(url)
        finally:
            shutdown()
        assert row["ok"] is True
        assert row["crl_number"] == "127"
        assert row["window_seconds"] == 649200
        assert row["fetched_at"] == _SAMPLE_TIME.isoformat()
        assert row["observed_age_seconds"] == 5400

    def test_a_failed_fetch_still_writes_a_row(self, sampler: ModuleType) -> None:
        """A gap in the series must not be ambiguous.

        If failures were skipped, a fortnight in which the CDP was down for two
        days would be indistinguishable from a fortnight in which the sampler
        itself was not running — and the operator would set a liveness alarm
        from a series that had silently deleted the liveness failures.
        """
        url, shutdown = _serve(b"not a crl", status=503)
        try:
            row = sampler.sample(url)
        finally:
            shutdown()
        assert row["ok"] is False
        assert "503" in str(row["error"])
        assert row["fetched_at"]

    def test_a_body_that_is_not_a_crl_is_recorded_not_raised(
        self, sampler: ModuleType
    ) -> None:
        """A CDP answering 200 with a login page must not stop the schedule."""
        url, shutdown = _serve(b"<html>sign in</html>")
        try:
            row = sampler.sample(url)
        finally:
            shutdown()
        assert row["ok"] is False
        assert "DER" in str(row["error"])

    def test_an_unreachable_cdp_is_recorded_not_raised(
        self, sampler: ModuleType
    ) -> None:
        row = sampler.sample("http://127.0.0.1:1/ca.crl", timeout=2.0)
        assert row["ok"] is False
        assert row["error"]


class TestLog:
    def test_append_creates_the_directory_and_keeps_prior_rows(
        self, sampler: ModuleType, tmp_path: Path
    ) -> None:
        target = tmp_path / "nested" / "crl-samples.jsonl"
        sampler.append(str(target), {"fetched_at": "a", "ok": True})
        sampler.append(str(target), {"fetched_at": "b", "ok": True})
        rows = [json.loads(line) for line in target.read_text().splitlines()]
        assert [r["fetched_at"] for r in rows] == ["a", "b"]

    def test_percentiles_are_nearest_rank(self, sampler: ModuleType) -> None:
        values = [1, 2, 3, 4, 5, 6]
        assert sampler._percentile(values, 0.5) == 3
        assert sampler._percentile(values, 0.95) == 6
        assert sampler._percentile([7], 0.5) == 7


class TestSummary:
    def _write(self, sampler: ModuleType, target: Path, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            sampler.append(str(target), row)

    def _row(self, *, at: str, number: str, age: int) -> dict[str, Any]:
        return {
            "fetched_at": at,
            "ok": True,
            "issuer": "CN=CONTOSO-CA01-CA",
            "crl_number": number,
            "observed_age_seconds": age,
            "window_seconds": 649200,
        }

    def test_a_crl_number_regression_is_reported(
        self, sampler: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The false-positive risk the watermark control has to tolerate.

        A CDP that round-robins replicas at different vintages will serve a
        lower CRL Number now and then. Each occurrence here is a sample where a
        strict monotonic watermark would have refused a document the CA
        legitimately published — which is the difference between "enable the
        control" and "enable it with the retry, or advisory".
        """
        target = tmp_path / "samples.jsonl"
        self._write(sampler, target, [
            self._row(at="2026-08-01T00:00:00+00:00", number="120", age=100),
            self._row(at="2026-08-01T00:30:00+00:00", number="121", age=200),
            self._row(at="2026-08-01T01:00:00+00:00", number="119", age=300),
        ])
        assert sampler.summarize(str(target)) == 0
        out = capsys.readouterr().out
        assert "REGRESSIONS: 1" in out
        assert "watermark 121 -> served 119" in out

    def test_a_clean_series_says_so_rather_than_staying_silent(
        self, sampler: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """"No regressions" has to be stated, or zero looks like not-checked."""
        target = tmp_path / "samples.jsonl"
        self._write(sampler, target, [
            self._row(at="2026-08-01T00:00:00+00:00", number="120", age=100),
            self._row(at="2026-08-01T00:30:00+00:00", number="121", age=200),
        ])
        assert sampler.summarize(str(target)) == 0
        assert "regressions: none" in capsys.readouterr().out

    def test_a_served_age_reaching_the_window_leaves_no_room_for_a_ceiling(
        self, sampler: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The case WI-052 assumed it was in: no overlap, so no gap.

        When the CDP really does serve documents as old as the published
        window, the floor (above the observed maximum, or healthy CRLs are
        refused) sits at or above the bound (below the window, or the ceiling
        adds nothing to `nextUpdate`). Nothing fits between them.
        """
        target = tmp_path / "samples.jsonl"
        self._write(sampler, target, [
            self._row(at="2026-08-01T00:00:00+00:00", number="120", age=100),
            self._row(at="2026-08-07T00:00:00+00:00", number="121", age=650000),
        ])
        sampler.summarize(str(target))
        assert "cannot be a replay control" in capsys.readouterr().out

    def test_a_served_age_below_the_window_leaves_a_usable_gap(
        self, sampler: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The case a CA with CRL **overlap** is actually in — and the reason
        this measurement is worth taking rather than deriving.

        A CA that republishes every `CRLPeriod` but stamps a longer window
        serves documents no older than the *publication interval*, while an
        attacker replaying an unexpired document reaches the whole *window*.
        Those are different quantities, and the gap between them — exactly the
        overlap — is where a ceiling can be both safe and binding. Deriving the
        floor from the window instead of from the served age closes that gap by
        construction (UNFILED item 24).
        """
        target = tmp_path / "samples.jsonl"
        self._write(sampler, target, [
            self._row(at="2026-08-01T00:00:00+00:00", number="120", age=100),
            self._row(at="2026-08-07T00:00:00+00:00", number="121", age=604800),
        ])
        sampler.summarize(str(target))
        out = capsys.readouterr().out
        assert "DO overlap" in out
        assert "604800s or it fires on healthy publication" in out
        assert "below 649200s to bind at all" in out

    def test_failed_samples_are_counted_in_the_summary(
        self, sampler: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        target = tmp_path / "samples.jsonl"
        self._write(sampler, target, [
            self._row(at="2026-08-01T00:00:00+00:00", number="120", age=100),
            {"fetched_at": "2026-08-01T00:30:00+00:00", "ok": False, "error": "HTTP 503"},
        ])
        sampler.summarize(str(target))
        out = capsys.readouterr().out
        assert "(1 ok, 1 failed)" in out
        assert "HTTP 503" in out

    def test_an_absent_log_is_an_error_not_an_empty_summary(
        self, sampler: ModuleType, tmp_path: Path
    ) -> None:
        """Reporting "0 samples, all healthy" from a missing file is the
        failure-is-silence shape this whole item is about."""
        assert sampler.summarize(str(tmp_path / "nope.jsonl")) == 1
