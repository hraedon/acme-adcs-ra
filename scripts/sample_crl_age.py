#!/usr/bin/env python3
"""Sample a CDP's published CRL over time, so the freshness alarm has data.

Why this exists (UNFILED item 22). The RA records ``crl_this_update`` on every
revocation confirmation, so in principle the age distribution of the CRLs it
acts on is derivable from ``audit_log``. In practice it is not: the lab
validation procedure restores the store to its pre-run fingerprint at the end
of every session, which is exactly right for isolation and is amnesia for
measurement. Every ``crl-verified`` confirmation this project has ever produced
has been deleted by the teardown that followed it. WI-052 was therefore not
un-measured but **un-measurable**, and no number of further validation rounds
would have changed that.

So the sampler deliberately does **not** use the RA, its store, or its audit
trail. It needs nothing but CDP reach, it writes append-only outside anything a
teardown restores, and it can run from any host that can fetch the URL.

What it measures, and what each number is for:

``observed_age_seconds``
    ``now - thisUpdate`` at the moment of the fetch. This is the quantity
    ``ACME_RA_REVOCATION_CONFIRM_CRL_MAX_AGE_SECONDS`` is compared against, so
    its distribution — not the CA's registry configuration — is what says
    whether a given ceiling would refuse real, healthy CRLs. Set the ceiling
    above the observed maximum with margin, or accept false refusals.

``window_seconds``
    ``nextUpdate - thisUpdate`` of the served document: the CA's real
    publication window, including whatever overlap it actually applies. The lab
    CA's registry values do not decompose to the window it publishes, which is
    why this is measured rather than derived (WI-052).

``crl_number``
    The CRL Number extension (RFC 5280 §5.2.3), which the CA must increase
    monotonically. Tracking it across samples measures how often a CDP serves a
    **regressed** document — the replica-skew false-positive risk that the
    monotonic watermark control (UNFILED item 23) has to tolerate. A CDP that
    never regresses here can carry a strict watermark; one that does needs the
    retry.

Two failure modes are recorded rather than hidden, because a sampler that drops
its failures measures only the CA's good days:

* a fetch that fails (DNS, connect, timeout, HTTP status, oversize body) still
  writes a row, with ``ok: false`` and the reason. Gaps in the series would
  otherwise be indistinguishable from the sampler not having run;
* a body that will not parse as a CRL likewise writes a row rather than
  aborting the schedule.

Usage::

    # one sample, appended to the log
    python scripts/sample_crl_age.py --url http://ca.example/crl/ca.crl \
        --out ~/lab-evidence/crl-samples.jsonl

    # a supervised loop (a scheduled task or cron entry calling --once is
    # preferable in production; this is for a host that is simply left running)
    python scripts/sample_crl_age.py --url ... --out ... --interval 1800

    # what the data says
    python scripts/sample_crl_age.py --out ... --summarize

The summary is the deliverable: it prints the observed age distribution, the
window, and any CRL Number regressions, which is what a ceiling and a watermark
should be set from.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import sys
import time
from datetime import UTC, datetime
from types import FrameType
from typing import Any

import requests
from cryptography import x509

# A CRL big enough to matter is still small. The cap is here because the
# response is chosen by whoever answers the CDP, not by the operator, and this
# script is expected to run unattended for weeks.
DEFAULT_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
DEFAULT_INTERVAL = 1800.0

# Set by the signal handlers so a loop stops between samples rather than
# half-way through writing one.
_STOP = False


def _handle_stop(signum: int, frame: FrameType | None) -> None:
    global _STOP
    _STOP = True


def _fetch(url: str, timeout: float, max_bytes: int, follow_redirects: bool) -> tuple[bytes | None, dict[str, Any]]:
    """Fetch *url*, returning ``(body, metadata)``; ``body`` is None on failure.

    Redirects are not followed by default, matching the RA's own default
    (``revocation_confirm_crl_follow_redirects``): the hop target is chosen by
    whoever answers the CDP, and a sampler that quietly follows one is
    measuring a different endpoint than the RA is.
    """
    meta: dict[str, Any] = {}
    try:
        with requests.get(
            url, timeout=timeout, stream=True, allow_redirects=follow_redirects
        ) as response:
            meta["http_status"] = response.status_code
            meta["content_type"] = response.headers.get("Content-Type")
            if response.status_code != 200:
                meta["error"] = f"HTTP {response.status_code}"
                return None, meta
            body = bytearray()
            for chunk in response.iter_content(64 * 1024):
                body.extend(chunk)
                if len(body) > max_bytes:
                    meta["error"] = f"body exceeded {max_bytes} bytes"
                    meta["bytes"] = len(body)
                    return None, meta
    except requests.RequestException as exc:
        meta["error"] = f"{type(exc).__name__}: {exc}"
        return None, meta
    meta["bytes"] = len(body)
    return bytes(body), meta


def _parse(body: bytes) -> tuple[x509.CertificateRevocationList | None, str | None]:
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            return loader(body), None
        except ValueError:
            continue
    return None, "body is neither valid DER nor PEM CRL"


def sample(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    follow_redirects: bool = False,
) -> dict[str, Any]:
    """Take one sample. Always returns a row; never raises for a bad CDP."""
    started = datetime.now(UTC)
    monotonic_start = time.monotonic()
    row: dict[str, Any] = {
        "fetched_at": started.isoformat(),
        "source_url": url,
        "ok": False,
    }
    body, meta = _fetch(url, timeout, max_bytes, follow_redirects)
    row.update(meta)
    row["fetch_seconds"] = round(time.monotonic() - monotonic_start, 3)
    if body is None:
        return row

    row["sha256"] = hashlib.sha256(body).hexdigest()
    crl, parse_error = _parse(body)
    if crl is None:
        row["error"] = parse_error
        return row

    this_update = crl.last_update_utc
    next_update = crl.next_update_utc
    # Age is measured against the fetch time, not "now": in a loop the two can
    # differ by the whole timeout, and the number is supposed to describe the
    # document as served.
    row["issuer"] = crl.issuer.rfc4514_string()
    row["this_update"] = this_update.isoformat() if this_update else None
    row["next_update"] = next_update.isoformat() if next_update else None
    if this_update is not None:
        row["observed_age_seconds"] = int((started - this_update).total_seconds())
    if next_update is not None:
        row["remaining_seconds"] = int((next_update - started).total_seconds())
    if this_update is not None and next_update is not None:
        row["window_seconds"] = int((next_update - this_update).total_seconds())

    try:
        crl_number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        row["crl_number"] = str(crl_number)
    except x509.ExtensionNotFound:
        row["crl_number"] = None

    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
    except x509.ExtensionNotFound:
        row["is_delta"] = False
    else:
        row["is_delta"] = True

    row["entry_count"] = len(crl)
    row["ok"] = True
    return row


def append(path: str, row: dict[str, Any]) -> None:
    """Append one row, flushed and fsynced.

    The whole point of this file is to survive things — a reboot mid-series, a
    teardown, an unattended host losing power. A buffered write that never
    reaches the platter reproduces the exact defect the sampler exists to fix.
    """
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _percentile(values: list[int], fraction: float) -> int:
    """Nearest-rank percentile. No numpy dependency for nine numbers."""
    if not values:
        raise ValueError("no values")
    ordered = sorted(values)
    rank = max(1, min(len(ordered), math.ceil(fraction * len(ordered))))
    return ordered[rank - 1]


def summarize(path: str) -> int:
    """Print what the series says. Returns a process exit code."""
    try:
        with open(path, encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        print(f"no sample log at {path}", file=sys.stderr)
        return 1
    if not rows:
        print(f"sample log {path} is empty", file=sys.stderr)
        return 1

    good = [r for r in rows if r.get("ok")]
    bad = [r for r in rows if not r.get("ok")]
    print(f"samples:          {len(rows)}  ({len(good)} ok, {len(bad)} failed)")
    print(f"span:             {rows[0]['fetched_at']} -> {rows[-1]['fetched_at']}")
    if bad:
        # Failures are part of the measurement: a CDP that is unreachable for a
        # day is a liveness fact about the publication pipeline, which is
        # exactly what the age ceiling is being demoted to alarm on.
        reasons: dict[str, int] = {}
        for row in bad:
            reasons[str(row.get("error", "unknown"))] = reasons.get(str(row.get("error", "unknown")), 0) + 1
        print("failed fetches:")
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"  {count:5d}  {reason}")
    if not good:
        print("no successful samples: nothing to derive a ceiling from")
        return 1

    issuers = sorted({str(r.get("issuer")) for r in good})
    print(f"issuer(s):        {', '.join(issuers)}")

    ages = [int(r["observed_age_seconds"]) for r in good if r.get("observed_age_seconds") is not None]
    if ages:
        print("observed age (s), the quantity max_age_seconds is compared against:")
        print(f"  min             {min(ages)}")
        print(f"  median          {_percentile(ages, 0.5)}")
        print(f"  p95             {_percentile(ages, 0.95)}")
        print(f"  max             {max(ages)}   ({max(ages) / 86400:.2f} days)")

    windows = sorted({int(r["window_seconds"]) for r in good if r.get("window_seconds") is not None})
    if windows:
        print(f"window(s) served: {windows}")
        # The bound that makes the ceiling non-binding as a replay control: any
        # ceiling at or above the window admits a CRL from the whole of the
        # previous publication period (UNFILED item 20).
        print(f"  binding upper bound for a replay ceiling: {min(windows)}")

    numbered = [r for r in good if r.get("crl_number") is not None]
    if numbered:
        distinct = sorted({int(r["crl_number"]) for r in numbered})
        print(f"CRL Numbers:      {len(distinct)} distinct, {distinct[0]}..{distinct[-1]}")
        regressions = []
        highest = None
        for row in numbered:
            value = int(row["crl_number"])
            if highest is not None and value < highest:
                regressions.append((row["fetched_at"], highest, value))
            highest = max(highest, value) if highest is not None else value
        if regressions:
            # Each of these is a sample where a strict monotonic watermark
            # would have refused a document the CA legitimately served.
            print(f"CRL Number REGRESSIONS: {len(regressions)} (replica skew — the watermark needs its retry)")
            for when, was, saw in regressions[:10]:
                print(f"  {when}  watermark {was} -> served {saw}")
        else:
            print("CRL Number regressions: none (a strict watermark would not have false-refused)")
    else:
        print("CRL Numbers:      ABSENT from every sample; a watermark must fall back to thisUpdate")

    ages_when_new = [
        int(r["observed_age_seconds"])
        for r in good
        if r.get("observed_age_seconds") is not None
    ]
    if ages_when_new and windows:
        ceiling = max(ages_when_new)
        print()
        print("Reading:")
        print(f"  a liveness alarm must sit above {ceiling}s or it fires on healthy publication;")
        print(f"  a replay bound would have to sit below {min(windows)}s to bind at all.")
        if ceiling >= min(windows):
            print("  These do not overlap: on this CA the ceiling cannot be a replay control.")
        else:
            print("  These DO overlap on this CA; a binding ceiling exists in between.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", help="CDP URL to sample (the CRL the RA is configured against)")
    parser.add_argument("--out", required=True, help="JSONL sample log; appended to, never rewritten")
    parser.add_argument("--interval", type=float, default=None,
                        help=f"loop, sampling every N seconds (default: one sample and exit; typical {DEFAULT_INTERVAL:.0f})")
    parser.add_argument("--count", type=int, default=None, help="stop after N samples in loop mode")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--follow-redirects", action="store_true",
                        help="follow CDP redirects (off by default, matching the RA)")
    parser.add_argument("--summarize", action="store_true", help="summarize --out and exit")
    args = parser.parse_args(argv)

    if args.summarize:
        return summarize(args.out)
    if not args.url:
        parser.error("--url is required unless --summarize is given")

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    taken = 0
    while True:
        row = sample(
            args.url,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
            follow_redirects=args.follow_redirects,
        )
        append(args.out, row)
        taken += 1
        if row.get("ok"):
            print(
                f"{row['fetched_at']}  crl_number={row.get('crl_number')} "
                f"age={row.get('observed_age_seconds')}s window={row.get('window_seconds')}s"
            )
        else:
            print(f"{row['fetched_at']}  FAILED: {row.get('error')}", file=sys.stderr)
        if args.interval is None:
            return 0 if row.get("ok") else 1
        if args.count is not None and taken >= args.count:
            return 0
        # Sleep in short slices so a stop signal is honoured promptly rather
        # than after the whole interval.
        deadline = time.monotonic() + args.interval
        while not _STOP and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))
        if _STOP:
            print("stopping on signal", file=sys.stderr)
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
