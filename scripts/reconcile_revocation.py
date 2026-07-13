#!/usr/bin/env python3
"""Read-only revocation reconciliation (WI-017)."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path


_ISSUED_DISPOSITION = 3
_REVOKED_DISPOSITION = 21


@dataclass(frozen=True)
class _CaRecord:
    request_id: str
    serial: str
    revoked: bool


@dataclass(frozen=True)
class _ReconciliationResult:
    in_sync: list[str]
    revoked_at_ca_valid_in_ra: list[str]
    revoked_in_ra_active_at_ca: list[str]

    @property
    def drift_count(self) -> int:
        return len(self.revoked_at_ca_valid_in_ra) + len(self.revoked_in_ra_active_at_ca)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare RA store revocation state with a certutil -view export."
    )
    parser.add_argument("--db", required=True, type=Path, help="Path to the RA SQLite database.")
    parser.add_argument(
        "--ca-export", required=True, type=Path, help="Path to the certutil -view text export."
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit a JSON report instead of human-readable text."
    )
    return parser.parse_args(argv)


def _canonical_serial(value: str) -> str:
    """Normalize a serial-number string to uppercase hex without leading zeros."""
    serial = "".join(value.split()).upper()
    if serial.startswith("0X"):
        serial = serial[2:]
    serial = serial.lstrip("0")
    if not serial:
        serial = "0"
    return serial


def _load_ra_serials(db_path: Path) -> dict[str, bool]:
    """Return a mapping of serial number to RA revocation state (True = revoked)."""
    uri = f"file:{db_path.resolve()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT serial_number, status FROM certificates WHERE serial_number IS NOT NULL"
        ).fetchall()

    result: dict[str, bool] = {}
    for row in rows:
        raw_serial = row["serial_number"]
        if not raw_serial:
            continue
        serial = _canonical_serial(str(raw_serial))
        result[serial] = str(row["status"]).lower() == "revoked"
    return result


def _parse_ca_export(path: Path) -> dict[str, _CaRecord]:
    """Parse a certutil -view text export into a serial -> CA record mapping."""
    text = path.read_text(encoding="utf-8", errors="replace")
    records: dict[str, _CaRecord] = {}

    request_id: str | None = None
    serial: str | None = None
    disposition: int | None = None

    def _flush_block() -> None:
        if request_id is None or serial is None or disposition is None:
            return
        if disposition == _REVOKED_DISPOSITION:
            revoked = True
        elif disposition == _ISSUED_DISPOSITION:
            revoked = False
        else:
            return
        canonical = _canonical_serial(serial)
        records[canonical] = _CaRecord(
            request_id=request_id,
            serial=canonical,
            revoked=revoked,
        )

    for line in text.splitlines():
        if re.match(r"^\s*Row Index:\s*\d+", line):
            _flush_block()
            request_id = None
            serial = None
            disposition = None
            continue

        rid_match = re.match(r"^\s*Request ID:\s*(\d+)\s*$", line)
        if rid_match:
            request_id = rid_match.group(1)
            continue

        serial_match = re.match(r"^\s*Serial Number:\s*([0-9A-Fa-f\s]+?)\s*$", line)
        if serial_match:
            serial = serial_match.group(1)
            continue

        disp_match = re.match(r"^\s*Disposition:\s*(\d+)", line)
        if disp_match:
            disposition = int(disp_match.group(1))

    _flush_block()
    return records


def _reconcile(
    ra_serials: dict[str, bool],
    ca_records: dict[str, _CaRecord],
) -> _ReconciliationResult:
    """Classify certificates into in-sync or drift buckets."""
    in_sync: list[str] = []
    revoked_at_ca_valid_in_ra: list[str] = []
    revoked_in_ra_active_at_ca: list[str] = []

    for serial in set(ra_serials) & set(ca_records):
        ra_revoked = ra_serials[serial]
        ca_revoked = ca_records[serial].revoked

        if ra_revoked == ca_revoked:
            in_sync.append(serial)
        elif ca_revoked and not ra_revoked:
            revoked_at_ca_valid_in_ra.append(serial)
        elif ra_revoked and not ca_revoked:
            revoked_in_ra_active_at_ca.append(serial)

    return _ReconciliationResult(
        in_sync=sorted(in_sync),
        revoked_at_ca_valid_in_ra=sorted(revoked_at_ca_valid_in_ra),
        revoked_in_ra_active_at_ca=sorted(revoked_in_ra_active_at_ca),
    )


def _json_report(result: _ReconciliationResult, ra_count: int, ca_count: int) -> str:
    payload = {
        "compared_serials": len(result.in_sync) + result.drift_count,
        "ra_certificate_count": ra_count,
        "ca_certificate_count": ca_count,
        "drift_count": result.drift_count,
        "in_sync": result.in_sync,
        "revoked_at_ca_valid_in_ra": result.revoked_at_ca_valid_in_ra,
        "revoked_in_ra_active_at_ca": result.revoked_in_ra_active_at_ca,
    }
    return json.dumps(payload, indent=2)


def _human_report(result: _ReconciliationResult, ra_count: int, ca_count: int) -> str:
    lines = [
        "Revocation reconciliation report",
        f"  RA certificates with serials: {ra_count}",
        f"  CA certificates with serials: {ca_count}",
        f"  Serials compared: {len(result.in_sync) + result.drift_count}",
        f"  In sync: {len(result.in_sync)}",
        (
            f"  Revoked at CA, valid in RA: "
            f"{len(result.revoked_at_ca_valid_in_ra)}"
        ),
        (
            f"  Revoked in RA, active at CA: "
            f"{len(result.revoked_in_ra_active_at_ca)}"
        ),
    ]

    if result.revoked_at_ca_valid_in_ra:
        lines.append("")
        lines.append("Serials revoked at CA but still valid in RA:")
        for serial in result.revoked_at_ca_valid_in_ra:
            lines.append(f"  {serial}")

    if result.revoked_in_ra_active_at_ca:
        lines.append("")
        lines.append("Serials revoked in RA but still active at CA (run Revoke-Cert.ps1):")
        for serial in result.revoked_in_ra_active_at_ca:
            lines.append(f"  {serial}")

    if result.drift_count == 0:
        lines.append("")
        lines.append("PASS: revocation state is in sync.")

    return "\n".join(lines)


def _run(db_path: Path, ca_export_path: Path, *, json_output: bool) -> tuple[str, int]:
    """Perform the reconciliation and return (report, exit_code)."""
    ra_serials = _load_ra_serials(db_path)
    ca_records = _parse_ca_export(ca_export_path)
    result = _reconcile(ra_serials, ca_records)

    if json_output:
        report = _json_report(result, len(ra_serials), len(ca_records))
    else:
        report = _human_report(result, len(ra_serials), len(ca_records))

    exit_code = 0 if result.drift_count == 0 else 1
    return report, exit_code


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)
    try:
        report, exit_code = _run(args.db, args.ca_export, json_output=args.json)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
