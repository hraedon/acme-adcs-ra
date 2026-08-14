#!/usr/bin/env python3
"""Read-only revocation reconciliation (WI-017).

This tool answers one question: **is everything the RA believes is revoked
actually revoked at the CA?** It is the control an operator leans on to close a
revocation incident, so the way it fails matters as much as the way it passes.

The 2026-08-18 scan (F2) found it could report PASS while live, domain-trusted
certificates the RA had revoked were still active at the CA. Four separate
reasons, all of which turned missing information into apparent agreement:

* the issued disposition was wrong (3, where ADCS uses 20 — see the comment on
  ``Test-SerialRevokedAtCa`` in ``Revoke-Cert.ps1``), so every ordinary issued
  row was silently dropped;
* rows with any other disposition were dropped too, including rows the parser
  simply failed to read;
* the comparison ran over the *intersection* of the two inventories, so an RA
  serial absent from the export was not compared and not counted;
* only RA status ``revoked`` was treated as needing CA revocation, although
  ``quarantined`` certificates are equally live at the CA and travel the same
  pull-agent path (see ``Store.list_revoked_certificates``).

The rule now is the opposite one: **PASS requires proof, not the absence of
disagreement.** Every serial the RA knows about must be accounted for in the
export, the export must parse cleanly, and only then can zero drift mean
anything. Anything less exits 2 (indeterminate) rather than 0.

Exit codes:
    0  PASS   — full coverage, no drift.
    1  DRIFT  — the two sides disagree about at least one serial.
    2  ERROR  — the comparison could not be completed, so PASS is unprovable.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ADCS request dispositions (certsrv `Disposition` column). 20 is issued and 21
# is revoked; `Revoke-Cert.ps1` restricts on exactly these two values and its
# comments record the same mapping. The previous value here (3) matched no
# ordinary row, so the parser discarded every issued certificate it saw.
_ISSUED_DISPOSITION = 20
_REVOKED_DISPOSITION = 21

# RFC 5280 reason 8, removeFromCRL: the UN-revoke. `scripts/lib/RevocationLib.ps1`
# records what the lab established — a certificate placed on hold and then given
# reason 8 ends up off the CRL and valid while **ADCS keeps its Disposition at
# 21**. So disposition alone cannot decide revocation, and reading it as
# revoked produces a PASS for a certificate relying parties still accept
# (2026-08-18 wave 3 F1).
_REMOVE_FROM_CRL_REASON = 8

# Dispositions that legitimately carry no usable certificate: the request never
# became one, so a row bearing one is not a coverage gap. Anything *else* that
# is unrecognized is treated as a parse problem rather than skipped, because a
# disposition this tool does not understand is exactly the case where guessing
# "not revoked" is the dangerous answer.
_NON_CERTIFICATE_DISPOSITIONS = frozenset(
    {
        2,  # denied
        3,  # pending (under submission)
        9,  # pending (awaiting manager approval)
        30,  # failed
        31,  # denied
    }
)

# RA certificate statuses that mean "this certificate must not be usable" and
# therefore must be revoked at the CA. `quarantined` belongs here: the CA issued
# it, a post-issuance verifier rejected it, and it is live at the CA until the
# pull agent revokes it.
_MUST_BE_REVOKED_STATUSES = frozenset({"revoked", "quarantined"})


class ReconciliationError(Exception):
    """The comparison could not be completed, so PASS cannot be claimed."""


@dataclass(frozen=True)
class _CaRecord:
    request_id: str
    serial: str
    revoked: bool


@dataclass(frozen=True)
class _RaRecord:
    serial: str
    status: str

    @property
    def must_be_revoked(self) -> bool:
        return self.status in _MUST_BE_REVOKED_STATUSES


@dataclass(frozen=True)
class _ReconciliationResult:
    in_sync: list[str]
    revoked_at_ca_valid_in_ra: list[str]
    revoked_in_ra_active_at_ca: list[str]
    # Serials the RA holds that the export does not mention at all. Not
    # "agreement" — the export did not cover them, so nothing was checked.
    ra_serials_absent_from_ca: list[str]
    # Blocks the parser could not turn into a usable record.
    parse_problems: list[str] = field(default_factory=list)

    @property
    def drift_count(self) -> int:
        return len(self.revoked_at_ca_valid_in_ra) + len(self.revoked_in_ra_active_at_ca)

    @property
    def coverage_complete(self) -> bool:
        return not self.ra_serials_absent_from_ca and not self.parse_problems


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
    parser.add_argument(
        "--ca-export-exit-code",
        type=int,
        default=0,
        help=(
            "certutil's exit status from producing --ca-export. A non-zero value "
            "means the export is untrustworthy and the run exits 2 without "
            "comparing anything."
        ),
    )
    return parser.parse_args(argv)


def _canonical_serial(value: str) -> str:
    """Normalize a serial-number string to uppercase hex without leading zeros."""
    serial = "".join(value.split()).upper()
    serial = serial.removeprefix("0X")
    serial = serial.lstrip("0")
    if not serial:
        serial = "0"
    return serial


def _load_ra_records(db_path: Path) -> dict[str, _RaRecord]:
    """Return a mapping of serial number to the RA's view of that certificate.

    Where two rows share a serial and disagree, the one demanding revocation
    wins: this decides whether an operator goes looking for a live certificate,
    and the failure that costs nothing is the one that sends them looking.
    """
    uri = f"file:{db_path.resolve()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT serial_number, status FROM certificates WHERE serial_number IS NOT NULL"
        ).fetchall()

    result: dict[str, _RaRecord] = {}
    for row in rows:
        raw_serial = row["serial_number"]
        if not raw_serial:
            continue
        serial = _canonical_serial(str(raw_serial))
        record = _RaRecord(serial=serial, status=str(row["status"]).lower())
        existing = result.get(serial)
        if existing is not None and existing.must_be_revoked and not record.must_be_revoked:
            continue
        result[serial] = record
    return result


def _parse_ca_export(path: Path) -> tuple[dict[str, _CaRecord], list[str]]:
    """Parse a ``certutil -view`` text export.

    Returns ``(records, problems)``. A block that carries a serial but whose
    disposition is missing or unrecognized becomes a *problem*, not a silent
    omission — the old behaviour dropped it, which is indistinguishable from
    "the CA has no such certificate" and reads downstream as agreement.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    records: dict[str, _CaRecord] = {}
    problems: list[str] = []

    block: dict[str, Any] = {
        "request_id": None,
        "serial": None,
        "disposition": None,
        "reason": None,
    }

    def _flush_block() -> None:
        request_id = block["request_id"]
        serial = block["serial"]
        disposition = block["disposition"]
        reason = block["reason"]
        if serial is None:
            # No serial: a denied/failed/pending request, or the export's
            # preamble. Nothing to reconcile against and nothing missing.
            return
        canonical = _canonical_serial(serial)
        if disposition is None:
            problems.append(
                f"serial {canonical} appears with no Disposition value"
            )
            return
        if disposition == _REVOKED_DISPOSITION:
            # Disposition 21 with reason 8 is the un-revoke: live at the CA.
            revoked = reason != _REMOVE_FROM_CRL_REASON
        elif disposition == _ISSUED_DISPOSITION:
            revoked = False
        elif disposition in _NON_CERTIFICATE_DISPOSITIONS:
            # A serial on a denied/failed/pending row is not a live
            # certificate; recording it as "active" would invent drift.
            return
        else:
            problems.append(
                f"serial {canonical} has unrecognized Disposition {disposition}"
            )
            return
        records[canonical] = _CaRecord(
            request_id=request_id or "",
            serial=canonical,
            revoked=revoked,
        )

    saw_any_row = False
    for line in text.splitlines():
        if re.match(r"^\s*Row Index:\s*\d+", line):
            saw_any_row = True
            _flush_block()
            block["request_id"] = None
            block["serial"] = None
            block["disposition"] = None
            block["reason"] = None
            continue

        rid_match = re.match(r"^\s*Request ID:\s*(\d+)\s*$", line)
        if rid_match:
            block["request_id"] = rid_match.group(1)
            continue

        serial_match = re.match(r"^\s*Serial Number:\s*([0-9A-Fa-f\s]+?)\s*$", line)
        if serial_match:
            block["serial"] = serial_match.group(1)
            continue

        disp_match = re.match(r"^\s*Disposition:\s*(\d+)", line)
        if disp_match:
            block["disposition"] = int(disp_match.group(1))
            continue

        # certutil labels this column "Revocation Reason" (and localizes it), so
        # match either the schema name or the English label, and tolerate the
        # trailing "-- Unspecified"-style annotation certutil appends.
        reason_match = re.match(
            r"^\s*(?:Request\.RevokedReason|Revocation Reason):\s*(?:0x[0-9a-fA-F]+\s*\()?(\d+)",
            line,
        )
        if reason_match:
            block["reason"] = int(reason_match.group(1))

    _flush_block()

    if not saw_any_row and not records:
        problems.append(
            "the export contains no certutil rows at all; it is empty, "
            "truncated, or was not produced by `certutil -view`"
        )
    return records, problems


def _reconcile(
    ra_records: dict[str, _RaRecord],
    ca_records: dict[str, _CaRecord],
    parse_problems: list[str],
) -> _ReconciliationResult:
    """Classify certificates into in-sync, drift, and not-covered buckets.

    Iterates the RA's inventory rather than the intersection: a serial the RA
    knows about and the export does not is the single most important thing this
    tool can report, and the intersection could not express it. CA serials with
    no RA row are *not* reported — the CA legitimately issues certificates this
    RA never requested.
    """
    in_sync: list[str] = []
    revoked_at_ca_valid_in_ra: list[str] = []
    revoked_in_ra_active_at_ca: list[str] = []
    absent_from_ca: list[str] = []

    for serial, ra_record in ra_records.items():
        ca_record = ca_records.get(serial)
        if ca_record is None:
            absent_from_ca.append(serial)
            continue
        if ra_record.must_be_revoked == ca_record.revoked:
            in_sync.append(serial)
        elif ca_record.revoked:
            revoked_at_ca_valid_in_ra.append(serial)
        else:
            revoked_in_ra_active_at_ca.append(serial)

    return _ReconciliationResult(
        in_sync=sorted(in_sync),
        revoked_at_ca_valid_in_ra=sorted(revoked_at_ca_valid_in_ra),
        revoked_in_ra_active_at_ca=sorted(revoked_in_ra_active_at_ca),
        ra_serials_absent_from_ca=sorted(absent_from_ca),
        parse_problems=list(parse_problems),
    )


def _json_report(result: _ReconciliationResult, ra_count: int, ca_count: int) -> str:
    payload = {
        "compared_serials": len(result.in_sync) + result.drift_count,
        "ra_certificate_count": ra_count,
        "ca_certificate_count": ca_count,
        "drift_count": result.drift_count,
        "coverage_complete": result.coverage_complete,
        "in_sync": result.in_sync,
        "revoked_at_ca_valid_in_ra": result.revoked_at_ca_valid_in_ra,
        "revoked_in_ra_active_at_ca": result.revoked_in_ra_active_at_ca,
        "ra_serials_absent_from_ca": result.ra_serials_absent_from_ca,
        "parse_problems": result.parse_problems,
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
        f"  RA serials not covered by the export: {len(result.ra_serials_absent_from_ca)}",
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

    if result.ra_serials_absent_from_ca:
        lines.append("")
        lines.append(
            "Serials the RA holds that the CA export does not mention. These "
            "were NOT checked; the export does not cover the RA's inventory:"
        )
        for serial in result.ra_serials_absent_from_ca:
            lines.append(f"  {serial}")

    if result.parse_problems:
        lines.append("")
        lines.append("Rows that could not be interpreted:")
        for problem in result.parse_problems:
            lines.append(f"  {problem}")

    lines.append("")
    if not result.coverage_complete:
        lines.append(
            "INDETERMINATE: the export does not account for every certificate "
            "the RA knows about, so 'in sync' cannot be established. Re-run the "
            "export against the correct CA and confirm certutil succeeded."
        )
    elif result.drift_count == 0:
        lines.append(
            f"PASS: revocation state is in sync across all {len(result.in_sync)} "
            "RA certificates."
        )
    else:
        lines.append("DRIFT: see the buckets above.")

    return "\n".join(lines)


def _run(
    db_path: Path,
    ca_export_path: Path,
    *,
    json_output: bool,
    ca_export_exit_code: int = 0,
) -> tuple[str, int]:
    """Perform the reconciliation and return (report, exit_code)."""
    if ca_export_exit_code != 0:
        raise ReconciliationError(
            f"certutil exited {ca_export_exit_code} producing the CA export; "
            "its contents cannot be trusted, so no comparison was attempted"
        )
    ra_records = _load_ra_records(db_path)
    ca_records, parse_problems = _parse_ca_export(ca_export_path)
    result = _reconcile(ra_records, ca_records, parse_problems)

    if json_output:
        report = _json_report(result, len(ra_records), len(ca_records))
    else:
        report = _human_report(result, len(ra_records), len(ca_records))

    if not result.coverage_complete:
        exit_code = 2
    elif result.drift_count:
        exit_code = 1
    else:
        exit_code = 0
    return report, exit_code


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)
    try:
        report, exit_code = _run(
            args.db,
            args.ca_export,
            json_output=args.json,
            ca_export_exit_code=args.ca_export_exit_code,
        )
    except Exception as exc:  # noqa: BLE001 - CLI top-level: clean error + exit code, not a traceback
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
