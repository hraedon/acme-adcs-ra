#!/usr/bin/env python3
"""Check or update the pinned InstallVerifyLib.ps1 digest in each entry point.

Five privileged PowerShell entry points authenticate ``scripts/lib/
InstallVerifyLib.ps1`` against a digest literal before executing it, because
that library is the code which authenticates the privileged script tree and so
cannot authenticate itself. The consequence is that **editing the library
invalidates all five pins at once**, and a stale pin does not fail quietly: the
entry point refuses to run at all.

``tests/pester/InstallVerify.Tests.ps1`` catches a stale pin, but only once the
suite runs -- which for most contributors means after a push, on a red CI job,
with no obvious remedy in the failure text. This script is the remedy.

    python scripts/lib_digest.py            # check; exit 1 if any pin is stale
    python scripts/lib_digest.py --write    # rewrite every stale pin

The digest MUST match what the entry points compute at run time: strict UTF-8,
CRLF and lone CR normalised to LF, SHA-256, lowercase hex. Normalising line
endings is what lets a CRLF checkout on Windows produce the same digest as an
LF checkout on Linux; if you change the recipe here, change it in all five
entry points and in the Pester test in the same commit.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HELPER = REPO_ROOT / "scripts" / "lib" / "InstallVerifyLib.ps1"
ENTRY_POINTS = (
    "Revoke-Cert.ps1",
    "Set-OfficerRights.ps1",
    "Sync-Revocations.ps1",
    "Register-MaintenanceTasks.ps1",
    "Reconcile-Revocation.ps1",
)
PIN_RE = re.compile(r"(\$installVerifyExpectedSha256 = ')([0-9a-f]{64})(')")


def canonical_digest(path: Path) -> str:
    """SHA-256 over strict-UTF-8, LF-normalised bytes — the run-time recipe."""
    raw = path.read_bytes()
    text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite stale pins in place instead of only reporting them",
    )
    args = parser.parse_args(argv)

    if not HELPER.is_file():
        print(f"error: helper not found at {HELPER}", file=sys.stderr)
        return 2

    expected = canonical_digest(HELPER)
    stale: list[str] = []
    missing: list[str] = []

    for name in ENTRY_POINTS:
        path = REPO_ROOT / "scripts" / name
        if not path.is_file():
            missing.append(name)
            continue
        # newline="" so CRLF survives into the string. Without it, read_text's
        # universal-newline translation turns every CRLF into \n in memory, and
        # writing back with newline="" then emits LF -- rewriting a Windows
        # checkout's entire file to change one 64-character hex string.
        # Measured before the fix: 514 CRLF lines became 514 LF lines.
        #
        # The Linux round-trip check that "proved" this tool safe could not see
        # it, because an LF file stays LF whatever the newline handling does.
        # A check whose failure mode is silence proves nothing.
        with path.open("r", encoding="utf-8", newline="") as handle:
            text = handle.read()
        match = PIN_RE.search(text)
        if match is None:
            # An entry point that lost its pin is a worse problem than a stale
            # one: it would load the helper without authenticating it.
            missing.append(name)
            continue
        if match.group(2) == expected:
            continue
        stale.append(name)
        if args.write:
            path.write_text(
                PIN_RE.sub(rf"\g<1>{expected}\g<3>", text, count=1),
                encoding="utf-8",
                newline="",
            )

    if missing:
        for name in missing:
            print(
                f"MISSING {name}: no $installVerifyExpectedSha256 pin found. "
                "Every privileged entry point must authenticate the helper "
                "before executing it.",
                file=sys.stderr,
            )
        return 2

    if not stale:
        print(f"all {len(ENTRY_POINTS)} pins match {expected}")
        return 0

    if args.write:
        for name in stale:
            print(f"updated {name} -> {expected}")
        print(
            "\nRe-run the Pester suite before committing: the pin and the "
            "helper ship as one authenticated release set."
        )
        return 0

    for name in stale:
        print(f"STALE {name}: expected {expected}", file=sys.stderr)
    print(
        "\nRun `python scripts/lib_digest.py --write` to update them. Until "
        "then these entry points will refuse to run.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
