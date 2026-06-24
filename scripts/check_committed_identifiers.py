"""Mechanical gate against committing work-domain identifiers.

The forbidden identifier list is supplied at run time via the
``ACME_RA_FORBIDDEN_IDENTIFIERS`` environment variable (whitespace-separated)
so the denylist itself never lands in the repository. The gate is a no-op when
the variable is empty or unset. In CI it is wired to a repository secret.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

MIN_IDENTIFIER_LENGTH = 4
_BINARY_SNIFF_LEN = 8192
_SKIP_DIRS = frozenset({"samples", ".venv"})

_ENV_VAR = "ACME_RA_FORBIDDEN_IDENTIFIERS"


@dataclass(frozen=True)
class Violation:
    identifier: str
    path: Path
    line_number: int
    line: str


def _filter_identifiers(identifiers: frozenset[str]) -> frozenset[str]:
    """Lowercase, strip, and drop empty or short identifiers."""
    return frozenset(
        token.lower()
        for token in (i.strip() for i in identifiers)
        if len(token) >= MIN_IDENTIFIER_LENGTH
    )


def parse_identifier_set(raw: str) -> frozenset[str]:
    """Build a normalized set of identifiers from a whitespace-separated string."""
    return _filter_identifiers(frozenset(raw.split()))


def scan_text(text: str, identifiers: frozenset[str]) -> Iterator[Violation]:
    """Yield a violation for every occurrence of one of *identifiers*.

    The match is case-insensitive and counts any substring occurrence; real
    identifiers such as ``WORK-DOMAIN`` can legitimately appear inside longer
    tokens.
    """
    identifiers = _filter_identifiers(identifiers)
    if not identifiers:
        return
    for line_number, line in enumerate(text.splitlines(), start=1):
        lower = line.lower()
        for identifier in identifiers:
            start = 0
            while True:
                offset = lower.find(identifier, start)
                if offset == -1:
                    break
                yield Violation(
                    identifier=identifier,
                    path=Path("."),
                    line_number=line_number,
                    line=line,
                )
                start = offset + len(identifier)


def _sniff_encoding(chunk: bytes) -> str | None:
    """Return the text encoding if *chunk* starts with a known BOM, else None."""
    if chunk.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if chunk.startswith(b"\xfe\xff"):
        return "utf-16-be"
    if chunk.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return None


def _is_binary(chunk: bytes) -> bool:
    """Heuristic: null byte present without a recognized text BOM → binary."""
    if _sniff_encoding(chunk) is not None:
        return False
    return b"\x00" in chunk


def scan_files(identifiers: frozenset[str], paths: list[Path]) -> list[Violation]:
    """Scan every readable text file in *paths* for forbidden identifiers.

    UTF-16 files (common in Windows tooling output) are detected via BOM and
    decoded correctly rather than misclassified as binary by the null-byte
    heuristic.
    """
    violations: list[Violation] = []
    for path in paths:
        try:
            with path.open("rb") as f:
                chunk = f.read(_BINARY_SNIFF_LEN)
        except OSError:
            continue
        if _is_binary(chunk):
            continue
        encoding = _sniff_encoding(chunk) or "utf-8"
        try:
            text = path.read_text(encoding=encoding, errors="replace")
        except OSError:
            continue
        for violation in scan_text(text, identifiers):
            violations.append(replace(violation, path=path))
    return violations


def collect_tracked_paths() -> list[Path]:
    """Return tracked file paths from ``git ls-files``, excluding obvious skips."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
    )
    paths: list[Path] = []
    for raw in result.stdout.split("\0"):
        if not raw:
            continue
        path = Path(raw)
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        paths.append(path)
    return paths


def print_report(violations: list[Violation]) -> None:
    violations.sort(key=lambda v: (str(v.path), v.line_number, v.identifier))
    print("Committed identifier violations detected:", file=sys.stderr)
    for v in violations:
        print(f"  {v.path}:{v.line_number}: {v.identifier!r}", file=sys.stderr)
        print(f"      {v.line.rstrip()}", file=sys.stderr)
    print(f"\nTotal: {len(violations)} violation(s)", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Gate that prevents committing forbidden domain identifiers.",
    )
    parser.parse_args(argv)

    raw = os.environ.get(_ENV_VAR, "")
    if not raw.strip():
        print(
            f"{_ENV_VAR} is empty or unset; skipping identifier gate.",
            file=sys.stderr,
        )
        return 0

    identifiers = parse_identifier_set(raw)
    if not identifiers:
        print(
            f"{_ENV_VAR} contained no usable identifiers (minimum "
            f"length is {MIN_IDENTIFIER_LENGTH} characters); skipping gate.",
            file=sys.stderr,
        )
        return 0

    paths = collect_tracked_paths()
    violations = scan_files(identifiers, paths)
    if violations:
        print_report(violations)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
