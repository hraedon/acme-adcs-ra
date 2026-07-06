"""Tests for the EAB lifecycle helper (WI-011).

Invokes ``scripts/eab.py`` via subprocess to verify the output format and
that secrets are stdout-only (never on stderr, never written to disk). Keeps
the tests simple and cross-platform.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from acme_adcs_ra.config import RAConfig

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "eab.py"

# base64url without padding: A-Z a-z 0-9 - _  (43 chars for 32 bytes)
_BASE64URL_43 = re.compile(r"^[A-Za-z0-9_-]{43}$")
# UUID4 hex without dashes: 32 hex chars
_KID_32HEX = re.compile(r"^[0-9a-f]{32}$")


def _run(args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *(args or [])],
        capture_output=True,
        text=True,
        check=True,
    )


def _extract_allowlist_dicts(stdout: str) -> list[dict[str, str]]:
    """Parse the ACME_RA_EAB_ALLOWLIST JSON array from the helper output."""
    line = next(line for line in stdout.splitlines() if line.startswith("ACME_RA_EAB_ALLOWLIST="))
    json_value = line.split("=", 1)[1]
    return json.loads(json_value)


def _extract_san_line(stdout: str, kid: str) -> str:
    """Return the ACME_RA_SAN_SCOPES__<KID>__DNS_PATTERNS line."""
    return next(
        line
        for line in stdout.splitlines()
        if line.startswith(f"ACME_RA_SAN_SCOPES__{kid}__DNS_PATTERNS=")
    )


class TestEabGenerate:
    def test_output_contains_32_hex_kid(self) -> None:
        result = _run()
        entries = _extract_allowlist_dicts(result.stdout)
        assert len(entries) == 1
        kid = entries[0]["kid"]
        assert _KID_32HEX.match(kid), f"kid {kid!r} is not 32 hex chars"

    def test_output_contains_base64url_mac_key(self) -> None:
        result = _run()
        entries = _extract_allowlist_dicts(result.stdout)
        assert len(entries) == 1
        mac_key = entries[0]["mac_key"]
        assert _BASE64URL_43.match(mac_key), (
            f"mac_key {mac_key!r} is not a 43-char base64url string (32 bytes)"
        )

    def test_output_contains_san_scopes_line_with_kid(self) -> None:
        result = _run()
        entries = _extract_allowlist_dicts(result.stdout)
        kid = entries[0]["kid"]
        san_line = _extract_san_line(result.stdout, kid)
        # Placeholder DNS patterns present (no real work-domain identifiers).
        assert "*.WORK-DOMAIN.local" in san_line

    def test_output_contains_password_warning(self) -> None:
        result = _run()
        assert "TREAT LIKE A PASSWORD" in result.stdout

    def test_secrets_not_on_stderr(self) -> None:
        result = _run()
        assert result.stderr == "", f"unexpected stderr: {result.stderr!r}"

    def test_each_run_produces_distinct_credential(self) -> None:
        r1 = _run()
        r2 = _run()
        k1 = _extract_allowlist_dicts(r1.stdout)[0]["kid"]
        k2 = _extract_allowlist_dicts(r2.stdout)[0]["kid"]
        assert k1 != k2, "each run must mint a fresh kid"

    def test_no_files_written(self, tmp_path: Path) -> None:
        """The helper must never write to disk — output is stdout-only."""
        before = set(p for p in tmp_path.rglob("*") if p.is_file())
        # Run from tmp_path so the CWD is observable (the script doesn't write,
        # but this guards against a future regression that does).
        subprocess.run(
            [sys.executable, str(_SCRIPT)],
            capture_output=True,
            text=True,
            check=True,
            cwd=str(tmp_path),
        )
        after = set(p for p in tmp_path.rglob("*") if p.is_file())
        assert before == after, "helper wrote files to disk (must be stdout-only)"

    def test_env_block_loads_into_raconfig(self, tmp_path: Path) -> None:
        """The helper's stdout must be parseable by RAConfig via an env file."""
        result = _run()
        env_path = tmp_path / "acme-ra.env"
        env_path.write_text(result.stdout, encoding="utf-8")

        cfg = RAConfig(_env_file=str(env_path))
        entries = cfg.eab_allowlist
        assert len(entries) == 1
        assert _KID_32HEX.match(entries[0].kid)
        assert entries[0].mac_key.get_secret_value()  # non-empty secret
        assert entries[0].kid in cfg.san_scopes
        assert "*.WORK-DOMAIN.local" in cfg.san_scopes[entries[0].kid].dns_patterns


class TestEabRotate:
    def test_rotate_mentions_old_kid_and_prints_new_one(self) -> None:
        old_kid = "0123456789abcdef0123456789abcdef"
        result = _run(["--rotate", old_kid])
        # The old kid is referenced in the checklist.
        assert old_kid in result.stdout, "rotation checklist must reference the old kid"
        # A new kid is minted (different from the old one).
        new_kid = _extract_allowlist_dicts(result.stdout)[0]["kid"]
        assert _KID_32HEX.match(new_kid)
        assert new_kid != old_kid, "rotation must mint a new kid"

    def test_rotate_prints_checklist(self) -> None:
        result = _run(["--rotate", "0123456789abcdef0123456789abcdef"])
        assert "Rotation checklist" in result.stdout
        assert "restart" in result.stdout.lower()

    def test_rotate_secrets_not_on_stderr(self) -> None:
        result = _run(["--rotate", "0123456789abcdef0123456789abcdef"])
        assert result.stderr == "", f"unexpected stderr: {result.stderr!r}"

    def test_rotate_new_kid_distinct_across_runs(self) -> None:
        old = "0123456789abcdef0123456789abcdef"
        r1 = _run(["--rotate", old])
        r2 = _run(["--rotate", old])
        k1 = _extract_allowlist_dicts(r1.stdout)[0]["kid"]
        k2 = _extract_allowlist_dicts(r2.stdout)[0]["kid"]
        assert k1 != k2

    def test_rotate_env_block_loads_into_raconfig(self, tmp_path: Path) -> None:
        """The rotation output must also be parseable by RAConfig."""
        old_kid = "0123456789abcdef0123456789abcdef"
        result = _run(["--rotate", old_kid])
        env_path = tmp_path / "acme-ra.env"
        env_path.write_text(result.stdout, encoding="utf-8")

        cfg = RAConfig(_env_file=str(env_path))
        entries = cfg.eab_allowlist
        assert len(entries) == 1
        new_kid = entries[0].kid
        assert new_kid != old_kid
        assert new_kid in cfg.san_scopes


class TestEabSanScopeValueParsable:
    def test_san_scope_value_is_valid_json_array(self) -> None:
        """The SAN scope line must contain a parseable JSON array so pydantic
        loads it as ``list[str]``."""
        result = _run()
        kid = _extract_allowlist_dicts(result.stdout)[0]["kid"]
        san_line = _extract_san_line(result.stdout, kid)
        json_value = san_line.split("=", 1)[1]
        patterns = json.loads(json_value)
        assert patterns == ["*.WORK-DOMAIN.local"]
