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
from acme_adcs_ra.store import Store

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


# ---------------------------------------------------------------------------
# audit subcommand (WI-018) — read-only kid → scope → last-used view
# ---------------------------------------------------------------------------

_AUDIT_KIDS = [
    {
        "kid": "kid-001",
        "mac_key": "mac-AAA-do-not-leak-001",
        "patterns": ["*.WORK-DOMAIN.local", "srv01.WORK-DOMAIN.local"],
    },
    {
        "kid": "kid-002",
        "mac_key": "mac-BBB-do-not-leak-002",
        "patterns": ["exact.WORK-DOMAIN.local"],
    },
    {
        "kid": "kid-003",
        "mac_key": "mac-CCC-do-not-leak-003",
        "patterns": None,
    },
    {
        "kid": "kid-004",
        "mac_key": "mac-DDD-do-not-leak-004",
        "patterns": ["*.prod.WORK-DOMAIN.local"],
    },
]

_KID001_ACCOUNT_TS = "2026-01-01T00:00:00Z"
_KID001_ORDER_TS = "2026-01-03T00:00:00Z"
_KID002_ACCOUNT_TS = "2026-02-01T00:00:00Z"


def _make_audit_env_file(tmp_path: Path) -> Path:
    """Build an acme-ra.env with 4 kids for audit tests.

    kid-001: wildcard + exact patterns
    kid-002: exact-only pattern (no wildcard)
    kid-003: no SAN scope line (NO SCOPE — fail-closed)
    kid-004: wildcard pattern, never used
    """
    allowlist = json.dumps(
        [{"kid": k["kid"], "mac_key": k["mac_key"]} for k in _AUDIT_KIDS]
    )
    lines = [f"ACME_RA_EAB_ALLOWLIST={allowlist}"]
    for k in _AUDIT_KIDS:
        if k["patterns"] is not None:
            lines.append(
                f"ACME_RA_SAN_SCOPES__{k['kid']}__DNS_PATTERNS="
                f"{json.dumps(k['patterns'])}"
            )
    env_path = tmp_path / "acme-ra.env"
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return env_path


def _make_audit_db(tmp_path: Path) -> Path:
    """Create a test DB with accounts/orders for kid-001 and kid-002.

    kid-001: account (_KID001_ACCOUNT_TS) + order (_KID001_ORDER_TS)
             → last-used = _KID001_ORDER_TS (the max)
    kid-002: account (_KID002_ACCOUNT_TS) only → last-used = _KID002_ACCOUNT_TS
    kid-003 / kid-004: nothing → never
    """
    db_path = tmp_path / "acme_ra.db"
    store = Store(db_path)
    with store._connect() as conn:
        conn.execute(
            "INSERT INTO accounts (id, status, jwk_json, eab_kid, contact, created_at) "
            "VALUES ('acct-1', 'valid', '{}', 'kid-001', '[]', ?)",
            (_KID001_ACCOUNT_TS,),
        )
        conn.execute(
            "INSERT INTO accounts (id, status, jwk_json, eab_kid, contact, created_at) "
            "VALUES ('acct-2', 'valid', '{}', 'kid-002', '[]', ?)",
            (_KID002_ACCOUNT_TS,),
        )
        conn.execute(
            "INSERT INTO orders (id, account_id, status, identifiers, authorizations, "
            "finalize_url, certificate_url, expires, created_at, updated_at) "
            "VALUES ('order-1', 'acct-1', 'valid', '[]', '[]', 'http://x/f', NULL, "
            "'2026-12-31T00:00:00Z', ?, ?)",
            (_KID001_ORDER_TS, _KID001_ORDER_TS),
        )
    return db_path


def _run_audit(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Run the audit subcommand against the standard fixture env + db."""
    env = _make_audit_env_file(tmp_path)
    db = _make_audit_db(tmp_path)
    return _run(["audit", "--env", str(env), "--db", str(db)])


class TestEabAudit:
    def test_audit_lists_every_kid_with_scope_patterns(self, tmp_path: Path) -> None:
        result = _run_audit(tmp_path)
        for k in _AUDIT_KIDS:
            assert k["kid"] in result.stdout, f"{k['kid']} missing from audit output"
        assert "*.WORK-DOMAIN.local" in result.stdout
        assert "srv01.WORK-DOMAIN.local" in result.stdout
        assert "exact.WORK-DOMAIN.local" in result.stdout
        assert "*.prod.WORK-DOMAIN.local" in result.stdout

    def test_audit_never_prints_mac_key_material(self, tmp_path: Path) -> None:
        result = _run_audit(tmp_path)
        assert "do-not-leak" not in result.stdout
        assert "mac-AAA" not in result.stdout
        assert "mac-BBB" not in result.stdout
        assert "mac-CCC" not in result.stdout
        assert "mac-DDD" not in result.stdout
        assert "mac_key" not in result.stdout

    def test_audit_flags_wildcard_scopes(self, tmp_path: Path) -> None:
        result = _run_audit(tmp_path)
        assert "WILDCARD" in result.stdout

    def test_audit_last_used_from_store(self, tmp_path: Path) -> None:
        result = _run_audit(tmp_path)
        # kid-001's last-used is the order timestamp (max of account + order).
        assert _KID001_ORDER_TS in result.stdout
        # The account-only timestamp (not the max) must NOT appear.
        assert _KID001_ACCOUNT_TS not in result.stdout
        # kid-002's account timestamp appears (account-only, no order).
        assert _KID002_ACCOUNT_TS in result.stdout

    def test_audit_unused_kid_shows_never(self, tmp_path: Path) -> None:
        result = _run_audit(tmp_path)
        assert "never" in result.stdout

    def test_audit_no_scope_kid_flagged(self, tmp_path: Path) -> None:
        result = _run_audit(tmp_path)
        assert "NO SCOPE" in result.stdout

    def test_audit_exits_zero(self, tmp_path: Path) -> None:
        result = _run_audit(tmp_path)
        assert result.returncode == 0

    def test_audit_abbreviates_long_kid(self, tmp_path: Path) -> None:
        long_kid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        allowlist = json.dumps([{"kid": long_kid, "mac_key": "mac-xxx-do-not-leak"}])
        env_content = (
            f"ACME_RA_EAB_ALLOWLIST={allowlist}\n"
            f'ACME_RA_SAN_SCOPES__{long_kid}__DNS_PATTERNS='
            f'{json.dumps(["*.WORK-DOMAIN.local"])}\n'
        )
        env_path = tmp_path / "acme-ra.env"
        env_path.write_text(env_content, encoding="utf-8")
        db_path = tmp_path / "acme_ra.db"
        result = _run(["audit", "--env", str(env_path), "--db", str(db_path)])
        assert "a1b2c3d4..." in result.stdout
        assert long_kid not in result.stdout

    def test_audit_empty_allowlist(self, tmp_path: Path) -> None:
        env_path = tmp_path / "acme-ra.env"
        env_path.write_text("ACME_RA_EAB_ALLOWLIST=[]\n", encoding="utf-8")
        db_path = tmp_path / "acme_ra.db"
        result = _run(["audit", "--env", str(env_path), "--db", str(db_path)])
        assert "No EAB credentials configured" in result.stdout
        assert result.returncode == 0
