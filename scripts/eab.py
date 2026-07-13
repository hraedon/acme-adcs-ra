#!/usr/bin/env python3
"""EAB lifecycle helper for acme-adcs-ra (WI-011).

Mints a high-entropy EAB credential (kid + MAC key) and prints the env-var
lines an operator pastes into the locked-down ``acme-ra.env``. Never logs
secrets, never writes to disk, never accepts a MAC key as input (the MAC key
is always freshly generated).

The output uses the env-var format ``RAConfig`` actually loads:

* ``ACME_RA_EAB_ALLOWLIST`` is a JSON array of ``{"kid": "...", "mac_key": "..."}``
  objects (pydantic-settings nested-delimiter lists are not supported for
  ``list[EABEntry]``).
* ``ACME_RA_SAN_SCOPES__<KID>__DNS_PATTERNS`` is a JSON array of DNS patterns.

Treat the output like a password — never commit it, never paste it into chat
or a ticket, and ACL the env file to the gMSA + Administrators only.

Usage:
    python scripts/eab.py                 # mint a new credential (default)
    python scripts/eab.py --rotate OLD   # rotate, retiring OLD kid
    python scripts/eab.py audit --env acme-ra.env --db acme_ra.db
                                        # audit: kid → SAN scope → last-used

The ``audit`` subcommand is read-only: it loads the EAB allowlist + SAN scopes
from the env file (or ACME_RA_* environment), reads last-used timestamps from
the SQLite store, and prints a table. It never prints MAC key material.

This script holds no signing key and performs no enrollment — it is an
operator/admin tool only.

Copyright (c) 2026 acme-adcs-ra contributors. MIT licensed.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sqlite3
import sys
import uuid
from pathlib import Path

from acme_adcs_ra.config import RAConfig

# A warning banner prepended to every block of output so an operator cannot
# accidentally paste it into a committed file without seeing the warning.
_WARNING_BANNER = (
    "# !!! TREAT LIKE A PASSWORD — never commit, never paste into chat/tickets. !!!\n"
    "# !!! ACL the env file to the gMSA + Administrators only.                  !!!"
)

# Placeholder SAN patterns — operators replace these with their real domain
# before use. No work-domain identifiers in committed files (AGENTS.md).
_PLACEHOLDER_DNS_PATTERNS = '["*.WORK-DOMAIN.local"]'


def _new_kid() -> str:
    """Return a 128-bit kid as 32 hex chars (UUID4, dashes stripped)."""
    return uuid.uuid4().hex


def _new_mac_key() -> str:
    """Return a base64url-encoded MAC key from 32 random bytes (>=256 bits).

    ``secrets.token_urlsafe(32)`` returns base64url without padding, which is
    what the EAB JWS verification expects (``_base64url_decode`` tolerates
    missing padding).
    """
    return secrets.token_urlsafe(32)


def _format_env_block(kid: str, mac_key: str) -> str:
    """Return the env-var lines an operator pastes into ``acme-ra.env``.

    ``ACME_RA_EAB_ALLOWLIST`` is a JSON array (pydantic-settings loads it as
    ``list[EABEntry]``). ``ACME_RA_SAN_SCOPES__<KID>__DNS_PATTERNS`` is a JSON
    array of DNS patterns. Both values are unquoted so the embedded JSON
    double quotes are preserved verbatim.
    """
    eab_json = json.dumps([{"kid": kid, "mac_key": mac_key}], separators=(",", ":"))
    return (
        f"{_WARNING_BANNER}\n"
        f"ACME_RA_EAB_ALLOWLIST={eab_json}\n"
        f"ACME_RA_SAN_SCOPES__{kid}__DNS_PATTERNS={_PLACEHOLDER_DNS_PATTERNS}\n"
    )


def _print_credential() -> int:
    """Mint and print a new EAB credential. Returns 0 on success."""
    kid = _new_kid()
    mac_key = _new_mac_key()
    sys.stdout.write(_format_env_block(kid, mac_key))
    return 0


_ROTATE_CHECKLIST = """\
# Rotation checklist (retiring kid {old_kid}):
#   1. Mint the new credential above and merge it into ACME_RA_EAB_ALLOWLIST
#      in acme-ra.env as a JSON array (do not remove the old kid until the
#      cutover is complete — both must be valid during the cutover).
#   2. Add ACME_RA_SAN_SCOPES__<NEW_KID>__DNS_PATTERNS for the new account
#      (replace the placeholder).
#   3. Restart the RA app pool so the new env vars take effect.
#   4. Re-issue the ACME client's EAB credential (kid + MAC key) and point
#      the client (Certify the Web) at the new kid.
#   5. Confirm the new account can create an account + issue a test cert.
#   6. Once the old account is no longer used, remove the old kid's entry from
#      ACME_RA_EAB_ALLOWLIST and its SAN scope from acme-ra.env, restart the
#      RA, and confirm the old account can no longer create new orders
#      (existing orders/certs remain valid).
#   7. Keep the old kid's audit trail (account-created, certificate-issued)
#      for the standard audit retention period.
"""


def _print_rotation(old_kid: str) -> int:
    """Mint a new credential and print the rotation checklist for old_kid."""
    kid = _new_kid()
    mac_key = _new_mac_key()
    sys.stdout.write(_format_env_block(kid, mac_key))
    sys.stdout.write(_ROTATE_CHECKLIST.format(old_kid=old_kid))
    return 0


# ---------------------------------------------------------------------------
# audit subcommand (WI-018) — read-only kid → scope → last-used view
# ---------------------------------------------------------------------------


def _load_config(env_file: str | None) -> RAConfig:
    """Load RAConfig from *env_file*, or from the environment if None."""
    if env_file:
        # _env_file is a pydantic-settings runtime init kwarg; its stubs don't
        # expose it (same pattern as acme_adcs_ra.__main__).
        return RAConfig(_env_file=env_file)  # type: ignore[call-arg]
    return RAConfig()


def _last_used(db_path: Path, kid: str) -> str | None:
    """Return the most recent account/order timestamp for *kid*, or None.

    Queries the later of MAX(accounts.created_at) and MAX(orders.created_at)
    for the kid. Returns None if the kid has never been used or the database
    does not exist / is unreadable. Read-only: never writes to the store.
    """
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            acct_row = conn.execute(
                "SELECT MAX(created_at) FROM accounts WHERE eab_kid = ?", (kid,)
            ).fetchone()
            order_row = conn.execute(
                "SELECT MAX(o.created_at) FROM orders o "
                "JOIN accounts a ON o.account_id = a.id "
                "WHERE a.eab_kid = ?",
                (kid,),
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return None
    acct_ts = acct_row[0] if acct_row is not None else None
    order_ts = order_row[0] if order_row is not None else None
    candidates = [ts for ts in (acct_ts, order_ts) if ts]
    return max(candidates) if candidates else None


def _print_audit(env_file: str | None, db_path_override: str | None) -> int:
    """Print kid → SAN scope → last-used for every configured EAB credential.

    Never prints MAC key material — only kid, scope patterns, last-used
    timestamp, and flags. Read-only: does not write to the store.
    """
    config = _load_config(env_file)
    db_path = Path(db_path_override) if db_path_override else config.db_path

    entries = config.eab_allowlist
    if not entries:
        sys.stdout.write(
            "No EAB credentials configured (ACME_RA_EAB_ALLOWLIST is empty).\n"
        )
        return 0

    rows: list[tuple[str, str, str, str]] = []
    n_wildcard = 0
    n_no_scope = 0
    n_never = 0

    for entry in sorted(entries, key=lambda e: e.kid):
        kid = entry.kid
        kid_disp = f"{kid[:8]}..." if len(kid) > 8 else kid
        scope = config.san_scopes.get(kid)
        patterns = scope.dns_patterns if scope else []
        if patterns:
            scope_disp = ", ".join(patterns)
        else:
            scope_disp = "(no scope — fail-closed)"
        has_wildcard = any(p.startswith("*.") for p in patterns)
        last = _last_used(db_path, kid)
        last_disp = last if last is not None else "never"
        flags: list[str] = []
        if not patterns:
            flags.append("NO SCOPE")
            n_no_scope += 1
        elif has_wildcard:
            flags.append("WILDCARD")
            n_wildcard += 1
        if last is None:
            n_never += 1
        rows.append((kid_disp, scope_disp, last_disp, " ".join(flags)))

    headers = ("KID", "SAN SCOPE PATTERNS", "LAST USED", "FLAGS")
    widths = [
        max(len(headers[i]), max((len(row[i]) for row in rows), default=0))
        for i in range(len(headers))
    ]

    sys.stdout.write(
        "EAB scope audit — kid → SAN scope → last-used (no MAC keys shown)\n\n"
    )
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    sys.stdout.write(fmt.format(*headers) + "\n")
    sys.stdout.write("  ".join("-" * w for w in widths) + "\n")
    for row in rows:
        sys.stdout.write(fmt.format(*row) + "\n")
    sys.stdout.write("\n")
    sys.stdout.write(
        f"{len(rows)} kid(s): {n_wildcard} wildcard, {n_no_scope} no-scope, "
        f"{n_never} never-used.\n"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Mint an EAB credential (kid + MAC key) for acme-adcs-ra. "
            "Output is stdout-only — paste it into the locked-down acme-ra.env. "
            "Never commit the output; treat it like a password. "
            "Use the 'audit' subcommand for a read-only scope view."
        ),
    )
    parser.add_argument(
        "--rotate",
        metavar="OLD_KID",
        help=(
            "Rotate: mint a new credential and print a checklist for retiring "
            "OLD_KID. The old kid is NOT modified — you update acme-ra.env by "
            "hand per the checklist."
        ),
    )
    subparsers = parser.add_subparsers(
        dest="command",
        help="subcommands:",
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help=(
            "Read-only: show every configured kid, its SAN scope patterns, and "
            "last-used timestamp. Never prints MAC keys."
        ),
    )
    audit_parser.add_argument(
        "--env",
        metavar="ENV_FILE",
        default=None,
        help=(
            "Path to the acme-ra.env file to load EAB allowlist + SAN scopes "
            "from. If omitted, reads ACME_RA_* environment variables."
        ),
    )
    audit_parser.add_argument(
        "--db",
        metavar="DB_PATH",
        default=None,
        help=(
            "Path to the RA SQLite database for last-used timestamps. If "
            "omitted, uses ACME_RA_DB_PATH (or the default acme_ra.db)."
        ),
    )

    args = parser.parse_args(argv)

    if args.rotate:
        return _print_rotation(args.rotate)
    if args.command == "audit":
        return _print_audit(getattr(args, "env", None), getattr(args, "db", None))
    return _print_credential()


if __name__ == "__main__":
    sys.exit(main())
