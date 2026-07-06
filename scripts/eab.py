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

This script holds no signing key and performs no enrollment — it is an
operator/admin tool only.

Copyright (c) 2026 acme-adcs-ra contributors. MIT licensed.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import uuid

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Mint an EAB credential (kid + MAC key) for acme-adcs-ra. "
            "Output is stdout-only — paste it into the locked-down acme-ra.env. "
            "Never commit the output; treat it like a password."
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
    args = parser.parse_args(argv)

    if args.rotate:
        return _print_rotation(args.rotate)
    return _print_credential()


if __name__ == "__main__":
    sys.exit(main())
