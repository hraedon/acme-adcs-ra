"""SQLite persistence for accounts, orders, authorizations, certificates, and audit.

The store is intentionally plain sqlite3 — no ORM, no migrations beyond
``CREATE TABLE IF NOT EXISTS``.  It is part of the issuance path and therefore
carries no signing primitives.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Sequence

from cryptography import x509

from acme_adcs_ra.jws import jwk_thumbprint


# ---------------------------------------------------------------------------
# Status enums — replace bare string literals throughout the codebase
# ---------------------------------------------------------------------------


class OrderStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"
    REVOKED = "revoked"


class CertStatus(StrEnum):
    VALID = "valid"
    REVOKED = "revoked"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return a UTC RFC 3339 / ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_iso_plus(seconds: int) -> str:
    """Return a UTC RFC 3339 timestamp ``seconds`` in the future."""
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


_ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _parse_iso(ts: str) -> datetime:
    """Parse a UTC RFC 3339 timestamp produced by ``_now_iso``.

    Only accepts the ``%Y-%m-%dT%H:%M:%SZ`` format that ``_now_iso`` emits.
    Returns a timezone-aware datetime (UTC). Raises ``ValueError`` if *ts*
    does not match.
    """
    return datetime.strptime(ts, _ISO_FORMAT).replace(tzinfo=timezone.utc)


def is_expired(expires: str, *, now: datetime | None = None) -> bool:
    """Return True if an RFC 3339 ``expires`` timestamp is at or past ``now``.

    Used to enforce RFC 8555 §7.1.6: an order whose ``expires`` is in the past
    MUST NOT be finalized, and the server SHOULD transition it to ``invalid``.
    """
    return _parse_iso(expires) <= (now or datetime.now(timezone.utc))


def _dump_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))


def _load_json(text: str | None) -> Any:
    if text is None:
        return None
    return json.loads(text)


def _serial_from_pem(cert_pem: str) -> str:
    """Return the certificate serial number as uppercase hex."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    return format(cert.serial_number, "x").upper()


NONCE_TTL_SECONDS: int = 1800  # 30 minutes
NONCE_GC_PROBABILITY: int = 100  # 1-in-N chance to clean expired nonces on create


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccountRecord:
    id: str
    status: str
    jwk_json: str
    eab_kid: str
    created_at: str
    contact: list[str]
    orders_url: str | None = None


@dataclass(frozen=True)
class OrderRecord:
    id: str
    account_id: str
    status: str
    identifiers: list[dict[str, str]]
    authorizations: list[str]
    finalize_url: str
    certificate_url: str | None
    expires: str
    created_at: str
    updated_at: str
    processing_started_at: str | None = None


@dataclass(frozen=True)
class AuthorizationRecord:
    id: str
    account_id: str
    order_id: str
    identifier: dict[str, str]
    status: str
    expires: str
    challenges: list[ChallengeRecord]


@dataclass(frozen=True)
class ChallengeRecord:
    id: str
    authz_id: str
    type: str
    status: str
    token: str
    url: str
    validated_at: str | None


@dataclass(frozen=True)
class CertificateRecord:
    id: str
    order_id: str
    account_id: str
    cert_pem: str
    chain_pem: list[str]
    template: str
    requester: str
    issued_at: str
    metadata: dict[str, str]
    serial_number: str | None = None
    status: str = "valid"
    revocation_reason: int | None = None
    revoked_at: str | None = None


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    jwk_json TEXT NOT NULL,
    eab_kid TEXT NOT NULL,
    contact TEXT NOT NULL,  -- JSON array
    created_at TEXT NOT NULL,
    jwk_thumbprint TEXT  -- RFC 7638 account-key identity, for dedup
);
CREATE INDEX IF NOT EXISTS idx_accounts_thumbprint
    ON accounts (jwk_thumbprint);

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonces_created_at
    ON nonces (created_at);

CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    status TEXT NOT NULL,
    identifiers TEXT NOT NULL,  -- JSON array
    authorizations TEXT NOT NULL,  -- JSON array of URLs
    finalize_url TEXT NOT NULL,
    certificate_url TEXT,
    expires TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    processing_started_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_orders_status_created
    ON orders (status, created_at);

CREATE TABLE IF NOT EXISTS authorizations (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    order_id TEXT NOT NULL REFERENCES orders(id),
    identifier TEXT NOT NULL,  -- JSON object
    status TEXT NOT NULL,
    expires TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    authz_id TEXT NOT NULL REFERENCES authorizations(id),
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    token TEXT NOT NULL,
    url TEXT NOT NULL,
    validated_at TEXT
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES orders(id),
    account_id TEXT NOT NULL REFERENCES accounts(id),
    cert_pem TEXT NOT NULL,
    chain_pem TEXT NOT NULL,  -- JSON array
    template TEXT NOT NULL,
    requester TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    metadata TEXT NOT NULL,  -- JSON object
    serial_number TEXT,
    status TEXT NOT NULL DEFAULT 'valid',
    revocation_reason TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    account_id TEXT,
    order_id TEXT,
    sans TEXT,  -- JSON array
    template TEXT,
    requester TEXT,
    outcome TEXT NOT NULL,
    details TEXT NOT NULL,  -- JSON object
    timestamp TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class Store:
    """SQLite-backed RA store."""

    def __init__(
        self,
        db_path: Path,
        order_expiry_seconds: int = 3600,
        max_authorizations_per_order: int = 50,
    ) -> None:
        self._db_path = db_path
        self._order_expiry_seconds = order_expiry_seconds
        self._max_authorizations_per_order = max_authorizations_per_order
        # Ensure parent directory exists so SQLite can create the file.
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        # FastAPI runs sync handlers in a threadpool, so issuance requests open
        # concurrent connections. Without a busy timeout, a second writer hits
        # "database is locked" immediately and surfaces as a 500 instead of the
        # graceful CAS-loss path; WAL lets readers proceed alongside one writer.
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._migrate_certificates_table(conn)
            self._migrate_accounts_table(conn)
            self._migrate_orders_table(conn)
            self._migrate_authorizations_table(conn)

    def _migrate_accounts_table(self, conn: sqlite3.Connection) -> None:
        """Add the jwk_thumbprint column to accounts if missing (dedup support)."""
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(accounts)").fetchall()
        }
        if "jwk_thumbprint" not in columns:
            conn.execute("ALTER TABLE accounts ADD COLUMN jwk_thumbprint TEXT")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_accounts_thumbprint "
                "ON accounts (jwk_thumbprint)"
            )

    def _migrate_certificates_table(self, conn: sqlite3.Connection) -> None:
        """Add revocation columns to certificates if they are missing."""
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(certificates)"
            ).fetchall()
        }
        for column, ddl in (
            ("serial_number", "TEXT"),
            ("status", "TEXT NOT NULL DEFAULT 'valid'"),
            ("revocation_reason", "TEXT"),
            ("revoked_at", "TEXT"),
        ):
            if column not in columns:
                conn.execute(f"ALTER TABLE certificates ADD COLUMN {column} {ddl}")

    def _migrate_orders_table(self, conn: sqlite3.Connection) -> None:
        """Add processing_started_at column to orders if missing."""
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(orders)"
            ).fetchall()
        }
        if "processing_started_at" not in columns:
            conn.execute("ALTER TABLE orders ADD COLUMN processing_started_at TEXT")

    def _migrate_authorizations_table(self, conn: sqlite3.Connection) -> None:
        """Drop the dead challenges JSON column from authorizations if present.

        WI-005: the column was written but never read — challenges are sourced
        from the challenges table via JOIN in get_authorization. SQLite 3.35.0+
        supports ALTER TABLE DROP COLUMN; older versions leave it as harmless
        dead weight.
        """
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(authorizations)"
            ).fetchall()
        }
        if "challenges" in columns:
            try:
                conn.execute("ALTER TABLE authorizations DROP COLUMN challenges")
            except sqlite3.OperationalError:
                pass

    def _certificate_from_row(self, row: sqlite3.Row) -> CertificateRecord:
        reason_raw = row["revocation_reason"]
        revocation_reason = int(reason_raw) if reason_raw is not None else None
        return CertificateRecord(
            id=row["id"],
            order_id=row["order_id"],
            account_id=row["account_id"],
            cert_pem=row["cert_pem"],
            chain_pem=_load_json(row["chain_pem"]),
            template=row["template"],
            requester=row["requester"],
            issued_at=row["issued_at"],
            metadata=_load_json(row["metadata"]),
            serial_number=row["serial_number"],
            status=row["status"],
            revocation_reason=revocation_reason,
            revoked_at=row["revoked_at"],
        )

    def _account_from_row(self, row: sqlite3.Row) -> AccountRecord:
        return AccountRecord(
            id=row["id"],
            status=row["status"],
            jwk_json=row["jwk_json"],
            eab_kid=row["eab_kid"],
            created_at=row["created_at"],
            contact=_load_json(row["contact"]) or [],
        )

    def _order_from_row(self, row: sqlite3.Row) -> OrderRecord:
        return OrderRecord(
            id=row["id"],
            account_id=row["account_id"],
            status=row["status"],
            identifiers=_load_json(row["identifiers"]),
            authorizations=_load_json(row["authorizations"]),
            finalize_url=row["finalize_url"],
            certificate_url=row["certificate_url"],
            expires=row["expires"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            processing_started_at=row["processing_started_at"],
        )


    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def create_account(
        self,
        *,
        jwk: dict[str, Any],
        eab_kid: str,
        status: str = "valid",
        contact: Sequence[str] | None = None,
    ) -> AccountRecord:
        account_id = uuid.uuid4().hex
        created_at = _now_iso()
        contact_list = list(contact or [])
        thumbprint = jwk_thumbprint(jwk)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO accounts
                    (id, status, jwk_json, eab_kid, contact, created_at, jwk_thumbprint)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account_id,
                    status,
                    _dump_json(jwk),
                    eab_kid,
                    _dump_json(contact_list),
                    created_at,
                    thumbprint,
                ),
            )
        return AccountRecord(
            id=account_id,
            status=status,
            jwk_json=_dump_json(jwk),
            eab_kid=eab_kid,
            created_at=created_at,
            contact=contact_list,
        )

    def get_account(self, account_id: str) -> AccountRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
        if row is None:
            return None
        return self._account_from_row(row)

    def get_account_by_jwk(self, jwk: dict[str, Any]) -> AccountRecord | None:
        """Return the account whose key matches this JWK (RFC 7638 thumbprint).

        Used to make newAccount idempotent (RFC 8555 §7.3): the same account key
        returns the existing account rather than creating a duplicate.
        """
        thumbprint = jwk_thumbprint(jwk)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE jwk_thumbprint = ?", (thumbprint,)
            ).fetchone()
        if row is None:
            return None
        return self._account_from_row(row)

    def update_account_key(
        self, account_id: str, new_jwk: dict[str, Any]
    ) -> None:
        """Replace an account's public key (RFC 8555 §7.3.5 keyChange).

        Updates both ``jwk_json`` and the ``jwk_thumbprint`` index so
        subsequent JWS verifications use the new key and the old key is
        no longer accepted. The thumbprint is recomputed from ``new_jwk``
        so the caller cannot desync the index from the stored JWK.
        """
        thumbprint = jwk_thumbprint(new_jwk)
        with self._connect() as conn:
            conn.execute(
                "UPDATE accounts SET jwk_json = ?, jwk_thumbprint = ? WHERE id = ?",
                (_dump_json(new_jwk), thumbprint, account_id),
            )

    # ------------------------------------------------------------------
    # Nonces
    # ------------------------------------------------------------------

    def create_nonce(self) -> str:
        nonce = uuid.uuid4().hex + uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO nonces (nonce, created_at) VALUES (?, ?)",
                (nonce, now_str),
            )
            # Probabilistic GC safety net: clean expired nonces on ~1% of
            # creations so the table doesn't grow unbounded if the admin
            # cron is missed (threat-model §4.G). The admin endpoint remains
            # the primary cleanup path; this is a belt-and-suspenders fallback.
            # Bounded by LIMIT to avoid holding the writer lock too long.
            if uuid.uuid4().int % NONCE_GC_PROBABILITY == 0:
                cutoff = (now - timedelta(seconds=NONCE_TTL_SECONDS)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                conn.execute(
                    "DELETE FROM nonces WHERE rowid IN "
                    "(SELECT rowid FROM nonces WHERE created_at < ? LIMIT 5000)",
                    (cutoff,),
                )
        return nonce

    def consume_nonce(self, nonce: str) -> bool:
        """Return True if the nonce existed and was removed (not replayed)."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM nonces WHERE nonce = ?", (nonce,))
            return cursor.rowcount == 1

    def cleanup_expired_nonces(self) -> int:
        """Delete all nonces older than NONCE_TTL_SECONDS. Returns count deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=NONCE_TTL_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM nonces WHERE created_at < ?", (cutoff,))
            return cursor.rowcount

    # ------------------------------------------------------------------
    # Orders
    # ------------------------------------------------------------------

    def get_order(self, order_id: str) -> OrderRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM orders WHERE id = ?", (order_id,)
            ).fetchone()
        if row is None:
            return None
        return self._order_from_row(row)

    def update_order_status(
        self,
        order_id: str,
        status: str,
        *,
        certificate_url: str | None = None,
    ) -> None:
        updated_at = _now_iso()
        with self._connect() as conn:
            if certificate_url is not None:
                conn.execute(
                    """
                    UPDATE orders
                    SET status = ?, certificate_url = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (status, certificate_url, updated_at, order_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE orders
                    SET status = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (status, updated_at, order_id),
                )

    def transition_order_to_processing(self, order_id: str) -> bool:
        """Atomically transition an order from 'ready' to 'processing'.

        M3: prevents double-issuance on concurrent or retried finalize calls.
        Returns True if the transition succeeded, False if the order was not
        in 'ready' state (already processing/valid or other).
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, updated_at = ?, processing_started_at = ? "
                "WHERE id = ? AND status = ?",
                (OrderStatus.PROCESSING, updated_at, updated_at, order_id,
                 OrderStatus.READY),
            )
            return cursor.rowcount == 1

    def transition_pending_to_ready(self, order_id: str) -> bool:
        """Atomically transition an order from 'pending' to 'ready'.

        M-2: CAS-guarded on ``status = 'pending'`` so a concurrent finalize
        that has already moved the order to ``processing`` (or any other state)
        cannot be clobbered back to ``ready`` by a late/racing challenge
        validation. Clears ``processing_started_at`` (it should already be
        NULL for a pending order, but the clear is explicit for safety).
        Returns True if the transition was applied, False if the order was no
        longer ``pending`` (the caller simply returns — the order has moved on).
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, processing_started_at = NULL, "
                "updated_at = ? WHERE id = ? AND status = ?",
                (OrderStatus.READY, updated_at, order_id, OrderStatus.PENDING),
            )
            return cursor.rowcount == 1

    def transition_processing_to_ready(self, order_id: str) -> bool:
        """Atomically transition an order from 'processing' back to 'ready'.

        Operator-initiated reconciliation of an order wedged in 'processing'
        (e.g. after a crash mid-enrollment where no certificate was recorded).
        CAS-guarded on ``status = 'processing'`` so it can never clobber a live
        enrollment or a concurrent transition. Clears ``processing_started_at``.
        Returns True if the transition was applied.

        **Safety:** the caller (an operator via the admin endpoint) MUST first
        confirm from the ADCS CA database that no certificate was issued for
        this order's request — otherwise re-finalizing would double-issue.
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, processing_started_at = NULL, "
                "updated_at = ? WHERE id = ? AND status = ?",
                (OrderStatus.READY, updated_at, order_id, OrderStatus.PROCESSING),
            )
            return cursor.rowcount == 1

    def transition_processing_to_valid(
        self, order_id: str, certificate_url: str
    ) -> bool:
        """Atomically transition an order from 'processing' to 'valid'.

        Reconciliation for the case where enrollment succeeded and a certificate
        row was recorded, but the order's status flip was missed (e.g. a crash
        between ``create_certificate`` and ``update_order_status``). CAS-guarded
        on ``status = 'processing'``. Returns True if the transition was applied.
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, certificate_url = ?, "
                "processing_started_at = NULL, updated_at = ? "
                "WHERE id = ? AND status = ?",
                (OrderStatus.VALID, certificate_url, updated_at, order_id,
                 OrderStatus.PROCESSING),
            )
            return cursor.rowcount == 1

    def transition_active_to_invalid(self, order_id: str) -> bool:
        """Atomically transition a still-active order to 'invalid'.

        CAS-guarded on ``status IN ('pending', 'ready')`` so it can never clobber
        an order a concurrent finalize has already moved to ``processing`` or
        ``valid`` (the double-issuance guard). Used by finalize's expiry check
        (RFC 8555 §7.1.6) so a stale snapshot cannot flip a now-processing order
        to ``invalid`` out from under a live enrollment. Returns True if applied.
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, updated_at = ? "
                "WHERE id = ? AND status IN (?, ?)",
                (OrderStatus.INVALID, updated_at, order_id,
                 OrderStatus.PENDING, OrderStatus.READY),
            )
            return cursor.rowcount == 1

    def transition_to_revoked(self, order_id: str) -> bool:
        """Atomically transition an order to 'revoked' (CAS-guarded).

        WI-003: replaces the non-CAS ``update_order_status(order_id, "revoked")``
        call in ``revoke_cert``. CAS-guarded on ``status IN ('valid', 'processing')``
        so it can never clobber an order a concurrent finalize has moved to
        ``invalid`` or that is still ``pending``/``ready`` (no cert to revoke).
        The ``valid``→``revoked`` path is the normal case; ``processing``→``revoked``
        handles the crash-window where the cert was recorded but the status flip
        was missed (same window as ``transition_processing_to_valid``). Returns
        True if the transition was applied.
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, updated_at = ? "
                "WHERE id = ? AND status IN (?, ?)",
                (OrderStatus.REVOKED, updated_at, order_id,
                 OrderStatus.VALID, OrderStatus.PROCESSING),
            )
            return cursor.rowcount == 1

    def list_orders_by_status(
        self, status: str, *, limit: int = 100
    ) -> list[OrderRecord]:
        """Return orders with the given status, newest first.

        Used by the admin monitoring endpoint to list orders stuck in
        ``processing`` (threat-model §4.D: monitor time-in-``processing`` p99).
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM orders WHERE status = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return [self._order_from_row(row) for row in rows]

    def count_recent_orders_by_kid(
        self,
        eab_kid: str,
        window_seconds: int,
        *,
        now: datetime | None = None,
    ) -> int:
        """Count orders created within the rolling window for a given EAB kid.

        WI-016: the rate-limit check counts orders across all ACME accounts
        that share the same EAB kid, so a leaked credential cannot evade the
        limit by creating multiple account keys. The window is computed from
        ``created_at`` timestamps in the store. Pass ``now`` for deterministic
        testing; production callers omit it (uses wall-clock UTC).
        """
        current = now or datetime.now(timezone.utc)
        cutoff = (current - timedelta(seconds=window_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM orders o "
                "JOIN accounts a ON o.account_id = a.id "
                "WHERE a.eab_kid = ? AND o.created_at >= ?",
                (eab_kid, cutoff),
            ).fetchone()
        return int(row[0])

    def count_all_recent_orders(
        self,
        window_seconds: int,
        *,
        now: datetime | None = None,
    ) -> int:
        """Count all orders created within the rolling window (global backstop).

        WI-016: a global ceiling that bounds total order creation across all
        accounts, independent of the per-kid limit.
        """
        current = now or datetime.now(timezone.utc)
        cutoff = (current - timedelta(seconds=window_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM orders WHERE created_at >= ?",
                (cutoff,),
            ).fetchone()
        return int(row[0])

    def sweep_expired_orders(self) -> int:
        """Transition every still-active expired order to 'invalid'.

        RFC 8555 §7.1.6: the server SHOULD move an expired order (and its
        authorizations) to ``invalid``. This sweep transitions the **order**
        rows; the order's authorization/challenge rows are left as-is (a
        follow-up — the invalid order can no longer be finalized, so the stale
        authz are unreachable, not a security gap). Only ``pending``/``ready``
        orders are swept — ``processing``/``valid``/``invalid``/``revoked`` are
        terminal or operator-reconcilable and are left alone. Returns the count
        transitioned.

        Intended to be driven by an external cron via the admin endpoint (the
        same operator pattern as ``cleanup_expired_nonces``); expiry is also
        enforced lazily at finalize so issuance can never proceed past expiry
        even between sweeps.
        """
        now = datetime.now(timezone.utc)
        now_str = _now_iso()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, expires FROM orders WHERE status IN (?, ?)",
                (OrderStatus.PENDING, OrderStatus.READY),
            ).fetchall()
            expired_ids = [
                row["id"] for row in rows
                if is_expired(row["expires"], now=now)
            ]
            if not expired_ids:
                return 0
            # Batch to stay under SQLite's default 999 host-parameter limit.
            total = 0
            for i in range(0, len(expired_ids), 900):
                batch = expired_ids[i:i + 900]
                placeholders = ",".join("?" for _ in batch)
                cursor = conn.execute(
                    f"UPDATE orders SET status = ?, updated_at = ? "
                    f"WHERE id IN ({placeholders}) AND status IN (?, ?)",
                    (OrderStatus.INVALID, now_str, *batch,
                     OrderStatus.PENDING, OrderStatus.READY),
                )
                total += cursor.rowcount
            return total

    def create_order_with_authz(
        self,
        *,
        account_id: str,
        identifiers: Sequence[dict[str, str]],
        challenge_url_fn: Callable[[str], str],
        authz_url_fn: Callable[[str], str],
        finalize_url_fn: Callable[[str], str],
    ) -> OrderRecord:
        """Create an order with authorizations and challenge URLs atomically.

        H5: replaces the former non-transactional sequence of create_order →
        create_authorization → update_challenge_url → raw SQL update.  The
        ``*_fn`` callbacks produce the URLs from IDs (the store does not know
        about the server's URL scheme).
        """
        order_id = uuid.uuid4().hex
        created_at = _now_iso()
        expires = _now_iso_plus(self._order_expiry_seconds)
        authz_urls: list[str] = []

        with self._connect() as conn:
            # Create the order row with placeholder authorizations — will be
            # updated in the same transaction below.
            conn.execute(
                """
                INSERT INTO orders
                (id, account_id, status, identifiers, authorizations, finalize_url,
                 certificate_url, expires, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    order_id,
                    account_id,
                    OrderStatus.PENDING,
                    _dump_json(list(identifiers)),
                    _dump_json([]),  # placeholder
                    finalize_url_fn(order_id),
                    None,
                    expires,
                    created_at,
                    created_at,
                ),
            )

            for identifier in identifiers:
                authz_id = uuid.uuid4().hex
                challenge_id = uuid.uuid4().hex
                token = uuid.uuid4().hex + uuid.uuid4().hex
                challenge_url = challenge_url_fn(challenge_id)

                # Insert challenge first (FK dependency).
                conn.execute(
                    """
                    INSERT INTO challenges
                    (id, authz_id, type, status, token, url, validated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (challenge_id, authz_id, "http-01", "pending", token, challenge_url, None),
                )

                # Insert authorization — challenges are in the challenges table (SSoT).
                conn.execute(
                    """
                    INSERT INTO authorizations
                    (id, account_id, order_id, identifier, status, expires)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        authz_id,
                        account_id,
                        order_id,
                        _dump_json(identifier),
                        "pending",
                        expires,
                    ),
                )

                authz_urls.append(authz_url_fn(authz_id))

            # Update the order row with the real authz URLs.
            conn.execute(
                "UPDATE orders SET authorizations = ? WHERE id = ?",
                (_dump_json(authz_urls), order_id),
            )

        return OrderRecord(
            id=order_id,
            account_id=account_id,
            status=OrderStatus.PENDING,
            identifiers=list(identifiers),
            authorizations=authz_urls,
            finalize_url=finalize_url_fn(order_id),
            certificate_url=None,
            expires=expires,
            created_at=created_at,
            updated_at=created_at,
        )

    # ------------------------------------------------------------------
    # Authorizations + Challenges
    # ------------------------------------------------------------------

    def get_authorization(self, authz_id: str) -> AuthorizationRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM authorizations WHERE id = ?", (authz_id,)
            ).fetchone()
            if row is None:
                return None
            # H4: challenges table is the single source of truth — derive the
            # challenge list by JOINing rather than reading the JSON blob.
            challenge_rows = conn.execute(
                "SELECT * FROM challenges WHERE authz_id = ?", (authz_id,)
            ).fetchall()
            challenges = [
                ChallengeRecord(
                    id=cr["id"],
                    authz_id=cr["authz_id"],
                    type=cr["type"],
                    status=cr["status"],
                    token=cr["token"],
                    url=cr["url"],
                    validated_at=cr["validated_at"],
                )
                for cr in challenge_rows
            ]
        return AuthorizationRecord(
            id=row["id"],
            account_id=row["account_id"],
            order_id=row["order_id"],
            identifier=_load_json(row["identifier"]),
            status=row["status"],
            expires=row["expires"],
            challenges=challenges,
        )

    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM challenges WHERE id = ?", (challenge_id,)
            ).fetchone()
        if row is None:
            return None
        return ChallengeRecord(
            id=row["id"],
            authz_id=row["authz_id"],
            type=row["type"],
            status=row["status"],
            token=row["token"],
            url=row["url"],
            validated_at=row["validated_at"],
        )

    def update_authorization_status(
        self,
        authz_id: str,
        status: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE authorizations SET status = ? WHERE id = ?",
                (status, authz_id),
            )

    def update_challenge_status(
        self,
        challenge_id: str,
        status: str,
        *,
        validated_at: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE challenges
                SET status = ?, validated_at = ?
                WHERE id = ?
                """,
                (status, validated_at, challenge_id),
            )

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    def get_certificate_by_order(self, order_id: str) -> CertificateRecord | None:
        """Return the certificate for an order, if one exists.

        M3: used by the finalize path to detect double-issuance — if a
        certificate already exists for this order, do not re-enroll.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE order_id = ?", (order_id,)
            ).fetchone()
        if row is None:
            return None
        return self._certificate_from_row(row)

    def create_certificate(
        self,
        *,
        order_id: str,
        account_id: str,
        cert_pem: str,
        chain_pem: Sequence[str],
        template: str,
        requester: str,
        metadata: dict[str, str] | None = None,
    ) -> CertificateRecord:
        cert_id = uuid.uuid4().hex
        issued_at = _now_iso()
        serial_number = _serial_from_pem(cert_pem)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO certificates
                (id, order_id, account_id, cert_pem, chain_pem, template,
                 requester, issued_at, metadata, serial_number, status,
                 revocation_reason, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cert_id,
                    order_id,
                    account_id,
                    cert_pem,
                    _dump_json(list(chain_pem)),
                    template,
                    requester,
                    issued_at,
                    _dump_json(metadata or {}),
                    serial_number,
                    CertStatus.VALID,
                    None,
                    None,
                ),
            )
        return CertificateRecord(
            id=cert_id,
            order_id=order_id,
            account_id=account_id,
            cert_pem=cert_pem,
            chain_pem=list(chain_pem),
            template=template,
            requester=requester,
            issued_at=issued_at,
            metadata=metadata or {},
            serial_number=serial_number,
        )

    def get_certificate(self, cert_id: str) -> CertificateRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
        if row is None:
            return None
        return self._certificate_from_row(row)

    def get_certificate_by_serial(
        self,
        serial_hex: str,
        account_id: str | None = None,
    ) -> CertificateRecord | None:
        """Look up a certificate by its uppercase hex serial number.

        When *account_id* is provided the lookup is scoped to
        ``(serial_number, account_id)`` so that a serial collision
        (possible in test with a static fixture cert) cannot return
        another account's row.  When *account_id* is ``None`` the
        legacy serial-only behaviour is preserved for callers that
        do not have an account context.
        """
        with self._connect() as conn:
            if account_id is not None:
                row = conn.execute(
                    "SELECT * FROM certificates WHERE serial_number = ? AND account_id = ?",
                    (serial_hex.upper(), account_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM certificates WHERE serial_number = ?",
                    (serial_hex.upper(),),
                ).fetchone()
        if row is None:
            return None
        return self._certificate_from_row(row)

    def revoke_certificate(
        self,
        cert_id: str,
        reason: int | None,
        *,
        revoked_at: str | None = None,
    ) -> CertificateRecord | None:
        """Mark a certificate as revoked in the RA store (CAS-guarded).

        M-3: the UPDATE is guarded on ``status = 'valid'`` so concurrent
        revocations are idempotent — the first revocation wins and its
        reason/timestamp are preserved; a concurrent caller sees the existing
        (now-revoked) record returned unchanged. If the cert was already
        revoked, no row is updated and the existing revoked record is returned
        (the caller treats this as idempotent success). Returns ``None`` only
        when no certificate row exists for *cert_id*.
        """
        timestamp = revoked_at or _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE certificates "
                "SET status = ?, "
                "    revocation_reason = ?, "
                "    revoked_at = ? "
                "WHERE id = ? AND status = ?",
                (CertStatus.REVOKED, reason, timestamp, cert_id, CertStatus.VALID),
            )
            if cursor.rowcount == 1:
                # This caller won the CAS — the cert was 'valid', now 'revoked'.
                row = conn.execute(
                    "SELECT * FROM certificates WHERE id = ?", (cert_id,)
                ).fetchone()
                if row is None:
                    return None
                return self._certificate_from_row(row)
            # No row updated: either the cert doesn't exist, or it was already
            # revoked (a concurrent revocation won the CAS). Return the current
            # record so the caller can distinguish the two cases (None = not
            # found; a revoked record = idempotent success).
        return self.get_certificate(cert_id)

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def record_audit(
        self,
        *,
        event_type: str,
        account_id: str | None = None,
        order_id: str | None = None,
        sans: Sequence[str] | None = None,
        template: str | None = None,
        requester: str | None = None,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist an unconditional audit row for every issuance event.

        Returns the audit event dict so callers can feed an extension hook
        (e.g. a SIEM emitter in Phase 3).
        """
        timestamp = _now_iso()
        event: dict[str, Any] = {
            "event_type": event_type,
            "account_id": account_id,
            "order_id": order_id,
            "sans": list(sans or []),
            "template": template,
            "requester": requester,
            "outcome": outcome,
            "details": details or {},
            "timestamp": timestamp,
        }
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_log
                (event_type, account_id, order_id, sans, template, requester,
                 outcome, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type,
                    account_id,
                    order_id,
                    _dump_json(event["sans"]),
                    template,
                    requester,
                    outcome,
                    _dump_json(event["details"]),
                    timestamp,
                ),
            )
        event["id"] = cursor.lastrowid
        return event

    def list_audit_events(
        self,
        *,
        account_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list[Any] = []
        if account_id is not None:
            query += " AND account_id = ?"
            params.append(account_id)
        if event_type is not None:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "account_id": row["account_id"],
                "order_id": row["order_id"],
                "sans": _load_json(row["sans"]),
                "template": row["template"],
                "requester": row["requester"],
                "outcome": row["outcome"],
                "details": _load_json(row["details"]),
                "timestamp": row["timestamp"],
            }
            for row in rows
        ]
