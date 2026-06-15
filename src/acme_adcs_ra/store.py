"""SQLite persistence for accounts, orders, authorizations, certificates, and audit.

The store is intentionally plain sqlite3 — no ORM, no migrations beyond
``CREATE TABLE IF NOT EXISTS``.  It is part of the issuance path and therefore
carries no signing primitives.
"""

from __future__ import annotations

import json
import random
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from cryptography import x509

from acme_adcs_ra.jws import jwk_thumbprint


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
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authorizations (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    order_id TEXT NOT NULL REFERENCES orders(id),
    identifier TEXT NOT NULL,  -- JSON object
    status TEXT NOT NULL,
    expires TEXT NOT NULL,
    challenges TEXT NOT NULL  -- JSON array
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

    def __init__(self, db_path: Path, order_expiry_seconds: int = 3600) -> None:
        self._db_path = db_path
        self._order_expiry_seconds = order_expiry_seconds
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
        return AccountRecord(
            id=row["id"],
            status=row["status"],
            jwk_json=row["jwk_json"],
            eab_kid=row["eab_kid"],
            created_at=row["created_at"],
            contact=_load_json(row["contact"]) or [],
        )

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
        return AccountRecord(
            id=row["id"],
            status=row["status"],
            jwk_json=row["jwk_json"],
            eab_kid=row["eab_kid"],
            created_at=row["created_at"],
            contact=_load_json(row["contact"]) or [],
        )

    # ------------------------------------------------------------------
    # Nonces
    # ------------------------------------------------------------------

    def create_nonce(self) -> str:
        nonce = uuid.uuid4().hex + uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO nonces (nonce, created_at) VALUES (?, ?)",
                (nonce, now.strftime("%Y-%m-%dT%H:%M:%SZ")),
            )
            # Probabilistic GC: ~1% of nonce creations also purge expired nonces.
            if random.random() < 0.01:
                cutoff = (now - timedelta(seconds=NONCE_TTL_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
                conn.execute("DELETE FROM nonces WHERE created_at < ?", (cutoff,))
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

    def create_order(
        self,
        *,
        account_id: str,
        identifiers: Sequence[dict[str, str]],
        authorizations: Sequence[str],
        finalize_url: str,
        certificate_url: str | None = None,
        status: str = "pending",
        expires: str | None = None,
    ) -> OrderRecord:
        order_id = uuid.uuid4().hex
        created_at = _now_iso()
        if expires is None:
            expires = _now_iso_plus(self._order_expiry_seconds)
        with self._connect() as conn:
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
                    status,
                    _dump_json(list(identifiers)),
                    _dump_json(list(authorizations)),
                    finalize_url,
                    certificate_url,
                    expires,
                    created_at,
                    created_at,
                ),
            )
        return OrderRecord(
            id=order_id,
            account_id=account_id,
            status=status,
            identifiers=list(identifiers),
            authorizations=list(authorizations),
            finalize_url=finalize_url,
            certificate_url=certificate_url,
            expires=expires,
            created_at=created_at,
            updated_at=created_at,
        )

    def get_order(self, order_id: str) -> OrderRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM orders WHERE id = ?", (order_id,)
            ).fetchone()
        if row is None:
            return None
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
        )

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
                "UPDATE orders SET status = ?, updated_at = ? "
                "WHERE id = ? AND status = 'ready'",
                ("processing", updated_at, order_id),
            )
            return cursor.rowcount == 1

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
                    "pending",
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

                # Insert authorization with a minimal JSON blob (H4: challenges
                # table is the source of truth, this blob is legacy).
                conn.execute(
                    """
                    INSERT INTO authorizations
                    (id, account_id, order_id, identifier, status, expires, challenges)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        authz_id,
                        account_id,
                        order_id,
                        _dump_json(identifier),
                        "pending",
                        expires,
                        _dump_json([]),  # H4: unused blob, challenges table is SSoT
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
            status="pending",
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

    def create_authorization(
        self,
        *,
        account_id: str,
        order_id: str,
        identifier: dict[str, str],
        challenge_type: str = "http-01",
        challenge_url: str = "",
        status: str = "pending",
        expires: str | None = None,
    ) -> AuthorizationRecord:
        authz_id = uuid.uuid4().hex
        challenge_id = uuid.uuid4().hex
        token = uuid.uuid4().hex + uuid.uuid4().hex
        if expires is None:
            expires = _now_iso()
        challenge = ChallengeRecord(
            id=challenge_id,
            authz_id=authz_id,
            type=challenge_type,
            status="pending",
            token=token,
            url=challenge_url,
            validated_at=None,
        )
        challenges = [challenge]
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO authorizations
                (id, account_id, order_id, identifier, status, expires, challenges)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authz_id,
                    account_id,
                    order_id,
                    _dump_json(identifier),
                    status,
                    expires,
                    _dump_json([c.__dict__ for c in challenges]),
                ),
            )
            conn.execute(
                """
                INSERT INTO challenges
                (id, authz_id, type, status, token, url, validated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (challenge_id, authz_id, challenge_type, "pending", token, challenge_url, None),
            )
        return AuthorizationRecord(
            id=authz_id,
            account_id=account_id,
            order_id=order_id,
            identifier=identifier,
            status=status,
            expires=expires,
            challenges=challenges,
        )

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

    def update_challenge_url(self, challenge_id: str, url: str) -> None:
        """Update the URL of a challenge after its id is known.

        H4: the challenges table is the single source of truth; no longer
        dual-writes the authorizations.challenges JSON blob.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE challenges SET url = ? WHERE id = ?",
                (url, challenge_id),
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
                    "valid",
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
        """Mark a certificate as revoked in the RA store."""
        timestamp = revoked_at or _now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE certificates
                SET status = 'revoked',
                    revocation_reason = ?,
                    revoked_at = ?
                WHERE id = ?
                """,
                (reason, timestamp, cert_id),
            )
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
