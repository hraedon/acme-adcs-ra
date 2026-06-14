"""RA configuration — loaded from env vars (ACME_RA_*) and/or a config file.

No real secrets or work-domain identifiers in committed files.
All values use placeholders (CA01, WORK-DOMAIN.local, etc.).
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class EABEntry(BaseModel):
    """One EAB credential mapping kid → MAC key (base64url)."""

    kid: str
    mac_key: SecretStr


class SANScope(BaseModel):
    """DNS SAN patterns allowed for a given account (EAB kid)."""

    dns_patterns: list[str] = []


class RAConfig(BaseSettings):
    """Top-level RA settings. Loads from env vars prefixed ACME_RA_*."""

    model_config = SettingsConfigDict(
        env_prefix="ACME_RA_",
        env_nested_delimiter="__",
        # Allow a .env file next to the config or specified via ACME_RA_CONFIG_PATH
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- EAB allowlist -------------------------------------------------------
    eab_allowlist: list[EABEntry] = []

    # --- ADCS target (placeholders only) -------------------------------------
    adcs_host: str = "CA01.WORK-DOMAIN.local"
    adcs_template: str = "ACME-ServerAuth"
    adcs_ca_name: str = "CONTOSO-CA01-CA"

    # --- ACME server surface -------------------------------------------------
    base_url: str = "http://localhost:8000"
    terms_of_service: str = ""

    # --- SAN scope per account (kid → allowed DNS glob patterns) -------------
    san_scopes: dict[str, SANScope] = {}

    # --- Storage -------------------------------------------------------------
    db_path: Path = Path("acme_ra.db")
    # ACME order/authz lifetime (RFC 8555 §7.1.4). Orders must not be born
    # expired or well-behaved clients reject them immediately.
    order_expiry_seconds: int = 3600

    # --- SIEM / audit emission -----------------------------------------------
    # Auditing every issuance is mandatory (hard rule). There is no toggle.
    # The default sink is JSON-lines next to the database; syslog and Splunk
    # HEC are optional operator-configured targets.
    siem_sink: Literal["jsonl", "syslog", "hec"] = "jsonl"
    siem_jsonl_path: Path | None = None
    siem_syslog_host: str = ""
    siem_syslog_port: int = 514
    siem_syslog_proto: Literal["udp", "tcp"] = "udp"
    siem_hec_url: str = ""
    siem_hec_token: SecretStr = Field(default_factory=lambda: SecretStr(""))
    siem_hec_index: str = ""
    siem_hec_sourcetype: str = "acme-adcs-ra"

    @model_validator(mode="after")
    def _no_duplicate_eab_kids(self) -> "RAConfig":
        """Duplicate kids would silently overwrite EAB credentials — reject them."""
        seen: set[str] = set()
        for entry in self.eab_allowlist:
            if entry.kid in seen:
                raise ValueError(f"duplicate EAB kid: {entry.kid}")
            seen.add(entry.kid)
        return self

    def eab_keys_by_kid(self) -> dict[str, str]:
        """Return {kid: mac_key} for fast EAB lookup.

        The mac_key value is the base64url-encoded key as stored in config.
        Use ``eab_key_bytes`` when the raw key bytes are needed (e.g. HMAC).
        """
        return {e.kid: e.mac_key.get_secret_value() for e in self.eab_allowlist}

    def eab_key_bytes(self, kid: str) -> bytes | None:
        """Return the decoded EAB MAC key bytes for a kid, or None if unknown."""
        mac_key_b64 = self.eab_keys_by_kid().get(kid)
        if mac_key_b64 is None:
            return None
        # base64url decode, tolerating missing padding.
        padding_needed = (-len(mac_key_b64)) % 4
        return base64.urlsafe_b64decode(mac_key_b64 + ("=" * padding_needed))
