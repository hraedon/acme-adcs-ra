"""RA configuration — loaded from env vars (ACME_RA_*) and/or a config file.

No real secrets or work-domain identifiers in committed files.
All values use placeholders (CA01, WORK-DOMAIN.local, etc.).
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, SecretStr, model_validator
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

    # --- SAN scope per account (kid → allowed DNS glob patterns) -------------
    san_scopes: dict[str, SANScope] = {}

    # --- Storage -------------------------------------------------------------
    db_path: Path = Path("acme_ra.db")

    # --- Audit ---------------------------------------------------------------
    # Auditing every issuance is mandatory (hard rule). There is no toggle.

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
        """Return {kid: mac_key} for fast EAB lookup."""
        return {e.kid: e.mac_key.get_secret_value() for e in self.eab_allowlist}
