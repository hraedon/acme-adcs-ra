"""SIEM audit emission (Phase 3).

Mirrors cert-watch's export pattern: a small ``SiemEmitter`` class reads config
and fans audit events out to one or more sinks.  Sinks are fail-open — a SIEM
problem must never block or roll back an audited action.

Supported sinks:
  * ``jsonl`` (default) — append one JSON object per line to a configured path.
  * ``syslog`` — forward JSON events to a UDP/TCP syslog target.
  * ``hec`` — POST events to a Splunk HTTP Event Collector endpoint.

Config lives on ``RAConfig`` so it is env/file-driven like the rest of the RA.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from logging.handlers import SysLogHandler
from pathlib import Path
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("acme_adcs_ra.siem")


def _instance_id() -> str:
    return socket.gethostname()


@dataclass(frozen=True)
class SiemConfig:
    """SIEM sink configuration.

    Fields are intentionally plain (no work-domain identifiers, no secrets
    committed).  The HEC token is a SecretStr when carried on ``RAConfig``;
    this dataclass receives the already-decoded string.
    """

    sink: Literal["jsonl", "syslog", "hec"] = "jsonl"
    jsonl_path: Path | None = None
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_proto: Literal["udp", "tcp"] = "udp"
    hec_url: str = ""
    hec_token: str = ""
    hec_index: str = ""
    hec_sourcetype: str = "acme-adcs-ra"


class SiemEmitter:
    """Fan audit events out to configured SIEM sinks.

    The default sink is JSON-lines to a file derived from the RA database path
    so emission is testable and visible out of the box.  Syslog and HEC are
    optional operator-configured targets.

    Startup probe (C-2):
      * **jsonl** — on construction, verify the parent directory is writable
        (mkdir parents; open for append / write+remove a probe byte).  If it
        fails, set ``enabled=False`` and log at **ERROR**.  The RA-store write
        is unaffected (fail-open applies to emission, not to the local store
        row).
      * **HEC** / **syslog** — validate that required config fields are present
        and non-empty; a network reachability probe is optional (don't block
        startup on it).
    """

    SCHEMA_VERSION = "acme-adcs-ra-audit/1"

    def __init__(self, config: SiemConfig) -> None:
        self._config = config
        self._jsonl_path = config.jsonl_path
        self._syslog: logging.Logger | None = None
        self._pool: ThreadPoolExecutor | None = None
        self._enabled: bool | None = None  # None = not yet probed

        if config.sink == "syslog":
            if config.syslog_host:
                self._setup_syslog()
            else:
                logger.error(
                    "SIEM syslog sink enabled but syslog_host is empty; disabling"
                )
        if config.sink == "hec":
            if config.hec_url and config.hec_token:
                self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ra-siem-hec")
            else:
                logger.error(
                    "SIEM HEC sink enabled but hec_url or hec_token is empty; disabling"
                )
        if config.sink == "jsonl":
            self._probe_jsonl()

    def _probe_jsonl(self) -> None:
        """C-2: startup probe for the jsonl sink.

        Verify the target path is writable by opening it for append and
        closing immediately.  On failure, set ``enabled=False`` and log at
        ERROR.  This catches typo'd paths, unwritable directories, and paths
        that are directories themselves.
        """
        path = self._jsonl_path
        if path is None:
            self._enabled = False
            logger.error(
                "SIEM jsonl sink enabled but jsonl_path is not configured; disabling"
            )
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Open the actual target path for append — validates it is a
            # writable file (not a directory, not a permissions problem).
            with open(path, "a", encoding="utf-8"):
                pass
            self._enabled = True
        except Exception:
            self._enabled = False
            logger.error(
                "SIEM jsonl startup probe failed for %s; disabling SIEM emission. "
                "Issuance will continue but events will NOT be written to this sink.",
                path,
                exc_info=True,
            )

    @property
    def enabled(self) -> bool:
        if self._enabled is not None:
            return self._enabled
        # Fallback for non-jsonl sinks that don't set _enabled during init.
        if self._config.sink == "syslog":
            return self._syslog is not None
        if self._config.sink == "hec":
            return bool(self._config.hec_url and self._config.hec_token)
        return False

    def close(self) -> None:
        if self._syslog is not None:
            for handler in self._syslog.handlers:
                try:
                    handler.close()
                except Exception:
                    logger.warning("syslog handler close failed", exc_info=True)
            self._syslog.handlers.clear()
            self._syslog = None
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    def _setup_syslog(self) -> None:
        try:
            socktype = (
                socket.SOCK_STREAM if self._config.syslog_proto == "tcp" else socket.SOCK_DGRAM
            )
            handler = SysLogHandler(
                address=(self._config.syslog_host, self._config.syslog_port),
                socktype=socktype,
            )
            handler.setFormatter(logging.Formatter("acme-adcs-ra: %(message)s"))
            lg = logging.getLogger("acme_adcs_ra.siem.syslog")
            lg.setLevel(logging.INFO)
            lg.propagate = False
            lg.handlers = [handler]
            self._syslog = lg
        except Exception:
            logger.warning("syslog sink setup failed; disabling it", exc_info=True)

    def export(self, event: dict[str, Any]) -> None:
        """Emit one audit event to the configured sink(s).

        Fail-open: any exception is logged but never propagated.
        """
        if not self.enabled:
            return
        wrapped = self._wrap_event(event)
        try:
            if self._config.sink == "jsonl":
                self._to_jsonl(wrapped)
            elif self._config.sink == "syslog":
                self._to_syslog(wrapped)
            elif self._config.sink == "hec":
                self._to_hec(wrapped)
        except Exception:
            logger.warning("SIEM export failed for event_type=%s", event.get("event_type"), exc_info=True)

    def _wrap_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Add correlation/schema fields to the store audit event."""
        return {
            "schema_version": self.SCHEMA_VERSION,
            "instance": _instance_id(),
            **event,
        }

    def _to_jsonl(self, event: dict[str, Any]) -> None:
        path = self._jsonl_path
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, default=str, sort_keys=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def _to_syslog(self, event: dict[str, Any]) -> None:
        if self._syslog is None:
            return
        self._syslog.info(json.dumps(event, default=str, sort_keys=True))

    def _to_hec(self, event: dict[str, Any]) -> None:
        if self._pool is None:
            return
        self._pool.submit(self._hec_post, event)

    def _hec_post(self, event: dict[str, Any]) -> None:
        cfg = self._config
        try:
            envelope: dict[str, Any] = {
                "event": event,
                "sourcetype": cfg.hec_sourcetype,
                "time": time.time(),
            }
            if cfg.hec_index:
                envelope["index"] = cfg.hec_index
            req = Request(
                cfg.hec_url,
                data=json.dumps(envelope, default=str).encode("utf-8"),
                method="POST",
                headers={
                    "Authorization": f"Splunk {cfg.hec_token}",
                    "Content-Type": "application/json",
                },
            )
            with urlopen(req, timeout=10) as resp:
                if not (200 <= resp.status < 300):
                    logger.warning("HEC export non-2xx: %s", resp.status)
        except HTTPError as exc:
            logger.warning("HEC export non-2xx: %s", exc.code)
        except URLError:
            logger.warning("HEC export failed", exc_info=True)
        except Exception:
            logger.warning("HEC export failed", exc_info=True)


def build_siem_config(config: Any) -> SiemConfig:
    """Build a ``SiemConfig`` from ``RAConfig`` SIEM fields."""
    hec_token_secret = getattr(config, "siem_hec_token", None)
    hec_token = (
        hec_token_secret.get_secret_value()
        if hec_token_secret is not None and hasattr(hec_token_secret, "get_secret_value")
        else str(hec_token_secret or "")
    )
    return SiemConfig(
        sink=getattr(config, "siem_sink", "jsonl"),
        jsonl_path=getattr(config, "siem_jsonl_path", None),
        syslog_host=getattr(config, "siem_syslog_host", ""),
        syslog_port=getattr(config, "siem_syslog_port", 514),
        syslog_proto=getattr(config, "siem_syslog_proto", "udp"),
        hec_url=getattr(config, "siem_hec_url", ""),
        hec_token=hec_token,
        hec_index=getattr(config, "siem_hec_index", ""),
        hec_sourcetype=getattr(config, "siem_hec_sourcetype", "acme-adcs-ra"),
    )


def default_jsonl_path(db_path: Path) -> Path:
    """Default SIEM JSONL path: alongside the SQLite database file."""
    return db_path.with_suffix(".siem.jsonl")
