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
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from logging.handlers import SysLogHandler
from pathlib import Path
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from acme_adcs_ra.config import RAConfig

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
    # Seconds a TCP syslog send may block before it is abandoned. Without a
    # deadline a stalled receiver parks the sender indefinitely.
    syslog_timeout_seconds: float = 5.0
    # Maximum audit events held in memory awaiting OFF-BOX delivery (syslog
    # or HEC). See SiemEmitter._submit_bounded for why an unbounded queue
    # was a liability.
    hec_queue_max: int = 1000


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
        self._enabled: bool = False
        # Backpressure accounting for BOTH off-box sinks (see _submit_bounded).
        self._sink_inflight = 0
        self._sink_dropped = 0
        self._sink_lock = threading.Lock()

        if config.sink == "syslog":
            if config.syslog_host:
                self._setup_syslog()
                if self._syslog is not None:
                    # One worker, so syslog records stay in submission order.
                    self._pool = ThreadPoolExecutor(
                        max_workers=1, thread_name_prefix="ra-siem-syslog"
                    )
            else:
                logger.error(
                    "SIEM syslog sink enabled but syslog_host is empty; disabling"
                )
            self._enabled = self._syslog is not None
        elif config.sink == "hec":
            parsed_hec = urlparse(config.hec_url)
            hec_url_is_safe = (
                parsed_hec.scheme == "https"
                and parsed_hec.hostname is not None
                and parsed_hec.username is None
                and parsed_hec.password is None
            )
            if hec_url_is_safe and config.hec_token:
                self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ra-siem-hec")
            else:
                logger.error(
                    "SIEM HEC sink requires an https URL without embedded credentials "
                    "and a non-empty token; disabling"
                )
            self._enabled = self._pool is not None
        elif config.sink == "jsonl":
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
            logger.exception(
                "SIEM jsonl startup probe failed for %s; disabling SIEM emission. "
                "Issuance will continue but events will NOT be written to this sink.",
                path,
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

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
            # A TCP syslog socket with no timeout blocks indefinitely once the
            # receiver stops reading: `SysLogHandler` does a plain `sendall`,
            # and a full send buffer parks the caller until the peer drains it.
            # UDP cannot block this way, but the timeout is harmless there.
            # `SysLogHandler.socket` exists at runtime for both socket types but
            # is not declared in typeshed, hence getattr.
            sock: socket.socket | None = getattr(handler, "socket", None)
            if socktype == socket.SOCK_STREAM and sock is not None:
                sock.settimeout(self._config.syslog_timeout_seconds)
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
        """Hand the event to the bounded worker, or drop it under backpressure.

        Previously this called ``Logger.info`` inline, which for a TCP sink is a
        blocking ``sendall`` on the calling thread — and the calling thread is
        the event loop, because ``_audit`` runs on the issuance request path.
        A syslog receiver that stops reading (or a network path that stalls)
        therefore stalled *issuance itself*, in the single-process deployment,
        with no timeout and no bound. TCP syslog is the shipped production
        setting in ``deploy/iis/web.config``, so this was the default posture.

        The HEC sink already had exactly this treatment for exactly this reason;
        syslog simply never got it. Both now share one bounded queue: the local
        audit row is already durable before this runs, so dropping the newest
        event under sustained backpressure bounds memory deterministically and
        is counted rather than silent.
        """
        if self._syslog is None:
            return
        self._submit_bounded(self._syslog_send, event, "syslog")

    def _syslog_send(self, event: dict[str, Any]) -> None:
        try:
            if self._syslog is not None:
                self._syslog.info(json.dumps(event, default=str, sort_keys=True))
        finally:
            with self._sink_lock:
                self._sink_inflight -= 1

    def _submit_bounded(
        self, fn: Any, event: dict[str, Any], label: str
    ) -> None:
        """Queue off-box delivery with a hard ceiling on outstanding work.

        Shared by both off-box sinks. ``ThreadPoolExecutor``'s work queue is a
        ``SimpleQueue`` — unbounded — so a stalled receiver otherwise lets the
        backlog grow without limit while audit events keep arriving. Measured
        on the HEC path before it was bounded: 5000 events submitted against a
        dead endpoint left 4987 queued, which is an unauthenticated peer turning
        the audit path into memory exhaustion on an issuance-path host.

        On overflow the event is dropped *from the off-box sink only* — the
        durable record is the audit table row, already committed by the time
        this runs — and counted, so the loss is visible rather than silent.
        """
        if self._pool is None:
            return
        with self._sink_lock:
            if self._sink_inflight >= self._config.hec_queue_max:
                self._sink_dropped += 1
                dropped = self._sink_dropped
                # First drop, then every 100th: a sustained outage stays visible
                # without the log itself becoming the flood.
                if dropped == 1 or dropped % 100 == 0:
                    logger.error(
                        "SIEM %s queue full (%d in flight, max %d); dropped %d "
                        "audit event(s) from the %s sink so far. The local audit "
                        "table still holds every event. Check sink reachability.",
                        label, self._sink_inflight, self._config.hec_queue_max,
                        dropped, label,
                    )
                return
            self._sink_inflight += 1
        try:
            self._pool.submit(fn, event)
        except RuntimeError:
            # Pool already shut down (close() raced with a late event).
            with self._sink_lock:
                self._sink_inflight -= 1

    def _to_hec(self, event: dict[str, Any]) -> None:
        """Hand the event to the bounded HEC worker pool."""
        self._submit_bounded(self._hec_post, event, "HEC")

    @property
    def sink_dropped(self) -> int:
        """Audit events dropped from the off-box sink due to backpressure."""
        with self._sink_lock:
            return self._sink_dropped

    def _hec_post(self, event: dict[str, Any]) -> None:
        try:
            self._hec_post_inner(event)
        finally:
            with self._sink_lock:
                self._sink_inflight -= 1

    def _hec_post_inner(self, event: dict[str, Any]) -> None:
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


def build_siem_config(config: RAConfig) -> SiemConfig:
    """Build a ``SiemConfig`` from ``RAConfig`` SIEM fields."""
    jsonl_path = config.siem_jsonl_path
    if jsonl_path is None and config.siem_sink == "jsonl":
        jsonl_path = default_jsonl_path(config.db_path)
    hec_token = config.siem_hec_token.get_secret_value()
    return SiemConfig(
        sink=config.siem_sink,
        jsonl_path=jsonl_path,
        syslog_host=config.siem_syslog_host,
        syslog_port=config.siem_syslog_port,
        syslog_proto=config.siem_syslog_proto,
        syslog_timeout_seconds=config.siem_syslog_timeout_seconds,
        hec_url=config.siem_hec_url,
        hec_token=hec_token,
        hec_index=config.siem_hec_index,
        hec_sourcetype=config.siem_hec_sourcetype,
        hec_queue_max=config.siem_hec_queue_max,
    )


def default_jsonl_path(db_path: Path) -> Path:
    """Default SIEM JSONL path: alongside the SQLite database file."""
    return db_path.with_suffix(".siem.jsonl")
