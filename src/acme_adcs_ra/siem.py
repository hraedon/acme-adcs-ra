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

import contextlib
import json
import logging
import socket
import sys
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


class _RaisingSysLogHandler(SysLogHandler):
    """A ``SysLogHandler`` whose transport failures reach the caller.

    The stock handler funnels every :meth:`emit` exception into
    ``logging.Handler.handleError``, which reports to stderr and **returns**.
    ``Logger.info()`` therefore returns normally after a send that never left
    the host, so any delivery accounting that infers success from that return
    counts a dead collector as delivered — which is exactly what
    :meth:`SiemEmitter.probe_offbox_delivery` and
    :meth:`SiemEmitter._syslog_send` do.

    Measured against a killed TCP collector, the stock handler swallowed a
    ``ConnectionResetError`` followed by four ``BrokenPipeError``s while the
    emitter recorded five successful deliveries and the ``audit_offbox_required``
    startup probe still answered "syslog accepted the probe over TCP". The
    off-box trail is the control meant to survive a compromise of this host, so
    it must fail loudly. Found by the 2026-08-17 Daybreak review (F4); it is the
    same defect class as wave-3 F2, which was fixed for the HEC sink only.

    Two behaviours the stock handler does not give us:

    * ``handleError`` re-raises, so a failed send propagates out of
      ``Logger.info()`` to the caller's ``try/except``.
    * A failed TCP send drops the dead socket. ``emit`` calls ``createSocket``
      whenever ``self.socket`` is falsy, so the next event reconnects instead of
      wedging the sink until the process restarts. ``createSocket`` re-applies
      the send timeout, which the stock implementation does not carry across a
      reconnect (and never applied at all when the *initial* connect failed and
      the socket was created lazily on first emit).
    """

    def __init__(self, *args: Any, send_timeout: float | None = None, **kwargs: Any) -> None:
        self._send_timeout = send_timeout
        super().__init__(*args, **kwargs)
        self._apply_send_timeout()

    def _apply_send_timeout(self) -> None:
        """Bound a TCP send so a collector that stops reading cannot park us.

        A TCP syslog socket with no timeout blocks indefinitely once the
        receiver stops draining: ``SysLogHandler`` does a plain ``sendall`` and
        a full send buffer parks the caller. UDP cannot block this way, so the
        timeout is only meaningful — though harmless — for streams. ``socket``
        exists at runtime for both socket types but is not declared in typeshed,
        hence the getattr.
        """
        if self._send_timeout is None or self.socktype != socket.SOCK_STREAM:
            return
        sock: socket.socket | None = getattr(self, "socket", None)
        if sock is not None:
            sock.settimeout(self._send_timeout)

    def createSocket(self) -> None:
        super().createSocket()
        self._apply_send_timeout()

    def handleError(self, record: logging.LogRecord) -> None:
        exc = sys.exc_info()[1]
        # Drop the dead stream so the next emit reconnects via createSocket().
        # Datagram sockets are connectionless, so there is nothing to rebuild.
        if self.socktype == socket.SOCK_STREAM and not self.unixsocket:
            sock: socket.socket | None = getattr(self, "socket", None)
            if sock is not None:
                # Best-effort: this socket is already broken, and the caller is
                # about to get the real transport error re-raised below. A
                # failure to close it must not mask that.
                with contextlib.suppress(Exception):
                    sock.close()
            self.socket = None
        if exc is None:
            # handleError is only reached from an active except block, so this
            # is defensive; still raise, because returning would silently
            # restore the "failure counts as delivery" bug.
            raise OSError("syslog emit failed with no exception in flight")
        raise exc


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

    That last decision stands for the *optional* case and is wrong for the
    required one (2026-08-18 wave 3 F2). ``audit_offbox_required`` asserted only
    that an emitter had been constructed from syntactically valid config, so a
    revoked HEC token, a wrong index, or an endpoint that answers 403 to
    everything left the RA issuing certificates while believing an off-box audit
    trail was in force — and the trail is precisely the control meant to survive
    a compromise of this host. :meth:`probe_offbox_delivery` is therefore called
    by ``create_app`` **when the operator has required off-box audit**, and
    refuses startup if delivery cannot be demonstrated. The optional path is
    unchanged and still never blocks on the network.
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
        # Delivery health. Dropping events on backpressure was already counted;
        # events the sink *rejected* were only logged at WARNING, so a sustained
        # total failure (revoked token, wrong index) was indistinguishable from a
        # healthy quiet period. Counted so it can be asserted on and surfaced.
        self._offbox_failures = 0
        self._offbox_delivered = 0
        self._offbox_last_error: str | None = None
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
            # _RaisingSysLogHandler, not the stock SysLogHandler: the stock one
            # swallows transport errors, which made every failed send count as
            # a delivery and let the audit_offbox_required probe pass with the
            # collector dead. It also owns the send timeout, so a reconnect
            # cannot silently come back unbounded.
            handler = _RaisingSysLogHandler(
                address=(self._config.syslog_host, self._config.syslog_port),
                socktype=socktype,
                send_timeout=self._config.syslog_timeout_seconds,
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
            self._syslog_send_inner(event)
        except Exception as exc:  # noqa: BLE001 - emission must not raise into the pool
            self._record_offbox_result(f"{type(exc).__name__}: {exc}")
        else:
            self._record_offbox_result(None)
        finally:
            with self._sink_lock:
                self._sink_inflight -= 1

    def _syslog_send_inner(self, event: dict[str, Any]) -> None:
        if self._syslog is not None:
            self._syslog.info(json.dumps(event, default=str, sort_keys=True))

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

    @property
    def offbox_failures(self) -> int:
        """Audit events the off-box sink rejected or failed to accept."""
        with self._sink_lock:
            return self._offbox_failures

    @property
    def offbox_delivered(self) -> int:
        """Audit events the off-box sink acknowledged."""
        with self._sink_lock:
            return self._offbox_delivered

    @property
    def offbox_last_error(self) -> str | None:
        """The most recent off-box delivery failure, if any."""
        with self._sink_lock:
            return self._offbox_last_error

    def _record_offbox_result(self, error: str | None) -> None:
        """Account for one off-box delivery attempt.

        A sustained rejection used to be a stream of identical WARNINGs with no
        state behind them. The first failure and every hundredth escalate to
        ERROR — the same shape as the backpressure counter beside it, so a total
        outage is visible without the log becoming the flood.
        """
        with self._sink_lock:
            if error is None:
                self._offbox_delivered += 1
                self._offbox_failures = 0
                return
            self._offbox_failures += 1
            self._offbox_last_error = error
            failures = self._offbox_failures
            delivered = self._offbox_delivered
        if failures == 1 or failures % 100 == 0:
            logger.error(
                "Off-box audit delivery has failed %d time(s) in a row (%d "
                "delivered since start); last error: %s. The local audit table "
                "still holds every event, but nothing is leaving this host — "
                "which is the trail meant to survive a compromise of it.",
                failures, delivered, error,
            )

    def probe_offbox_delivery(self) -> tuple[bool, str]:
        """Demonstrate that an audit event can actually reach the off-box sink.

        Called by ``create_app`` only when ``audit_offbox_required`` is set: the
        optional path deliberately does not block startup on the network.

        Returns ``(ok, detail)``. ``detail`` explains a failure, or describes what
        was and was not proven on success — which matters for syslog, where the
        common UDP transport cannot acknowledge anything and the honest answer is
        "the socket accepted it".
        """
        cfg = self._config
        if not self._enabled:
            return False, "the SIEM emitter is disabled"
        if cfg.sink == "hec":
            event = {
                "schema": self.SCHEMA_VERSION,
                "event_type": "audit-offbox-startup-probe",
                "outcome": "success",
                "detail": "startup delivery probe for audit_offbox_required",
            }
            try:
                self._hec_post_inner(event, raise_on_error=True)
            except Exception as exc:  # noqa: BLE001 - any failure is a failed probe
                return False, f"HEC rejected the startup probe: {exc}"
            return True, "HEC acknowledged a probe event with a 2xx"
        if cfg.sink == "syslog":
            try:
                self._syslog_send_inner(
                    {
                        "schema": self.SCHEMA_VERSION,
                        "event_type": "audit-offbox-startup-probe",
                        "outcome": "success",
                    }
                )
            except Exception as exc:  # noqa: BLE001
                return False, f"syslog refused the startup probe: {exc}"
            if cfg.syslog_proto.lower() == "udp":
                # Worth stating rather than implying: UDP is fire-and-forget, so
                # this proves the socket accepted the datagram and nothing about
                # whether anything is listening. TCP is strictly better here —
                # it at least detects a refused or broken connection — but
                # neither proves receipt, because syslog has no acknowledgment.
                return True, (
                    "syslog accepted the probe over UDP, which cannot detect a "
                    "missing collector at all; reachability is NOT proven. Use "
                    "syslog_proto=tcp to at least detect transport failure, or "
                    "the HEC sink to prove receipt."
                )
            # Precise about what this proves: the TCP connection was
            # established and the send completed without error. That is a live
            # transport, NOT an application-level acknowledgment — syslog has no
            # such thing, so a collector that accepts bytes and drops them still
            # passes. HEC is the sink that can prove receipt.
            return True, (
                "syslog TCP send completed with no transport error; the "
                "collector is reachable but syslog cannot acknowledge receipt"
            )
        return False, f"sink {cfg.sink!r} is not an off-box sink"

    def _hec_post(self, event: dict[str, Any]) -> None:
        try:
            self._hec_post_inner(event)
        finally:
            with self._sink_lock:
                self._sink_inflight -= 1

    def _hec_post_inner(
        self, event: dict[str, Any], *, raise_on_error: bool = False
    ) -> None:
        """Deliver one event to HEC.

        ``raise_on_error`` is for the startup probe, which needs the failure
        rather than a log line. The ordinary path keeps swallowing everything:
        audit emission is fail-open by design because the durable record is the
        local table row, already committed before this runs.
        """
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
                    self._record_offbox_result(f"HTTP {resp.status}")
                    if raise_on_error:
                        raise RuntimeError(f"HTTP {resp.status}")
                    return
        except HTTPError as exc:
            logger.warning("HEC export non-2xx: %s", exc.code)
            self._record_offbox_result(f"HTTP {exc.code}")
            if raise_on_error:
                raise
        except URLError as exc:
            logger.warning("HEC export failed", exc_info=True)
            self._record_offbox_result(f"{type(exc).__name__}: {exc}")
            if raise_on_error:
                raise
        except Exception as exc:
            logger.warning("HEC export failed", exc_info=True)
            self._record_offbox_result(f"{type(exc).__name__}: {exc}")
            if raise_on_error:
                raise
        else:
            self._record_offbox_result(None)


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
