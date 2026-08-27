"""Regression tests for the 2026-08-18 Codex scan of `7325cdb`→`47bb9f7`.

Three low-severity, high-confidence findings, recorded in
`docs/UNFILED-WORK-ITEMS.md` as items 7–9 while the work-item store was
refusing writes. Two of them are covered here; the third is a wiring gap with
nothing to regress yet.

* item 8 — `probe_offbox_delivery` returned **True** for `syslog_proto=udp`
  whenever the socket accepted the datagram, which it always does. The returned
  *detail* said in as many words that reachability was not proven, but the
  boolean is what gates startup, so `audit_offbox_required` refused nothing on
  UDP. This is the prerequisite for item 7: deletion in `audit_retention` is
  gated on that same probe, so wiring the sweep while UDP passed would have made
  the hole load-bearing for destroying the only surviving copy of audit rows.
* item 9 — `_apply_send_timeout` ran *after* `SysLogHandler.createSocket()` had
  already resolved and connected, so `siem_syslog_timeout_seconds` bounded sends
  only. DNS and the TCP handshake fell back to the OS default, so a blackholed
  collector could stall service construction or the single reconnect worker well
  past the configured deadline.
* item 7 — `run_sweep` has no production caller. Nothing to assert until it
  gains one; `TestUdpCannotBeLoadBearingForDeletion` covers the gate that must
  hold when it does.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import Any, ClassVar

import pytest

from acme_adcs_ra import siem as siem_module
from acme_adcs_ra.audit_retention import evaluate
from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.siem import SiemConfig, SiemEmitter

from .test_audit_retention import _Config, _store_with_cert


def _closed_udp_port() -> int:
    """A port with nothing bound to it.

    Binding and releasing is the only portable way to name a free port. UDP
    makes the race harmless: the point of these tests is that the send succeeds
    regardless of what is or is not listening.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _udp_emitter(port: int) -> SiemEmitter:
    return SiemEmitter(
        SiemConfig(
            sink="syslog",
            syslog_host="127.0.0.1",
            syslog_port=port,
            syslog_proto="udp",
        )
    )


class TestUdpCannotSatisfyOffboxRequired:
    """item 8 — a datagram the kernel accepted is not off-box audit delivery."""

    def test_the_original_reproduction_now_fails_the_probe(self) -> None:
        """Scanner's repro: an unused port answered `enabled=True, ok=True`."""
        emitter = _udp_emitter(_closed_udp_port())
        try:
            # Still enabled: the sink is usable, and the optional (not
            # required) path must keep working. It is the *gate* that refuses.
            assert emitter.enabled is True
            ok, detail = emitter.probe_offbox_delivery()
            assert ok is False, (
                "a UDP probe to a port with no collector reported the off-box "
                "audit trail as demonstrated"
            )
            assert "fire-and-forget" in detail
        finally:
            emitter.close()

    def test_a_live_collector_does_not_rescue_udp(self) -> None:
        """The refusal is about what UDP can *prove*, not about this collector.

        A listening socket makes no difference: the probe cannot tell this case
        apart from the one above, which is exactly why it must not answer yes to
        either. Asserting only the closed-port case would leave a "fix" that
        merely detected refusal — impossible on UDP — looking correct.
        """
        collector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        collector.bind(("127.0.0.1", 0))
        emitter = _udp_emitter(collector.getsockname()[1])
        try:
            ok, _ = emitter.probe_offbox_delivery()
            assert ok is False
        finally:
            emitter.close()
            collector.close()

    def test_config_refuses_the_combination_at_startup(self) -> None:
        """Fail at config validation, not only at the probe: it is a posture.

        This refusal is unconditional and has no override, because it is about
        whether ``required`` can assert anything at all -- a datagram socket
        accepts bytes with nothing listening. See
        ``test_offbox_syslog_acknowledgement.py``, which pins that the
        acknowledgement flag does not reach UDP.
        """
        with pytest.raises(ValueError, match="fire-and-forget"):
            RAConfig(
                audit_offbox_required=True,
                siem_sink="syslog",
                siem_syslog_host="collector.example",
                siem_syslog_proto="udp",
            )

    def test_config_refuses_tcp_as_the_load_bearing_posture(self) -> None:
        """A live TCP peer is not an authenticated or confidential collector.

        Still the DEFAULT, which is what this test pins. Unlike UDP above,
        this one is reachable by explicit acknowledgement --
        ``audit_offbox_allow_unauthenticated_syslog`` -- because refusing it
        outright stranded every estate whose SIEM is behind a syslog relay and
        the realistic response was to turn the whole requirement off.
        """
        with pytest.raises(ValueError, match="does not authenticate the collector"):
            RAConfig(
                audit_offbox_required=True,
                siem_sink="syslog",
                siem_syslog_host="collector.example",
                siem_syslog_proto="tcp",
            )

    def test_config_accepts_authenticated_https_hec(self) -> None:
        cfg = RAConfig(
            audit_offbox_required=True,
            siem_sink="hec",
            siem_hec_url="https://collector.example/services/collector",
            siem_hec_token="placeholder-token",
        )
        assert cfg.siem_sink == "hec"

    def test_udp_without_the_requirement_is_untouched(self) -> None:
        """Off-box audit is opt-in; UDP stays available to everyone else."""
        cfg = RAConfig(
            siem_sink="syslog",
            siem_syslog_host="collector.example",
            siem_syslog_proto="udp",
        )
        assert cfg.audit_offbox_required is False

    def test_tcp_without_the_requirement_is_untouched(self) -> None:
        cfg = RAConfig(
            siem_sink="syslog",
            siem_syslog_host="collector.example",
            siem_syslog_proto="tcp",
        )
        assert cfg.audit_offbox_required is False


class TestUdpCannotBeLoadBearingForDeletion:
    """items 7+8 interlocked — the gate that must hold when the sweep is wired."""

    def test_retention_refuses_to_prune_behind_a_udp_sink(
        self, tmp_path: Path
    ) -> None:
        """Every other gate open, a real UDP emitter, and deletion still refused.

        `evaluate` checks `siem.enabled` before it probes, and a UDP emitter is
        enabled — so the probe is the only thing standing between a configured
        retention window and deleting audit rows whose delivery was never
        demonstrated.
        """
        store = _store_with_cert(tmp_path, validity_days=90)
        config = _Config(
            audit_retention_days=3650,
            audit_prune_enabled=True,
            audit_offbox_required=True,
        )
        emitter = _udp_emitter(_closed_udp_port())
        try:
            assert emitter.enabled is True, "the enabled gate must not be what saves us"
            decision = evaluate(config, store, emitter)  # type: ignore[arg-type]
            assert decision.may_prune is False
            assert "not currently healthy" in decision.reason
        finally:
            emitter.close()


class _RecordingSocket(socket.socket):
    """Records the timeout in force at the moment `connect` was called."""

    connect_timeouts: ClassVar[list[float | None]] = []

    def connect(self, address: Any) -> None:  # type: ignore[override]
        type(self).connect_timeouts.append(self.gettimeout())
        super().connect(address)


class TestSyslogConnectIsBounded:
    """item 9 — one wall-clock deadline over resolution and establishment."""

    TIMEOUT = 1.5

    @staticmethod
    def _listener() -> tuple[socket.socket, int]:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        return srv, srv.getsockname()[1]

    def _tcp_emitter(self, port: int) -> SiemEmitter:
        return SiemEmitter(
            SiemConfig(
                sink="syslog",
                syslog_host="127.0.0.1",
                syslog_port=port,
                syslog_proto="tcp",
                syslog_timeout_seconds=self.TIMEOUT,
            )
        )

    def test_connect_carries_a_deadline(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pre-fix the socket was connected wide open: `gettimeout()` was None."""
        srv, port = self._listener()
        _RecordingSocket.connect_timeouts = []
        monkeypatch.setattr(siem_module.socket, "socket", _RecordingSocket)
        emitter = self._tcp_emitter(port)
        try:
            assert emitter.enabled is True
            recorded = _RecordingSocket.connect_timeouts
            assert recorded, "no connect was observed; the test instrument missed"
            for observed in recorded:
                assert observed is not None, "connect ran with no deadline at all"
                assert 0 < observed <= self.TIMEOUT
        finally:
            emitter.close()
            srv.close()

    def test_the_send_deadline_survives_the_connect_deadline(self) -> None:
        """The connect budget is the *remaining* time; sends get the full knob.

        Without this the two would be easy to conflate, and a slow connect would
        silently shorten every subsequent send.
        """
        srv, port = self._listener()
        emitter = self._tcp_emitter(port)
        try:
            handler = emitter._syslog.handlers[0]  # type: ignore[union-attr]
            assert handler.socket.gettimeout() == pytest.approx(self.TIMEOUT)
        finally:
            emitter.close()
            srv.close()

    def test_resolution_cannot_outlast_the_deadline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A resolver that never answers must not park service construction.

        `getaddrinfo` takes no timeout and blocks in the OS resolver, so pre-fix
        this slept for the stub's full duration and then connected happily.
        """
        stall = 30.0
        released = threading.Event()

        def hanging_getaddrinfo(*_args: Any, **_kwargs: Any) -> list[Any]:
            released.wait(stall)
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9)),
            ]

        monkeypatch.setattr(siem_module.socket, "getaddrinfo", hanging_getaddrinfo)
        started = time.monotonic()
        emitter = self._tcp_emitter(9)
        elapsed = time.monotonic() - started
        released.set()  # let the abandoned daemon thread finish promptly
        try:
            # The setup failure disables the sink rather than raising, which is
            # the existing contract for an unreachable collector.
            assert emitter.enabled is False
            assert elapsed < stall / 2, (
                f"construction waited {elapsed:.1f}s on a resolver that never "
                f"answered, against a {self.TIMEOUT}s deadline"
            )
        finally:
            emitter.close()

    def test_datagram_sockets_keep_the_stock_path(self) -> None:
        """Only streams connect, so only streams needed a connect deadline."""
        emitter = _udp_emitter(_closed_udp_port())
        try:
            assert emitter.enabled is True
            handler = emitter._syslog.handlers[0]  # type: ignore[union-attr]
            assert handler.socktype == socket.SOCK_DGRAM
        finally:
            emitter.close()
