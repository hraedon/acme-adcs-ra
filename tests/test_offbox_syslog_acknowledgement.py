"""The off-box audit requirement keeps its strictness but stops stranding estates.

``audit_offbox_required`` asserts a *destination* property: the audit trail
leaves the box, and delivery is demonstrable. The 2026-08-25 remediation made
that switch additionally demand authenticated HTTPS HEC, which is a
*transport-security* property the switch does not name — and, because this
codebase offers no syslog-over-TLS transport, the practical effect was that any
estate reaching its SIEM through a syslog relay could not satisfy the
requirement at all.

The realistic response to a refused start is ``audit_offbox_required=false``,
which is strictly worse than TCP syslog: it drops the off-box requirement
entirely rather than just the transport strictness. So the strict posture stays
the default and the weaker one is reachable only by explicit acknowledgement —
the shape this repo already uses for ``-AllowInsecureUrl`` and
``-AllowUntrustedScriptPath``.

Three properties are load-bearing here and each has a test below:

* UDP is **not** reachable through the acknowledgement. That refusal is about
  whether "required" can mean anything (a datagram socket accepts bytes with
  nothing listening), not about transport security.
* The acknowledgement cannot be silently inert. Setting it without
  ``audit_offbox_required`` refuses, because an operator who sets a
  security-relevant switch and watches the RA start must not be left unable to
  tell whether anything leaves the host.
* The weakened posture is recorded in the trail it weakens, not only in the
  config file that chose it.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest
from pydantic import ValidationError

from acme_adcs_ra import siem as siem_module
from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.siem import SiemEmitter, build_siem_config


def _syslog_config(tmp_path: Path, **overrides: object) -> RAConfig:
    kwargs: dict[str, object] = {
        "base_url": "http://testserver",
        "db_path": tmp_path / "ra.db",
        "audit_offbox_required": True,
        "siem_sink": "syslog",
        "siem_syslog_host": "siem.example",
        "siem_syslog_proto": "tcp",
    }
    kwargs.update(overrides)
    return RAConfig(**kwargs)  # type: ignore[arg-type]


def _emitter_without_a_socket(cfg: RAConfig) -> SiemEmitter:
    """Build the emitter without letting it open a real syslog socket.

    The subject here is the *shape of the probe event*, not the transport, and
    the handler resolves its host at construction time. Patching the handler
    class rather than the send path keeps ``probe_offbox_delivery`` running its
    real branch logic.
    """
    with mock.patch.object(siem_module, "_RaisingSysLogHandler") as handler_cls:
        handler_cls.return_value = mock.MagicMock()
        return SiemEmitter(build_siem_config(cfg))


class TestTheDefaultStaysStrict:
    def test_tcp_syslog_alone_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(
            ValidationError, match="does not authenticate the collector"
        ):
            _syslog_config(tmp_path)

    def test_the_refusal_names_the_way_out(self, tmp_path: Path) -> None:
        """A refusal an operator cannot act on becomes
        ``audit_offbox_required=false``."""
        with pytest.raises(ValidationError) as excinfo:
            _syslog_config(tmp_path)
        message = str(excinfo.value)
        assert "audit_offbox_allow_unauthenticated_syslog=true" in message
        assert "hec" in message

    def test_jsonl_is_still_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="jsonl"):
            RAConfig(
                base_url="http://testserver",
                db_path=tmp_path / "ra.db",
                audit_offbox_required=True,
                siem_sink="jsonl",
            )

    def test_hec_still_has_to_be_authenticated_https(self, tmp_path: Path) -> None:
        """The acknowledgement is about syslog; it must not relax HEC."""
        with pytest.raises(ValidationError, match="authenticated HTTPS HEC"):
            RAConfig(
                base_url="http://testserver",
                db_path=tmp_path / "ra.db",
                audit_offbox_required=True,
                audit_offbox_allow_unauthenticated_syslog=True,
                siem_sink="hec",
                siem_hec_url="http://siem.example/services/collector",
                siem_hec_token="placeholder-token",
            )


class TestTheAcknowledgementIsNarrow:
    def test_tcp_syslog_is_accepted_once_acknowledged(self, tmp_path: Path) -> None:
        cfg = _syslog_config(
            tmp_path, audit_offbox_allow_unauthenticated_syslog=True
        )
        assert cfg.siem_sink == "syslog"
        assert cfg.audit_offbox_allow_unauthenticated_syslog is True

    def test_udp_is_refused_even_when_acknowledged(self, tmp_path: Path) -> None:
        """The UDP refusal is about provable delivery, not transport security.

        If the acknowledgement reached UDP it would re-open the hole the
        2026-08-18 round closed: the probe cannot tell a working collector from
        none at all, so ``required`` would assert nothing.
        """
        with pytest.raises(ValidationError, match="fire-and-forget"):
            _syslog_config(
                tmp_path,
                siem_syslog_proto="udp",
                audit_offbox_allow_unauthenticated_syslog=True,
            )

    def test_the_udp_refusal_says_the_flag_does_not_reach_it(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ValidationError) as excinfo:
            _syslog_config(
                tmp_path,
                siem_syslog_proto="udp",
                audit_offbox_allow_unauthenticated_syslog=True,
            )
        assert "does NOT reach it" in str(excinfo.value)

    def test_acknowledgement_without_the_requirement_is_refused(
        self, tmp_path: Path
    ) -> None:
        """A security switch that is silently inert is the failure mode this
        repo has paid for repeatedly."""
        with pytest.raises(ValidationError, match="weakens nothing"):
            RAConfig(
                base_url="http://testserver",
                db_path=tmp_path / "ra.db",
                audit_offbox_required=False,
                audit_offbox_allow_unauthenticated_syslog=True,
            )


class TestThePostureIsRecordedWhereItMatters:
    def test_the_startup_probe_event_names_the_weakened_transport(
        self, tmp_path: Path
    ) -> None:
        """A reader of the trail can tell the two postures apart without
        access to the RA host's configuration."""
        cfg = _syslog_config(
            tmp_path, audit_offbox_allow_unauthenticated_syslog=True
        )
        emitter = _emitter_without_a_socket(cfg)
        sent: list[dict[str, object]] = []
        emitter._syslog_send_inner = sent.append  # type: ignore[method-assign]

        ok, _detail = emitter.probe_offbox_delivery()

        assert ok is True
        assert len(sent) == 1
        assert sent[0]["offbox_transport"] == "syslog-unauthenticated"

    def test_an_unacknowledged_syslog_probe_is_not_labelled_weakened(
        self, tmp_path: Path
    ) -> None:
        """Negative control: the label must track the acknowledgement, not
        merely the sink. A constant would pass the test above."""
        cfg = RAConfig(
            base_url="http://testserver",
            db_path=tmp_path / "ra.db",
            audit_offbox_required=False,
            siem_sink="syslog",
            siem_syslog_host="siem.example",
            siem_syslog_proto="tcp",
        )
        emitter = _emitter_without_a_socket(cfg)
        sent: list[dict[str, object]] = []
        emitter._syslog_send_inner = sent.append  # type: ignore[method-assign]

        emitter.probe_offbox_delivery()

        assert sent[0]["offbox_transport"] == "syslog"
