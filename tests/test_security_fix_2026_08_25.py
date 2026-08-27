"""Focused regressions for the 2026-08-25 low-severity remediations."""

from __future__ import annotations

import ctypes
import inspect
import json
import sqlite3
from pathlib import Path
from typing import Any

from acme_adcs_ra.audit_coalesce import DenialCoalescer
from acme_adcs_ra.store import Store
from lab import spike_mode_a


def _audit_rows(store: Store, event_type: str) -> list[sqlite3.Row]:
    connection = sqlite3.connect(store._db_path)
    connection.row_factory = sqlite3.Row
    try:
        return list(
            connection.execute(
                "SELECT * FROM audit_log WHERE event_type = ? ORDER BY id",
                (event_type,),
            ).fetchall()
        )
    finally:
        connection.close()


def test_replayable_admin_events_coalesce_but_state_change_does_not(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "audit.db")
    coalescer = DenialCoalescer(60)
    replayable: list[tuple[str, dict[str, Any]]] = [
        (
            "admin-order-reclaim-not-found",
            {
                "details": {
                    "reason_code": "order-not-found",
                    "sample_order_id": "attacker-id",
                }
            },
        ),
        (
            "admin-order-reclaim-denied",
            {
                "account_id": "account-1",
                "order_id": "stored-order-1",
                "details": {"reason_code": "enrollment-in-flight"},
            },
        ),
        (
            "admin-order-reclaim-noop",
            {
                "account_id": "account-1",
                "order_id": "stored-order-1",
                "details": {"reason_code": "not-processing"},
            },
        ),
        (
            "admin-list-orders",
            {"details": {"reason_code": "read-only-list", "status": "ready"}},
        ),
        (
            "admin-revocation-confirm-deferred",
            {
                "account_id": "account-1",
                "order_id": "stored-order-1",
                "details": {"reason_code": "crl-evidence-capacity"},
            },
        ),
    ]

    for event_type, kwargs in replayable:
        for i in range(25):
            call_kwargs = dict(kwargs)
            call_kwargs["details"] = dict(kwargs["details"])
            if event_type == "admin-order-reclaim-not-found":
                call_kwargs["details"]["sample_order_id"] = f"attacker-id-{i}"
            if event_type == "admin-list-orders":
                call_kwargs["details"]["status"] = (
                    "ready" if i % 2 else "processing"
                )
                call_kwargs["details"]["limit"] = i + 1
            coalescer.record(
                store,
                event_type=event_type,
                outcome="failed",
                **call_kwargs,
            )
        rows = _audit_rows(store, event_type)
        assert len(rows) == 1
        assert json.loads(rows[0]["details"])["denial_count"] == 25

    for _ in range(25):
        coalescer.record(
            store,
            event_type="admin-order-reclaimed",
            account_id="account-1",
            order_id="stored-order-1",
            outcome="success",
            details={"new_status": "ready"},
        )
    assert len(_audit_rows(store, "admin-order-reclaimed")) == 25


def test_admin_target_rotation_cannot_churn_the_window_index(tmp_path: Path) -> None:
    store = Store(tmp_path / "audit-rotation.db")
    # A tiny cap makes the old eviction/reopen bypass reproducible without a
    # thousand fixture orders. Target ids must not create distinct windows.
    coalescer = DenialCoalescer(60, max_open_windows=2)

    for i in range(100):
        coalescer.record(
            store,
            event_type="admin-order-reclaim-denied",
            account_id=f"account-{i}",
            order_id=f"order-{i}",
            outcome="failed",
            details={
                "reason": "enrollment-in-flight",
                "reason_code": "enrollment-in-flight",
            },
        )

    rows = _audit_rows(store, "admin-order-reclaim-denied")
    assert len(rows) == 1
    assert json.loads(rows[0]["details"])["denial_count"] == 100


def test_lab_dacl_is_protected_and_has_only_the_three_allowed_trustees() -> None:
    class FakeAdvapi:
        sddl = ""

        def ConvertStringSecurityDescriptorToSecurityDescriptorW(
            self,
            sddl: str,
            revision: int,
            descriptor: Any,
            size: Any,
        ) -> bool:
            del size
            self.sddl = sddl
            assert revision == spike_mode_a._SDDL_REVISION_1
            descriptor._obj.value = 1234
            return True

    api = FakeAdvapi()
    attributes, descriptor = spike_mode_a._protected_security_attributes(
        "S-1-5-21-1-2-3-1001", api, inherit_to_children=True
    )

    assert api.sddl == (
        "O:S-1-5-21-1-2-3-1001D:P"
        "(A;OICI;FA;;;SY)"
        "(A;OICI;FA;;;BA)"
        "(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"
    )
    assert attributes.security_descriptor == descriptor.value == 1234
    assert attributes.inherit_handle == 0

    spike_mode_a._protected_security_attributes(
        "S-1-5-21-1-2-3-1001", api, inherit_to_children=False
    )
    assert api.sddl == (
        "O:S-1-5-21-1-2-3-1001D:P"
        "(A;;FA;;;SY)"
        "(A;;FA;;;BA)"
        "(A;;FA;;;S-1-5-21-1-2-3-1001)"
    )


def test_lab_key_creation_is_exclusive_and_never_uses_path_write_bytes() -> None:
    source = inspect.getsource(spike_mode_a._write_new_protected_private_key)
    assert "CreateFileW" in source
    assert "_CREATE_NEW" in source
    assert "_FILE_FLAG_OPEN_REPARSE_POINT" in source
    assert "0,  # no sharing" in source
    assert "write_bytes" not in source
    assert source.index("_reject_reparse_ancestors") < source.index("CreateFileW")


def test_lab_output_directory_is_fresh_protected_and_precedes_key_generation() -> None:
    directory_source = inspect.getsource(
        spike_mode_a._create_protected_output_directory
    )
    main_source = inspect.getsource(spike_mode_a.main)

    assert "_reject_reparse_ancestors" in directory_source
    assert "CreateDirectoryW" in directory_source
    assert "_ERROR_ALREADY_EXISTS" in directory_source
    assert "FileExistsError" in directory_source
    assert main_source.index("_create_protected_output_directory") < main_source.index(
        "build_csr"
    )
    assert main_source.index("build_csr") < main_source.index(
        "_write_new_protected_private_key"
    )
    assert ctypes.sizeof(spike_mode_a._SecurityAttributes) > 0
