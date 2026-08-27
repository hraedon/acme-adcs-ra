"""``scripts/lib_digest.py`` must not rewrite the files it repairs.

The tool exists so that editing ``InstallVerifyLib.ps1`` does not leave five
privileged entry points refusing to run. It repairs a 64-character hex literal,
and it must change **nothing else** — these are Windows PowerShell scripts, they
live in a checkout that may well have CRLF line endings, and a tool that
silently normalises 500 lines to LF while fixing one string is not a repair, it
is a diff nobody asked for sitting on top of an authenticated release set.

The first version did exactly that. ``read_text`` applies universal-newline
translation, so CRLF arrived as ``\\n`` in memory and was written back as ``\\n``:
measured, 514 CRLF lines became 514 LF lines.

**The round-trip check that missed it is the more useful lesson.** The tool was
verified on Linux by breaking a pin, repairing it, and confirming the file was
byte-identical to HEAD — which passed, and proved nothing about this, because an
LF file stays LF whatever the newline handling does. The check could not fail
for the reason it was supposed to be checking. So the fixture below is CRLF
**on purpose**: it is the only shape in which the property is observable.
"""

from __future__ import annotations

import hashlib
import importlib.util
import shutil
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRY_POINTS = (
    "Revoke-Cert.ps1",
    "Set-OfficerRights.ps1",
    "Sync-Revocations.ps1",
    "Register-MaintenanceTasks.ps1",
    "Reconcile-Revocation.ps1",
)


def _load_tool(root: Path) -> ModuleType:
    """Import lib_digest.py pointed at a throwaway tree."""
    spec = importlib.util.spec_from_file_location(
        "lib_digest_under_test", REPO_ROOT / "scripts" / "lib_digest.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.REPO_ROOT = root
    module.HELPER = root / "scripts" / "lib" / "InstallVerifyLib.ps1"
    return module


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A copy of the real scripts tree, so the pins are genuinely consistent."""
    scripts = tmp_path / "scripts"
    (scripts / "lib").mkdir(parents=True)
    shutil.copy2(
        REPO_ROOT / "scripts" / "lib" / "InstallVerifyLib.ps1", scripts / "lib"
    )
    for name in ENTRY_POINTS:
        shutil.copy2(REPO_ROOT / "scripts" / name, scripts / name)
    return tmp_path


def _to_crlf(path: Path) -> bytes:
    raw = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    path.write_bytes(raw)
    return raw


def test_repairing_a_crlf_entry_point_changes_only_the_pin(tree: Path) -> None:
    target = tree / "scripts" / "Revoke-Cert.ps1"
    pristine = _to_crlf(target)
    assert pristine.count(b"\r\n") > 100, "fixture is not actually CRLF"

    broken = pristine.replace(
        b"$installVerifyExpectedSha256 = '01a351",
        b"$installVerifyExpectedSha256 = '00dead",
    )
    assert broken != pristine, "fixture failed to break the pin"
    target.write_bytes(broken)

    tool = _load_tool(tree)
    assert tool.main(["--write"]) == 0

    repaired = target.read_bytes()
    assert hashlib.sha256(repaired).hexdigest() == hashlib.sha256(pristine).hexdigest(), (
        "repairing the pin must leave the file byte-identical to its pristine "
        "state; it rewrote something else"
    )
    assert repaired.count(b"\r\n") == pristine.count(b"\r\n")
    assert repaired.count(b"\n") - repaired.count(b"\r\n") == 0, (
        "a bare LF appeared in a CRLF file"
    )


def test_an_lf_entry_point_stays_lf(tree: Path) -> None:
    """The other direction: the fix must not paste CRLF into an LF checkout."""
    target = tree / "scripts" / "Sync-Revocations.ps1"
    pristine = target.read_bytes().replace(b"\r\n", b"\n")
    target.write_bytes(pristine)
    target.write_bytes(
        pristine.replace(
            b"$installVerifyExpectedSha256 = '01a351",
            b"$installVerifyExpectedSha256 = '00dead",
        )
    )

    tool = _load_tool(tree)
    assert tool.main(["--write"]) == 0

    repaired = target.read_bytes()
    assert repaired == pristine
    assert b"\r\n" not in repaired


def test_check_mode_reports_a_stale_pin_without_touching_the_file(tree: Path) -> None:
    target = tree / "scripts" / "Reconcile-Revocation.ps1"
    broken = target.read_bytes().replace(
        b"$installVerifyExpectedSha256 = '01a351",
        b"$installVerifyExpectedSha256 = '00dead",
    )
    target.write_bytes(broken)

    tool = _load_tool(tree)
    assert tool.main([]) == 1, "check mode must exit non-zero on a stale pin"
    assert target.read_bytes() == broken, "check mode must not write"


def test_a_missing_pin_is_a_different_and_louder_failure(tree: Path) -> None:
    """An entry point with no pin would load the helper unauthenticated.

    That is worse than a stale pin, so it gets its own exit code and is never
    silently 'repaired' by inserting one.
    """
    target = tree / "scripts" / "Set-OfficerRights.ps1"
    text = target.read_text(encoding="utf-8")
    target.write_text(
        text.replace("$installVerifyExpectedSha256 = '", "$notThePin = '"),
        encoding="utf-8",
    )

    tool = _load_tool(tree)
    assert tool.main(["--write"]) == 2


def test_a_consistent_tree_passes(tree: Path) -> None:
    tool = _load_tool(tree)
    assert tool.main([]) == 0
