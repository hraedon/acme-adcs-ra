"""Wheel artifact test: verify fixture PEMs are packaged correctly.

Builds the wheel and inspects its contents to ensure package data (the
fixture PEMs) are included.  This guards against build-config regressions
that could silently drop the fixtures from the installed wheel.
"""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent


class TestWheelArtifacts:
    """Verify the built wheel contains expected package data."""

    def test_fixture_pems_in_wheel(self, tmp_path: Path) -> None:
        """fake_cert.pem and fake_chain.pem must be in the wheel."""
        # Build the wheel into a temp directory
        wheel_dir = tmp_path / "dist"
        wheel_dir.mkdir()

        try:
            result = subprocess.run(
                ["uv", "build", "--wheel", "--out-dir", str(wheel_dir), str(ROOT)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            pytest.skip("uv build not available — skipping wheel artifact test")

        assert result.returncode == 0, (
            f"uv build failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

        wheels = list(wheel_dir.glob("*.whl"))
        assert len(wheels) == 1, f"Expected exactly one .whl, found: {wheels}"
        whl_path = wheels[0]

        with zipfile.ZipFile(whl_path) as zf:
            names = set(zf.namelist())

        expected = {
            "acme_adcs_ra/fixtures/fake_cert.pem",
            "acme_adcs_ra/fixtures/fake_chain.pem",
        }
        for pem in expected:
            assert pem in names, (
                f"Expected '{pem}' in wheel {whl_path.name}, "
                f"but it was not found. Wheel contents:\n"
                + "\n".join(sorted(names))
            )
