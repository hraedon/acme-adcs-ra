"""acme-adcs-ra — an ACME Registration Authority for ADCS.

Speaks ACME (RFC 8555) on the front, holds no signing key, forwards CSRs to the
existing ADCS issuing CA via /certsrv/ as a passwordless gMSA. See README.md and
docs/architecture.md.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    # Single source of truth is pyproject.toml; reading the installed
    # distribution's metadata means this can never drift from it the way a
    # hand-maintained literal did (it sat at "0.1.0" through eight releases).
    __version__ = _version("acme-adcs-ra")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0+unknown"
