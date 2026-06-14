"""acme-adcs-ra — an ACME Registration Authority for ADCS.

Speaks ACME (RFC 8555) on the front, holds no signing key, forwards CSRs to the
existing ADCS issuing CA via /certsrv/ as a passwordless gMSA. See README.md and
docs/architecture.md. Charter stage — no runtime behaviour yet.
"""

__version__ = "0.1.0"
