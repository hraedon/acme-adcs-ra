"""Console entry point for acme-adcs-ra.

Loads configuration from the environment and starts the FastAPI ACME server.
"""

from __future__ import annotations

import sys
import urllib.parse

import uvicorn

from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.enrollment import CertsrvEnrollmentLeg, FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store


def _build_policy(config: RAConfig) -> IssuancePolicy:
    return IssuancePolicy(
        allowed_kids=set(config.eab_keys_by_kid().keys()),
        san_scopes={kid: scope.dns_patterns for kid, scope in config.san_scopes.items()},
        template=config.adcs_template,
    )


def main() -> int:
    config = RAConfig()
    store = Store(config.db_path)
    policy = _build_policy(config)
    # Use the real ADCS leg on Windows if the spike is implemented, otherwise
    # the fake leg.  For dev/CI on Linux this always selects FakeEnrollmentLeg.
    enrollment: FakeEnrollmentLeg | CertsrvEnrollmentLeg = (
        CertsrvEnrollmentLeg() if sys.platform == "win32" else FakeEnrollmentLeg()
    )
    context = ServerContext(
        config=config,
        store=store,
        policy=policy,
        enrollment=enrollment,
    )
    app = create_app(context)
    # Extract host/port from base_url if present; default to localhost:8000.
    parsed = urllib.parse.urlparse(config.base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8000
    uvicorn.run(app, host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
