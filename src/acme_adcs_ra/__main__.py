"""Console entry point for acme-adcs-ra.

Loads configuration from the environment and starts the FastAPI ACME server.
"""

from __future__ import annotations

import os
import sys
import urllib.parse

import uvicorn

from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.enrollment import CertsrvEnrollmentLeg, FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import CertsrvRevocationLeg, FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store


def _build_policy(config: RAConfig) -> IssuancePolicy:
    return IssuancePolicy(
        allowed_kids=set(config.eab_keys_by_kid().keys()),
        san_scopes={kid: scope.dns_patterns for kid, scope in config.san_scopes.items()},
        template=config.adcs_template,
    )


def main() -> int:
    # Behind IIS the secret-bearing .env (EAB MAC keys, HEC token) lives in the
    # locked-down data dir, not the worker's CWD — let the deployment point at it.
    dotenv = os.environ.get("ACME_RA_DOTENV")
    # _env_file is a pydantic-settings runtime init kwarg; its stubs don't expose it.
    config = RAConfig(_env_file=dotenv) if dotenv else RAConfig()  # type: ignore[call-arg]
    store = Store(config.db_path, order_expiry_seconds=config.order_expiry_seconds)
    policy = _build_policy(config)
    # Use the real ADCS legs on Windows (Negotiate/SSPI as the gMSA), otherwise
    # the fake legs.  For dev/CI on Linux this always selects Fake*Leg.
    enrollment: FakeEnrollmentLeg | CertsrvEnrollmentLeg = (
        CertsrvEnrollmentLeg(
            host=config.adcs_host,
            template=config.adcs_template,
            ca_name=config.adcs_ca_name,
            ca_bundle=config.adcs_ca_bundle,
        )
        if sys.platform == "win32"
        else FakeEnrollmentLeg()
    )
    revocation: FakeRevocationLeg | CertsrvRevocationLeg = (
        CertsrvRevocationLeg(
            host=config.adcs_host,
            ca_bundle=config.adcs_ca_bundle,
        )
        if sys.platform == "win32"
        else FakeRevocationLeg()
    )
    context = ServerContext(
        config=config,
        store=store,
        policy=policy,
        enrollment=enrollment,
        revocation=revocation,
    )
    app = create_app(context)
    # Bind address: explicit bind_host/bind_port win (the reverse-proxy/IIS case,
    # where the proxy assigns a loopback port via $HTTP_PLATFORM_PORT and base_url
    # stays the PUBLIC URL). Otherwise derive from base_url (direct-serve lab use).
    parsed = urllib.parse.urlparse(config.base_url)
    host = config.bind_host or parsed.hostname or "127.0.0.1"
    # IIS/HttpPlatformHandler assigns the loopback port via $HTTP_PLATFORM_PORT;
    # honour it when bind_port is unset so web.config needs no port plumbing.
    platform_port = os.environ.get("HTTP_PLATFORM_PORT")
    port = (
        config.bind_port
        or (int(platform_port) if platform_port and platform_port.isdigit() else None)
        or parsed.port
        or 8000
    )
    # When TLS material is configured, uvicorn terminates TLS itself (the no-proxy
    # deployment). Behind a TLS-terminating proxy (IIS) leave these unset and let
    # the proxy do TLS; trust_proxy then makes the JWS URL check see the public
    # scheme/host (threat-model §4.D).
    ssl_certfile = str(config.tls_certfile) if config.tls_certfile else None
    ssl_keyfile = str(config.tls_keyfile) if config.tls_keyfile else None
    uvicorn.run(
        app,
        host=host,
        port=port,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
        proxy_headers=config.trust_proxy,
        forwarded_allow_ips=config.forwarded_allow_ips,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
