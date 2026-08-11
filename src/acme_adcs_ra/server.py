"""FastAPI ACME server (RFC 8555 subset) for the ADCS Registration Authority.

This module is the composition root — it wires the app, includes routers,
and sets up the exception handler. Route logic lives in routes/, shared
state in app_state.py, finalize helpers in finalize.py, CSR validation in
csr_validation.py, and JSON serializers in serializers.py.

This module only **verifies** JWS signatures and CSRs; it never signs anything.
The enrollment leg (``EnrollmentLeg``) forwards accepted CSRs to ADCS.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import AcmeError
from acme_adcs_ra.app_state import (
    ServerContext,
    _default_nonce_bucket,
    _default_siem_emitter,
)
from acme_adcs_ra.routes.acme import router as acme_router
from acme_adcs_ra.routes.admin import router as admin_router
from acme_adcs_ra.siem import SiemEmitter

__all__ = ["ServerContext", "create_app"]


def _package_version() -> str:
    """The installed distribution version, or a marker when running unpackaged."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("acme-adcs-ra")
    except PackageNotFoundError:  # pragma: no cover - source checkout without install
        return "0+unknown"


def create_app(context: ServerContext) -> FastAPI:
    """Build a FastAPI app wired to the supplied server context."""
    # Wire the default SIEM emitter when no test/operator hook is supplied.
    _siem_emitter: SiemEmitter | None = None
    if context.audit_hook is None:
        _siem_emitter = _default_siem_emitter(context.config)
        context.audit_hook = _siem_emitter.export
    if context.nonce_bucket is None:
        context.nonce_bucket = _default_nonce_bucket(context.config)

    # H-3: shut down the SIEM emitter pool on app shutdown via lifespan.
    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> Any:
        yield
        if _siem_emitter is not None:
            _siem_emitter.close()

    app = FastAPI(
        title="acme-adcs-ra",
        # Read from installed package metadata rather than a second hand-
        # maintained literal — this string drifted to 1.6.0 while pyproject
        # said 1.7.0, and it is the version an operator reads when working out
        # which build is actually deployed.
        version=_package_version(),
        lifespan=_lifespan,
        # The interactive docs publish the full route inventory — including
        # every /acme/admin/* endpoint — to any unauthenticated caller that can
        # reach the RA. That undoes the same intent as web.config's
        # removeServerHeader. ACME is a machine protocol; there is no operator
        # workflow that needs Swagger on an issuance-path host.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.context = context

    @app.exception_handler(AcmeError)
    async def acme_exception_handler(request: Request, exc: AcmeError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status,
            content=exc.to_problem(),
            headers={"Content-Type": "application/problem+json", **exc.headers},
        )

    app.include_router(acme_router)
    app.include_router(admin_router)

    return app
