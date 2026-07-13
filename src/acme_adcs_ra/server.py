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

from acme_adcs_ra.app_state import ServerContext, _default_siem_emitter
from acme_adcs_ra.acme_errors import AcmeError
from acme_adcs_ra.routes.acme import router as acme_router
from acme_adcs_ra.routes.admin import router as admin_router
from acme_adcs_ra.siem import SiemEmitter

__all__ = ["ServerContext", "create_app"]


def create_app(context: ServerContext) -> FastAPI:
    """Build a FastAPI app wired to the supplied server context."""
    # Wire the default SIEM emitter when no test/operator hook is supplied.
    _siem_emitter: SiemEmitter | None = None
    if context.audit_hook is None:
        _siem_emitter = _default_siem_emitter(context.config)
        context.audit_hook = _siem_emitter.export

    # H-3: shut down the SIEM emitter pool on app shutdown via lifespan.
    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> Any:  # noqa: ARG001
        yield
        if _siem_emitter is not None:
            _siem_emitter.close()

    app = FastAPI(title="acme-adcs-ra", version="1.0.0", lifespan=_lifespan)
    app.state.context = context

    @app.exception_handler(AcmeError)
    async def acme_exception_handler(request: Request, exc: AcmeError) -> JSONResponse:  # noqa: ARG001
        return JSONResponse(
            status_code=exc.status,
            content=exc.to_problem(),
            headers={"Content-Type": "application/problem+json", **exc.headers},
        )

    app.include_router(acme_router)
    app.include_router(admin_router)

    return app
