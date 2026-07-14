"""Directory and nonce endpoints (RFC 8555 §7.1.1, §7.2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response

from acme_adcs_ra.app_state import (
    ServerContext,
    _ACME_PATHS,
    _url,
    get_context,
)

router = APIRouter()


@router.get("/directory", response_model=dict)
async def directory(ctx: ServerContext = Depends(get_context)) -> dict[str, Any]:
    meta: dict[str, Any] = {"externalAccountRequired": True}
    if ctx.config.terms_of_service:
        meta["termsOfService"] = ctx.config.terms_of_service
    return {
        "newNonce": _url(ctx, _ACME_PATHS["newNonce"]),
        "newAccount": _url(ctx, _ACME_PATHS["newAccount"]),
        "newOrder": _url(ctx, _ACME_PATHS["newOrder"]),
        "revokeCert": _url(ctx, _ACME_PATHS["revokeCert"]),
        "keyChange": _url(ctx, _ACME_PATHS["keyChange"]),
        "meta": meta,
    }


def _nonce_response(ctx: ServerContext) -> Response:
    nonce = ctx.store.create_nonce()
    return Response(
        status_code=204,
        headers={
            "Replay-Nonce": nonce,
            "Cache-Control": "no-store",
        },
    )


@router.head(_ACME_PATHS["newNonce"])
async def new_nonce_head(ctx: ServerContext = Depends(get_context)) -> Response:
    return _nonce_response(ctx)


@router.get(_ACME_PATHS["newNonce"])
async def new_nonce_get(ctx: ServerContext = Depends(get_context)) -> Response:
    return _nonce_response(ctx)
