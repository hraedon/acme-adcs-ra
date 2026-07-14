"""ACME protocol routes (RFC 8555 subset).

Aggregator that composes the per-resource route modules into a single
``router`` consumed by ``server.py``. Each endpoint lives in its own module:

- ``directory``       — directory + nonce (§7.1.1, §7.2)
- ``accounts``         — account creation with EAB (§7.3)
- ``orders``           — order creation, rate limiting, finalize (§7.1, §7.4)
- ``authorizations``   — authz retrieval + challenge (§7.5)
- ``certificates``     — cert retrieval (§7.4.2)
- ``revocation``       — revokeCert (§7.6)
- ``key_change``       — account-key rollover (§7.3.5)
"""

from __future__ import annotations

from fastapi import APIRouter

from acme_adcs_ra.routes.accounts import router as accounts_router
from acme_adcs_ra.routes.authorizations import router as authorizations_router
from acme_adcs_ra.routes.certificates import router as certificates_router
from acme_adcs_ra.routes.directory import router as directory_router
from acme_adcs_ra.routes.key_change import router as key_change_router
from acme_adcs_ra.routes.orders import router as orders_router
from acme_adcs_ra.routes.revocation import router as revocation_router

router = APIRouter()
router.include_router(directory_router)
router.include_router(accounts_router)
router.include_router(orders_router)
router.include_router(authorizations_router)
router.include_router(certificates_router)
router.include_router(revocation_router)
router.include_router(key_change_router)
