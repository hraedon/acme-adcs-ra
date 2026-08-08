# Security review — 2026-08-07

Scope: ACME/JWS authentication, EAB gating, issuance policy, `/certsrv/`
response handling, order state/rate limiting, revocation/admin surfaces,
SIEM transport, SQLite persistence, Windows deployment scripts, and locked
dependencies.

## Closed findings

1. **High — CA-capable certificate not self-rejected.** A dangerously drifted
   template could return `CA=true` or signing key usage while still carrying
   only the serverAuth EKU. The RA now rejects CA-capable CSR extensions before
   enrollment and independently rejects CA-capable issued certificates before
   recording or serving them.
2. **Medium — Common Name bypassed SAN scope.** The template takes the subject
   from the CSR, but policy previously scoped only SANs. A client could pair an
   allowed SAN with an out-of-scope CN for legacy CN consumers. CSR and issued
   certificate CNs must now be members of the requested DNS SAN set.
3. **Medium — certsrv response was not bound to the CSR key.** The production
   enrollment leg now compares SubjectPublicKeyInfo bytes and fails closed if
   ADCS returns a certificate for a different key.
4. **Medium — issuance rate-limit TOCTOU.** Counting and creating orders used
   separate transactions, so parallel requests could all observe a below-limit
   count. The authoritative decision is now serialized with `BEGIN IMMEDIATE`
   and the order is inserted in the same transaction.
5. **Medium — unbounded JWS request buffering.** The verifier read the full
   unauthenticated body before applying the CSR cap. It now enforces a
   configurable 64 KiB limit while streaming and rejects oversized declared
   lengths before reading the body.
6. **Medium — loose account-key algorithm/key acceptance.** Made-up `RS*`/`ES*`
   names that happened to end in a known hash size were accepted, EC algorithm
   names were not tied to their curves, and weak RSA account keys were allowed.
   Algorithms are now exact, EC curve-matched, and RSA keys require 2048 bits.
7. **Low — EAB cross-endpoint/environment replay.** EAB MAC verification did
   not check its protected `url`; it is now bound to the public `newAccount`
   request URL.
8. **Medium — HEC token could be sent over plaintext HTTP.** The HEC sink now
   enables only for HTTPS URLs without embedded credentials.
9. **Dependency — vulnerable cryptography release.** The lockfile selected
   `cryptography` 49.0.0, which the dependency audit reported under
   `PYSEC-2026-3552`. The project metadata and lock now require the fixed
   50.0.0 release, and a fresh audit reports no known vulnerabilities.

## Validation and residual work

Local results: 480 Python tests passed, one platform-specific test skipped; all
61 Pester tests passed; Ruff and strict mypy passed; the lockfile and
publication-plumbing checks passed; and the exact locked dependency closure
reported no known vulnerabilities. The only test warning was the existing
Starlette/httpx TestClient deprecation.

Because this review changes the issuance leg, the standing project rule also
requires the live Windows/ADCS re-proof in `docs/live-reproof-runbook.md` before
these changes are piloted or released. That environment-dependent proof was not
available in this workspace. Operator-owned controls in
`docs/pre-pilot-checklist.md` remain mandatory, especially the network
allowlist, host hardening, token/EAB rotation, SIEM monitoring, and revocation
reconciliation.

## Live re-proof — PASSED (2026-08-08)

The live re-proof was performed against commit `5d30937` on the lab RA host
(the lab Windows host, ADCS CA `CA01`, Mode A). Core 12 cases passed (issuance,
serverAuth-only EKU, chain off the existing CA, out-of-scope SAN denial,
revoke→410, reason-7 rejection) plus 3 new security-hardening checks (CA-capable
CSR rejected, keyCertSign CSR rejected, out-of-scope CN rejected). CA DB
confirmed requester = `WORK-DOMAIN\gMSA-acme-ra$`, template = `ACME-ServerAuth`.
cryptography 50.0.0 verified on Windows Server 2025 / Python 3.14. See the
validation log in `docs/pre-pilot-checklist.md`.
