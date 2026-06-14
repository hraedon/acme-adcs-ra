# Plan 001 — Lab spike & MVP

**Status:** proposed 2026-06-13
**Author:** Opus 4.8 (promoted from `maybe-projects/acme-to-adcs-bridge.md`)
**Strategic role:** acme-adcs-ra is charter-stage. Unlike the read-only siblings,
this is **issuance-path infrastructure**, so the sequencing is built around one
hard feasibility gate — a lab spike — before any meaningful ACME-server code. The
charter, architecture, and the Mode A/C `certsrv` runbook exist; this plan turns
them into a proven round-trip, then a minimal server.

## Ground truth at time of writing

- Charter (`README.md`), design spine (`docs/architecture.md`), and the
  enrollment runbook (`docs/certsrv-setup.md`, Modes A and C) exist. No code.
- Lab: issuing CA **CA01** (OCSP working, IIS present; `/certsrv/` Web
  Enrollment **not yet installed but installable**). Offline root is a separate
  offline box.
- Production dependency, unproven: the work CA has Web Enrollment ("CertEnroll")
  installed but **possibly broken** — must be fixed/verified before prod.

## The feasibility gate (do this before writing the ACME server)

### WI-1 — Mode A enrollment spike on CA01
Execute `docs/certsrv-setup.md` Mode A end to end and **correct the runbook from
reality**: install Web Enrollment on CA01, create the `ACME-ServerAuth`
server-auth template, create + install `gMSA-acme-ra`, and prove that a process
**running as the gMSA** can submit a CSR to `/certsrv/certfnsh.asp` over
**Negotiate** and get back an ADCS-issued cert on the existing chain.
- **AC:** a ~30-line spike script (running as the gMSA, `requests-negotiate-sspi`)
  issues a server-auth cert with a SAN from the CSR; the cert chains to the
  existing root; the CA database shows requester = `gMSA-acme-ra$`;
  `docs/certsrv-setup.md` Mode A is updated to match what actually worked.
- **This AC is the project's promotion-from-feasibility gate.** Everything below
  is ordinary engineering; this is the only unproven-physics step.

### WI-2 — Document Mode C deltas from the lab
With A proven, validate the Mode C delegation specifics (C1 web-enrollment-on-
separate-host SPNs + constrained delegation) enough to confirm the runbook is
correct, even if A is the chosen deployment. (C2/CES SOAP left as documented, not
spiked, unless role-purity is prioritized.)
- **AC:** `docs/certsrv-setup.md` Mode C section reflects verified delegation
  steps or is explicitly marked "documented, not lab-verified."

## Phase 0 — Project infrastructure

### WI-0.1 — Skeleton + tooling
- `pyproject.toml` (FastAPI/SQLite/`cryptography`; Windows SSPI dep platform-gated;
  `[dev]` ruff/mypy/pytest/httpx); `src/acme_adcs_ra/` skeleton; console entry.
- **Architecture test from day one:** assert no signing primitive
  (`sign`/private-key signing of a cert) is reachable from the issuance path — the
  "no signing key, ever" guardrail, enforced mechanically.
- **AC:** install + ruff + mypy --strict + pytest green on the skeleton; the
  no-signing-key test exists and passes.

### WI-0.2 — Git + private remote + CI
- `git init`; **private** remote (this repo will carry references to a real work
  CA topology — public is gated on a written sanitization review,
  `docs/publication-review.md`).
- CI: ruff + mypy --strict + pytest on Linux (the SSPI enrollment leg is gated
  out; it's exercised on the Windows lab host, not CI).
- **AC:** CI green; secrets/DB/config gitignored.

## Phase 2 — Minimal ACME server (after the gate)

### WI-2.1 — RFC 8555 subset wired to the enrollment leg
`directory`, `newNonce`, `newAccount` **with EAB**, `newOrder`, authz/challenge,
`finalize` (accept CSR), `certificate`. On finalize, call the proven Mode A
enrollment leg; return the ADCS cert + chain. SQLite for accounts/orders/certs.
- **AC:** Certify the Web (EAB-configured) completes an order against the RA and
  installs an ADCS-issued cert; the RA never holds a signing key (architecture
  test still green).

### WI-2.2 — Issuance policy + EAB gating
Deterministic policy: the EAB account maps to the allowed template and the
permitted SAN scope; requests outside policy are refused, not issued. Network
allowlist documented.
- **AC:** an in-policy request issues; an out-of-policy SAN is refused with a
  clear ACME error; no LLM in the path.

## Phase 3 — Audit emission & hardening

- Emit every issuance to SIEM (reuse cert-watch's export pattern); record in the
  RA store. Revocation passthrough. Threat-model doc before any prod pilot.
- **AC:** every issuance produces a SIEM event + an RA-store row; a documented
  threat model exists.

## Explicitly not in this plan

- **Becoming a CA / holding a signing key** — the cardinal non-goal.
- CES/WSTEP transport (Mode C2) implementation — documented only, built only if
  role-purity is prioritized later.
- Production pilot — gated on the threat model (Phase 3) and the work
  web-enrollment fix.

## Sequencing rationale

The Mode A spike (WI-1) is first because it is the only step whose feasibility is
unproven; a remote-less ACME server built before it would be effort spent on an
unvalidated foundation. Phase 0 infra runs alongside. The ACME server (Phase 2)
is deferred until the enrollment leg is real, because that's the seam everything
else hangs on.

## Decisions

1. **Project name** `acme-adcs-ra` (RA encodes "no signing key"). Rename trivial
   pre-remote.
2. **Deployment mode** — spike A; decide A-vs-C for prod after the spike, weighing
   CA role-purity vs. the Kerberos-delegation cost.
3. **Repo visibility** — private now; public only after a sanitization review
   (carries real work-CA topology references).
