# AGENTS.md

Conventions and quick reference for agents (and humans) working on acme-adcs-ra.

## What this is

An **ACME Registration Authority** for ADCS: speaks ACME (RFC 8555) on the front,
holds **no signing key**, forwards CSRs to the existing ADCS issuing CA over the
Web Enrollment (`/certsrv/`) surface as a passwordless **gMSA**. It exists so
Certify the Web can renew ADFS/Exchange-class certs off the existing chain with
no new intermediate. See `README.md` for the charter.

## Orient

1. **Read `docs/architecture.md`** — the design spine: the RA model, the ACME
   surfaces, the enrollment leg, the transport modes, the security model.
2. **Read `docs/certsrv-setup.md`** — how to configure the ADCS Web Enrollment
   surface in Mode A and Mode C. The lab spike validates this.
3. The first plan is `plans/001-spike-and-mvp.md`.

## Hard rules (issuance infra — these REPLACE the read-only family rules)

- **No signing key. Ever.** This is an RA. It must never hold a CA/private signing
  key or sign a certificate itself. If a change moves toward that, stop. An
  architecture test asserts no signing primitive is invoked in the issuance path.
- **In the issuance path — treat every issue-capable code path as
  security-critical.** This is not read-only software; there is no "it's just
  analysis" safety margin.
- **Passwordless to ADCS.** Authenticate as a **gMSA** via Negotiate/SSPI
  (`pyspnego`, SPNEGO + RFC 5929 channel binding so EPA=Require is supported;
  ambient process identity via in-tree `negotiate_auth.NegotiateAuth`). **No
  stored ADCS passwords.** EAB keys and any secrets are never committed.
- **Deterministic issuance policy.** Which template, which SANs are permitted, who
  may request — explicit policy code. **No LLM in the issuance decision path.**
- **Least privilege.** One **server-authentication-only** template; subject/SAN
  from the CSR; the gMSA holds minimal Enroll rights. This bounds a compromise to
  TLS-service spoofing, short of client-auth/PKINIT domain-takeover.
- **Gate the ACME front.** EAB (External Account Binding) pinned to the
  authorized client(s) + network allowlist.
- **Audit every issuance.** RA store + emit (SIEM). No silent issuance.
- **No work-domain identifiers in committed files.** Real CA names, hostnames,
  template names, EAB keys, and configs live in gitignored local config /
  `samples/` — placeholders (`CA01`, `WORK-DOMAIN.local`) in committed docs.

## Stack / build

FastAPI + SQLite + `cryptography`. The Windows SSPI enrollment dependency is
platform-gated (`sys_platform == 'win32'`) so CI on Linux is unaffected; the
enrollment leg is exercised via the lab/Windows host.

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src
```

## Transport modes

- **Mode A** — Web Enrollment (`/certsrv/`) installed on the CA itself. Simplest;
  no Kerberos delegation needed (enrollment is local to the CA). Matches the
  production CA's existing posture.
- **Mode C** — a separate Web-Enrollment or CES host fronting the CA. Keeps the CA
  role-pure, but the enrollment host enrolls *on behalf of* the requester, which
  requires **Kerberos constrained delegation** to the CA. See `docs/certsrv-setup.md`.

## Boundary

[cert-watch](../cert-watch/) = cert lifecycle; [adcs-lens](../adcs-lens/) = CA
posture; this = automated issuance off the CA. The RA's gMSA/template is itself an
ESC surface adcs-lens would flag — scope it tightly.

## Status

**Released: v1.6.0 (2026-07-24) — feature-complete for the charter.** v1.5 added
automated CA-side revocation (template-scoped officer restriction; two-identity
default + opt-in single-identity `-LocalMode`) + self-enforced serverAuth EKU
(Plans 004–006); the **v1.6 hardening sweep** (Plan 007) closed Finding E-1,
added a Pester suite + deterministic CI (`uv sync --locked`), proved the
two-identity compromise-independence property live, and added the live-re-proof
runbook. The repo is public and CI-gated (incl. a monthly rot-canary). Re-entry
rules:

- **Any change to the issuance leg earns a live lab re-proof** (the standing
  project rule — see the validation log in `docs/pre-pilot-checklist.md` and the
  procedure in `docs/live-reproof-runbook.md`). Latest: WI-028 (v1.5, 2026-07-23)
  + WI-035/036 (v1.6, 2026-07-23/24).
- **Remaining before pilot (not code debt):** the operator-owned §B–E items; and
  completing WI-036's literal revoke-by-revoker round-trip, which is blocked by an
  **out-of-project homelab AD/KDS defect** (newly-created gMSAs can't obtain a
  usable managed password — NOT clock skew, that was ruled out). The two-identity
  *compromise-independence* property is already proven live. WI numbering:
  WI-011..015 exist only in plan documents, not the store — file new items with an
  explicit identifier ≥ WI-040.
- A production pilot is gated on the operator-owned sections (§B–E) of
  `docs/pre-pilot-checklist.md`; those are per-deployment, not code debt.
- If the scheduled CI run has gone red, fix CI first — it is
  dependency/runner rot (pip-audit especially), not a code regression.

**Plans 001–006 complete; at the production-pilot bar (v1.5 on `main`).**
WI-001–WI-010 (ACME server, EAB/policy, enrollment, SIEM audit, out-of-band
revocation) and WI-011–WI-014 (operator-enablement artifacts) shipped for 1.0;
Plans 004–006 (WI-021–WI-034) add the automated CA-side revocation loop, EKU
self-enforcement, and the single-identity option for v1.5.
**WI-015** (live lab re-proof against the exact piloted commit) **PASSED**
2026-07-13 on the lab host against `7d5c5b9` — all 12 cases (issue, policy
denial, revocation, reason-7 rejection, chain off the existing CA). **Plan 003**
(WI-016–WI-020) is complete: in-app per-account order rate limiting, RA-vs-CA
revocation reconciliation (read-only), EAB scope audit view, `keyChange`
(RFC 8555 §7.3.5), and locale-robust `certfnsh.asp` parsing. See `docs/operations.md`.
Post-review security fixes: M-1 (reason 7 rejected), M-2 (CAS-guarded
pending→ready), M-3 (CAS-guarded cert revocation, now with a deterministic
`won_cas` signal), and MED-1 (post-issuance SAN verification — the issued
cert's SANs are checked against the order, not just the CSR).

Auth is SPNEGO + channel binding
(`negotiate_auth.NegotiateAuth` over `pyspnego`) against `/certsrv/` **EPA=Require**.
**CA-side revocation is out-of-band (WI-010)**: ADCS Web Enrollment exposes no
revocation endpoint, so `revokeCert` records the revocation in the RA store
only (cert → revoked, GET → 410) with an honest audit
(`revocation_scope=ra-store-only`, `ca_crl_updated=false`). The operator closes
the loop by running `scripts/Revoke-Cert.ps1` (a CA officer, not the gMSA),
which runs `certutil -revoke` and republishes the CRL. The enrollment gMSA
gains no CA-officer rights (threat-model §E).
