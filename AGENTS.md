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

**Status update (2026-08-15, post-validation):** Daybreak's review of `f495092`
(the E2E-proven tip) found the installer's ACL claim was bypassable —
`/inheritance:r` removes only *inherited* ACEs, so an attacker's explicit ACEs
and ownership survived the "claim" — plus registration tokens on the command
line and two commit-before-audit orderings. All four are fixed on
`security-review-2026-08-15-daybreak` (takeown+/reset+read-back-proof for the
tree; switch-only `-AdminToken`/`-ConfirmToken`; account/keyChange audit
atomicity, fault-injection proven); WI-014 stays deferred. See
`docs/security-review-2026-08-15-daybreak.md`. **The installer change owes a
live install run before the next release** — CI executes neither takeown nor
the read-back proof.

**Released: v1.9.1 (2026-08-14), live-proven on `bef2022` — two external
security reviews.** There is **no 1.9.0 release**: that line shipped only as
`rc1`/`rc2`, and the re-proof that gates a tag found a red lint gate on the rc2
tip and a `Set-OfficerRights.ps1` defect on the first-provisioning path, so the
fixed build ships as 1.9.1. The
2026-08-14 scan of rc1 found seventeen further findings, two blocking: ACME
**reason 8 (removeFromCRL) was accepted and reached `certutil`**, so a revokeCert
carrying it recorded a successful revocation while asking the CA to *un-revoke*
(Plan 004 recorded the CA-side effect: "off the CRL and valid"); and
post-issuance **transport** failures orphaned live certificates on a path the
2026-08-13 quarantine work did not reach. All seventeen are fixed — see
`docs/security-review-2026-08-14.md`, including the one place the stricter
default was deliberately not taken and why.

v1.9 closes
ten findings from an external static scan of v1.8.0 (separated
revocation-confirm authority with optional CRL proof, certificate quarantine,
atomic issuance+audit, read-path nonce rejection, credential floors, bounded
HEC queue, off-box audit gate on the constructed emitter, JWS type guards, RA
URL validation in the revocation scripts, OfficerRights activation proof).
**The live re-proof of those fixes then found two defects Linux CI structurally
cannot see** — Windows PowerShell 5.1 language semantics that `pwsh` 7 differs
on, one inside the review's own fix. Read `docs/security-review-2026-08-13.md`
§ Proof status before touching the PowerShell.

v1.8 (2026-08-11) bound URL validation to `base_url` and added account
eviction. v1.7 (2026-08-08) closed
nine findings from the 2026-08-07 security review (CA-capable CSR/cert
rejection, CN→SAN binding, certsrv key binding, rate-limit TOCTOU fix, JWS
streaming cap, algorithm exactness, EAB URL binding, HEC HTTPS enforcement,
cryptography ≥50.0.0) — live re-proven against ADCS. v1.5–v1.6 added
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
  + WI-035/036 (v1.6, 2026-07-23/24) + 2026-08-07 security-hardening (2026-08-08)
  + 2026-08-11 security review (26/26, incl. the new §A.1 front-control checks)
  + **2026-08-13 review (on `26eae31`; found two PowerShell defects)**
  + **2026-08-14 review (on `bef2022`; found one blocking PowerShell defect and
  a red lint gate on the rc2 tip)**. The rule is *on the exact commit being
  shipped* — a re-proof on an earlier commit does not transfer.
- **Run the whole re-proof, not the delta, and start it from a known config.**
  The 2026-08-14 pass is automated end to end (methodology in the gitignored
  `samples/lab-validation-runbook.md`). One toggle left set by an earlier step
  silently changed what three later steps proved, so the driver now asserts the
  default configuration before it measures anything.
- **A green cross-platform Pester run is not evidence about the CA host.** The
  two defects the 2026-08-13 re-proof found were Windows PowerShell 5.1 *language*
  semantics — a single-element array has no `.Count` under 5.1 but yields `1`
  under `pwsh` 7; `$PSNativeCommandUseErrorActionPreference` defaults differ —
  not Windows-only APIs, which is the gap everyone anticipates. Linux Pester was
  green while the shipped script was broken on the CA.
- **Two review lessons worth carrying forward.** (1) Every finding in the
  2026-08-11 review was in an *inherited framework default* — FastAPI's docs
  endpoints, Starlette's `request.url`, uvicorn's proxy-header trust, the
  `jsonl` sink path — never in hand-written security logic. Audit the defaults
  you did not choose. (2) The 480-test suite would not have caught any of them,
  and the missing order endpoint survived three "proven end-to-end" milestones
  because every proof used a hand-rolled client sharing the server's
  assumptions. **Mutation-verify new security tests** (three of the review's own
  tests initially passed against both vulnerable and fixed code), and prefer a
  client nobody here wrote for the next interop proof.
- **Remaining before pilot (not code debt):** the operator-owned §B–E items. The
  two-identity round-trip (WI-036) is now **fully proven live** (2026-07-24) — a
  separate revoker gMSA revoked at the CA and confirmed back, enrollment gMSA held
  no officer rights. (RCA of the earlier block, an out-of-project homelab AD issue
  — NOT clocks: new gMSAs need explicit AES etypes, else RC4 is added and blocked.)
  WI numbering: WI-011..015 exist only in plan documents, not the store — file new
  items with an explicit identifier ≥ WI-040.
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

**Previously on `main`: the 2026-08-11 security review** (13 findings; see
`docs/security-review-2026-08-11.md`). The load-bearing two: the JWS **and** EAB
URL bindings were derived from `str(request.url)` — i.e. the client's `Host`
header — so they only proved a client was self-consistent and an EAB minted for
another deployment verified here (which meant the 2026-08-07 EAB-replay fix was
never actually closed); and `account.status` was never read while the EAB kid was
re-checked only at finalize, so pulling a kid stopped issuance but left the
account able to **revoke its own live certificates**. Both are fixed and
live-proven (26/26 checks, 2026-08-11). Also: nonce token bucket, `/docs`
disabled, off-box audit gate, the previously-404 order/account resource
endpoints, and the PKCS#7 chain now bound to the leaf.
**Consequence for operators: `ACME_RA_BASE_URL` is now security configuration** —
wrong value ⇒ everything fail-closes.

