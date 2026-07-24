# Live re-proof runbook (WI-038)

**Why this exists.** Cloud CI **cannot reach an ADCS CA**, so a green CI run does
**not** confirm that the enrollment and revocation legs still work — those depend
on a real CA, a domain-joined RA host, and a passwordless gMSA. This runbook is
the repeatable procedure for proving the ADCS integration end-to-end, plus the
cadence at which it must be run so "proven" does not decay silently.

> **Green CI ≠ ADCS-verified.** CI (lint + type + Python unit + Pester
> pure-logic + identifier-gate + pip-audit) proves the code and the operator
> scripts' *logic*. It does not prove issuance or CA-side revocation. Only this
> live re-proof does.

## Cadence (when to run it)

Run the full live re-proof:

1. **At every release** (before tagging), on the exact commit being shipped.
2. **Before any production pilot.**
3. **On a fixed interval while deployed** (recommended: quarterly) — a rot check
   against ADCS/OS/template drift the monthly Python rot-canary can't see.
4. **After any change to the issuance leg** (the standing project rule).

Record each run in the validation log in
[`pre-pilot-checklist.md`](pre-pilot-checklist.md).

## Prerequisites

- The deployed build on the RA host is the commit under test (`pip install
  --force-reinstall` the wheel into the app-pool venv; **deploy the entire
  `scripts/` directory including `scripts/lib/`** — the officer/registration
  scripts dot-source `scripts/lib/`).
- Access to the CA host (to provision/verify officer rights) and the RA host.
- A throwaway EAB credential + admin token in the RA dotenv (removed at teardown).

## Procedure

### A. Issuance + EKU (shared leg)

1. Start the RA app pool; confirm `GET /directory` → 200.
2. Drive a full ACME round-trip (new-account EAB → order → challenge → finalize →
   cert). Confirm: serverAuth-only EKU (WI-026 passes on a real cert),
   `clientAuth` absent, chain off the existing CA (no new intermediate), SAN from
   the CSR, requester = the enrollment gMSA in the CA DB.
3. Provoke a policy denial (out-of-scope SAN) → rejected at finalize.
4. Confirm reason-7 revocation is rejected (`badRevocationReason`).

### B. Automated revocation — two-identity (recommended topology)

1. Provision a dedicated revoker gMSA on a utility host: grant it
   **Certificate Manager (`0x2`, not Manage-CA)** on the CA security descriptor,
   apply the template-scoped `OfficerRights` (`Set-OfficerRights.ps1`), add
   `Certificate Service DCOM Access`, and confirm it belongs to **no** broader
   certificate-manager group (union-semantics constraint).
2. Register `Sync-Revocations.ps1` as a scheduled task **under the revoker gMSA**
   (`Register-MaintenanceTasks.ps1 -RegisterRevocationSync`, no `-LocalMode`,
   `-RequesterName <DOMAIN>\<enrollment-gMSA>$`).
3. Revoke a test cert in the RA (`revokeCert`), run the task, and confirm the
   round-trip: CA DB disposition = Revoked, RA pending set drains to empty,
   `ca_crl_updated=true`.
4. **Compromise independence:** confirm the **enrollment gMSA holds no officer
   rights** (its SID absent from the CA security descriptor's manager ACEs;
   `GetMyRoles` shows Enroll only).

### C. Automated revocation — single-identity (opt-in variant)

Same as B, but the enrollment gMSA itself holds the template-scoped officer
rights and the task runs on the RA host with `-LocalMode`. Confirm the
least-privilege bound holds: with the default (no `-PublishCrl`), the officer
revokes and confirms but the inline CRL republish is **denied** (needs Manage-CA);
the revocation appears at the next scheduled CRL publication.

### D. Enrollment-side bound (E-1)

Confirm the enrollment gMSA can enroll **only** `ACME-ServerAuth`, not `Machine`:
inspect the gMSA's live token (no `Machine`-enroll principal, e.g. Domain
Computers) and confirm issuance still works. See
[`revocation-scope-validation.md`](revocation-scope-validation.md) Finding E-1.

### E. Teardown (return to pristine)

Remove the `OfficerRights` value and restore the CA security descriptor to its
original bytes (back them up first); delete any test revoker gMSA + its CA grant;
unregister the scheduled tasks; restore the RA store DB + dotenv (removing the
throwaway EAB + admin token); stop the app pool if the deployment is parked.
Leave the CA and RA exactly as found. **Do not** revert the E-1 remediation (the
enrollment gMSA's restricted primary group is a permanent hardening, not a test
artifact).

## Environment gotchas (observed)

- **gMSA scheduled tasks** need `LogonType=Password` (a gMSA never logs on
  interactively). `Register-MaintenanceTasks.ps1` sets this.
- **`certutil` argument order:** `-config` must precede the `-revoke`/`-CRL` verb.
- **CA-side officer provisioning** must ship `scripts/lib/` alongside the scripts.
- **Newly-created gMSAs** require the domain's KDS + DC time to be healthy: if DC
  clocks disagree (e.g. Hyper-V VMIC syncing each DC to a skewed host clock), a
  new gMSA can be stamped with a KDS key index that other DCs treat as *future*,
  making its managed password unretrievable until the clocks converge. A working
  domain (synced DCs) is a prerequisite for provisioning a new revoker identity.
