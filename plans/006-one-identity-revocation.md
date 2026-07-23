# Plan 006 — Single-identity revocation deployment option

**Status:** PROPOSED → IN PROGRESS. Authored 2026-07-23 by qwen3.8-max-preview.
Successor to [Plan 005](005-v1.5-feature-complete.md) (automated revocation via a
**separate** `gMSA-acme-revoker$`). **No target version bump** — this is an
additional *deployment configuration* for the v1.5 revocation automation, not a
new feature surface. The RA's issuance path and ACME surface are unchanged.

## Why this exists

Plan 005 shipped automated CA-side revocation under a **dedicated revoker
identity** (`gMSA-acme-revoker$`), deliberately separate from the enrollment
gMSA. That separation buys *compromise independence*: stealing the enrollment
credential lets an attacker issue but not revoke, and vice-versa.

The operator question (raised 2026-07-23): the `OfficerRights` template-scoping
proven in Plan 004 already bounds *which* certs any officer can revoke. If the
**enrollment gMSA itself** is granted the same template-scoped officer rights,
do we still need a second identity?

**Answer (recorded in threat-model §E):** the scoping bounds blast radius
*per-capability*; the identity separation makes the two capabilities *fail
independently*. Collapsing to one identity preserves the template boundary
(`OfficerRights` → `ACME-ServerAuth` only) and the requester boundary
(`Revoke-Cert.ps1` WI-022 check), but loses independence — a single credential
compromise now grants issue **and** revoke in one motion, enabling a
mint-and-swap attack (revoke the legitimate cert, issue a spoof under the same
SAN) that no single compromise grants in the two-identity design.

That is a defensible engineering trade-off for deployments where operational
simplicity (one identity to provision, rotate, monitor; one host) outweighs the
independence guarantee — **provided the decision is made explicitly and
recorded**, not left to happen by default. This plan promotes the
single-identity pathway as a **first-class, documented deployment option**
alongside the two-identity default.

## Ground truth (what already supports this with zero code change)

- **`Sync-Revocations.ps1`** already defaults `-RequesterName` to
  `WORK-DOMAIN\gMSA-acme-ra$` (the enrollment gMSA) and runs
  `certutil -revoke -config` (remote-capable). The requester check passes
  trivially when the revoker *is* the enrollment gMSA — still meaningful
  (rejects certs the RA did not issue, e.g. another principal's
  `ACME-ServerAuth` cert; validation-matrix C2).
- **`Set-OfficerRights.ps1` / `Get-OfficerRights.ps1`** are identity-agnostic
  (`-OfficerSid`). Pointing `-OfficerSid` at the enrollment gMSA's SID
  provisions the single-identity restriction.
- **The RA surface** (`GET /acme/admin/revocations/pending`,
  `POST /acme/admin/revocations/{serial}/confirm`, `revokeCert`) is
  identity-agnostic — the pull agent presents the admin token regardless of
  which gMSA runs it.
- **`Register-MaintenanceTasks.ps1`** already runs tasks as the enrollment gMSA
  (`-TaskUser` default `WORK-DOMAIN\gMSA-acme-ra$`) on the RA host.

## Work items

### WI-031 — `Sync-Revocations.ps1` single-host mode *(the one code touch)*
- Add a `-LocalMode` switch that signals single-identity deployment intent and
  adjusts the mode banner/output accordingly. The invocation mechanism
  (`& $pwshExe -File Revoke-Cert.ps1`) is **unchanged** in both modes — the
  child-process invocation is the correct way to capture exit codes regardless
  of deployment topology. `-LocalMode` is a documentation/intent flag: it tells
  the operator (via the banner) that the agent is running on the RA host under
  the enrollment gMSA, which is also the revoker.
- **AC:** `-LocalMode` adjusts the mode banner to indicate single-identity
  deployment; the invocation mechanism is unchanged; exit code 5 still aborts
  the batch; dry-run still default.

### WI-032 — Revocation-sync task registration under the enrollment gMSA
- Extend `Register-MaintenanceTasks.ps1` with an **opt-in**
  `-RegisterRevocationSync` switch (+ `-CaConfig`, `-RaBaseUrl` reuse,
  `-LocalMode`) that registers the `acme-adcs-ra-sync-revocations` task
  alongside the nonce/sweep tasks, running as `-TaskUser` (default the
  enrollment gMSA). Off by default so the two-identity utility-host deployment
  is unaffected. Idempotent like the existing tasks.
- **AC:** `-RegisterRevocationSync` registers the sync task as the enrollment
  gMSA on the RA host; without it, behaviour is unchanged.

### WI-033 — Threat-model §E decision record *(the load-bearing doc)*
- `docs/threat-model.md` §E gains a **"Single-identity deployment (explicit,
  recorded option)"** subsection: what the scoping preserves (template +
  requester boundaries), what it loses (compromise independence; the
  mint-and-swap escalation now reachable via one credential; the revoker role
  becomes co-resident with the internet-facing enrollment path), the explicit
  operator decision required, and the audit-granularity reduction (issuance and
  revocation share a requester in the CA DB). State plainly that this is a
  *defensible but weaker* posture than the two-identity default, chosen for
  operational simplicity.

### WI-034 — operations.md single-identity deployment runbook
- `docs/operations.md` automated-revocation section gains a **"Deployment
  variant: single-identity (enrollment gMSA as its own revoker)"** subsection:
  when to choose it, the explicit trade-off (cross-ref threat-model §E),
  provisioning (`Set-OfficerRights.ps1 -OfficerSid <enrollment-gMSA-SID>` +
  DCOM access + `ManageCertificates`), scheduling
  (`Register-MaintenanceTasks.ps1 -RegisterRevocationSync -LocalMode`), and the
  monitoring differences (issuance + revocation share a CA-DB requester, so the
  reconciliation cross-check matters more). Reaffirm the two hard provisioning
  constraints still apply (union semantics; DCOM access).

## Sequencing

WI-031 → WI-032 (registration references `-LocalMode`) → WI-033/WI-034 (docs
reference the final script shape). WI-033 and WI-034 are independent of each
other.

## Explicitly out of scope

- **Any issuance-path or ACME-surface change.** The RA Python is untouched;
  ruff/mypy/pytest are a no-op confirmation, not a test of new behaviour.
- **Changing the two-identity default.** Single-identity is an *additional*
  opt-in option; the dedicated-revoker design remains the recommended posture.
- **Weakening the requester check or OfficerRights scoping** in single-identity
  mode — both remain mandatory; C2 (template-scoped, not requester-scoped) is
  exactly why the requester check stays.
