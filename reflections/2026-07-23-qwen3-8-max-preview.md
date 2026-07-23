---
model: qwen3.8-max-preview
datetime: 2026-07-23T12:00Z
project: acme-adcs-ra
---

# Session Reflection — 2026-07-23

**Work summary:** Implemented the full v1.5 automated-revocation feature set
(WI-022 through WI-027) on branch `v1.5-automated-revocation`. WI-026 (EKU
post-issuance verification) was already in-tree from a prior branch; merged it
in. Added the `GET /acme/admin/revocations/pending` pull endpoint (WI-023), the
`POST /acme/admin/revocations/{serial}/confirm` callback, the
`Sync-Revocations.ps1` pull agent (WI-024), the `Revoke-Cert.ps1` requester
check (WI-022), `Set-OfficerRights.ps1`/`Get-OfficerRights.ps1` (WI-025), the
operations.md automated-revocation runbook, and the threat-model §E addendum
(WI-027). Ran a cross-lineage adversarial review (kimi), fixed all CRITICAL/HIGH
findings, and landed at 461 tests passing, ruff clean, mypy clean.

---

## On the project

This codebase rewards discipline. The CAS-everywhere store, the honest audit
trail, the `RevocationLeg` protocol seam — all of it meant the v1.5 additions
slotted in without touching the issuance path at all. The one structural decision
that paid off most was keeping the enrollment gMSA and the revoker gMSA separate:
it meant the entire WI-024 agent could be built as a pure operator-side concern
with zero changes to the RA's security posture. The `ca_crl_updated` column was
the one piece of state the store was genuinely missing; adding it was a 5-line
migration and it made the pending/confirm loop actually terminate, which the
adversarial reviewer caught before it shipped as a silent infinite-re-revoke bug.

The PowerShell scripts are the weakest link in terms of testability — there's no
way to exercise them on Linux CI, so correctness rests on careful reading and the
live lab re-proof (WI-028). `Set-OfficerRights.ps1` in particular is doing
byte-level SD construction with no golden-bytes regression test; a drift there
would only surface on a real CA. That's an accepted gap given the platform
constraint, but it's the thing I'd most want a second pair of eyes on before a
production pilot.

## On the work done

The parallel-subagent approach worked well: kimi handled WI-023 (Python) while
glm handled WI-022/024/025 (PowerShell + docs) concurrently, and both delivered
clean implementations. The adversarial review (kimi, cross-lineage) was
genuinely useful — it caught H-4 (the pending set never shrinking) which was a
real design gap, not just a style nit. The fix (a `ca_crl_updated` column +
filtered query + idempotent confirm) is clean and matches the documented
semantics.

The one thing I'm less confident about is `Set-OfficerRights.ps1`'s
`certutil -setreg` fallback path. The script writes via certutil, verifies by
readback, and falls back to the PowerShell registry provider if the readback
doesn't match — but the fallback path itself lacks an immediate readback
verification (M-5 from the review). The main body does verify after the restart,
so it's not silent, but the contract is slightly asymmetric. Worth a look during
the WI-028 lab pass.

## On what remains

**Gates the v1.5 release (WI-028):**
1. Live lab re-proof on the deployed build: normal issuance + EKU check pass,
   provoked non-serverAuth issuance rejected by WI-026, automated revocation
   round-trip (RA `revokeCert` → agent → CA CRL) with requester check and
   officer restriction both active.
2. WI-030 `[R]` rows (A3, A4, A5, B2, C2, C3, C4, E2) — run on the officer
   provisioned during WI-028 setup, record results in
   `docs/revocation-scope-validation.md`.
3. WI-029: CHANGELOG `[1.5.0]`, version bump, tag, GitHub release.

**Nice to have (not blocking):**
- Offline golden-bytes test for `Set-OfficerRights.ps1` (C-1 from review).
- Readback verification after the registry-provider fallback in
  `Set-OfficerRights.ps1` (M-5).
- Integration test asserting `Sync-Revocations.ps1`'s constructed URLs match
  the FastAPI router paths (M-7).

## Gaps to flag

- `scripts/Set-OfficerRights.ps1:251-275` — registry-provider fallback path
  lacks immediate readback verification (M-5); the main body catches it after
  certsvc restart, but the function contract is asymmetric.
- `scripts/Set-OfficerRights.ps1` — no offline golden-bytes regression test;
  byte-level SD drift would only surface on a live CA (C-1). Accepted gap
  given platform constraint, but flag for WI-028 lab pass.
- `scripts/Sync-Revocations.ps1` — if a cert was already revoked at the CA
  out-of-band (before the agent ran), `Revoke-Cert.ps1` exits non-zero and the
  agent logs it as a failure without confirming. The RA audit stays at
  `ca_crl_updated=false` forever for that serial. Documented as a known
  limitation; operator must handle pre-existing CA revocations manually (M-4).
- `src/acme_adcs_ra/routes/admin.py:220` — the confirm endpoint strips `0x`
  prefix (M-2 fix applied), but the pending endpoint returns serials without
  `0x`, so this is defense-in-depth only; no active bug.
- WI-021 (EKU verification gap) is still open in the work-item store — it was
  the original MED-1 gap that WI-026 closes. Should be transitioned to done
  once WI-028 passes.
